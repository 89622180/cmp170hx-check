#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CMP 170HX 解锁上限只读自查（Ubuntu 直接运行 / 自动找卡 / 输出中文报告）

用法（目标机不需要任何 agent、不需要联网、只用系统自带 python3）：

    sudo python3 cmp170hx_check.py

    跑完在当前目录生成两个文件：
        cmp170hx_report_<主机名>_<时间>.txt     ← 人看的报告，直接发我
        cmp170hx_report_<主机名>_<时间>.json    ← 原始数据，留档/复核

其它用法：
    sudo python3 cmp170hx_check.py --regs          # 报告末尾附全部原始寄存器
    sudo python3 cmp170hx_check.py --smi           # 额外对照 nvidia-smi（会唤醒卡）
    sudo python3 cmp170hx_check.py -o /tmp/out     # 指定输出目录
    sudo python3 cmp170hx_check.py --bdf 0000:01:00.0 --uuid GPU-xxxx...   # 只跑一张
    python3 cmp170hx_check.py --render xxx.json    # 把旧 JSON 重新渲染成中文报告（不用 root）

安全性（与原脚本同一条边界，没有放宽）：
  * 只 mmap /sys/bus/pci/devices/<BDF>/resource0，O_RDONLY + PROT_READ
    （MAP_SHARED 但 PROT_READ，无任何写路径；本文件不存在 store/write 方法）
  * 只读白名单内的固定偏移，偏移表与原脚本 1032 行版本一致（GA100 dev_fuse.h + gpcprobe）
  * 不写 GPU 寄存器、不写 PCI 配置空间、不发 fuse READ 命令、不动 selector/control
  * 默认不起 nvidia-smi、不 ioctl、不碰 /dev/mem、不改驱动、不做任何"解锁"动作
  * 自动找卡只读 vendor/device/class 三个 sysfs 文本，不做 BAR 访问
  * 每张卡 fork 一个子进程读，父进程 20s 超时回收，防止 BAR0 读故障把整批拖死
  * 先验 UUID/Bus Location/PMC_BOOT_0 芯片签名/OPT_PCIE_DEVIDA fuse SKU，四关不过就停
  * 两遍读取逐字比对，不一致即判失败，不重试

偏移交叉核对来源：GA100 dev_fuse.h、https://github.com/matstatman/gpcprobe（2026-10-18 复核）
sysfs 访问路径：https://docs.kernel.org/PCI/sysfs-pci.html

v2026-11-15 修正（对照 https://arca.live/b/aihomelab/186266420 的 2026-10-18 回帖）：
  1) 显存基准改成 4 GiB / FBPA（驱动实测 64 GiB ÷ 16 个活跃 FBPA），
     旧版用"24 FBPA = 80 GiB"会把现役 16 分区的卡算成 53.3 GiB，与 nvidia-smi 对不上。
  2) "关掉的 8 个 FBPA = 两整条 HBM 栈"这个分组是错的：按 gpcprobe 的映射，
     位点 s = FBPA 4s..4s+3，关掉的 {2,3,8,9,12,13,22,23} 散在四个位点里、每位点占一半。
  3) SM 上限同时给出两种口径（按 GPC 父位 / 按挂缺陷 TPC 计数），两者不一致会明确提示。
  4) 显存物理天花板 = 板载 HBM 颗粒数，寄存器读不出来，不再假装能算。
  5) 删掉"顶级/良好/一般"这种社区档位标签——样本本身就从 108 散到 126，贴标签没信息量。
"""

import argparse
import datetime
import json
import mmap
import os
import platform
import re
import select
import signal
import socket
import struct
import sys
import time
import unicodedata
from pathlib import Path

VERSION = "2026-11-15.ubuntu.2"

SUPPORTED_DEVICES = {0x20C2: "CMP 170HX 8GB SKU", 0x2082: "CMP 170HX 10GB SKU"}
VENDOR_NVIDIA = 0x10DE
PAGE_BYTES = 4096
TIMEOUT_SECONDS = 20.0

# ---- GA100 拓扑常量（用于把缺陷/禁用位折算成 SM 与显存估算） ----
GPC_COUNT = 8
TPC_PER_GPC = 8
SM_PER_TPC = 2
SM_PER_GPC = TPC_PER_GPC * SM_PER_TPC          # 16
TOTAL_SM = GPC_COUNT * SM_PER_GPC              # 128
FULL_FBP = 12
FULL_FBPA = 24
FULL_FBIO = 24
# GA100 的 HBM 位点是 6 个，每个逻辑位点 s 带 FBPA 4s..4s+3；一个 FBP 带 2 个 FBPA
# （FBP i ↔ FBPA 2i、2i+1）。映射来源：
#   https://github.com/matstatman/gpcprobe/blob/master/gpc_probe.py
#   https://arca.live/b/aihomelab/186266420（2026-10-18 回帖纠正了"关掉的 8 个 FBPA
#   等于两整栈"这个分组：它们其实散在四个位点里，每位点半份）
FBPA_PER_SITE = 4
HBM_SITES = FULL_FBPA // FBPA_PER_SITE     # 6
FBPA_PER_FBP = 2
# 每 FBPA 的折算基准。GA100 满配 HBM2e 单栈 16 GiB、每栈 4 个 FBPA ⇒ 4 GiB / FBPA。
# 老版本这里写的是"全 24 FBPA = 80 GiB"（=3.33 GiB/FBPA），会把现役 16 FBPA 的卡
# 报成 53.3 GiB，而驱动实测是 64 GiB —— 那个基准是错的，已按实测口径改掉。
PER_FBPA_GIB = 4.0
# 板载 HBM 颗粒数量才是真上限：寄存器只能告诉你哪个分区死了，不能告诉你哪一栈有颗粒。
# 社区实测口径（同帖回帖，2026-10-18）：只焊 4 颗 ⇒ 64 GiB 封顶，fuse 全开也变不出颗粒。

# (name, BAR0 byte offset, accepted low-bit width). NO command/data ports.
REGISTERS = (
    ("PMC_BOOT_0", 0x00000000, 32),
    ("OPT_PCIE_DEVIDA", 0x008204D8, 16),
    ("OPT_GPC_DISABLE", 0x00820350, 8),
    ("OPT_GPC_DEFECTIVE", 0x008205C4, 8),
    ("STATUS_OPT_GPC", 0x00820C1C, 8),
    ("CTRL_OPT_GPC", 0x0082081C, 8),
    ("OPT_FBP_DISABLE", 0x00820364, 12),
    ("OPT_FBP_DEFECTIVE", 0x008205CC, 12),
    ("STATUS_OPT_FBP", 0x00820D38, 12),
    ("CTRL_OPT_FBP", 0x00820938, 12),
    ("OPT_FBPA_DISABLE", 0x00820368, 24),
    ("OPT_FBPA_DEFECTIVE", 0x008205D0, 24),
    ("STATUS_OPT_FBPA", 0x00820C18, 24),
    ("CTRL_OPT_FBPA", 0x00820818, 24),
    ("OPT_FBIO_DISABLE", 0x0082036C, 24),
    ("OPT_FBIO_DEFECTIVE", 0x008205D4, 24),
    ("STATUS_OPT_FBIO", 0x00820C14, 24),
    ("CTRL_OPT_FBIO", 0x00820814, 24),
    ("EN_SW_OVERRIDE", 0x00820040, 1),
    ("DISABLE_SW_OVERRIDE_STATUS", 0x00820084, 1),
    ("OPT_SECURE_GSP_DEBUG_DIS", 0x0082074C, 1),
) + tuple(
    ("OPT_TPC_DISABLE_GPC%d" % i, 0x00820760 + 4 * i, 8) for i in range(8)
) + tuple(
    ("OPT_TPC_GPC%d_DEFECTIVE" % i, off, 8)
    for i, off in enumerate((
        0x008205C8, 0x00820508, 0x0082050C, 0x00820514,
        0x00820564, 0x008205AC, 0x00820B84, 0x00820B80,
    ))
) + tuple(
    ("STATUS_OPT_TPC_GPC%d" % i, 0x00820C38 + 4 * i, 8) for i in range(8)
) + tuple(
    ("CTRL_OPT_TPC_GPC%d" % i, 0x00820838 + 4 * i, 8) for i in range(8)
)
ALLOWED_OFFSETS = frozenset(off for _, off, _ in REGISTERS)
REQUIRED_BAR_BYTES = ((max(ALLOWED_OFFSETS) // PAGE_BYTES) + 1) * PAGE_BYTES


class StopProbe(RuntimeError):
    pass


# 设备/驱动视图的根路径（保留为模块级可替换变量，便于离线自测）
SYSFS_PCI = Path("/sys/bus/pci/devices")
PROC_NVIDIA = Path("/proc/driver/nvidia/gpus")


# ---------------------------------------------------------------- 终端排版工具

def disp_width(text):
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in text)


def pad(text, width, align="<"):
    gap = max(0, width - disp_width(text))
    return (" " * gap + text) if align == ">" else (text + " " * gap)


def popcount(value):
    return bin(value & 0xFFFFFFFF).count("1")


def bit_indices(mask, width):
    return [i for i in range(width) if mask & (1 << i)]


def fmt_bits(indices):
    return ",".join(str(i) for i in indices) if indices else "-"


def fmt_mask(mask, width):
    return "0x%0*X" % ((width + 3) // 4, mask)


# ---------------------------------------------------------------- 身份与地址

def normalize_bdf(value):
    match = re.fullmatch(
        r"([0-9a-fA-F]{4}|[0-9a-fA-F]{8}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])", value)
    if not match:
        raise ValueError("BDF 格式应为 0000:03:00.0 这种完整形式")
    domain, bus, device, function = (int(part, 16) for part in match.groups())
    if domain > 0xFFFF or device > 0x1F:
        raise ValueError("PCI domain 或 device 号越界")
    return "%04x:%02x:%02x.%x" % (domain, bus, device, function)


def normalize_uuid(value):
    if not re.fullmatch(
            r"GPU-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            value, re.IGNORECASE):
        raise ValueError("UUID 应为完整物理 GPU UUID：GPU-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
    return "GPU-" + value[4:].lower()


class Target(object):
    def __init__(self, bdf, gpu_uuid=None):
        self.bdf = normalize_bdf(bdf)
        self.gpu_uuid = normalize_uuid(gpu_uuid) if gpu_uuid else None

    @property
    def device_path(self):
        return SYSFS_PCI / self.bdf

    @property
    def info_path(self):
        return PROC_NVIDIA / self.bdf / "information"

    def __repr__(self):
        return "<Target %s %s>" % (self.bdf, self.gpu_uuid or "auto")


def read_text(path):
    """只读打开（不允许符号链接跟随），限制长度，专供 /proc 与 /sys 小文本。"""
    fd = os.open(str(path), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        with os.fdopen(fd, "r", encoding="ascii", errors="replace") as stream:
            fd = None
            text = stream.read(16385)
        if len(text) > 16384:
            raise StopProbe("元数据异常大：%s" % path)
        return text
    finally:
        if fd is not None:
            os.close(fd)


def discover_targets(only_bdf=None):
    """只读 vendor/device/class 三个 sysfs 文本，找出所有 10de:20c2 / 10de:2082。"""
    root = SYSFS_PCI
    if not root.is_dir():
        raise StopProbe("找不到 /sys/bus/pci/devices，这台机器没有可用的 sysfs PCI 视图")
    found = []
    for entry in sorted(root.iterdir(), key=lambda p: p.name):
        try:
            vendor = int(read_text(entry / "vendor").strip(), 16)
            if vendor != VENDOR_NVIDIA:
                continue
            device = int(read_text(entry / "device").strip(), 16)
            if device not in SUPPORTED_DEVICES:
                continue
            if only_bdf and normalize_bdf(entry.name) != only_bdf:
                continue
            found.append(Target(entry.name))
        except (OSError, ValueError, StopProbe):
            continue
    if only_bdf and not found:
        raise StopProbe("指定的 %s 不是 10de:20c2 / 10de:2082，或该槽位没有对应设备" % only_bdf)
    return found


def card_uuid(target):
    """从驱动缓存的 /proc/driver/nvidia/gpus/<BDF>/information 读物理 UUID 与 Bus Location。"""
    info = read_text(target.info_path)
    uuids = re.findall(r"^GPU UUID[ \t]*:[ \t]*(\S+)[ \t]*\r?$", info, re.MULTILINE)
    locations = re.findall(r"^Bus Location[ \t]*:[ \t]*(\S+)[ \t]*\r?$", info, re.MULTILINE)
    if len(uuids) != 1 or len(locations) != 1:
        raise StopProbe("驱动缓存里的 UUID / Bus Location 缺失或有歧义")
    return normalize_uuid(uuids[0]), normalize_bdf(locations[0])


# ---------------------------------------------------------------- 前置检查

def preflight(target):
    device_path = target.device_path
    vendor = int(read_text(device_path / "vendor").strip(), 16)
    device = int(read_text(device_path / "device").strip(), 16)
    pci_class = int(read_text(device_path / "class").strip(), 16)
    if vendor != VENDOR_NVIDIA or device not in SUPPORTED_DEVICES or pci_class >> 16 != 0x03:
        raise StopProbe("这块卡不是支持的 CMP 170HX（10de:20c2 或 10de:2082）")
    try:
        driver = Path(os.readlink(str(device_path / "driver"))).name
    except OSError:
        raise StopProbe("该 BDF 没有绑定任何驱动（nvidia 驱动没起来？）")
    if driver != "nvidia":
        raise StopProbe("绑定的驱动是 %s，不是 nvidia；本脚本不换驱动" % driver)

    cached_uuid, cached_bdf = card_uuid(target)
    if target.gpu_uuid and cached_uuid != target.gpu_uuid:
        raise StopProbe("驱动缓存 UUID 与 --uuid 不一致（%s vs %s）" % (cached_uuid, target.gpu_uuid))
    if cached_bdf != target.bdf:
        raise StopProbe("驱动缓存 Bus Location 与 BDF 不一致（%s vs %s）" % (cached_bdf, target.bdf))
    target.gpu_uuid = target.gpu_uuid or cached_uuid

    enabled = int(read_text(device_path / "enable").strip(), 10)
    state = read_text(device_path / "power_state").strip()
    runtime = read_text(device_path / "power/runtime_status").strip()
    if enabled <= 0 or state != "D0" or runtime not in ("active", "unsupported"):
        raise StopProbe("卡不是已启用/已唤醒状态（enable=%d, %s, %s）；本脚本不会去唤醒它"
                        % (enabled, state, runtime))

    fields = read_text(device_path / "resource").splitlines()[0].split()
    if len(fields) != 3:
        raise StopProbe("sysfs BAR0 资源描述格式异常")
    start, end, flags = (int(value, 16) for value in fields)
    if start == 0 or end < start or not flags & 0x200 or flags & 0x100:
        raise StopProbe("BAR0 不是合法的内存资源；不会退回读 PCI 配置空间")
    bar_bytes = end - start + 1
    if bar_bytes < REQUIRED_BAR_BYTES:
        raise StopProbe("BAR0 太小（%d 字节），装不下白名单里的状态字" % bar_bytes)
    return {
        "driver": driver, "power_state": state, "runtime_status": runtime,
        "bar0_bytes": bar_bytes, "bar0_start": "0x%X" % start, "bar0_end": "0x%X" % end,
        "uuid_matched": True, "bdf_matched": True,
        "pci_device_id": device, "pci_id": "10de:%04x" % device,
        "sku": SUPPORTED_DEVICES[device],
    }


class ReadOnlyBar(object):
    """没有 store 方法；FD 与 VM 两层权限都禁止写入。"""

    def __init__(self, path):
        self.fd = os.open(str(path), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        self.pages = {}
        try:
            size = os.fstat(self.fd).st_size
            if size < REQUIRED_BAR_BYTES:
                raise StopProbe("sysfs resource0 不存在或被截断；不做任何退避访问")
        except BaseException:
            os.close(self.fd)
            self.fd = None
            raise

    def read32(self, offset):
        if offset not in ALLOWED_OFFSETS or offset % 4:
            raise StopProbe("读取越出固定寄存器白名单")
        page = (offset // PAGE_BYTES) * PAGE_BYTES
        if page not in self.pages:
            region = mmap.mmap(self.fd, PAGE_BYTES, flags=mmap.MAP_SHARED,
                               prot=mmap.PROT_READ, offset=page)
            try:
                words = memoryview(region).cast("I")
                if not words.readonly or words.itemsize != 4:
                    words.release()
                    raise StopProbe("映射出来的不是只读原生 uint32 视图")
            except BaseException:
                region.close()
                raise
            self.pages[page] = (region, words)
        return int(self.pages[page][1][(offset - page) // 4])

    def close(self):
        for region, words in self.pages.values():
            try:
                words.release()
            except Exception:
                pass
            region.close()
        self.pages.clear()
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def validate_word(name, value, width, expected_device):
    if value == 0xFFFFFFFF or value & 0xFFFF0000 == 0xBADF0000:
        raise StopProbe("%s 读到不可读/PRI 哨兵值 0x%08X；不重试" % (name, value))
    if value < 0 or value >= (1 << width):
        raise StopProbe("%s 出现了超出建模位宽的位；不做解释" % name)
    if name == "PMC_BOOT_0" and value != 0x170000A1:
        raise StopProbe("芯片签名不是 GA100（0x%08X），立刻停止后续读取" % value)
    if name == "OPT_PCIE_DEVIDA" and (expected_device not in SUPPORTED_DEVICES
                                      or value != expected_device):
        raise StopProbe("fuse SKU 与 PCI Device ID 不匹配；立刻停止后续读取")


# ---------------------------------------------------------------- 结果解释

def interpret(values):
    """把原始寄存器位折算成 GPC/TPC/FBP 状态与 SM、显存估算。"""
    result = {
        "classification_only_not_an_unlock_limit": True,
        "groups": {},
        "tpc_per_gpc": [],
        "sm": {},
        "vram": {},
        "gate_readouts": {name: values[name] for name in (
            "EN_SW_OVERRIDE", "DISABLE_SW_OVERRIDE_STATUS", "OPT_SECURE_GSP_DEBUG_DIS")},
    }

    for group, width in (("GPC", 8), ("FBP", 12), ("FBPA", 24), ("FBIO", 24)):
        disabled = values["OPT_%s_DISABLE" % group]
        defective = values["OPT_%s_DEFECTIVE" % group]
        effective = values["STATUS_OPT_%s" % group]
        result["groups"][group] = {
            "width": width,
            "fuse_disabled_mask": fmt_mask(disabled, width),
            "defective_mask": fmt_mask(defective, width),
            "effective_mask": fmt_mask(effective, width),
            "fuse_disabled_mask_int": disabled,
            "defective_mask_int": defective,
            "effective_mask_int": effective,
            "ctrl_opt_raw": fmt_mask(values["CTRL_OPT_%s" % group], 32),
            "fuse_disabled_indices": bit_indices(disabled, width),
            "defect_marked_indices": bit_indices(defective, width),
            "disabled_without_defect_flag": bit_indices(disabled & ~defective, width),
            "effective_disabled_indices": bit_indices(effective, width),
            "effective_enabled_count": width - popcount(effective),
            "effective_not_disabled_indices": bit_indices(~effective & ((1 << width) - 1), width),
            "fuse_and_effective_mask_equal": disabled == effective,
        }

    # ---- 逐 GPC 的 TPC 明细 + SM 折算 ----
    eff_sm = eff_tpc = 0
    rec_sm = rec_tpc = 0
    defect_sm = 0
    gpc_disabled_mask = values["STATUS_OPT_GPC"]
    gpc_defect_mask = values["OPT_GPC_DEFECTIVE"]
    for gpc in range(GPC_COUNT):
        disabled = values["OPT_TPC_DISABLE_GPC%d" % gpc]
        defective = values["OPT_TPC_GPC%d_DEFECTIVE" % gpc]
        effective = values["STATUS_OPT_TPC_GPC%d" % gpc]
        parent_off = bool(gpc_disabled_mask & (1 << gpc))
        parent_bad = bool(gpc_defect_mask & (1 << gpc))

        row = {
            "gpc": gpc,
            "parent_gpc_effectively_disabled": parent_off,
            "parent_gpc_defect_marked": parent_bad,
            "fuse_disabled_mask": fmt_mask(disabled, 8),
            "defective_mask": fmt_mask(defective, 8),
            "effective_mask": fmt_mask(effective, 8),
            "fuse_disabled_indices": bit_indices(disabled, 8),
            "defect_marked_indices": bit_indices(defective, 8),
            "disabled_without_local_defect_flag": bit_indices(disabled & ~defective, 8),
            "effective_disabled_indices": bit_indices(effective, 8),
        }

        if parent_off and parent_bad:
            row["state"] = "gpc_defective"
            row["enabled_tpc"] = 0
            row["recoverable_tpc"] = 0
            defect_sm += SM_PER_GPC
        elif parent_off:
            usable = TPC_PER_GPC - popcount(defective)
            row["state"] = "gpc_disabled_only"
            row["enabled_tpc"] = 0
            row["recoverable_tpc"] = usable
            rec_tpc += usable
            rec_sm += usable * SM_PER_TPC
            defect_sm += popcount(defective) * SM_PER_TPC
        else:
            enabled = TPC_PER_GPC - popcount(effective)
            recover = popcount(effective & ~defective)
            row["state"] = "active"
            row["enabled_tpc"] = enabled
            row["recoverable_tpc"] = recover
            eff_tpc += enabled
            eff_sm += enabled * SM_PER_TPC
            rec_tpc += recover
            rec_sm += recover * SM_PER_TPC
            defect_sm += popcount(defective) * SM_PER_TPC
        result["tpc_per_gpc"].append(row)

    # 第二种口径（与 arca.live 帖子一致）：只数"挂了缺陷标记的 TPC"，
    # 上限 = (64 − 标坏 TPC 数) × 2。和上面按 GPC 父位整组扣的算法应当一致；
    # 不一致就说明 GPC 父位与 TPC 子位对不上，值得在报告里点出来。
    defect_tpc_marked = sum(popcount(values["OPT_TPC_GPC%d_DEFECTIVE" % gpc])
                            for gpc in range(GPC_COUNT))
    result["sm"] = {
        "total_sm_on_die": TOTAL_SM,
        "effective_sm": eff_sm,
        "effective_tpc": eff_tpc,
        "recoverable_sm": rec_sm,
        "recoverable_tpc": rec_tpc,
        "defect_stuck_sm": defect_sm,
        "upper_bound_sm": eff_sm + rec_sm,
        "checked_sum_equals_die_total": (eff_sm + rec_sm + defect_sm) == TOTAL_SM,
        "defect_marked_tpc_total": defect_tpc_marked,
        "defect_marked_tpc_total_per_gpc": [
            popcount(values["OPT_TPC_GPC%d_DEFECTIVE" % gpc]) for gpc in range(GPC_COUNT)],
        "defect_based_ceiling_sm": (TOTAL_SM // SM_PER_TPC - defect_tpc_marked) * SM_PER_TPC,
        "both_ceiling_methods_agree": (
            (TOTAL_SM // SM_PER_TPC - defect_tpc_marked) * SM_PER_TPC) == (eff_sm + rec_sm),
    }

    # ---- 显存通路 ----
    fbpa = result["groups"]["FBPA"]
    fbp = result["groups"]["FBP"]
    fbpa_on = fbpa["effective_enabled_count"]
    clean_off = bit_indices(fbpa["fuse_disabled_mask_int"] & ~fbpa["defective_mask_int"],
                            FULL_FBPA)
    defect_on = bit_indices(fbpa["defective_mask_int"], FULL_FBPA)

    # 逻辑 HBM 位点：位点 s = FBPA 4s..4s+3（gpcprobe 的映射）。
    # "关掉的 FBPA = 两整栈"是错的；它们散在四个位点里、每位点半份。
    sites = []
    for site in range(HBM_SITES):
        lo = site * FBPA_PER_SITE
        rng = range(lo, lo + FBPA_PER_SITE)
        site_on = [i for i in rng if not (fbpa["effective_mask_int"] >> i) & 1]
        sites.append({
            "site": site,
            "fbpa_range": "%d-%d" % (lo, lo + FBPA_PER_SITE - 1),
            "enabled_count": len(site_on),
            "clean_disabled": [i for i in rng if i in clean_off],
            "defect_marked": [i for i in rng if i in defect_on],
            "whole_stack_off": len(site_on) == 0,
        })

    # FBP i 带 FBPA 2i、2i+1：把 FBP 掩码展开后应与 FBPA 掩码逐位相等。
    # 这是唯一一个能在这台机器上自证"位点映射"的交叉核对，所以每次都算一遍。
    def expand_fbp(mask):
        out = 0
        for i in range(FULL_FBP):
            if mask & (1 << i):
                out |= 1 << (FBPA_PER_FBP * i)
                out |= 1 << (FBPA_PER_FBP * i + 1)
        return out

    fbp_expanded = expand_fbp(fbp["effective_mask_int"])
    map_ok = fbp_expanded == fbpa["effective_mask_int"]
    map_ok_defect = expand_fbp(fbp["defective_mask_int"]) == fbpa["defective_mask_int"]

    result["vram"] = {
        "fbp_enabled": fbp["effective_enabled_count"], "fbp_total": FULL_FBP,
        "fbp_to_fbpa_map": "FBP i -> FBPA 2i, 2i+1",
        "fbp_mask_expanded_to_fbpa": fmt_mask(fbp_expanded, FULL_FBPA),
        "fbpa_mask_matches_expanded_fbp": map_ok,
        "fbpa_defect_mask_matches_expanded_fbp": map_ok_defect,
        "fbpa_enabled": fbpa_on, "fbpa_total": FULL_FBPA,
        "fbpa_clean_disabled": clean_off,
        "fbpa_defect_marked": defect_on,
        "fbio_enabled": result["groups"]["FBIO"]["effective_enabled_count"],
        "fbio_total": FULL_FBIO,
        "hbm_sites": HBM_SITES, "fbpa_per_site": FBPA_PER_SITE,
        "site_breakdown": sites,
        "per_fbpa_gib_assumed": PER_FBPA_GIB,
        "active_partitions_gib": round(fbpa_on * PER_FBPA_GIB, 1),
        "logic_ceiling_gib": round((fbpa_on + len(clean_off)) * PER_FBPA_GIB, 1),
        "logic_ceiling_partitions": fbpa_on + len(clean_off),
        # 寄存器只告诉你哪个分区被关/被标坏，告诉不了你那个分区背后到底焊没焊颗粒。
        # 板载 HBM 颗粒数才是硬上限；fuse 全开也变出不存在的颗粒。
        "physical_ceiling_gib": None,
        "physical_ceiling_note": "板载 HBM 颗粒数决定，BAR0 寄存器读不出来（需拆卡/查 BOM）。",
    }
    return result


# ---------------------------------------------------------------- 采集（子进程内）

def new_report(target):
    return {
        "script_version": VERSION,
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "target": {"bdf": target.bdf, "gpu_uuid": target.gpu_uuid,
                   "pci_id": None, "sku": None},
        "status": "STOPPED",
        "complete": False,
        "access_policy": {
            "path": "/sys/bus/pci/devices/<BDF>/resource0",
            "open": "O_RDONLY | O_CLOEXEC | O_NOFOLLOW",
            "mapping": "MAP_SHARED, PROT_READ; 白名单偏移，逐页按需映射",
            "gpu_register_writes_in_script": 0,
            "pci_config_writes_in_script": 0,
            "fuse_commands_in_script": 0,
            "fallback": "none",
            "planned_passes": 2,
        },
        "registers": [],
        "interpretation": None,
        "limits": [
            "掩码是配置/缺陷标记的记录，不是健康度测试。",
            "本脚本没有启用、也没有实测任何隐藏显存或停用 SM。",
            "SM / 显存数字是按缺陷标记折算的估算，不是实测上限。",
            "显存的物理天花板由板载 HBM 颗粒数决定，BAR0 读不出来。",
            "现有 NVIDIA 驱动可能独立于本脚本自行动作。",
        ],
    }


def collect(target, progress=lambda stage: None):
    report = new_report(target)
    bar = None
    try:
        progress("识别身份与现有电源状态")
        identity = preflight(target)
        report["identity_check"] = identity
        report["target"].update(pci_id=identity["pci_id"], sku=identity["sku"])
        progress("以只读方式打开 sysfs resource0")
        bar = ReadOnlyBar(target.device_path / "resource0")
        first = {}
        for pass_number in (1, 2):
            for index, (name, offset, width) in enumerate(REGISTERS):
                progress("第 %d 遍 %s @ 0x%08X" % (pass_number, name, offset))
                value = bar.read32(offset)
                if pass_number == 1:
                    report["registers"].append({
                        "name": name, "offset": "0x%08X" % offset,
                        "value": "0x%08X" % value, "second_read_matches": False})
                validate_word(name, value, width, identity["pci_device_id"])
                if pass_number == 1:
                    first[name] = value
                elif value != first[name]:
                    report["registers"][index]["second_value"] = "0x%08X" % value
                    raise StopProbe("%s 两遍读取不一致；不重试" % name)
                else:
                    report["registers"][index]["second_read_matches"] = True
        bar.close()
        bar = None
        progress("复核身份未发生变化")
        if preflight(target) != identity:
            raise StopProbe("快照期间身份或电源/资源状态发生变化")
        report["interpretation"] = interpret(first)
        report["complete"] = True
        report["status"] = "COMPLETE"
        report["matching_passes"] = 2
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if bar is not None:
            bar.close()
    return report


def send_event(fd, event):
    payload = (json.dumps(event, separators=(",", ":")) + "\n").encode("ascii")
    while payload:
        count = os.write(fd, payload)
        if count <= 0:
            raise RuntimeError("结果管道已关闭")
        payload = payload[count:]


def supervise(target, verbose=True):
    """子进程读卡，父进程超时回收：BAR0 读故障(SIGBUS)不会把整批扫描拖垮。"""
    read_fd, write_fd = os.pipe()
    try:
        pid = os.fork()
    except BaseException:
        os.close(read_fd)
        os.close(write_fd)
        raise
    if pid == 0:
        os.close(read_fd)
        try:
            try:
                import resource
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            except Exception:
                pass
            report = collect(target, lambda stage: send_event(write_fd, {"stage": stage}))
            send_event(write_fd, {"result": report})
        except BaseException:
            os._exit(3)
        finally:
            try:
                os.close(write_fd)
            except Exception:
                pass
        os._exit(0)

    os.close(write_fd)
    deadline = time.monotonic() + TIMEOUT_SECONDS
    buffer = b""
    last_stage = "启动子进程"
    result = None
    failure = None
    reaped, status = 0, 0

    def handle_event(event):
        nonlocal last_stage, result
        last_stage = event.get("stage", last_stage)
        if verbose:
            sys.stderr.write("\r  ... %-46s" % last_stage[:46])
            sys.stderr.flush()
        if "result" in event:
            result = event["result"]

    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([read_fd], [], [],
                                        min(0.25, max(0, deadline - time.monotonic())))
            if not ready:
                continue
            chunk = os.read(read_fd, 65536)
            buffer += chunk
            if len(buffer) > 262144:
                raise StopProbe("子进程返回内容异常大")
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                if line.strip():
                    handle_event(json.loads(line.decode("ascii", "replace")))
            if not chunk:
                # EOF：把没有换行收尾的残留事件也吃掉，避免漏掉最后一条结果
                if buffer.strip():
                    handle_event(json.loads(buffer.decode("ascii", "replace")))
                break
        else:
            failure = "读取超时（%.0f 秒），已请求终止，无任何退避访问" % TIMEOUT_SECONDS
    except (Exception, KeyboardInterrupt) as error:
        failure = "%s: %s" % (type(error).__name__, error)
    finally:
        try:
            os.close(read_fd)
        except Exception:
            pass
        reaped, status = os.waitpid(pid, os.WNOHANG)
        if not reaped and failure is None:
            grace = time.monotonic() + 0.3
            while not reaped and time.monotonic() < grace:
                time.sleep(0.01)
                reaped, status = os.waitpid(pid, os.WNOHANG)
        if not reaped:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            reap_deadline = time.monotonic() + 0.5
            while time.monotonic() < reap_deadline:
                reaped, status = os.waitpid(pid, os.WNOHANG)
                if reaped:
                    break
                time.sleep(0.01)
        if not reaped:
            failure = "已请求终止子进程，但系统未确认退出；停止后续探测"

    if verbose:
        sys.stderr.write("\r" + " " * 60 + "\r")
    if failure or result is None or not reaped or not os.WIFEXITED(status) \
            or os.WEXITSTATUS(status) != 0:
        report = new_report(target)
        report["last_stage"] = last_stage
        report["worker_exit_confirmed"] = bool(reaped)
        report["error"] = {"type": "WorkerStopped",
                           "message": failure or "子进程异常退出，没有拿到完整结果"}
        if reaped and os.WIFSIGNALED(status):
            report["error"]["signal"] = os.WTERMSIG(status)
            report["error"]["message"] = ("子进程被信号 %d 终止（BAR0 读故障/段错误的典型表现）"
                                          % os.WTERMSIG(status))
        return report
    result["last_stage"] = last_stage
    return result


# ---------------------------------------------------------------- 中文报告

def verdict(sm):
    """不评档：社区样本本身就从 108 散到 126，贴标签没有信息量。
    这里只把"这个上限是怎么来的"写成一行可核对的话。"""
    upper = sm.get("upper_bound_sm", 0)
    recover = sm.get("recoverable_sm", 0)
    stuck = sm.get("defect_stuck_sm", 0)
    return ("现役 %d + 仅禁未标坏 %d = %d SM；另有 %d SM 挂缺陷标记不可用"
            % (sm.get("effective_sm", 0), recover, upper, stuck))


ERROR_HINTS = (
    ("不是支持的 CMP 170HX", "这块卡的 PCI ID 不是 10de:20c2 / 10de:2082，脚本不碰它。用 lspci -nn 确认。"),
    ("没有绑定任何驱动", "卡在，但 nvidia 驱动没绑上；先确认 nvidia-smi 能看到它，驱动问题不归本脚本管。"),
    ("不是 nvidia", "该设备绑的是别的驱动（vfio-pci？），本脚本不换驱动。"),
    ("驱动缓存", "驱动缓存的身份信息与 sysfs 对不上；把卡拔插/重启后再试，别强行跑。"),
    ("不是已启用/已唤醒", "卡处于休眠/掉电状态；本脚本不会去唤醒它，先跑一次 nvidia-smi 让它进 D0 再来。"),
    ("BAR0", "BAR0 没正常暴露（被 BIOS 关掉 / Above 4G 没开 / 资源没分配）；先在 BIOS 里开 Above 4G Decoding。"),
    ("芯片签名不是 GA100", "读到的签名不是 GA100：可能映射到了错的卡，或卡本身异常。停止是对的。"),
    ("fuse SKU", "fuse 里的 SKU 和 PCI Device ID 不一致：这张卡可能被改过 ID，别继续。"),
    ("不可读/PRI", "读回全 F / PRI 哨兵值，说明这次读取不可信；重插卡或重启后再跑。"),
    ("两遍读取不一致", "两遍读到的值变了，说明有别的程序在动这张卡（监控/挖矿/驱动）；停掉别的进程再跑。"),
    ("超时", "20 秒没读完，卡可能挂死了；单独用 --bdf 再跑一次确认。"),
    ("信号", "子进程被信号打死，典型是 BAR0 读触发总线错误；这张卡状态可疑。"),
    ("找不到 /sys/bus/pci/devices", "不是 Linux，或 sysfs 没挂载。"),
    ("不是合法的内存资源", "BAR0 标志位不像内存资源；先在 BIOS 里开 Above 4G。"),
)


def hint_for(message):
    for key, hint in ERROR_HINTS:
        if key in message:
            return hint
    return "把整份报告发我，我来判断。"


def render_card(report, index, total, show_regs=False):
    out = []
    target = report.get("target") or {}
    line = "─" * 78
    out.append(line)
    head = "[卡 %d/%d]  %s" % (index + 1, total, target.get("bdf", "?"))
    if target.get("pci_id"):
        head += "   %s   %s" % (target["pci_id"], target.get("sku") or "")
    out.append(head)
    out.append(line)

    if report.get("error"):
        out.append("  状态        : 未完成（%s）" % report["status"])
        out.append("  UUID        : %s" % (target.get("gpu_uuid") or "未取到"))
        out.append("  失败原因    : %s" % report["error"].get("message", ""))
        if report.get("last_stage"):
            out.append("  停在阶段    : %s" % report["last_stage"])
        out.append("  建议        : %s" % hint_for(report["error"].get("message", "")))
        out.append("")
        return "\n".join(out)

    ident = report.get("identity_check") or {}
    interp = report.get("interpretation") or {}
    sm = interp.get("sm") or {}
    vram = interp.get("vram") or {}

    out.append("  UUID        : %s" % target.get("gpu_uuid"))
    out.append("  驱动 / 电源 : %s / %s / %s    BAR0: %.0f MiB @ %s"
               % (ident.get("driver"), ident.get("power_state"), ident.get("runtime_status"),
                  ident.get("bar0_bytes", 0) / 1048576.0, ident.get("bar0_start")))
    out.append("  读取状态    : COMPLETE（两遍逐字一致：%s）"
               % ("是" if report.get("matching_passes") == 2 else "否"))
    out.append("")

    # ---- GPC / TPC 明细 ----
    out.append("  ── GPC / TPC（每 GPC 8 TPC = 16 SM）" + "─" * 36)
    out.append("  " + pad("GPC", 5) + pad("缺陷标", 8) + pad("生效掩码", 10)
               + pad("生效禁用TPC", 17) + pad("标坏TPC", 17)
               + pad("现役", 6, ">") + pad("可救", 6, ">") + "  判定")
    for row in interp.get("tpc_per_gpc", []):
        state = row.get("state")
        if state == "gpc_defective":
            judgement = "整组挂牌缺陷，不可救"
        elif state == "gpc_disabled_only":
            judgement = "整组仅禁用 → 可救候选"
        else:
            if row.get("recoverable_tpc"):
                judgement = "在跑；可再救 %d TPC" % row["recoverable_tpc"]
            else:
                judgement = "在跑，无冗余"
        defect = "✔" if row.get("parent_gpc_defect_marked") else "-"
        out.append("  " + pad(str(row["gpc"]), 5) + pad(defect, 8)
                   + pad(row.get("effective_mask", "?"), 10)
                   + pad(fmt_bits(row.get("effective_disabled_indices", [])), 17)
                   + pad(fmt_bits(row.get("defect_marked_indices", [])), 17)
                   + pad(str(row.get("enabled_tpc", 0)), 6, ">")
                   + pad(str(row.get("recoverable_tpc", 0)), 6, ">")
                   + "  " + judgement)
    out.append("")

    # ---- SM 汇总 ----
    out.append("  ── SM 折算（按缺陷标记估算，非实测）" + "─" * 36)
    out.append("  " + pad("现役 SM", 14, ">") + " : %-4d (%d TPC)" % (sm.get("effective_sm", 0), sm.get("effective_tpc", 0)))
    out.append("  " + pad("可救 SM", 14, ">") + " : %-4d (%d TPC，仅\"禁用但未标缺陷\")"
               % (sm.get("recoverable_sm", 0), sm.get("recoverable_tpc", 0)))
    out.append("  " + pad("缺陷挂账 SM", 14, ">") + " : %-4d (挂牌缺陷，硬不可用)" % sm.get("defect_stuck_sm", 0))
    out.append("  " + pad("上限估算 SM", 14, ">") + " : %-4d ← 全开后估算 / die 满配 %d"
               % (sm.get("upper_bound_sm", 0), sm.get("total_sm_on_die", TOTAL_SM)))
    if sm.get("defect_based_ceiling_sm") is not None:
        out.append("  " + pad("按标坏 TPC 算", 14, ">")
                   + " : %-4d ← (64 − %d 个挂缺陷 TPC) × 2   [%s]"
                   % (sm.get("defect_based_ceiling_sm", 0),
                      sm.get("defect_marked_tpc_total", 0),
                      "与上行一致" if sm.get("both_ceiling_methods_agree") else "与上行不一致，检查父位/子位"))
    out.append("  " + pad("口径", 14, ">") + " : %s" % verdict(sm))
    out.append("")

    # ---- 显存通路 ----
    out.append("  ── 显存通路（FBP / FBPA / FBIO）" + "─" * 42)
    for group, width in (("FBP", FULL_FBP), ("FBPA", FULL_FBPA), ("FBIO", FULL_FBIO)):
        g = interp["groups"][group]
        out.append("  " + pad(group, 6) + " 启用 %2d/%d" % (g["effective_enabled_count"], width)
                   + "   仅禁用 %s" % pad(fmt_bits(g["disabled_without_defect_flag"]), 18)
                   + "  标坏 %s" % fmt_bits(g["defect_marked_indices"]))

    sites = vram.get("site_breakdown") or []
    if vram.get("fbpa_mask_matches_expanded_fbp") is not None:
        out.append("  映射核对 : FBP 掩码按 i→2i,2i+1 展开 = %s，与 FBPA 生效掩码%s；"
                   "缺陷掩码%s"
                   % (vram.get("fbp_mask_expanded_to_fbpa", "?"),
                      "一致" if vram.get("fbpa_mask_matches_expanded_fbp") else "不一致",
                      "也一致" if vram.get("fbpa_defect_mask_matches_expanded_fbp") else "不一致"))
    if sites:
        out.append("  HBM 位点（位点 s = FBPA 4s..4s+3；每 FBPA 折算 %.0f GiB）"
                   % vram.get("per_fbpa_gib_assumed", PER_FBPA_GIB))
        out.append("  " + pad("位点", 6) + pad("FBPA", 9) + pad("在位", 8)
                   + pad("仅关未标坏", 16) + pad("标坏", 16) + " 整栈")
        for s in sites:
            out.append("  " + pad(str(s["site"]), 6) + pad(s["fbpa_range"], 9)
                       + pad("%d/%d" % (s["enabled_count"], vram.get("fbpa_per_site", FBPA_PER_SITE)), 8)
                       + pad(fmt_bits(s["clean_disabled"]), 16)
                       + pad(fmt_bits(s["defect_marked"]), 16)
                       + (" 整栈灭" if s["whole_stack_off"] else " -"))
    out.append("  现役容量 : %d/24 分区 × %.0f GiB = %.1f GiB"
               % (vram.get("fbpa_enabled", 0), vram.get("per_fbpa_gib_assumed", PER_FBPA_GIB),
                  vram.get("active_partitions_gib", 0.0)))
    out.append("  逻辑上限 : %d/24 分区 × %.0f GiB = %.1f GiB（把\"仅关但未标坏\"的 %d 个分区算进去；"
               % (vram.get("logic_ceiling_partitions", 0),
                  vram.get("per_fbpa_gib_assumed", PER_FBPA_GIB),
                  vram.get("logic_ceiling_gib", 0.0),
                  len(vram.get("fbpa_clean_disabled") or [])))
    out.append("             条件性候选，不是实测值）")
    out.append("  物理上限 : 读不出来 —— %s" % vram.get("physical_ceiling_note", ""))
    out.append("")

    # ---- 开关门 / 一致性 ----
    gate = interp.get("gate_readouts") or {}
    out.append("  ── 开关门原值（只读记录，不解锁）" + "─" * 41)
    out.append("  EN_SW_OVERRIDE=%s  DISABLE_SW_OVERRIDE_STATUS=%s  OPT_SECURE_GSP_DEBUG_DIS=%s"
               % (gate.get("EN_SW_OVERRIDE"), gate.get("DISABLE_SW_OVERRIDE_STATUS"),
                  gate.get("OPT_SECURE_GSP_DEBUG_DIS")))
    same = [g for g in ("GPC", "FBP", "FBPA", "FBIO")
            if interp["groups"][g]["fuse_and_effective_mask_equal"]]
    diff = [g for g in ("GPC", "FBP", "FBPA", "FBIO")
            if not interp["groups"][g]["fuse_and_effective_mask_equal"]]
    if diff:
        out.append("  注意    : %s 的 fuse 禁用值与生效值不一致（可能有软件覆盖在起作用）"
                   % "/".join(diff))
    else:
        out.append("  一致性  : GPC/FBP/FBPA/FBIO 的 fuse 禁用值都等于生效值（未被软件改写）")
    out.append("")

    if show_regs:
        out.append("  ── 原始寄存器（%d 个）" % len(report.get("registers", [])) + "─" * 44)
        for reg in report.get("registers", []):
            out.append("  %-28s %s  %s%s" % (reg["name"], reg["offset"], reg["value"],
                                             "" if reg.get("second_read_matches") else "  ⚠"))
        out.append("")
    return "\n".join(out)


def render_summary(reports):
    out = ["", "═" * 92, " 全卡汇总（SM 上限 = 现役 + 可救；显存按 4 GiB/FBPA 折算；全部按缺陷标记推，非实测）",
           "═" * 92]
    out.append("  " + pad("#", 3) + pad("BDF", 15) + pad("SKU", 21)
               + pad("现役SM", 8, ">") + pad("可救SM", 8, ">") + pad("上限", 7, ">")
               + pad("缺陷", 6, ">") + pad("现役GiB", 9, ">") + pad("逻辑上限GiB", 13, ">"))
    ok = 0
    for i, rep in enumerate(reports):
        t = rep.get("target") or {}
        if rep.get("error"):
            out.append("  " + pad(str(i), 3) + pad(t.get("bdf", "?"), 15)
                       + pad("读取失败", 21) + pad("-", 8, ">") + pad("-", 8, ">")
                       + pad("-", 7, ">") + pad("-", 6, ">") + pad("-", 9, ">")
                       + pad("-", 13, ">") + "  见上文")
            continue
        ok += 1
        interp = rep.get("interpretation") or {}
        sm = interp.get("sm") or {}
        vram = interp.get("vram") or {}
        out.append("  " + pad(str(i), 3) + pad(t.get("bdf", "?"), 15)
                   + pad(t.get("sku", ""), 21)
                   + pad(str(sm.get("effective_sm", 0)), 8, ">")
                   + pad(str(sm.get("recoverable_sm", 0)), 8, ">")
                   + pad(str(sm.get("upper_bound_sm", 0)), 7, ">")
                   + pad(str(sm.get("defect_stuck_sm", 0)), 6, ">")
                   + pad("%.0f" % vram.get("active_partitions_gib", 0.0), 9, ">")
                   + pad("%.0f" % vram.get("logic_ceiling_gib", 0.0), 13, ">"))
    out.append("")
    good = [r for r in reports if not r.get("error")]
    if good:
        best = max(good, key=lambda r: r["interpretation"]["sm"]["upper_bound_sm"])
        out.append("  上限最高的一张：%s（%s，估算 %d SM）"
                   % (best["target"]["bdf"], best["target"].get("sku", ""),
                      best["interpretation"]["sm"]["upper_bound_sm"]))
    out.append("  读取成功 %d / 共 %d 张。" % (ok, len(reports)))
    out.append("")
    out.append("  ⚠ 这些数字都是按缺陷标记折算的估算值，不是实测上限；本脚本没有启用、")
    out.append("    也没有测试任何停用 SM 或隐藏显存，全程只读。显存的物理天花板是板载")
    out.append("    HBM 颗粒数，寄存器读不出来——所以\"逻辑上限\"只是条件性候选。")
    out.append("═" * 92)
    return "\n".join(out)


def render_header(reports, args, meta=None):
    now = datetime.datetime.now().astimezone()
    meta = meta or {}
    host = meta.get("host") or socket.gethostname()
    kernel = meta.get("kernel") or platform.release()
    when = meta.get("generated")
    if when:
        stamp = "%s（离线重渲染，原采集时间）" % when
    else:
        stamp = now.strftime("%Y-%m-%d %H:%M:%S %Z")
    out = ["=" * 78,
           " CMP 170HX 解锁上限只读自查  v%s" % VERSION,
           " 主机 %s   时间 %s" % (host, stamp),
           " 内核 %s   发现 %d 张受支持的卡" % (kernel, len(reports)),
           " 访问路径 /sys/bus/pci/devices/<BDF>/resource0（O_RDONLY + PROT_READ）",
           " 本脚本不写 GPU、不写 PCI 配置、不发 fuse 命令、不做任何解锁动作",
           "=" * 78]
    return "\n".join(out)


# ---------------------------------------------------------------- nvidia-smi 对照

def smi_snapshot():
    """可选：调一次 nvidia-smi 做交叉核对。会唤醒卡，所以默认不开。"""
    import subprocess
    try:
        done = subprocess.run(
            ["nvidia-smi",
             "--query-gpu=index,pci.bus_id,uuid,name,memory.total",
             "--format=csv,noheader"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    except Exception as error:
        return {"available": False, "error": str(error)}
    if done.returncode != 0:
        return {"available": False, "error": done.stderr.decode("utf-8", "replace").strip()}
    rows = []
    for line in done.stdout.decode("utf-8", "replace").splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 5:
            rows.append({"index": parts[0], "bdf": parts[1].lower(),
                         "uuid": parts[2], "name": parts[3], "memory_total": parts[4]})
    return {"available": True, "gpus": rows}


# ---------------------------------------------------------------- 主流程

def platform_error():
    if sys.platform != "linux":
        return "这个脚本只能在 Linux 上跑（当前是 %s）" % sys.platform
    if sys.implementation.name != "cpython":
        return "需要 CPython（当前是 %s）" % sys.implementation.name
    if platform.machine().lower() not in ("x86_64", "amd64") or sys.byteorder != "little":
        return "需要小端 x86-64（当前 %s）" % platform.machine()
    if struct.calcsize("I") != 4 or mmap.PAGESIZE != PAGE_BYTES:
        return "原生 uint32 或页大小不是 4 字节 / 4096 字节，无法保证对齐读取"
    if os.geteuid() != 0:
        return "需要 root 权限读 BAR0，请用 sudo 运行（脚本不会自己提权）"
    return None


def upgrade_report(report):
    """兼容旧版 JSON（缺 SM 或 HBM 位点折算）：重建掩码后重跑 interpret()。"""
    interp = report.get("interpretation")
    if not interp:
        return report
    if "sm" in interp and "site_breakdown" in (interp.get("vram") or {}):
        return report
    values = {}
    try:
        for group, width in (("GPC", 8), ("FBP", 12), ("FBPA", 24), ("FBIO", 24)):
            item = interp["groups"][group]
            for source, dest in (("fuse_disabled_indices", "OPT_%s_DISABLE" % group),
                                 ("defect_marked_indices", "OPT_%s_DEFECTIVE" % group),
                                 ("effective_disabled_indices", "STATUS_OPT_%s" % group)):
                mask = 0
                for bit in item.get(source, []):
                    mask |= 1 << bit
                values[dest] = mask
            values["CTRL_OPT_%s" % group] = 0
        for row in interp.get("tpc_per_gpc", []):
            gpc = row["gpc"]
            for source, dest in (
                    ("fuse_disabled_indices", "OPT_TPC_DISABLE_GPC%d" % gpc),
                    ("defect_marked_indices", "OPT_TPC_GPC%d_DEFECTIVE" % gpc),
                    ("effective_disabled_indices", "STATUS_OPT_TPC_GPC%d" % gpc)):
                mask = 0
                for bit in row.get(source, []):
                    mask |= 1 << bit
                values[dest] = mask
            values["CTRL_OPT_TPC_GPC%d" % gpc] = 0
        for name in ("EN_SW_OVERRIDE", "DISABLE_SW_OVERRIDE_STATUS",
                     "OPT_SECURE_GSP_DEBUG_DIS"):
            values[name] = (interp.get("gate_readouts") or {}).get(name, 0)
        report = dict(report)
        report["interpretation"] = interpret(values)
        report["upgraded_from_legacy_json"] = True
    except (KeyError, TypeError, ValueError):
        pass
    return report


def load_render_input(path_text):
    with open(path_text, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, dict) and "cards" in data:
        meta = {k: data.get(k) for k in ("host", "kernel", "generated", "script_version")}
        return [upgrade_report(card) for card in data["cards"]], meta
    if isinstance(data, dict) and "target" in data:
        return [upgrade_report(data)], {}
    raise SystemExit("这个 JSON 不是本脚本产出的格式：%s" % path_text)


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        description="CMP 170HX 解锁上限只读自查：自动找卡、纯只读、输出中文报告",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-o", "--outdir", default=".", help="报告输出目录（默认当前目录）")
    parser.add_argument("--regs", action="store_true", help="报告里附上全部原始寄存器")
    parser.add_argument("--smi", action="store_true", help="额外调 nvidia-smi 交叉核对（会唤醒卡）")
    parser.add_argument("--bdf", type=normalize_bdf, help="只跑这一张卡，例如 0000:01:00.0")
    parser.add_argument("--uuid", type=normalize_uuid, help="配合 --bdf 使用的完整 GPU UUID")
    parser.add_argument("--render", metavar="JSON", help="把已有的报告 JSON 重新渲染成中文报告")
    parser.add_argument("--json-only", action="store_true", help="只往 stdout 打 JSON，不打中文报告")
    parser.add_argument("--quiet", action="store_true", help="不打印进度")
    args = parser.parse_args(argv)

    # ---- 离线渲染模式 ----
    if args.render:
        reports, meta = load_render_input(args.render)
        text = "\n".join([render_header(reports, args, meta)]
                         + [render_card(r, i, len(reports), args.regs)
                            for i, r in enumerate(reports)]
                         + [render_summary(reports)])
        print(text)
        return 0

    problem = platform_error()
    if problem:
        sys.stderr.write("\n无法开始：%s\n" % problem)
        return 2

    verbose = not args.quiet
    try:
        targets = discover_targets(args.bdf)
    except (StopProbe, OSError) as error:
        sys.stderr.write("\n无法枚举设备：%s\n" % error)
        return 2
    if not targets:
        sys.stderr.write("\n没找到任何 10de:20c2 / 10de:2082 的卡。\n"
                         "先确认卡插好、nvidia 驱动已加载（nvidia-smi 能看到），"
                         "再用 lspci -nn | grep -i nvidia 核对 PCI ID。\n")
        return 2

    if verbose:
        sys.stderr.write("发现 %d 张卡，开始逐张只读扫描（不会写任何寄存器）\n" % len(targets))
    reports = []
    for index, target in enumerate(targets):
        if verbose:
            sys.stderr.write("[%d/%d] %s ..." % (index + 1, len(targets), target.bdf))
            sys.stderr.flush()
        try:
            report = supervise(target, verbose=verbose)
        except (Exception, KeyboardInterrupt) as error:
            report = new_report(target)
            report["error"] = {"type": type(error).__name__, "message": str(error)}
        reports.append(report)
        if verbose:
            sys.stderr.write("\r[%d/%d] %s  %s%s\n"
                             % (index + 1, len(targets), target.bdf,
                                "完成" if report.get("complete") else "失败",
                                "" if report.get("complete") else
                                "：" + report.get("error", {}).get("message", "")))

    smi = smi_snapshot() if args.smi else None

    header = render_header(reports, args)
    body = "\n".join(render_card(r, i, len(reports), args.regs) for i, r in enumerate(reports))
    footer = render_summary(reports)
    if smi is not None:
        footer += "\n\n [nvidia-smi 交叉核对]\n" + (
            json.dumps(smi, ensure_ascii=False, indent=2) if smi.get("available")
            else "  nvidia-smi 不可用：%s" % smi.get("error"))
    text = "\n".join([header, body, footer])

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = "cmp170hx_report_%s_%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", socket.gethostname()), stamp)
    outdir = Path(os.path.abspath(args.outdir))
    try:
        outdir.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        sys.stderr.write("输出目录不可用（%s），改为只打印到屏幕\n" % error)
        outdir = None

    payload = {
        "generated": datetime.datetime.now().astimezone().isoformat(),
        "host": socket.gethostname(),
        "kernel": platform.release(),
        "script_version": VERSION,
        "command": " ".join(sys.argv),
        "cards": reports,
        "nvidia_smi": smi,
    }

    if args.json_only:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        code = 0 if all(r.get("complete") for r in reports) else 1
        return code

    print(text)

    txt_path = json_path = None
    if outdir is not None:
        txt_path = outdir / (base + ".txt")
        json_path = outdir / (base + ".json")
        try:
            with open(txt_path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text + "\n")
            with open(json_path, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)
            print()
            print("报告已保存：")
            print("  %s" % txt_path)
            print("  %s" % json_path)
            print("  把 .txt（或整份 .json）发回来就行。")
        except OSError as error:
            sys.stderr.write("\n报告写入失败：%s\n" % error)

    ok = sum(1 for r in reports if r.get("complete"))
    return 0 if ok == len(reports) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\n已中断。\n")
        sys.exit(130)
