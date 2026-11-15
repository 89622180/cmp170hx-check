# cmp170hx-check —— CMP 170HX 解锁上限只读自查

在装有 NVIDIA CMP 170HX（`10de:20c2` 8G SKU / `10de:2082` 10G SKU）的 Ubuntu/Debian 机器上，
**一条命令**自动找卡、纯只读扫描 BAR0、落地中文报告 + 原始 JSON。不需要 agent，不需要额外装东西，只用系统自带的 `python3`。

## 一行跑完

```bash
curl -LsS https://raw.githubusercontent.com/89622180/cmp170hx-check/main/run.sh | sudo bash
```

跑完在当前目录生成两个文件：

```
cmp170hx_report_<主机名>_<时间>.txt    ← 人看的中文报告，直接发回来就行
cmp170hx_report_<主机名>_<时间>.json   ← 原始数据，留档/复核
```

带参数（`run.sh` 会把参数原样透传给脚本）：

```bash
curl -LsS https://raw.githubusercontent.com/89622180/cmp170hx-check/main/run.sh | sudo bash -s -- --regs
curl -LsS https://raw.githubusercontent.com/89622180/cmp170hx-check/main/run.sh | sudo bash -s -- --bdf 0000:01:00.0 --smi
```

如果这台机器到 `raw.githubusercontent.com` 不通（CN 网络常见），换 jsdelivr CDN 镜像，行为完全一样：

```bash
curl -LsS https://cdn.jsdelivr.net/gh/89622180/cmp170hx-check@main/run.sh | sudo bash
```

`run.sh` 自己也带这个回退：先试 GitHub raw，拉不到就自动改用 jsdelivr，你不用管。

## 全自动都做了什么

`run.sh` 依次做四步，任何一步失败就停下并说明原因：

1. **确认权限与解释器**：非 root 时自动加 `sudo`；找 `python3`（要求 3.8+）。
2. **拉脚本**：先试 GitHub raw，失败自动改用 jsdelivr CDN 镜像；本地已有同名脚本就直接用。
3. **运行前自检**：`ast.parse` 语法检查 + 体积校验 + 特征标记校验（确认拉到的确实是本仓库的自查脚本，而不是一个同名空文件），并比对发布版 sha256（不一致只警告，方便你自己换分支）。
4. **执行**：`sudo python3 -I -B cmp170hx_check.py`（`-I` 隔离模式、`-B` 不写字节码），然后按退出码告诉你结果。

脚本自己会：扫 `/sys/bus/pci/devices` 找出所有受支持的卡 → 逐张 fork 子进程只读读卡（父进程 20 s 超时回收，BAR0 读故障不会拖垮整批）→ 两遍读取逐字比对 → 先验 UUID / Bus Location / `PMC_BOOT_0` 芯片签名 / fuse SKU，四关不过立刻停。

## 直接运行（不经过 run.sh）

```bash
sudo python3 cmp170hx_check.py            # 自动找卡，全部扫一遍
sudo python3 cmp170hx_check.py --regs     # 报告末尾附全部原始寄存器
sudo python3 cmp170hx_check.py --smi      # 额外对照 nvidia-smi（会唤醒卡）
sudo python3 cmp170hx_check.py -o /tmp/out
sudo python3 cmp170hx_check.py --bdf 0000:01:00.0 --uuid GPU-xxxx...   # 只跑一张
python3 cmp170hx_check.py --render xxx.json    # 把旧 JSON 重新渲染成中文报告（不用 root）
python3 cmp170hx_check.py --json-only          # 只往 stdout 打 JSON
```

退出码：`0` 全部读完，`1` 有卡没读完（报告里每张卡都写了自己的失败原因和建议），`2` 环境不对（不是 Linux / 没 root / 没找到卡）。

## 报告怎么读

- `现役 SM` = 掩码里当前开着的 TPC × 2。
- `可救 SM` = 关着但**没**挂缺陷标记（`disabled_without_defect_flag`）→ 就是 FF 烧写 / VFI 那一步的目标，能不能真开、开了稳不稳，本脚本不管也测不了。
- `缺陷挂账 SM` = 挂了 defective 标记 → 硬不可用（覆写了也没意义）。
- `上限估算 SM` = 现役 + 可救。报告里同时给出第二种口径 `按标坏 TPC 算 = (64 − 挂缺陷 TPC 数) × 2`，两种算法应当一致，不一致会明确提示（说明 GPC 父位与 TPC 子位对不上）。
- 显存按 **4 GiB / FBPA** 折算：现役 16/24 分区 = 64 GiB（与驱动实际识别的 65536 MiB 对齐）。把"关着但没标坏"的分区也算进去得到**逻辑上限** 80 GiB，但这只是条件性候选。
- 报告里会打印 `映射核对`：把 FBP 掩码按 `i → 2i, 2i+1` 展开，与 FBPA 掩码逐位比对。这张卡上两者一致，等于用实测数据反证了位点映射。
- 另外给出 **HBM 位点表**：位点 `s` = FBPA `4s..4s+3`。社区原帖里"关掉的 8 个 FBPA = 两整条 HBM 栈"是错的，实测掩码 `{2,3,8,9} ∪ {12,13,22,23}` 散在四个位点里、每位点占一半；正解是"没有任何位点整栈灭"。

⚠️ 所有 SM / 显存数字都是**按缺陷标记折算的估算，不是实测**；脚本没有启用、也没有测试任何停用 SM 或隐藏显存。

**显存的物理天花板寄存器件读不出来**：FBP/FBPA 掩码只告诉你哪个分区被 fuse 关掉或被标坏，不告诉你那个分区背后焊没焊 HBM 颗粒。只焊 4 颗 ⇒ 64 GiB 封顶（社区拆卡口径，作者本人也说没 100% 目视确认），fuse 全开也变不出不存在的颗粒。JSON 里对应标记是 `physical_ceiling_gib: null` + `classification_only_not_an_unlock_limit: true`。

> 参考：arca.live 「AI 로컬 홈랩」帖 186266420 的 2026-10-18 回帖，逐条纠正了原帖的 SM 口径（应按"挂缺陷 TPC 计数"而非整组扣）、HBM 栈分组（应按 `4s..4s+3` 而非两大块）、以及显存基准（4 GiB/FBPA，不是 80 GiB ÷ 24）。

## 安全边界（脚本自己声明，与原社区版本同一条线，没有放宽）

只 `mmap` `/sys/bus/pci/devices/<BDF>/resource0`，`O_RDONLY` + `PROT_READ`，白名单固定偏移逐页映射；不存在任何写路径。不写 GPU 寄存器、不写 PCI 配置空间、不发 fuse READ 命令、不动 selector/control；默认不起 `nvidia-smi`、不 ioctl、不碰 `/dev/mem`、不改驱动、不做任何"解锁"动作；自动找卡只读 `vendor`/`device`/`class` 三个 sysfs 文本。

偏移交叉核对来源：GA100 `dev_fuse.h`、[matstatman/gpcprobe](https://github.com/matstatman/gpcprobe)；sysfs 访问路径见 [kernel docs: sysfs-pci](https://docs.kernel.org/PCI/sysfs-pci.html)。

## 来源

社区原版：arca.live「AI 로컬 홈랩」板块，作者 akaJ（帖 186266420），2026-11-11 由 cmpunlocker `general` 转出。本仓库这版在其基础上加了自动找卡、子进程超时回收、中文报告、JSON 留档与旧 JSON 重渲染。

## 已知限制

- 只能在 Linux x86-64（小端、页 4096、原生 uint32）上跑，需要 root。
- 卡必须已经在 D0 / 已唤醒；脚本不会去唤醒它，先跑一次 `nvidia-smi` 让它进 D0 再来。
- BAR0 没正常暴露（BIOS 没开 Above 4G Decoding / 资源没分配）会直接停，不会退回读 PCI 配置空间。
