#!/usr/bin/env bash
# CMP 170HX 解锁上限一键只读自查（Ubuntu / Debian / 任意带 root 的 Linux）
#
# 一行命令（无需先 clone 仓库、无需 agent、无需联网到 GitHub 以外的服务）：
#
#     curl -LsS https://raw.githubusercontent.com/89622180/cmp170hx-check/main/run.sh | sudo bash
#
# 想给脚本传参数（--regs / --smi / --bdf ...）：
#
#     curl -LsS https://raw.githubusercontent.com/89622180/cmp170hx-check/main/run.sh | sudo bash -s -- --regs
#
# 它做三件事：
#   1) 下载 cmp170hx_check.py（GitHub raw 失败时自动改用 jsdelivr CDN 镜像）
#   2) 先做语法自检（ast.parse）+ 体积/特征校验，再运行
#   3) sudo python3 -I -B 跑脚本：自动找卡、纯只读 BAR0、生成中文 .txt + 原始 .json
#
# 全程只读：不写 GPU 寄存器、不写 PCI 配置空间、不发 fuse 命令、不做任何解锁动作。

set -u

OWNER="89622180"
REPO="cmp170hx-check"
RAW_URL="https://raw.githubusercontent.com/${OWNER}/${REPO}/main/cmp170hx_check.py"
CDN_URL="https://cdn.jsdelivr.net/gh/${OWNER}/${REPO}@main/cmp170hx_check.py"
# 期望的 sha256（当前发布版本）。不一致只警告、不阻断，方便你自己换分支/本地改版。
EXPECTED_SHA256="3d0899fde9ef9cd3902b1b7801364ebb545007b8b10f1974680c10ec4751ce30"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        echo "!! 需要 root 权限读 BAR0，但当前不是 root 且没有 sudo。" >&2
        echo "   用 root 身份重新执行这条命令。" >&2
        exit 2
    fi
fi

PY=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 8) else 1)' 2>/dev/null; then
            PY="$candidate"
            break
        fi
    fi
done
if [ -z "$PY" ]; then
    echo "!! 没找到可用的 python3（需要 3.8+）。先装 python3：apt install -y python3" >&2
    exit 2
fi

DOWNLOAD_DIR="${TMPDIR:-/tmp}"
SCRIPT="${DOWNLOAD_DIR}/cmp170hx_check.py"

# 已经在本地拿到脚本（比如手动下过或仓库就在旁边），优先用本地这份。
if [ ! -s "$SCRIPT" ]; then
    fetch() {
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL --max-time 60 "$1" -o "$SCRIPT" && return 0
        elif command -v wget >/dev/null 2>&1; then
            wget -q -T 60 -O "$SCRIPT" "$1" && return 0
        fi
        return 1
    }
    echo "-> 下载 cmp170hx_check.py"
    if ! fetch "$RAW_URL"; then
        echo "   GitHub raw 没拉到，改用 jsdelivr CDN 镜像 ..."
        if ! fetch "$CDN_URL"; then
            echo "!! 两个来源都没拉到，检查一下网络（这台机器能不能通 GitHub）。" >&2
            exit 2
        fi
    fi
fi

if [ ! -s "$SCRIPT" ]; then
    echo "!! 下载结果为空文件：$SCRIPT" >&2
    exit 2
fi

# ---- 运行前自检：语法 + 是否是本脚本（不是随便一个同名文件）----
"$PY" - "$SCRIPT" <<'PYEOF'
import ast, sys
path = sys.argv[1]
src = open(path, "rb").read()
ast.parse(src.decode("utf-8"))
text = src.decode("utf-8")
marks = ("PMC_BOOT_0", "OPT_PCIE_DEVIDA", "ReadOnlyBar", "discover_targets")
missing = [m for m in marks if m not in text]
if missing:
    raise SystemExit("下载到的文件不像本仓库的自查脚本，缺少标记：%s" % ", ".join(missing))
if len(src) < 20000:
    raise SystemExit("下载到的文件过小（%d 字节），可能是一次被截断的下载" % len(src))
print("   自检通过：%d 字节，ast.parse OK" % len(src))
PYEOF
[ $? -eq 0 ] || exit 2

if command -v sha256sum >/dev/null 2>&1; then
    got="$(sha256sum "$SCRIPT" | awk '{print $1}')"
    if [ "$got" != "$EXPECTED_SHA256" ]; then
        echo "   注意：sha256 与发布版不一致（$got）——若你换了分支或本地改过，可忽略。"
    fi
fi

echo "-> 运行：$PY -I -B $SCRIPT $*"
# shellcheck disable=SC2086  # 故意把参数原样透传
$SUDO "$PY" -I -B "$SCRIPT" "$@"
rc=$?
echo
if [ $rc -eq 0 ]; then
    echo "全部卡读取成功。把生成的 .txt（或整份 .json）发回来即可。"
elif [ $rc -eq 1 ]; then
    echo "部分卡没读完，报告里每张卡都写了自己的失败原因和建议。"
else
    echo "没跑起来（退出码 $rc），看上面『无法开始』那一行的原因。"
fi
exit $rc
