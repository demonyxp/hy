#!/usr/bin/env bash
set -Eeuo pipefail

# 固定管理器版本，避免一次安装混入不同版本的文件。
VERSION=v0.5.0
if [[ ${EUID} -ne 0 ]]; then
    echo '请用 root 执行，或先运行 sudo -i。' >&2
    exit 1
fi
if [[ ! -d /run/systemd/system ]]; then
    echo '需要使用 systemd 的 Debian / Ubuntu / Amazon Linux 2023 服务器。' >&2
    exit 1
fi
if [[ ! -r /etc/os-release ]]; then
    echo '无法识别操作系统：缺少 /etc/os-release。' >&2
    exit 1
fi
# 仅识别已适配的系统，不把所有 DNF 系统都当成 Amazon Linux。
IFS=: read -r os_id os_version < <(
    # 在子进程读取，避免系统的 VERSION 覆盖管理器发布版本。
    # shellcheck source=/dev/null
    source /etc/os-release
    printf '%s:%s\n' "${ID:-}" "${VERSION_ID:-}"
)
case "$os_id:$os_version" in
    ubuntu:*|debian:*)
        package_manager=apt-get
        iproute_package=iproute2
        useradd_package=passwd
        ca_bundle=/etc/ssl/certs/ca-certificates.crt
        ;;
    amzn:2023)
        package_manager=dnf
        iproute_package=iproute
        useradd_package=shadow-utils
        ca_bundle=/etc/pki/tls/certs/ca-bundle.crt
        ;;
    *)
        echo '当前支持 Debian / Ubuntu / Amazon Linux 2023，不支持 Amazon Linux 2。' >&2
        exit 1
        ;;
esac
if ! command -v "$package_manager" >/dev/null; then
    echo "缺少系统包管理器 $package_manager，请先修复系统环境。" >&2
    exit 1
fi

missing=()
for pair in 'curl:curl' 'python3:python3' 'openssl:openssl' "ss:$iproute_package" "useradd:$useradd_package" 'nft:nftables'; do
    command -v "${pair%%:*}" >/dev/null || missing+=("${pair#*:}")
done
[[ -s "$ca_bundle" ]] || missing+=(ca-certificates)
if ((${#missing[@]})); then
    if [[ $package_manager == apt-get ]]; then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
    else
        # 只补齐缺失依赖，不执行系统升级，也不替换已经可用的 curl-minimal。
        dnf install -y "${missing[@]}"
    fi
fi

temp_dir=$(mktemp -d)
trap 'rm -rf -- "$temp_dir"' EXIT
curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 120 --retry 2 \
    "https://raw.githubusercontent.com/demonyxp/hy/${VERSION}/hy.py" -o "$temp_dir/hy.py"
curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 60 --retry 2 \
    "https://raw.githubusercontent.com/demonyxp/hy/${VERSION}/release.json" -o "$temp_dir/release.json"
python3 - "$temp_dir" "$VERSION" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
release = json.loads((root / 'release.json').read_text())
content = (root / 'hy.py').read_bytes()
if 'v' + release.get('version', '') != sys.argv[2] or hashlib.sha256(content).hexdigest() != release.get('sha256'):
    raise SystemExit('管理器版本或 SHA-256 校验失败，停止安装。')
compile(content, 'hy.py', 'exec')
PY
if (($# == 0)); then
    set -- install
fi
python3 "$temp_dir/hy.py" "$@"
