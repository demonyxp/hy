#!/usr/bin/env bash
set -Eeuo pipefail

# 固定管理器版本，避免一次安装混入不同版本的文件。
VERSION=v0.4.0
if [[ ${EUID} -ne 0 ]]; then
    echo '请用 root 执行，或先运行 sudo -i。' >&2
    exit 1
fi
if [[ ! -d /run/systemd/system ]]; then
    echo '需要使用 systemd 的 Debian / Ubuntu 服务器。' >&2
    exit 1
fi
if ! command -v apt-get >/dev/null; then
    echo '当前版本支持 Debian / Ubuntu。' >&2
    exit 1
fi

missing=()
for pair in 'curl:curl' 'python3:python3' 'openssl:openssl' 'ss:iproute2' 'useradd:passwd' 'nft:nftables'; do
    command -v "${pair%%:*}" >/dev/null || missing+=("${pair#*:}")
done
[[ -s /etc/ssl/certs/ca-certificates.crt ]] || missing+=(ca-certificates)
if ((${#missing[@]})); then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
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
