# HY — Hysteria2 中文一键部署

面向单服务器的中文部署工具：支持已有域名证书，也支持无域名、无现成证书的纯 IP 安装。安装官方 Hysteria2 内核，生成节点和客户端配置，用 `hy` 管理。

**支持 Ubuntu 22.04 / 24.04、Debian 12 / 13，amd64 / arm64，要求 systemd。** 纯 IP 模式自动生成自签证书；域名模式复用已有可信证书。云安全组需要另外放行所选 UDP 端口。

## 安装

以 root 执行固定版本的安装器：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/demonyxp/hy/v0.2.0/install.sh)
```

先选择安装模式：

### 模式 2：只有 IP，没有域名和证书

输入 `2`，填写服务器公网 IPv4 或 IPv6，其他选项按需要填写或回车使用默认值。无需宝塔、网站、DNS 解析，也无需填写证书路径。

工具自动生成有效期 10 年的独立自签证书，私钥保存在 `/etc/hy/selfsigned/`。客户端连接到输入的 IP；`hy.invalid` 只是自动填充的 TLS 校验名称，不需要购买或解析这个域名。

安装结束后复制 `hysteria2://` 链接导入 Hiddify / v2rayN，或导入对应客户端配置文件。没有 HTTPS 网站时直接使用这些链接/文件，不会要求发布订阅或额外开放订阅端口。

自签模式的导出方式：

- HY2 URI、Hiddify / v2rayN Base64 订阅：携带 `insecure=1` 和 `pinSHA256`，跳过公共 CA 验证并提供证书指纹；实际指纹校验取决于客户端是否保留和实现这个字段。
- Clash / Mihomo / FlClash：携带 `skip-cert-verify` 和 `fingerprint`，由内核固定证书指纹。
- sing-box：内嵌信任证书，保持 `insecure=false`。
- 官方 Hysteria2：固定 `pinSHA256`。

Mihomo、sing-box 和官方内核已测试错误证书/指纹会拒绝连接。第三方图形客户端的 URI 导入未逐个验证，导入后请确认保留了指纹；需要明确的证书校验时使用完整 Mihomo 或 sing-box 配置。

修改密码、混淆和 IP 时保留原证书，避免已有客户端指纹失效。自签证书不会自动轮换；遗失时应恢复 `/var/lib/hy/backups/` 中的备份。到期前重新部署并重新导入新配置，不要直接替换证书文件。

### 模式 1：已有域名和可信证书

先通过宝塔或其他 ACME 工具申请证书；域名应直接解析到服务器，节点域名不要开启普通 CDN 代理。选择 `1`，按提示输入：

1. **证书域名**：例如 `vpn.example.com`。
2. **连接地址**：默认与域名相同，也可以填写服务器公网 IP；SNI 仍使用证书域名。
3. **证书和私钥路径**：默认识别宝塔路径 `/www/server/panel/vhost/cert/域名/`，也可指定其他路径。
4. **UDP 端口**：默认 `24443`。
5. **节点密码**：回车自动生成；修改配置时回车保留原密码。
6. **混淆**：默认关闭；需要时开启 Salamander，导出配置会自动带上混淆密码。

域名模式检查证书链、域名、有效期和私钥匹配。两种模式均检查 UDP 端口占用，下载官方稳定版并校验 GitHub 提供的 SHA-256。它使用独立的 `hy-server.service` 和 `/etc/hy`，不覆盖 s-hy2 的 `/etc/hysteria` 或 3x-ui。

已有 v0.1.0 用户重复执行上述安装命令即可更新管理器，保留原配置。需要切换模式时运行 `hy configure`；切换后重新导入配置或更新订阅。

在云安全组、宝塔防火墙放行 **UDP 24443**（或你选择的端口）。如果系统用 UFW：

```bash
ufw allow 24443/udp
```

TCP 和 UDP 端口互相独立：Nginx 使用 TCP 443，不代表 UDP 443 被占用；启用 HTTP/3 的 Nginx 可能同时占用 UDP 443。本工具默认选择 UDP 24443，并会检查实际占用。

## 客户端

安装结束会直接打印 `hysteria2://` 链接，Hiddify 可从剪贴板导入。也可以随时执行：

```bash
hy export
```

导出位置：

| 文件 | 用途 |
| --- | --- |
| `/var/lib/hy/export/node.txt` | 单节点链接 |
| `/var/lib/hy/export/hiddify.txt` | Base64 节点列表订阅 |
| `/var/lib/hy/export/v2rayn.txt` | v2rayN 的 Base64 节点订阅；也可直接导入 `node.txt` |
| `/var/lib/hy/export/clash.yaml` | Clash Verge Rev / Mihomo 完整配置 |
| `/var/lib/hy/export/flclash.yaml` | FlClash / Mihomo 完整配置，本地导入 |
| `/var/lib/hy/export/sing-box.json` | sing-box 1.12+ 完整配置，本地 HTTP/SOCKS5 为 `127.0.0.1:7890` |
| `/var/lib/hy/export/native.json` | Hysteria2 官方客户端配置，本地 SOCKS5 为 `127.0.0.1:1080` |

`.yaml` 使用 JSON 格式排版：JSON 是 YAML 的子集，Mihomo 可以读取；这样密码中的引号、冒号、中文不会破坏配置。默认规则为局域网直连、GEOIP 中国直连、其余代理。FlClash 需要有效的 GeoIP 数据库；不同客户端自带的分流规则可能不同。

域名模式开启公共 CA 证书验证；纯 IP 模式按上面的方式携带证书身份。不需要 REALITY 的指纹、Short ID、Vision 或 ML-KEM 配置。没有预设虚高带宽值，使用 Hysteria2 默认拥塞控制；网速取决于线路和 UDP 通信质量。

**这些是同一个 HY2 节点的不同客户端格式。** Clash 需使用支持 Hysteria2 的 Mihomo 内核，旧版原版 Clash 不支持。Hiddify、v2rayN 请使用带 HY2 支持的新版。VLESS 是另一种协议，不是客户端名称；本工具不部署 VLESS，也不会生成无效的 `vless://` 链接。

sing-box 配置使用系统 DNS，局域网直连、其余代理，不依赖外部规则数据库；它提供本地代理端口，不自动启用 TUN。Hiddify 优先使用 `hiddify.txt` 订阅，让应用管理 TUN 和分流。

## HTTPS 订阅：使用已有网站

这是可选功能，纯 IP 安装无需执行。如果另有可信 HTTPS 网站，也可以在纯 IP 模式运行此命令并填写网站信息；本工具不启动 HTTP 明文订阅服务。

```bash
hy publish
```

输入已有站点根目录，例如 `/www/wwwroot/vpn.example.com`，以及 `https://vpn.example.com`。工具只在站点内创建一个随机目录：

```text
https://vpn.example.com/hy-sub-<随机令牌>/hiddify.txt
https://vpn.example.com/hy-sub-<随机令牌>/v2rayn.txt
https://vpn.example.com/hy-sub-<随机令牌>/clash.yaml
https://vpn.example.com/hy-sub-<随机令牌>/flclash.yaml
https://vpn.example.com/hy-sub-<随机令牌>/sing-box.json
```

复制对应订阅到客户端即可。**没有额外的 2096 端口或订阅进程，不修改 Nginx 配置、网站根目录或 SSL 配置。** 站点必须允许访问这些静态文件；如果网站把所有路径反代到应用，需自行配置静态访问。工具会尝试通过 HTTPS 下载并逐字核对内容，失败时明确显示未验证，不会把“文件已生成”当成“订阅已可用”。本机通过也不保证所有外网线路均可达。

订阅链接含访问凭据，随机路径相当于密码，请勿公开。不要把节点文件或配置备份提交到 GitHub；发布前确认站点不会对这些文件做公开缓存。重新执行 `hy publish` 会刷新原有链接。

撤销发布：

```bash
hy unpublish
```

撤销订阅不等于撤销已经导入的节点。需要撤销节点访问时，执行 `hy configure` 修改密码，再重新导入配置。

## 中文菜单与命令

直接运行 `hy` 打开菜单。

| 命令 | 功能 |
| --- | --- |
| `hy install` | 首次安装；已安装时只刷新管理脚本 |
| `hy configure` | 修改域名、连接地址、端口、密码、证书、混淆；自动备份，启动失败恢复旧配置 |
| `hy update` | 更新官方内核，校验 SHA-256；运行中的服务更新失败则恢复旧内核 |
| `hy export` | 显示节点并重新生成本地客户端文件 |
| `hy publish` / `hy unpublish` | 发布、刷新或撤销 HTTPS 订阅 |
| `hy doctor` | 检查服务、UDP 监听、DNS、证书和同步定时器 |
| `hy logs` | 查看最近 60 行服务日志 |
| `hy start` / `hy stop` / `hy restart` | 服务控制 |
| `hy sync-cert` | 立即同步源证书 |
| `hy backup` | 备份配置、证书和发布信息 |
| `hy uninstall` | 确认后卸载本工具，保留备份 |

## 证书续期

域名模式的证书仍由宝塔或你原有的 ACME 工具续期。`hy-cert-sync.timer` 每小时读取一次源证书，验证后同步到本工具专用目录；自签模式只校验和同步原证书，不自动更换指纹。使用独立低权限账户运行 Hysteria2，不修改宝塔私钥文件权限。整对证书通过符号链接原子切换；新握手会读取更新后的证书。

```bash
systemctl status hy-server hy-cert-sync.timer --no-pager
journalctl -u hy-cert-sync.service -n 30 --no-pager
```

## 失败处理与备份

- 安装下载或证书校验失败会停止；不会关闭防火墙、改内核、全局 sysctl 或 Nginx。
- 首次服务启动失败：保留文件供排查，运行 `hy logs` / `hy doctor`，修正后 `hy start`。
- `hy configure` 保存前备份；新配置无法持续运行时恢复旧配置与证书权限。
- `hy update` 替换前备份旧内核；重启失败则恢复。
- 备份位于 `/var/lib/hy/backups/`，包含密码和私钥，仅 root 可访问；按需要自行清理旧备份。
- 卸载只清理本工具专用路径与带归属标记的订阅文件，保留备份、专用系统账户和运行目录；可再次安装复用。
- 同一时间只允许一个 `hy` 操作，证书同步与手动配置不会并发写入。

**服务运行、TCP 可达、服务器下载快都不能证明客户端 HY2 可用。** 最后必须用导出的客户端配置测试真实 UDP 握手、访问网站和出口 IP。若超时，先检查 UDP 安全组、系统防火墙、CDN、DNS 和运营商线路。

## 项目范围与测试

这是单节点部署工具，不提供网页面板、多用户计费、流量套餐、自动改防火墙、自动卸载其他 VPN 或自动接管宝塔。

```bash
python3 -m unittest discover -s tests -v
bash -n install.sh
shellcheck install.sh
```

`tests/Dockerfile` 用于一次性 Ubuntu 24.04 测试环境。真实服务集成测试只能在可丢弃的 root/systemd 环境运行，不能在生产服务器运行测试脚本。

```bash
docker build -f tests/Dockerfile -t hy-test .
docker run -d --name hy-test --privileged --cgroupns=private \
  --tmpfs /run --tmpfs /run/lock -e HY_DISPOSABLE_TEST=1 hy-test
docker exec hy-test python3 -u tests/live_systemd.py
docker rm -f hy-test
```

集成测试覆盖实际安装、低权限服务、HY2 握手、Salamander、错误配置回滚、失败升级回滚、订阅发布/撤销、卸载和重装。可将官方 Linux 客户端二进制放入容器的 `/opt/test-clients/sing-box` 与 `/opt/test-clients/mihomo`，额外验证完整导出配置并进行真实代理请求；未提供时明确跳过。测试 HTTP 目标在容器内，因此握手测试会单独移除客户端的局域网直连规则，避免误测成直连。

v0.1.0 已在 Ubuntu 24.04 amd64 / Hysteria2 2.13.0 验证，客户端内核验证为 Mihomo 1.19.32 和 sing-box 1.14.3，包含开启/关闭混淆的真实代理请求。未对每个图形客户端逐一执行界面导入测试；其他支持平台仍需在实际服务器验证。

v0.2.0 在上述环境补充通过纯 IP 自动自签安装、三种客户端内核连接、混淆开关、错误指纹/证书拒绝、证书保持不变和切回原有证书模式测试。10 项单元测试在 Linux 全部通过。

参考：[Hysteria2 官方](https://github.com/HyNetworks/hysteria)、[服务端配置](https://v2.hysteria.network/zh/docs/advanced/Full-Server-Config/)、[节点 URI](https://v2.hysteria.network/docs/developers/URI-Scheme/)、[Mihomo Hysteria2 配置](https://wiki.metacubex.one/config/proxies/hysteria2/)、[sing-box Hysteria2 配置](https://sing-box.sagernet.org/configuration/outbound/hysteria2/)。
