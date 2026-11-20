# HY 可选管理面板

<!-- impeccable:product-schema 1 -->

## Platform
web

## Stack
沿用 Python 标准库管理器；可选面板采用原生 HTML/CSS/JavaScript 和 Python HTTP 后端。技术细节由用户授权自主决定。

## Users
自用 Hysteria2 服务器管理员，需要用中文查看状态、客户端流量并完成日常操作。

## Product Purpose
减少 SSH 菜单操作，提供状态、流量、客户端公网 IP 限速、服务启停和连接导出。

## Capabilities and Constraints
面板默认不安装；仅管理员登录，不开放注册。复用已有 HTTPS 网站，不新增面板公网端口。不替换网站原有应用。默认安装 HY2，可选增加 VLESS/REALITY TCP 备用，由独立 sing-box 服务运行。统一订阅包含已安装协议，服务独立启停；按客户端公网 IP 合并统计、共享限速。监控的最近活动不等于用户在线。

## Product Principles
真实数据；操作结果可确认；敏感连接信息只在登录后展示；安装和卸载边界明确。
