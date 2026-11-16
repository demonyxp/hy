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
默认不安装；仅管理员登录，不开放注册。复用已有 HTTPS 网站，不新增公网端口。不替换网站原有应用。复用 HY2 配置、统计与限速实现；监控的最近活动不等于用户在线。只导出 HY2 兼容配置，不引入其他协议。

## Product Principles
真实数据；操作结果可确认；敏感连接信息只在登录后展示；安装和卸载边界明确。
