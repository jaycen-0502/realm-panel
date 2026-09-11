# Realm Panel

一个零第三方 Go 依赖、主控端与 Agent 分离的轻量级 Realm 端口转发管理系统。主控面板和各节点 Agent 默认都使用 **6800/TCP**（位于不同机器，不会相互冲突）。

## 功能

- 网页面板登录、节点列表、规则添加与删除
- Agent 自动注册并每分钟刷新在线时间
- AES-256-GCM 加密面板到 Agent 的规则指令
- Token 请求头鉴权
- `nodes.json` 与 `rules.json` 原子持久化
- Agent 原子生成 Realm 多 `[[endpoints]]` 配置
- Realm 重启失败自动恢复旧配置
- Debian 11/12/13 与 Ubuntu 20.04/22.04/24.04 一键安装

## 主控端一键安装

在一台 Debian 或 Ubuntu x86_64 机器执行：

```bash
curl -fsSL https://raw.githubusercontent.com/jaycen-0502/realm-panel/main/install_panel.sh | sudo bash
```

脚本会生成面板密码和共享 Token，安装完成后显示登录地址及节点绑定命令。

也可以自行指定 Token 和面板密码：

```bash
curl -fsSL https://raw.githubusercontent.com/jaycen-0502/realm-panel/main/install_panel.sh \
  | sudo bash -s -- '你的长随机Token' '你的面板密码'
```

## 节点一键绑定

将安装结束时显示的命令复制到节点执行，或使用：

```bash
curl -fsSL https://raw.githubusercontent.com/jaycen-0502/realm-panel/main/install_agent.sh -o /tmp/install_agent.sh
sudo bash /tmp/install_agent.sh 'http://主控IP:6800' '共享Token' 'node-a'
```

Agent 会从 Realm 官方 GitHub Release 下载 Linux x86_64 版本，并注册 `realm.service` 与 `realm-agent.service`。

## 网络与安全

- 主控机器开放 `6800/TCP`，供浏览器和节点注册访问。
- 每台 Agent 节点开放 `6800/TCP`，且防火墙应只允许主控 IP 访问。
- 公网部署必须在面板和 Agent 前配置 HTTPS、VPN 或可信内网。加密载荷不能替代 HTTPS，因为请求头中的 Token 仍属于敏感信息。
- `/etc/realm-panel.env` 与 `/etc/realm/agent.env` 均为 root-only 权限，请妥善备份。

## 常用命令

```bash
systemctl status realm-panel --no-pager
systemctl status realm-agent --no-pager
systemctl status realm --no-pager
journalctl -u realm-panel -f
journalctl -u realm-agent -f
```

## 手动编译

```bash
go build -o realm-panel main.go
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o agent-linux-amd64 agent.go
```

本项目的 Realm 配置格式及二进制包来自 [zhboner/realm](https://github.com/zhboner/realm)。
