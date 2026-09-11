# Realm Panel

一个零第三方 Go 依赖、主控端与 Agent 分离的轻量级 Realm 端口转发管理系统。主控面板和各节点 Agent 默认都使用 **6800/TCP**（位于不同机器，不会相互冲突）。

## 功能

- 网页面板登录、节点列表、规则添加与删除
- 面板内“绑定新节点”窗口，可生成并复制一键安装命令
- 响应式运维控制台、深色模式、在线状态、移动端记录视图与无障碍键盘操作
- Agent 自动注册并每分钟刷新在线时间
- AES-256-GCM 加密面板到 Agent 的规则指令
- 短时 HMAC-SHA256 请求签名，Token 不通过网络发送
- 随机 Nonce 防重放、来源 IP 限制和按 IP 请求限速
- `nodes.json` 与 `rules.json` 原子持久化
- Agent 原子生成 Realm 多 `[[endpoints]]` 配置
- Realm 重启失败自动恢复旧配置
- Debian 11/12/13 与 Ubuntu 20.04/22.04/24.04 一键安装

## 主控端一键安装

在一台 Debian 或 Ubuntu x86_64 机器执行：

```bash
curl -fsSL https://raw.githubusercontent.com/jaycen-0502/realm-panel/main/install_panel.sh | sudo bash
```

脚本会在终端中提示输入管理员用户名和密码，并自动生成无需记忆的共享 Token。安装完成后显示登录地址及节点绑定命令。

也可以使用参数指定 Token、面板密码和用户名：

```bash
curl -fsSL https://raw.githubusercontent.com/jaycen-0502/realm-panel/main/install_panel.sh \
  | sudo bash -s -- '你的长随机Token' '你的面板密码' '你的管理员用户名'
```

重复执行上面的安装命令会自动保留现有用户名、密码、Token、节点和规则，并完成面板升级；不需要再次输入凭据。

## 节点一键绑定

登录面板后点击右上角“绑定新节点”，填写节点名称并复制生成的命令到节点服务器执行。也可以手动使用：

```bash
curl -fsSL https://raw.githubusercontent.com/jaycen-0502/realm-panel/main/install_agent.sh -o /tmp/install_agent.sh
sudo bash /tmp/install_agent.sh 'http://主控IP:6800' '共享Token' 'node-a'
```

Agent 会从 Realm 官方 GitHub Release 下载 Linux x86_64 版本，并注册 `realm.service` 与 `realm-agent.service`。

## 网络与安全

- 主控机器开放 `6800/TCP`，供浏览器和节点注册访问。
- 每台 Agent 节点开放 `6800/TCP`，且防火墙应只允许主控 IP 访问。
- 当 `MASTER_URL` 使用 IP 地址时，Agent 会自动拒绝来自其他源 IP 的控制请求；使用域名时应通过防火墙只允许主控出口 IP。
- 公网部署仍建议配置 HTTPS、WireGuard/VPN 或可信内网。HMAC 与加密载荷保护控制指令，但 HTTPS 还能隐藏流量元数据并提供服务端身份认证。
- 主控与节点时间误差需小于五分钟，以便短时签名验证。建议启用系统自带的 NTP 时间同步。
- `/etc/realm-panel.env` 与 `/etc/realm/agent.env` 均为 root-only 权限，请妥善备份。

## 故障隔离

Realm、Agent、主控面板是三个独立进程。实际端口转发完全由节点本地的 `realm.service` 承担：

- 主控面板宕机或网络中断，不影响任何已经运行的转发。
- Agent 宕机，不影响 Realm；仅暂时无法增加或删除规则。
- Agent 只在规则发生变化时重启 Realm，并在重启失败时恢复旧配置。
- 节点重启后，Realm 直接读取最后一次成功落盘的配置，不需要先连接主控。
- Agent 本地状态与配置采用原子替换，启动时会检查并修复意外中断造成的不一致。

主控和 Realm 使用独立的低权限系统账户运行；Systemd 服务启用了文件系统、设备、内核和 Linux capability 限制。Agent 因需要调用 `systemctl restart realm` 仍以 root 运行，但文件系统写权限被限制在 `/etc/realm`。

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
