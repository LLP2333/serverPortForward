# ServerPortForward

一个面向 Windows 10/11 的 VPN 端口转发管理器。它把只有 Windows VPN 能访问的 IPv4/TCP 服务映射到 Windows 本地端口，供同网络中的 macOS 或其他电脑访问。

程序使用 Go 编写，管理界面内嵌在单个 EXE 中，不需要安装 Node.js、WebView 或其他运行时。转发规则由 Windows `portproxy` 保存，因此退出本管理器后规则仍然有效。

> 安全提示：当前版本按需求将已管理端口开放给任意来源、任意 Windows 防火墙配置文件。任何能够路由到这台 Windows 的设备都可能尝试连接这些端口。只映射必要服务，并确认符合公司的 VPN 与信息安全规定。

## 功能

- 双击 EXE 后通过 UAC 自动请求管理员权限。
- 在仅绑定 `127.0.0.1` 的本地中文网页中管理规则。
- 创建、编辑、删除和测试 IPv4 到 IPv4 的 TCP 转发。
- 设置一个默认目标服务器，同时允许每条规则使用不同目标 IPv4。
- 默认监听 `0.0.0.0`，也可以选择 Windows 当前网卡的具体 IPv4。
- 自动创建和清理本工具专属的 Windows Defender 入站规则。
- 显示所有系统 `v4tov4` 规则；外部规则可删除，也可确认后接管编辑。
- 批量清除仅作用于本工具登记的规则，不执行系统级 `portproxy reset`。
- 检查 IP Helper、TCP 监听、VPN 目标、本地映射和防火墙状态。
- 显示 Windows 局域网地址并生成 macOS SSH 示例。
- 配置原子写入，系统操作失败时尽量回滚，并保留诊断信息。

首版只支持 IPv4/TCP，不支持 UDP、IPv6、Windows 服务或系统托盘。

## 在 macOS 上编译 Windows EXE

要求 Go 1.22 或更高版本。项目没有第三方依赖，也不需要 CGO。

```bash
cd /Users/llp/opensource/serverPortForward
make test
make build
```

生成文件：

```text
dist/server-port-forward-windows-amd64.exe
dist/server-port-forward-windows-arm64.exe
```

也可以直接执行：

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build \
  -trimpath -ldflags="-s -w -H=windowsgui" \
  -o dist/server-port-forward-windows-amd64.exe .
```

在 Windows PowerShell 中可以运行：

```powershell
.\build.ps1
```

## 使用方法

1. 将对应架构的 EXE 复制到 Windows 电脑。
2. 登录公司的 VPN，并先确认 Windows 本身可以访问目标服务器。
3. 双击 EXE，在 UAC 对话框中允许管理员权限。
4. 浏览器会自动打开本地管理页面。
5. 设置默认目标 IPv4，例如 `128.120.123.115`。
6. 创建规则：
   - 备注：`公司 SSH`
   - 监听地址：`0.0.0.0（所有网卡）`
   - Windows 端口：`71`
   - 目标 IPv4：`128.120.123.115`
   - 目标端口：`22`
7. 点击“测试”，确认目标、监听、本地映射和防火墙状态。
8. 在 Mac 上使用页面显示的 Windows 局域网 IPv4：

```bash
ssh -p 71 user@WINDOWS_LAN_IP
```

页面里的本机测试不能证明 Mac 到 Windows 的路由一定可用，最终仍需从 Mac 发起连接。

点击页面右上角“退出管理器”只会关闭管理网页和 EXE，不会停止已经保存到 Windows 的转发规则。

## 规则和防火墙边界

### 本工具管理的规则

创建规则时会依次执行等价于以下操作的固定参数命令：

```cmd
netsh interface portproxy add v4tov4 listenport=71 listenaddress=0.0.0.0 connectport=22 connectaddress=128.120.123.115 protocol=tcp
netsh advfirewall firewall add rule name=ServerPortForward-... group=ServerPortForward dir=in action=allow enable=yes protocol=TCP localport=71 localip=any remoteip=any profile=any
```

删除已管理规则时，同时删除它的专属防火墙规则。工具不会调用 shell，也不会把用户输入拼接成命令行脚本；地址和端口在执行前会严格验证。

### 系统外部规则

- 外部规则是 Windows 中已经存在、但不在本工具配置记录里的 `v4tov4` 规则。
- 直接删除外部规则时只删除 `portproxy`，不会猜测或删除现有防火墙规则。
- 编辑外部规则需要确认“接管”。接管后工具会记录该规则，并新增自己的专属防火墙规则；未知的原有防火墙规则仍保留。
- “清除已管理规则”不会影响外部规则。

## 持久数据

```text
%ProgramData%\ServerPortForward\config.json
%ProgramData%\ServerPortForward\logs\app.log
```

`config.json` 只保存默认目标地址、规则备注和本工具的防火墙归属，不保存账号、密码、VPN 凭据或 SSH 密钥。Windows 实际 `portproxy` 状态始终是界面显示和冲突判断的事实来源。

## 排障

### 1. Windows 无法访问 VPN 目标

先在 Windows PowerShell 中检查：

```powershell
Test-NetConnection -ComputerName 128.120.123.115 -Port 22
```

如果这里失败，端口转发也不会成功。请检查 VPN 是否已连接、目标 IP/端口是否正确，以及 VPN 路由或企业访问策略。

### 2. IP Helper 未运行

`portproxy` 依赖 Windows IP Helper 服务。界面可以在确认后启动服务，但不会修改其启动模式。如果服务被企业策略禁用，需联系管理员。

```powershell
Get-Service iphlpsvc
```

### 3. 规则存在但端口没有监听

```cmd
netsh interface portproxy show v4tov4
netstat -ano -p tcp | findstr ":71 "
```

检查 IP Helper 状态和本地端口冲突。页面诊断区域也会显示 `portproxy dump` 和所有匹配的监听行。

### 4. Windows 测试成功，但 Mac 无法连接

依次检查：

- Mac 使用的是 Windows 局域网 IPv4，而不是 VPN 地址或 `127.0.0.1`。
- Mac 能否 `ping` 或路由到 Windows 局域网地址。
- Windows 网络是否被识别为受企业策略限制的网络。
- VPN 客户端是否启用了“禁止本地局域网访问”、隔离或 kill switch。
- 第三方防火墙或终端安全软件是否拦截入站连接。

部分公司 VPN 明确禁止把 VPN 内服务转发给其他设备；这种限制不能由本工具绕过。

### 5. 查看原始 Windows 状态

```cmd
netsh interface portproxy show all
netsh interface portproxy dump
netsh advfirewall firewall show rule name=all
```

本工具不会提供全局 `netsh interface portproxy reset` 按钮，避免误删其他程序或管理员创建的规则。

## 本地 API 安全

管理 HTTP 服务只监听随机的 `127.0.0.1` 端口。启动 URL 使用一次性随机令牌换取 `HttpOnly`、`SameSite=Strict` 会话 Cookie；写操作还要求同源校验和独立 CSRF 令牌。API 只暴露预定义的 `netsh`、`netstat` 和 `sc` 操作，不提供任意命令执行接口。

## 官方参考

- [netsh interface portproxy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [netsh advfirewall](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-advfirewall)
- [Windows IP Helper 与 portproxy](https://learn.microsoft.com/en-us/windows/deployment/do/mcc-ent-troubleshooting)
