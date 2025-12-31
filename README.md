# HysterGuard

**Hysteria 2 + WireGuard 混合 VPN**

将 Hysteria 2 的 QUIC 传输和 Salamander 混淆作为外层，WireGuard 的加密隧道作为内层，打造既能混淆流量又能提供 VPN 级加密的综合解决方案。

## 特性

- ✅ **双重加密**: Hysteria 2 QUIC + WireGuard 加密
- ✅ **流量混淆**: Salamander 混淆，伪装成普通 HTTPS 流量
- ✅ **All-in-One**: 服务端单进程运行，无需额外端口
- ✅ **自动带宽**: 不配置带宽时自动探测
- ✅ **跨平台**: 支持 Linux / macOS / Windows
- ✅ **自动路由**: 自动配置系统路由和 DNS
- ✅ **IPv6 支持**: 完整的双栈支持
- ✅ **Windows 原生**: 内嵌 Wintun 驱动，无需额外安装

## 下载

从 [GitHub Releases](https://github.com/hysterguard/hysterguard/releases) 下载预编译的二进制文件。

| 平台 | 客户端 | 服务端 |
|------|--------|--------|
| Linux x86_64 | `hysterguard-client-linux-amd64` | `hysterguard-server-linux-amd64` |
| Linux ARM64 | `hysterguard-client-linux-arm64` | `hysterguard-server-linux-arm64` |
| macOS x86_64 | `hysterguard-client-darwin-amd64` | - |
| macOS ARM64 | `hysterguard-client-darwin-arm64` | - |
| Windows x64 | `hysterguard-client-windows-amd64.exe` | - |
| Windows ARM64 | `hysterguard-client-windows-arm64.exe` | - |

> **注意**: 服务端目前仅支持 Linux。

## 架构

```
┌─────────────────────────────────────────────────────────────────┐
│                          客户端                                  │
├─────────────────────────────────────────────────────────────────┤
│  应用流量 → TUN设备 → WireGuard加密 → Hysteria QUIC 混淆传输     │
└─────────────────────────────────────────────────────────────────┘
                              ↓ UDP over QUIC (混淆)
┌─────────────────────────────────────────────────────────────────┐
│                          服务端 (All-in-One)                     │
├─────────────────────────────────────────────────────────────────┤
│  Hysteria 解混淆 → WireGuard 解密 → TUN设备 → NAT → 互联网       │
└─────────────────────────────────────────────────────────────────┘
```

## 快速开始

### 1. 生成密钥对

```bash
# 服务端
wg genkey | tee server_private.key | wg pubkey > server_public.key

# 客户端
wg genkey | tee client_private.key | wg pubkey > client_public.key
```

### 2. 服务端配置

创建 `server.yaml`:

```yaml
listen: ":8443"

hysteria:
  auth: "your-password"
  tls:
    cert: "/path/to/fullchain.pem"
    key: "/path/to/privkey.pem"
  obfs:
    type: salamander
    password: "obfs-password"

wireguard:
  private_key: "<服务端私钥>"
  address:
    ipv4: "10.10.0.1/24"
    ipv6: "fd00::1/64"
  peers:
    - public_key: "<客户端公钥>"
      allowed_ips:
        - "10.10.0.2/32"
        - "fd00::2/128"
```

### 3. 客户端配置

创建 `client.yaml`:

```yaml
hysteria:
  server: "your-server.com:8443"
  auth: "your-password"
  sni: "www.microsoft.com"
  insecure: false
  obfs:
    type: salamander
    password: "obfs-password"

wireguard:
  private_key: "<客户端私钥>"
  peer:
    public_key: "<服务端公钥>"
    allowed_ips:
      - "0.0.0.0/0"
      - "::/0"
    persistent_keepalive: 25

tun:
  name: "hysterguard0"
  mtu: 1280
  address:
    ipv4: "10.10.0.2/24"
    ipv6: "fd00::2/64"
  dns:
    servers:
      - "8.8.8.8"
      - "8.8.4.4"
```

### 4. 运行

**Linux/macOS (需要 root 权限):**
```bash
sudo ./hysterguard-server-linux-amd64 -c server.yaml
sudo ./hysterguard-client-darwin-arm64 -c client.yaml
```

**Windows (需要管理员权限):**
```powershell
# 右键"以管理员身份运行"
.\hysterguard-client-windows-amd64.exe -c client.yaml
```

### 5. 验证

```bash
curl ip.sb      # 检查 IPv4
curl -6 ip.sb   # 检查 IPv6
```

## 平台支持

| 平台 | 客户端 | 服务端 | 说明 |
|------|--------|--------|------|
| Linux x86_64 | ✅ | ✅ | 完整支持 |
| Linux ARM64 | ✅ | ✅ | 完整支持 |
| macOS x86_64 | ✅ | ❌ | 客户端完整支持 |
| macOS ARM64 | ✅ | ❌ | 客户端完整支持 (Apple Silicon) |
| Windows x64 | ✅ | ❌ | 客户端完整支持 (内嵌 Wintun) |
| Windows ARM64 | ✅ | ❌ | 客户端完整支持 |

## Windows 客户端说明

Windows 客户端已**内嵌 Wintun 驱动**，无需额外安装：
- 首次运行时自动解压 `wintun.dll` 到程序目录
- 支持 IPv4/IPv6 双栈
- 自动配置路由和 DNS

**要求:**
- Windows 10/11
- 以管理员身份运行

## 配置详解

### 带宽配置 (可选)

```yaml
hysteria:
  bandwidth:
    up: "50 mbps"
    down: "200 mbps"
```

不配置时自动探测。支持单位: `bps`, `kbps`, `mbps`, `gbps`

### 出口网口配置 (Linux 服务端)

当服务器有多个网口时，可指定 VPN 流量出口：

```yaml
outbound:
  ipv4_device: "ens4"   # IPv4 走原生接口
  ipv6_device: "warp"   # IPv6 走 WARP 接口
```

留空或设为 `"auto"` 自动检测。

### PostUp/PostDown 钩子

```yaml
tun:
  post_up:
    - "echo 'VPN connected'"
  post_down:
    - "echo 'VPN disconnected'"
```

## 命令行选项

```bash
./hysterguard-client -c config.yaml -l debug

# 选项:
#   -c, --config     配置文件路径 (默认: config.yaml)
#   -l, --log-level  日志级别: debug, info, warn, error (默认: info)
```

## 从源码构建

```bash
git clone https://github.com/hysterguard/hysterguard.git
cd hysterguard

# 下载 Wintun DLL (Windows 构建需要)
./scripts/download_wintun.sh

# 编译所有平台
./scripts/build.sh all

# 或只编译当前平台
go build -o client ./cmd/client
go build -o server ./cmd/server
```

## 故障排除

### 连接不上服务器
- 检查防火墙是否开放了 Hysteria 端口
- 确认 TLS 证书有效
- 确认认证密码正确

### WireGuard 握手失败
- 检查公钥/私钥配对
- 确认 `allowed_ips` 配置正确

### Windows 无法上网
- 确保以管理员身份运行
- 检查日志中是否有路由配置错误
- 尝试手动添加路由测试

### Linux SSH 断开
使用策略路由保持 SSH 连接：

```yaml
tun:
  post_up:
    - "ip -4 rule add from <服务器IP> lookup main priority 100"
  post_down:
    - "ip -4 rule delete from <服务器IP> lookup main priority 100"
```

## License

MIT License
