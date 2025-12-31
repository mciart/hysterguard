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

### 1. 编译

```bash
cd hysterguard

# 编译所有平台
./scripts/build.sh all

# 或只编译当前平台
./scripts/build.sh current
```

编译产物在 `build/output/` 目录。

### 2. 生成密钥对

```bash
# 服务端
wg genkey | tee server_private.key | wg pubkey > server_public.key

# 客户端
wg genkey | tee client_private.key | wg pubkey > client_public.key
```

### 3. 服务端配置

创建 `server.yaml`:

```yaml
# 外部监听地址
listen: ":8443"

# Hysteria 配置
hysteria:
  auth: "your-password"
  tls:
    cert: "/path/to/fullchain.pem"
    key: "/path/to/privkey.pem"
  obfs:
    type: salamander
    password: "obfs-password"

# WireGuard 配置
wireguard:
  private_key: "<服务端私钥>"
  listen_port: 51820  # 仅用于配置，不实际监听
  address:
    ipv4: "10.10.0.1/24"
    ipv6: "fd00::1/64"
  peers:
    - public_key: "<客户端公钥>"
      allowed_ips:
        - "10.10.0.2/32"
        - "fd00::2/128"
```

### 4. 客户端配置

创建 `client.yaml`:

```yaml
# Hysteria 配置
hysteria:
  server: "your-server.com:8443"
  auth: "your-password"
  sni: "www.microsoft.com"  # TLS SNI 伪装
  insecure: false
  obfs:
    type: salamander
    password: "obfs-password"
  # bandwidth:  # 可选，不配置则自动探测
  #   up: "50 mbps"
  #   down: "200 mbps"

# WireGuard 配置
wireguard:
  private_key: "<客户端私钥>"
  peer:
    public_key: "<服务端公钥>"
    allowed_ips:
      - "0.0.0.0/0"
      - "::/0"
    persistent_keepalive: 25

# TUN 设备配置
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

### 5. 运行

```bash
# 服务端 (需要 root 权限)
sudo ./server-linux-amd64 -c server.yaml

# 客户端 (需要 root 权限)
sudo ./client-darwin-arm64 -c client.yaml
```

### 6. 验证

```bash
# 检查 IP
curl ip.sb

# 检查 IPv6
curl -6 ip.sb
```

## 配置详解

### 带宽配置

带宽配置是可选的。如果不指定，Hysteria 2 会自动探测最佳带宽：

```yaml
hysteria:
  # 方式 1: 不配置，使用自动带宽
  # bandwidth: 省略

  # 方式 2: 手动指定
  bandwidth:
    up: "50 mbps"      # 上传带宽
    down: "200 mbps"   # 下载带宽
```

支持的单位: `bps`, `kbps`, `mbps`, `gbps`

### DNS 配置

连接 VPN 后自动配置 DNS：

```yaml
tun:
  dns:
    servers:
      - "8.8.8.8"        # Google DNS
      - "1.1.1.1"        # Cloudflare DNS
      - "2001:4860:4860::8888"  # IPv6 DNS
```

断开连接后自动恢复原始 DNS。

### PostUp/PostDown 钩子

在 TUN 接口启动后/关闭前执行自定义命令：

```yaml
tun:
  post_up:
    - "ip -4 rule add from 服务器公网IP lookup main"
    - "echo 'VPN connected' >> /var/log/vpn.log"
  post_down:
    - "ip -4 rule delete from 服务器公网IP lookup main"
```

**常见用途**:
- 添加策略路由（保持 SSH 连接）
- 设置防火墙规则
- 记录日志

### TLS 证书

服务端需要有效的 TLS 证书。推荐使用 Let's Encrypt:

```bash
# 使用 certbot
sudo certbot certonly --standalone -d your-domain.com
```

或者使用自签证书（客户端需设置 `insecure: true`）。

## 命令行选项

```bash
# 客户端
./client -c config.yaml -l debug

# 服务端
./server -c config.yaml -l debug

# 选项:
#   -c, --config   配置文件路径 (默认: config.yaml)
#   -l, --log-level 日志级别: debug, info, warn, error (默认: info)
```

## 平台支持

| 平台 | 客户端 | 服务端 | 说明 |
|------|--------|--------|------|
| Linux x86_64 | ✅ | ✅ | 完整支持 |
| Linux ARM64 | ✅ | ✅ | 完整支持 |
| macOS x86_64 | ✅ | ✅ | 完整支持 |
| macOS ARM64 | ✅ | ✅ | 完整支持 (Apple Silicon) |
| Windows x64 | ⚠️ | ⚠️ | 需要 wintun.dll |

## 故障排除

### 连接不上服务器

1. 检查防火墙是否开放了 Hysteria 端口 (如 8443)
2. 确认 TLS 证书有效
3. 确认认证密码和混淆密码正确

### 握手失败

1. 检查客户端和服务端的 WireGuard 公钥/私钥是否匹配
2. 确认 `allowed_ips` 配置正确

### IPv6 不工作

1. 确认服务端配置了 IPv6 地址 (`fd00::1/64`)
2. 确认服务端 peer 的 `allowed_ips` 包含客户端 IPv6 地址
3. 确认服务端开启了 IPv6 NAT

### DNS 泄漏

确认配置了 DNS 服务器:

```yaml
tun:
  dns:
    servers:
      - "8.8.8.8"
```

### 在服务器上运行客户端导致 SSH 断开

如果你在 VPS 上运行客户端（如测试 Linux 客户端），VPN 会接管所有流量导致 SSH 断开。

**解决方案**: 使用策略路由让服务器公网 IP 的流量走原路由：

```yaml
tun:
  post_up:
    - "ip -4 rule add from 你的服务器公网IP lookup main"
  post_down:
    - "ip -4 rule delete from 你的服务器公网IP lookup main"
```

**调试**: 使用 `-l debug` 检查 PostUp 是否执行：

```bash
sudo ./client-linux-amd64 -c client.yaml -l debug
# 查看输出中是否有 "Executing hooks type=PostUp"
```

**验证规则是否生效**:

```bash
ip rule show
# 应该能看到: from 你的IP lookup main
```

## License

MIT License
