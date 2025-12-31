// Package tunnel - WireGuard 设备包装模块
package tunnel

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/hysterguard/hysterguard/internal/config"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// WireGuardDevice WireGuard 设备包装
type WireGuardDevice struct {
	config    *config.ClientConfig
	transport UDPTransport
	logger    *slog.Logger

	tunDevice tun.Device
	wgDevice  *device.Device
	bind      *HysteriaBind

	mu     sync.RWMutex
	closed atomic.Bool
}

// NewWireGuardDevice 创建 WireGuard 设备
func NewWireGuardDevice(cfg *config.ClientConfig, transport UDPTransport, logger *slog.Logger) (*WireGuardDevice, error) {
	return &WireGuardDevice{
		config:    cfg,
		transport: transport,
		logger:    logger,
	}, nil
}

// Start 启动 WireGuard 设备
func (d *WireGuardDevice) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// 根据平台选择 TUN 设备名称
	tunName := d.config.TUN.Name
	if runtime.GOOS == "darwin" {
		// macOS 要求 TUN 设备名称为 utun[0-9]* 格式
		// 使用 "utun" 让系统自动分配编号
		tunName = "utun"
		d.logger.Debug("macOS detected, using automatic utun naming")
	}

	// 创建 TUN 设备
	d.logger.Debug("Creating TUN device", "name", tunName)
	tunDev, err := tun.CreateTUN(tunName, d.config.TUN.MTU)
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %w", err)
	}
	d.tunDevice = tunDev

	realName, err := tunDev.Name()
	if err == nil {
		d.logger.Info("TUN device created", "name", realName)
	}

	// 创建自定义 Bind（使用 Hysteria 传输）
	d.bind = NewHysteriaBind(d.transport, d.logger)

	// 创建 WireGuard 设备
	wgLogger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			d.logger.Debug(fmt.Sprintf("[WG] "+format, args...))
		},
		Errorf: func(format string, args ...any) {
			d.logger.Error(fmt.Sprintf("[WG] "+format, args...))
		},
	}

	wgDev := device.NewDevice(tunDev, d.bind, wgLogger)
	d.wgDevice = wgDev

	// 配置 WireGuard
	ipcConfig, err := d.buildIpcConfig()
	if err != nil {
		tunDev.Close()
		return fmt.Errorf("failed to build IPC config: %w", err)
	}

	d.logger.Debug("Applying WireGuard configuration")
	if err := wgDev.IpcSet(ipcConfig); err != nil {
		tunDev.Close()
		return fmt.Errorf("failed to configure WireGuard: %w", err)
	}

	// 启动设备
	if err := wgDev.Up(); err != nil {
		tunDev.Close()
		return fmt.Errorf("failed to bring up WireGuard device: %w", err)
	}

	// 配置 TUN 设备 IP 地址
	if err := d.configureTUNAddress(); err != nil {
		d.logger.Warn("Failed to configure TUN address (may need manual configuration)", "error", err)
		// 不返回错误，允许用户手动配置
	}

	// 执行 PostUp 钩子
	if len(d.config.TUN.PostUp) > 0 {
		ExecuteHooks(d.config.TUN.PostUp, d.logger, "PostUp")
	}

	d.logger.Info("WireGuard device started successfully")
	return nil
}

// Stop 停止 WireGuard 设备
func (d *WireGuardDevice) Stop() error {
	if d.closed.Swap(true) {
		return nil
	}

	// 执行 PostDown 钩子（在关闭设备之前）
	if len(d.config.TUN.PostDown) > 0 {
		ExecuteHooks(d.config.TUN.PostDown, d.logger, "PostDown")
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.wgDevice != nil {
		d.wgDevice.Close()
		d.wgDevice = nil
	}

	if d.tunDevice != nil {
		d.tunDevice.Close()
		d.tunDevice = nil
	}

	return nil
}

// GetTUNName 获取 TUN 设备名称
func (d *WireGuardDevice) GetTUNName() string {
	if d.tunDevice == nil {
		return ""
	}
	name, err := d.tunDevice.Name()
	if err != nil {
		return ""
	}
	return name
}

// buildIpcConfig 构建 WireGuard IPC 配置
func (d *WireGuardDevice) buildIpcConfig() (string, error) {
	var builder strings.Builder

	// 私钥
	privateKey, err := decodeWireGuardKey(d.config.WireGuard.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}
	builder.WriteString(fmt.Sprintf("private_key=%s\n", hex.EncodeToString(privateKey)))

	// Peer 配置
	publicKey, err := decodeWireGuardKey(d.config.WireGuard.Peer.PublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid peer public key: %w", err)
	}
	builder.WriteString(fmt.Sprintf("public_key=%s\n", hex.EncodeToString(publicKey)))

	// Endpoint - 使用占位符地址，实际流量通过 Hysteria 传输
	// WireGuard 需要一个 endpoint 但我们通过自定义 Bind 重定向流量
	builder.WriteString(fmt.Sprintf("endpoint=%s\n", "127.0.0.1:51820"))

	// Allowed IPs
	for _, allowedIP := range d.config.WireGuard.Peer.AllowedIPs {
		builder.WriteString(fmt.Sprintf("allowed_ip=%s\n", allowedIP))
	}

	// Persistent Keepalive
	if d.config.WireGuard.Peer.PersistentKeepalive > 0 {
		builder.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", d.config.WireGuard.Peer.PersistentKeepalive))
	}

	return builder.String(), nil
}

// configureTUNAddress 配置 TUN 设备 IP 地址
func (d *WireGuardDevice) configureTUNAddress() error {
	// 获取 TUN 设备名称
	name, err := d.tunDevice.Name()
	if err != nil {
		return err
	}

	d.logger.Debug("Configuring TUN address",
		"device", name,
		"ipv4", d.config.TUN.Address.IPv4,
		"ipv6", d.config.TUN.Address.IPv6,
	)

	// 提取 IP 地址（不含 CIDR）
	ipv4 := d.config.TUN.Address.IPv4
	if idx := strings.Index(ipv4, "/"); idx > 0 {
		ipv4 = ipv4[:idx]
	}

	switch runtime.GOOS {
	case "darwin":
		// macOS 使用 ifconfig
		// ifconfig utunX inet 10.0.0.2 10.0.0.1 netmask 255.255.255.0
		// 第一个 IP 是本地地址，第二个是对端地址（网关）
		gateway := strings.TrimSuffix(ipv4, ".2") + ".1" // 假设网关是 .1
		if err := runCommand("ifconfig", name, "inet", ipv4, gateway, "netmask", "255.255.255.0"); err != nil {
			return fmt.Errorf("failed to configure IPv4: %w", err)
		}

		// 配置 IPv6 地址
		ipv6 := d.config.TUN.Address.IPv6
		if ipv6 != "" {
			// 提取 IPv6 地址（不含前缀长度）
			ipv6Addr := ipv6
			prefixLen := "64"
			if idx := strings.Index(ipv6, "/"); idx > 0 {
				ipv6Addr = ipv6[:idx]
				prefixLen = ipv6[idx+1:]
			}
			// macOS: ifconfig utunX inet6 fd00::2 prefixlen 64
			if err := runCommand("ifconfig", name, "inet6", ipv6Addr, "prefixlen", prefixLen); err != nil {
				d.logger.Warn("Failed to configure IPv6", "error", err)
			} else {
				d.logger.Info("IPv6 address configured", "device", name, "ip", ipv6)
			}
		}

		d.logger.Info("TUN interface configured", "device", name, "ip", ipv4)

	case "linux":
		// Linux 使用 ip 命令
		if err := runCommand("ip", "addr", "add", d.config.TUN.Address.IPv4, "dev", name); err != nil {
			return fmt.Errorf("failed to add IPv4 address: %w", err)
		}

		// 配置 IPv6 地址
		ipv6 := d.config.TUN.Address.IPv6
		if ipv6 != "" {
			if err := runCommand("ip", "-6", "addr", "add", ipv6, "dev", name); err != nil {
				d.logger.Warn("Failed to configure IPv6 address", "error", err)
			} else {
				d.logger.Info("IPv6 address configured", "device", name, "ip", ipv6)
			}
		}

		if err := runCommand("ip", "link", "set", name, "up"); err != nil {
			return fmt.Errorf("failed to bring up interface: %w", err)
		}

		// 添加路由
		for _, allowedIP := range d.config.WireGuard.Peer.AllowedIPs {
			if allowedIP != "0.0.0.0/0" && allowedIP != "::/0" {
				if err := runCommand("ip", "route", "add", allowedIP, "dev", name); err != nil {
					d.logger.Warn("Failed to add route", "route", allowedIP, "error", err)
				}
			}
		}

		d.logger.Info("TUN interface configured", "device", name, "ip", d.config.TUN.Address.IPv4)

	default:
		d.logger.Warn("Automatic TUN configuration not supported on this platform, please configure manually")
	}

	return nil
}

// runCommand 执行系统命令
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(output))
	}
	return nil
}

// decodeWireGuardKey 解码 WireGuard 密钥（base64）
func decodeWireGuardKey(s string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: expected 32, got %d", len(key))
	}
	return key, nil
}

// HysteriaBind 实现 WireGuard Bind 接口，使用 Hysteria 传输
type HysteriaBind struct {
	transport UDPTransport
	logger    *slog.Logger

	mu      sync.Mutex
	closed  atomic.Bool
	recvBuf []byte
}

// NewHysteriaBind 创建 Hysteria Bind
func NewHysteriaBind(transport UDPTransport, logger *slog.Logger) *HysteriaBind {
	return &HysteriaBind{
		transport: transport,
		logger:    logger,
		recvBuf:   make([]byte, 65535),
	}
}

// Open 实现 Bind.Open
func (b *HysteriaBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.logger.Debug("HysteriaBind.Open called", "port", port)

	// 重置关闭标志（WireGuard 的 BindUpdate 会先调用 Close 再调用 Open）
	b.closed.Store(false)

	// 返回一个接收函数
	recvFunc := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		if b.closed.Load() {
			return 0, net.ErrClosed
		}

		// 从 Hysteria 传输层读取数据
		size, addr, err := b.transport.ReadFrom(packets[0])
		if err != nil {
			return 0, err
		}

		sizes[0] = size

		// 解析端点
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			return 0, fmt.Errorf("unexpected address type: %T", addr)
		}

		eps[0] = &HysteriaEndpoint{
			addr: udpAddr,
		}

		return 1, nil
	}

	return []conn.ReceiveFunc{recvFunc}, 0, nil
}

// Close 实现 Bind.Close
func (b *HysteriaBind) Close() error {
	b.closed.Store(true)
	return nil
}

// SetMark 实现 Bind.SetMark（不支持）
func (b *HysteriaBind) SetMark(mark uint32) error {
	return nil // Hysteria 不需要 socket mark
}

// Send 实现 Bind.Send
func (b *HysteriaBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if b.closed.Load() {
		b.logger.Debug("HysteriaBind.Send: bind is closed")
		return net.ErrClosed
	}

	hyEp, ok := ep.(*HysteriaEndpoint)
	if !ok {
		return fmt.Errorf("unexpected endpoint type: %T", ep)
	}

	b.logger.Debug("HysteriaBind.Send",
		"endpoint", hyEp.addr.String(),
		"packets", len(bufs),
	)

	for i, buf := range bufs {
		n, err := b.transport.WriteTo(buf, hyEp.addr)
		if err != nil {
			b.logger.Error("HysteriaBind.Send failed",
				"packet", i,
				"size", len(buf),
				"endpoint", hyEp.addr.String(),
				"error", err,
			)
			return err
		}
		b.logger.Debug("HysteriaBind.Send success", "packet", i, "bytes", n)
	}

	return nil
}

// ParseEndpoint 实现 Bind.ParseEndpoint
func (b *HysteriaBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil, err
	}
	return &HysteriaEndpoint{addr: addr}, nil
}

// BatchSize 实现 Bind.BatchSize
func (b *HysteriaBind) BatchSize() int {
	return 1 // Hysteria 不支持批量发送
}

// HysteriaEndpoint 实现 WireGuard Endpoint 接口
type HysteriaEndpoint struct {
	addr *net.UDPAddr
}

func (e *HysteriaEndpoint) ClearSrc() {}

func (e *HysteriaEndpoint) SrcToString() string {
	return ""
}

func (e *HysteriaEndpoint) DstToString() string {
	return e.addr.String()
}

func (e *HysteriaEndpoint) DstToBytes() []byte {
	addr := e.addr.AddrPort()
	b, _ := addr.MarshalBinary()
	return b
}

func (e *HysteriaEndpoint) DstIP() netip.Addr {
	addr, _ := netip.AddrFromSlice(e.addr.IP)
	return addr
}

func (e *HysteriaEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}
