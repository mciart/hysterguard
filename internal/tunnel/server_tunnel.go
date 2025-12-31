// Package tunnel - 服务端隧道模块
package tunnel

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/hysterguard/hysterguard/internal/config"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// ServerTunnel 服务端隧道（集成 WireGuard）
type ServerTunnel struct {
	config *config.ServerConfig
	logger *slog.Logger

	tunDevice tun.Device
	wgDevice  *device.Device

	// HysteriaServerBind - 用于直接接收来自 Hysteria 的数据包
	hysteriaBind *HysteriaServerBind

	mu     sync.RWMutex
	closed atomic.Bool
	done   chan struct{}
}

// NewServerTunnel 创建服务端隧道
func NewServerTunnel(cfg *config.ServerConfig, logger *slog.Logger) (*ServerTunnel, error) {
	return &ServerTunnel{
		config: cfg,
		logger: logger,
		done:   make(chan struct{}),
	}, nil
}

// Start 启动服务端隧道（包含 WireGuard）- 全内存方式，无需端口监听
func (t *ServerTunnel) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.logger.Info("Starting WireGuard server (all-in-one mode)")

	// 1. 创建 TUN 设备
	tunName := "wg0"
	if runtime.GOOS == "darwin" {
		tunName = "utun"
	}

	t.logger.Debug("Creating TUN device", "name", tunName)
	tunDev, err := tun.CreateTUN(tunName, 1420)
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %w", err)
	}
	t.tunDevice = tunDev

	realName, err := tunDev.Name()
	if err == nil {
		t.logger.Info("TUN device created", "name", realName)
	}

	// 2. 创建 HysteriaServerBind（内存通道，不监听端口）
	t.hysteriaBind = NewHysteriaServerBind()

	// 3. 创建 WireGuard 设备
	wgLogger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			t.logger.Debug(fmt.Sprintf("[WG] "+format, args...))
		},
		Errorf: func(format string, args ...any) {
			t.logger.Error(fmt.Sprintf("[WG] "+format, args...))
		},
	}

	wgDev := device.NewDevice(tunDev, t.hysteriaBind, wgLogger)
	t.wgDevice = wgDev

	// 4. 配置 WireGuard
	ipcConfig, err := t.buildIpcConfig()
	if err != nil {
		tunDev.Close()
		return fmt.Errorf("failed to build IPC config: %w", err)
	}

	t.logger.Debug("Applying WireGuard configuration")
	if err := wgDev.IpcSet(ipcConfig); err != nil {
		tunDev.Close()
		return fmt.Errorf("failed to configure WireGuard: %w", err)
	}

	// 5. 启动 WireGuard 设备
	if err := wgDev.Up(); err != nil {
		tunDev.Close()
		return fmt.Errorf("failed to bring up WireGuard device: %w", err)
	}

	// 6. 配置 TUN 设备 IP 地址和路由
	if err := t.configureTUNAddress(); err != nil {
		t.logger.Warn("Failed to configure TUN address", "error", err)
	}

	// 7. 开启 IP 转发和 NAT（Linux）
	if runtime.GOOS == "linux" {
		t.setupNAT()
	}

	// 8. 执行 PostUp 钩子
	if len(t.config.WireGuard.PostUp) > 0 {
		ExecuteHooks(t.config.WireGuard.PostUp, t.logger, "PostUp")
	}

	t.logger.Info("WireGuard server started (no port listening - all-in-one)",
		"address", t.config.WireGuard.Address.IPv4,
	)

	return nil
}

// GetBind 获取 HysteriaServerBind（供 Hysteria 服务端使用）
func (t *ServerTunnel) GetBind() *HysteriaServerBind {
	return t.hysteriaBind
}

// Stop 停止服务端隧道
func (t *ServerTunnel) Stop() error {
	if t.closed.Swap(true) {
		return nil
	}

	// 执行 PostDown 钩子（在关闭设备之前）
	if len(t.config.WireGuard.PostDown) > 0 {
		ExecuteHooks(t.config.WireGuard.PostDown, t.logger, "PostDown")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.wgDevice != nil {
		t.wgDevice.Close()
		t.wgDevice = nil
	}

	if t.tunDevice != nil {
		t.tunDevice.Close()
		t.tunDevice = nil
	}

	if t.hysteriaBind != nil {
		t.hysteriaBind.Close()
		t.hysteriaBind = nil
	}

	close(t.done)
	t.logger.Info("WireGuard server stopped")
	return nil
}

// Wait 等待服务关闭
func (t *ServerTunnel) Wait() <-chan struct{} {
	return t.done
}

// buildIpcConfig 构建 WireGuard IPC 配置
func (t *ServerTunnel) buildIpcConfig() (string, error) {
	var builder strings.Builder

	// 私钥
	privateKey, err := decodeWireGuardKey(t.config.WireGuard.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}
	builder.WriteString(fmt.Sprintf("private_key=%s\n", hex.EncodeToString(privateKey)))

	// 不再需要监听端口
	// builder.WriteString(fmt.Sprintf("listen_port=%d\n", t.config.WireGuard.ListenPort))

	// Peers
	for _, peer := range t.config.WireGuard.Peers {
		publicKey, err := decodeWireGuardKey(peer.PublicKey)
		if err != nil {
			return "", fmt.Errorf("invalid peer public key: %w", err)
		}
		builder.WriteString(fmt.Sprintf("public_key=%s\n", hex.EncodeToString(publicKey)))

		for _, allowedIP := range peer.AllowedIPs {
			builder.WriteString(fmt.Sprintf("allowed_ip=%s\n", allowedIP))
		}

		if peer.PersistentKeepalive > 0 {
			builder.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.PersistentKeepalive))
		}
	}

	return builder.String(), nil
}

// configureTUNAddress 配置 TUN 设备 IP 地址
func (t *ServerTunnel) configureTUNAddress() error {
	name, err := t.tunDevice.Name()
	if err != nil {
		return err
	}

	t.logger.Debug("Configuring server TUN address",
		"device", name,
		"ipv4", t.config.WireGuard.Address.IPv4,
		"ipv6", t.config.WireGuard.Address.IPv6,
	)

	ipv4 := t.config.WireGuard.Address.IPv4
	if idx := strings.Index(ipv4, "/"); idx > 0 {
		ipv4 = ipv4[:idx]
	}

	switch runtime.GOOS {
	case "darwin":
		gateway := strings.TrimSuffix(ipv4, ".1") + ".2"
		if err := runCommand("ifconfig", name, "inet", ipv4, gateway, "netmask", "255.255.255.0"); err != nil {
			return fmt.Errorf("failed to configure IPv4: %w", err)
		}
		t.logger.Info("TUN interface configured", "device", name, "ip", ipv4)

	case "linux":
		// 配置 IPv4
		if err := runCommand("ip", "addr", "add", t.config.WireGuard.Address.IPv4, "dev", name); err != nil {
			return fmt.Errorf("failed to add IPv4 address: %w", err)
		}

		// 配置 IPv6（如果配置了）
		if t.config.WireGuard.Address.IPv6 != "" {
			if err := runCommand("ip", "-6", "addr", "add", t.config.WireGuard.Address.IPv6, "dev", name); err != nil {
				t.logger.Warn("Failed to add IPv6 address", "error", err)
			} else {
				t.logger.Info("IPv6 address configured", "device", name, "ip", t.config.WireGuard.Address.IPv6)
			}
		}

		if err := runCommand("ip", "link", "set", name, "up"); err != nil {
			return fmt.Errorf("failed to bring up interface: %w", err)
		}
		t.logger.Info("TUN interface configured", "device", name, "ip", t.config.WireGuard.Address.IPv4)

	default:
		t.logger.Warn("Automatic TUN configuration not supported on this platform")
	}

	return nil
}

// setupNAT 配置 NAT（Linux）
func (t *ServerTunnel) setupNAT() {
	t.logger.Debug("Setting up IP forwarding and NAT")

	// 开启 IPv4 转发
	if err := runCommand("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		t.logger.Warn("Failed to enable IPv4 forwarding", "error", err)
	}

	// 开启 IPv6 转发
	if err := runCommand("sysctl", "-w", "net.ipv6.conf.all.forwarding=1"); err != nil {
		t.logger.Warn("Failed to enable IPv6 forwarding", "error", err)
	}

	// IPv4 NAT
	ipv4 := t.config.WireGuard.Address.IPv4
	if idx := strings.Index(ipv4, "/"); idx > 0 {
		network := ipv4[:idx]
		parts := strings.Split(network, ".")
		if len(parts) == 4 {
			network = fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
		}

		if err := runCommand("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", network, "-j", "MASQUERADE"); err != nil {
			t.logger.Warn("Failed to add IPv4 NAT rule", "error", err)
		} else {
			t.logger.Info("IPv4 NAT configured", "network", network)
		}
	}

	// IPv6 NAT（如果配置了 IPv6）
	ipv6 := t.config.WireGuard.Address.IPv6
	if ipv6 != "" {
		// 提取 IPv6 网段，如 fd00::1/64 -> fd00::/64
		// 简化处理：直接使用固定的 fd00::/64 网段
		ipv6Network := "fd00::/64"
		if err := runCommand("ip6tables", "-t", "nat", "-A", "POSTROUTING", "-s", ipv6Network, "-j", "MASQUERADE"); err != nil {
			t.logger.Warn("Failed to add IPv6 NAT rule", "error", err)
		} else {
			t.logger.Info("IPv6 NAT configured", "network", ipv6Network)
		}
	}
}

// decodeWireGuardKeyServer 解码 WireGuard 密钥
func decodeWireGuardKeyServer(s string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: expected 32, got %d", len(key))
	}
	return key, nil
}

// runCommandServer 执行系统命令
func runCommandServer(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(output))
	}
	return nil
}
