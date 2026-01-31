// Package tunnel - 服务端隧道模块
package tunnel

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/hysterguard/hysterguard/internal/config"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// ServerTunnel 服务端隧道（集成 WireGuard）
type ServerTunnel struct {
	config *config.ServerConfig
	logger *slog.Logger

	tunDevice  tun.Device
	wgDevice   *device.Device
	wgBind     conn.Bind // 标准 UDP 绑定
	listenPort uint16    // 实际监听端口

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

// Start 启动服务端隧道（包含 WireGuard）- 监听真实 UDP 端口
func (t *ServerTunnel) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// 解析监听地址获取端口
	listenAddr := t.config.WireGuard.Listen
	_, portStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return fmt.Errorf("invalid listen address %s: %w", listenAddr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port in listen address: %w", err)
	}

	t.logger.Info("Starting WireGuard server (local mode)", "listen", listenAddr)

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

	// 2. 创建标准 UDP 绑定（监听真实端口）
	t.wgBind = conn.NewDefaultBind()

	// 3. 创建 WireGuard 设备
	wgLogger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			t.logger.Debug(fmt.Sprintf("[WG] "+format, args...))
		},
		Errorf: func(format string, args ...any) {
			t.logger.Error(fmt.Sprintf("[WG] "+format, args...))
		},
	}

	wgDev := device.NewDevice(tunDev, t.wgBind, wgLogger)
	t.wgDevice = wgDev

	// 4. 配置 WireGuard（包含监听端口）
	ipcConfig, err := t.buildIpcConfig()
	if err != nil {
		tunDev.Close()
		return fmt.Errorf("failed to build IPC config: %w", err)
	}
	// 添加监听端口配置
	ipcConfig = fmt.Sprintf("listen_port=%d\n%s", port, ipcConfig)

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

	t.listenPort = uint16(port)
	t.logger.Info("WireGuard listening on UDP port", "port", t.listenPort)

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

	t.logger.Info("WireGuard server started (local mode)",
		"listen", listenAddr,
		"address", t.config.WireGuard.Address.IPv4,
	)

	return nil
}

// GetListenPort 获取实际监听的端口
func (t *ServerTunnel) GetListenPort() uint16 {
	return t.listenPort
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

	if t.wgBind != nil {
		t.wgBind.Close()
		t.wgBind = nil
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

	// 获取 VPN 网段
	ipv4Network := ""
	ipv4 := t.config.WireGuard.Address.IPv4
	if idx := strings.Index(ipv4, "/"); idx > 0 {
		network := ipv4[:idx]
		parts := strings.Split(network, ".")
		if len(parts) == 4 {
			ipv4Network = fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
		}
	}

	ipv6Network := "fd00::/64"

	// 获取 IPv4 出口设备
	ipv4Device := t.config.Outbound.IPv4Device
	if ipv4Device == "" || ipv4Device == "auto" {
		if detected, err := detectOutboundDevice(4); err == nil && detected != "" {
			ipv4Device = detected
			t.logger.Info("Auto-detected IPv4 outbound device", "device", ipv4Device)
		}
	}

	// 获取 IPv6 出口设备
	ipv6Device := t.config.Outbound.IPv6Device
	if ipv6Device == "" || ipv6Device == "auto" {
		if detected, err := detectOutboundDevice(6); err == nil && detected != "" {
			ipv6Device = detected
			t.logger.Info("Auto-detected IPv6 outbound device", "device", ipv6Device)
		}
	}

	// 配置 IPv4 策略路由（如果指定了设备）
	if ipv4Device != "" && ipv4Network != "" {
		t.setupPolicyRouting(4, ipv4Device, ipv4Network)
	}

	// 配置 IPv6 策略路由（如果指定了设备）
	if ipv6Device != "" && t.config.WireGuard.Address.IPv6 != "" {
		t.setupPolicyRouting(6, ipv6Device, ipv6Network)
	}

	// 获取 TUN 设备名称
	tunName := "wg0"
	if t.tunDevice != nil {
		if name, err := t.tunDevice.Name(); err == nil {
			tunName = name
		}
	}

	// 配置 FORWARD 链规则（允许 VPN 流量转发）
	// 许多 Linux 发行版默认 FORWARD 策略为 DROP
	t.logger.Debug("Setting up FORWARD rules", "device", tunName)

	// IPv4 FORWARD 规则
	if err := runCommand("iptables", "-A", "FORWARD", "-i", tunName, "-j", "ACCEPT"); err != nil {
		t.logger.Debug("FORWARD rule add result", "direction", "in", "error", err)
	}
	if err := runCommand("iptables", "-A", "FORWARD", "-o", tunName, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"); err != nil {
		t.logger.Debug("FORWARD rule add result", "direction", "out", "error", err)
	}
	t.logger.Info("IPv4 FORWARD rules configured", "device", tunName)

	// IPv6 FORWARD 规则
	if t.config.WireGuard.Address.IPv6 != "" {
		if err := runCommand("ip6tables", "-A", "FORWARD", "-i", tunName, "-j", "ACCEPT"); err != nil {
			t.logger.Debug("IPv6 FORWARD rule add result", "direction", "in", "error", err)
		}
		if err := runCommand("ip6tables", "-A", "FORWARD", "-o", tunName, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"); err != nil {
			t.logger.Debug("IPv6 FORWARD rule add result", "direction", "out", "error", err)
		}
		t.logger.Info("IPv6 FORWARD rules configured", "device", tunName)
	}

	// IPv4 NAT（不指定 -o，让 MASQUERADE 自动适应）
	if ipv4Network != "" {
		if err := runCommand("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", ipv4Network, "-j", "MASQUERADE"); err != nil {
			t.logger.Warn("Failed to add IPv4 NAT rule", "error", err)
		} else {
			t.logger.Info("IPv4 NAT configured", "network", ipv4Network)
		}
	}

	// IPv6 NAT（不指定 -o，让 MASQUERADE 自动适应）
	if t.config.WireGuard.Address.IPv6 != "" {
		if err := runCommand("ip6tables", "-t", "nat", "-A", "POSTROUTING", "-s", ipv6Network, "-j", "MASQUERADE"); err != nil {
			t.logger.Warn("Failed to add IPv6 NAT rule", "error", err)
		} else {
			t.logger.Info("IPv6 NAT configured", "network", ipv6Network)
		}
	}
}

// setupPolicyRouting 配置策略路由
// 使用专用路由表强制 VPN 流量走指定设备
func (t *ServerTunnel) setupPolicyRouting(ipVersion int, device string, vpnNetwork string) {
	var tableID string
	var ipCmd string

	if ipVersion == 4 {
		tableID = "100"
		ipCmd = "ip"
	} else {
		tableID = "101"
		ipCmd = "ip"
	}

	t.logger.Debug("Setting up policy routing", "version", ipVersion, "device", device, "table", tableID)

	// 获取该设备的网关
	gateway, err := getDeviceGateway(ipVersion, device)
	if err != nil {
		t.logger.Warn("Failed to get gateway for device, skipping policy routing", "device", device, "error", err)
		return
	}

	// 1. 添加路由表中的默认路由
	var routeArgs []string
	if ipVersion == 4 {
		routeArgs = []string{"route", "add", "default", "via", gateway, "dev", device, "table", tableID}
	} else {
		// IPv6 可能没有 via，直接用 dev
		if gateway != "" {
			routeArgs = []string{"-6", "route", "add", "default", "via", gateway, "dev", device, "table", tableID}
		} else {
			routeArgs = []string{"-6", "route", "add", "default", "dev", device, "table", tableID}
		}
	}

	if err := runCommand(ipCmd, routeArgs...); err != nil {
		// 路由可能已存在
		t.logger.Debug("Route add result (may already exist)", "error", err)
	}

	// 2. 添加策略规则：来自 VPN 网段的流量使用专用路由表
	var ruleArgs []string
	if ipVersion == 4 {
		ruleArgs = []string{"rule", "add", "from", vpnNetwork, "lookup", tableID, "priority", "100"}
	} else {
		ruleArgs = []string{"-6", "rule", "add", "from", vpnNetwork, "lookup", tableID, "priority", "100"}
	}

	if err := runCommand(ipCmd, ruleArgs...); err != nil {
		t.logger.Debug("Rule add result (may already exist)", "error", err)
	}

	if ipVersion == 4 {
		t.logger.Info("IPv4 policy routing configured", "device", device, "table", tableID, "gateway", gateway)
	} else {
		t.logger.Info("IPv6 policy routing configured", "device", device, "table", tableID)
	}
}

// getDeviceGateway 获取设备的网关地址
func getDeviceGateway(ipVersion int, device string) (string, error) {
	var args []string

	if ipVersion == 4 {
		args = []string{"route", "show", "dev", device}
	} else {
		args = []string{"-6", "route", "show", "dev", device}
	}

	output, err := exec.Command("ip", args...).Output()
	if err != nil {
		return "", err
	}

	// 解析输出，查找 default via xxx 或直接返回空（对于点对点接口）
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "default") {
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "via" && i+1 < len(parts) {
					return parts[i+1], nil
				}
			}
		}
	}

	// 对于点对点接口（如 warp），可能没有 via，返回空字符串表示直连
	return "", nil
}

// detectOutboundDevice 自动检测出口网口
// 使用 `ip route get <目标IP>` 获取实际出口设备
func detectOutboundDevice(ipVersion int) (string, error) {
	var args []string

	if ipVersion == 4 {
		args = []string{"route", "get", "1.1.1.1"}
	} else {
		args = []string{"-6", "route", "get", "2606:4700::1111"}
	}

	output, err := exec.Command("ip", args...).Output()
	if err != nil {
		return "", err
	}

	// 解析输出，提取 "dev xxx" 字段
	// 示例: "1.1.1.1 via 192.168.1.1 dev ens4 src 192.168.1.209 uid 0"
	// 示例: "2606:4700::1111 from :: dev warp proto kernel src 2606:4700:..."
	outputStr := string(output)
	parts := strings.Fields(outputStr)
	for i, part := range parts {
		if part == "dev" && i+1 < len(parts) {
			return parts[i+1], nil
		}
	}

	return "", fmt.Errorf("could not parse device from: %s", outputStr)
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
