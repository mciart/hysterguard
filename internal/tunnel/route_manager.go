// Package tunnel - 路由管理模块
package tunnel

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"runtime"
	"strings"
)

// RouteManager 路由管理器
type RouteManager struct {
	logger      *slog.Logger
	serverIP    string
	gateway     string
	tunGateway  string
	tunDevice   string // 实际的 TUN 设备名称
	routesAdded []string
	configured  bool
}

// NewRouteManager 创建路由管理器
func NewRouteManager(serverAddr string, tunGateway string, tunDevice string, logger *slog.Logger) *RouteManager {
	// 从服务器地址提取 IP
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		host = serverAddr
	}

	return &RouteManager{
		logger:     logger,
		serverIP:   host,
		tunGateway: tunGateway,
		tunDevice:  tunDevice,
	}
}

// Setup 配置路由（将所有流量导向 VPN）
func (r *RouteManager) Setup() error {
	r.logger.Info("Setting up VPN routes", "server", r.serverIP, "tunGateway", r.tunGateway)

	switch runtime.GOOS {
	case "darwin":
		return r.setupDarwin()
	case "linux":
		return r.setupLinux()
	default:
		r.logger.Warn("Automatic route configuration not supported on this platform")
		return nil
	}
}

// Teardown 恢复原始路由
func (r *RouteManager) Teardown() error {
	if !r.configured {
		return nil
	}

	r.logger.Info("Restoring original routes")

	switch runtime.GOOS {
	case "darwin":
		return r.teardownDarwin()
	case "linux":
		return r.teardownLinux()
	default:
		return nil
	}
}

// setupDarwin macOS 路由配置
func (r *RouteManager) setupDarwin() error {
	// 1. 获取当前默认网关
	gateway, err := r.getDefaultGatewayDarwin()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %w", err)
	}
	r.gateway = gateway
	r.logger.Debug("Current default gateway", "gateway", gateway)

	// 2. 添加到服务器的直接路由（确保 Hysteria 连接不走 VPN）
	r.logger.Debug("Adding direct route to server", "server", r.serverIP, "gateway", gateway)
	if err := r.runCmd("route", "add", "-host", r.serverIP, gateway); err != nil {
		r.logger.Warn("Failed to add server route (may already exist)", "error", err)
	} else {
		r.routesAdded = append(r.routesAdded, r.serverIP)
	}

	// 3. 删除默认路由
	r.logger.Debug("Removing default route")
	if err := r.runCmd("route", "delete", "default"); err != nil {
		return fmt.Errorf("failed to delete default route: %w", err)
	}

	// 4. 通过分裂路由添加0.0.0.0/1和128.0.0.0/1（比默认路由更具体，不会被覆盖）
	// 这样做比删除默认路由更安全
	r.logger.Debug("Adding VPN routes (IPv4)")
	if err := r.runCmd("route", "add", "-net", "0.0.0.0/1", r.tunGateway); err != nil {
		return fmt.Errorf("failed to add route 0.0.0.0/1: %w", err)
	}
	if err := r.runCmd("route", "add", "-net", "128.0.0.0/1", r.tunGateway); err != nil {
		return fmt.Errorf("failed to add route 128.0.0.0/1: %w", err)
	}

	// 5. 添加 IPv6 路由（::/1 和 8000::/1）
	if r.tunDevice != "" {
		r.logger.Debug("Adding VPN routes (IPv6)", "device", r.tunDevice)
		// 使用 -inet6 参数添加 IPv6 路由
		if err := r.runCmd("route", "add", "-inet6", "::/1", "-interface", r.tunDevice); err != nil {
			r.logger.Warn("Failed to add IPv6 route ::/1", "error", err)
		}
		if err := r.runCmd("route", "add", "-inet6", "8000::/1", "-interface", r.tunDevice); err != nil {
			r.logger.Warn("Failed to add IPv6 route 8000::/1", "error", err)
		}
	}

	r.configured = true
	r.logger.Info("VPN routes configured successfully")
	return nil
}

// teardownDarwin macOS 路由恢复
func (r *RouteManager) teardownDarwin() error {
	var errs []error

	// 1. 删除 VPN 路由 (IPv4)
	r.logger.Debug("Removing VPN routes")
	if err := r.runCmd("route", "delete", "-net", "0.0.0.0/1"); err != nil {
		errs = append(errs, err)
	}
	if err := r.runCmd("route", "delete", "-net", "128.0.0.0/1"); err != nil {
		errs = append(errs, err)
	}

	// 删除 IPv6 路由
	r.runCmd("route", "delete", "-inet6", "::/1")
	r.runCmd("route", "delete", "-inet6", "8000::/1")

	// 2. 恢复默认路由
	if r.gateway != "" {
		r.logger.Debug("Restoring default route", "gateway", r.gateway)
		if err := r.runCmd("route", "add", "default", r.gateway); err != nil {
			errs = append(errs, err)
		}
	}

	// 3. 删除服务器直接路由
	for _, route := range r.routesAdded {
		r.logger.Debug("Removing server route", "route", route)
		if err := r.runCmd("route", "delete", "-host", route); err != nil {
			errs = append(errs, err)
		}
	}

	r.configured = false
	r.routesAdded = nil

	if len(errs) > 0 {
		r.logger.Warn("Some routes could not be removed", "errors", errs)
	} else {
		r.logger.Info("Original routes restored")
	}

	return nil
}

// setupLinux Linux 路由配置
func (r *RouteManager) setupLinux() error {
	// 1. 获取当前默认网关
	gateway, err := r.getDefaultGatewayLinux()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %w", err)
	}
	r.gateway = gateway
	r.logger.Debug("Current default gateway", "gateway", gateway)

	// 2. 添加到服务器的直接路由
	r.logger.Debug("Adding direct route to server")
	if err := r.runCmd("ip", "route", "add", r.serverIP, "via", gateway); err != nil {
		r.logger.Warn("Failed to add server route", "error", err)
	} else {
		r.routesAdded = append(r.routesAdded, r.serverIP)
	}

	// 3. 使用分裂路由 (IPv4)
	r.logger.Debug("Adding VPN routes (IPv4)")
	if err := r.runCmd("ip", "route", "add", "0.0.0.0/1", "via", r.tunGateway); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}
	if err := r.runCmd("ip", "route", "add", "128.0.0.0/1", "via", r.tunGateway); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}

	// 4. 添加 IPv6 路由
	if r.tunDevice != "" {
		r.logger.Debug("Adding VPN routes (IPv6)", "device", r.tunDevice)
		if err := r.runCmd("ip", "-6", "route", "add", "::/1", "dev", r.tunDevice); err != nil {
			r.logger.Warn("Failed to add IPv6 route ::/1", "error", err)
		}
		if err := r.runCmd("ip", "-6", "route", "add", "8000::/1", "dev", r.tunDevice); err != nil {
			r.logger.Warn("Failed to add IPv6 route 8000::/1", "error", err)
		}
	}

	r.configured = true
	r.logger.Info("VPN routes configured successfully")
	return nil
}

// teardownLinux Linux 路由恢复
func (r *RouteManager) teardownLinux() error {
	var errs []error

	// 删除 VPN 路由 (IPv4)
	r.runCmd("ip", "route", "del", "0.0.0.0/1")
	r.runCmd("ip", "route", "del", "128.0.0.0/1")

	// 删除 IPv6 路由
	r.runCmd("ip", "-6", "route", "del", "::/1")
	r.runCmd("ip", "-6", "route", "del", "8000::/1")

	// 删除服务器路由
	for _, route := range r.routesAdded {
		r.runCmd("ip", "route", "del", route)
	}

	r.configured = false
	r.routesAdded = nil

	if len(errs) > 0 {
		r.logger.Warn("Some routes could not be removed")
	} else {
		r.logger.Info("Original routes restored")
	}

	return nil
}

// getDefaultGatewayDarwin 获取 macOS 默认网关
func (r *RouteManager) getDefaultGatewayDarwin() (string, error) {
	cmd := exec.Command("netstat", "-rn")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "default" {
			return fields[1], nil
		}
	}

	return "", fmt.Errorf("default gateway not found")
}

// getDefaultGatewayLinux 获取 Linux 默认网关
func (r *RouteManager) getDefaultGatewayLinux() (string, error) {
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// 格式: default via 192.168.1.1 dev eth0
	fields := strings.Fields(string(output))
	for i, field := range fields {
		if field == "via" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}

	return "", fmt.Errorf("default gateway not found")
}

// runCmd 执行命令
func (r *RouteManager) runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %s - %s", name, args, err, string(output))
	}
	return nil
}
