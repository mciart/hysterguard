// Package tunnel - 路由管理模块
package tunnel

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

// RouteManager 路由管理器
type RouteManager struct {
	mu           sync.RWMutex
	logger       *slog.Logger
	serverIP     string
	gateway      string
	tunGateway   string
	tunDevice    string   // 实际的 TUN 设备名称
	routesAdded  []string // 非服务器路由（如 VPN 默认路由标记）
	serverRoutes []string // 服务器 IP 直连路由（动态管理）
	configured   bool
}

// NewRouteManager 创建路由管理器
func NewRouteManager(serverAddr string, tunGateway string, tunDevice string, logger *slog.Logger) *RouteManager {
	// 从服务器地址提取 IP
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		host = serverAddr
	}

	return &RouteManager{
		logger:       logger,
		serverIP:     host,
		tunGateway:   tunGateway,
		tunDevice:    tunDevice,
		serverRoutes: make([]string, 0),
	}
}

// UpdateServerIP 更新服务器 IP 并动态调整路由
// 用于处理 CDN/DDNS 场景下服务器 IP 变化
func (r *RouteManager) UpdateServerIP(newIP string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if newIP == "" {
		return fmt.Errorf("new IP cannot be empty")
	}

	// 检查 IP 是否已在路由表中
	for _, ip := range r.serverRoutes {
		if ip == newIP {
			r.logger.Debug("Server IP already in route table", "ip", newIP)
			return nil
		}
	}

	r.logger.Info("Updating server route for new IP", "oldIP", r.serverIP, "newIP", newIP)

	// 添加新 IP 的直连路由
	if err := r.addServerRoute(newIP); err != nil {
		r.logger.Warn("Failed to add route for new server IP", "ip", newIP, "error", err)
		// 继续执行，不返回错误，因为可能路由已存在
	}

	r.serverIP = newIP
	return nil
}

// addServerRoute 添加服务器 IP 的直连路由（内部方法，调用时需持有锁）
func (r *RouteManager) addServerRoute(ip string) error {
	if ip == "" {
		return nil
	}

	var err error
	switch runtime.GOOS {
	case "darwin":
		if r.gateway != "" {
			err = r.runCmd("route", "add", "-host", ip, r.gateway)
		}
	case "linux":
		gateway, _ := r.getDefaultGatewayLinux()
		if gateway != "" {
			err = r.runCmd("ip", "route", "add", ip, "via", gateway)
		}
	case "windows":
		if r.gateway != "" {
			err = r.runCmd("route", "add", ip, "mask", "255.255.255.255", r.gateway, "metric", "1")
		}
	}

	if err == nil {
		r.serverRoutes = append(r.serverRoutes, ip)
		r.logger.Debug("Added server route", "ip", ip)
	}
	return err
}

// GetServerIP 获取当前配置的服务器 IP
func (r *RouteManager) GetServerIP() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.serverIP
}

// Setup 配置路由（将所有流量导向 VPN）
func (r *RouteManager) Setup() error {
	r.logger.Info("Setting up VPN routes", "server", r.serverIP, "tunGateway", r.tunGateway)

	switch runtime.GOOS {
	case "darwin":
		return r.setupDarwin()
	case "linux":
		return r.setupLinux()
	case "windows":
		return r.setupWindows()
	default:
		r.logger.Warn("Automatic route configuration not supported on this platform")
		return nil
	}
}

// Cleanup 恢复原始路由
func (r *RouteManager) Cleanup() error {
	if !r.configured {
		return nil
	}

	r.logger.Info("Restoring original routes")

	switch runtime.GOOS {
	case "darwin":
		return r.cleanupDarwin()
	case "linux":
		return r.cleanupLinux()
	case "windows":
		return r.cleanupWindows()
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
		r.serverRoutes = append(r.serverRoutes, r.serverIP)
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

// cleanupDarwin macOS 路由恢复
func (r *RouteManager) cleanupDarwin() error {
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

	// 3. 删除服务器直接路由（使用 serverRoutes）
	for _, route := range r.serverRoutes {
		r.logger.Debug("Removing server route", "route", route)
		if err := r.runCmd("route", "delete", "-host", route); err != nil {
			errs = append(errs, err)
		}
	}

	r.configured = false
	r.routesAdded = nil
	r.serverRoutes = nil

	if len(errs) > 0 {
		r.logger.Warn("Some routes could not be removed", "errors", errs)
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

// setupLinux Linux 路由配置 (FwMark 模式)
func (r *RouteManager) setupLinux() error {
	// 1. 获取当前默认网关
	gateway, err := r.getDefaultGatewayLinux()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %w", err)
	}
	r.logger.Debug("Current default gateway", "gateway", gateway)

	// 添加到服务器的直接路由 (Main 表)
	// 这是必须的，否则由 Hysteria 发出的 UDP 包会被 FwMark 规则路由进 VPN 隧道，导致死循环
	r.gateway = gateway // 保存网关以便动态添加路由
	r.logger.Debug("Adding direct route to server", "server", r.serverIP)
	if err := r.runCmd("ip", "route", "add", r.serverIP, "via", gateway); err != nil {
		r.logger.Warn("Failed to add server route (may already exist)", "error", err)
	} else {
		r.serverRoutes = append(r.serverRoutes, r.serverIP)
	}

	// 2. 添加路由到 table 51820
	r.logger.Debug("Adding routes to table 51820")
	// 添加 VPN 默认路由到表 51820
	if err := r.runCmd("ip", "route", "add", "default", "dev", r.tunDevice, "table", "51820"); err != nil {
		return fmt.Errorf("failed to add default route to table 51820: %w", err)
	}
	r.routesAdded = append(r.routesAdded, "default-51820") // 标记以便清理

	// 3. 添加策略路由规则
	r.logger.Debug("Adding policy routing rules")

	// 规则 1: 查找 main 表，但忽略默认路由 (为了让本地子网流量直连)
	// ip rule add lookup main suppress_prefixlength 0 priority 32764
	if err := r.runCmd("ip", "rule", "add", "lookup", "main", "suppress_prefixlength", "0", "priority", "32764"); err != nil {
		r.logger.Warn("Failed to add suppress_prefixlength rule", "error", err)
	}

	// 规则 2: 所有未标记(非VPN自身)流量查 51820 表
	// ip rule add not fwmark 51820 lookup 51820 priority 32765
	if err := r.runCmd("ip", "rule", "add", "not", "fwmark", "51820", "lookup", "51820", "priority", "32765"); err != nil {
		return fmt.Errorf("failed to add fwmark rule: %w", err)
	}

	// 4. 添加 IPv6 路由 (如果启用)
	if r.tunDevice != "" {
		// IPv6 同样逻辑
		r.runCmd("ip", "-6", "route", "add", "default", "dev", r.tunDevice, "table", "51820")
		r.runCmd("ip", "-6", "rule", "add", "lookup", "main", "suppress_prefixlength", "0", "priority", "32764")
		r.runCmd("ip", "-6", "rule", "add", "not", "fwmark", "51820", "lookup", "51820", "priority", "32765")
	}

	r.configured = true
	r.logger.Info("VPN routes configured successfully (FwMark mode)")
	return nil
}

// cleanupLinux Linux 路由清理 (FwMark 模式)
func (r *RouteManager) cleanupLinux() error {
	r.logger.Info("Cleaning up VPN routes (FwMark mode)")

	// 1. 清理服务器路由
	for _, route := range r.serverRoutes {
		r.runCmd("ip", "route", "del", route)
	}

	// 2. 删除策略路由规则
	// 顺序反向删除
	// ip rule del not fwmark 51820 lookup 51820
	r.runCmd("ip", "rule", "del", "not", "fwmark", "51820", "lookup", "51820")
	// ip rule del lookup main suppress_prefixlength 0
	r.runCmd("ip", "rule", "del", "lookup", "main", "suppress_prefixlength", "0")

	// IPv6 规则清理
	if r.tunDevice != "" {
		r.runCmd("ip", "-6", "rule", "del", "not", "fwmark", "51820", "lookup", "51820")
		r.runCmd("ip", "-6", "rule", "del", "lookup", "main", "suppress_prefixlength", "0")
	}

	// 3. 清空 51820 路由表
	r.runCmd("ip", "route", "flush", "table", "51820")
	if r.tunDevice != "" {
		r.runCmd("ip", "-6", "route", "flush", "table", "51820")
	}

	r.configured = false
	r.routesAdded = nil
	r.serverRoutes = nil
	r.logger.Info("VPN routes removed")
	return nil
}

// getDefaultGatewayLinux 获取 Linux 默认网关 (FwMark 模式下仅用于日志)
func (r *RouteManager) getDefaultGatewayLinux() (string, error) {
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	fields := strings.Fields(string(output))
	for i, field := range fields {
		if field == "via" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}

	return "", fmt.Errorf("default gateway not found")
}

// setupWindows Windows 路由配置
func (r *RouteManager) setupWindows() error {
	// 1. 获取当前默认网关
	gateway, err := r.getDefaultGatewayWindows()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %w", err)
	}
	r.gateway = gateway
	r.logger.Debug("Current default gateway", "gateway", gateway)

	// 2. 获取 TUN 接口索引
	ifIndex, err := r.getInterfaceIndex(r.tunDevice)
	if err != nil {
		r.logger.Warn("Failed to get interface index, routes may bind to wrong interface", "error", err)
		ifIndex = ""
	} else {
		r.logger.Debug("Got TUN interface index", "device", r.tunDevice, "index", ifIndex)
	}

	// 3. 添加到服务器的直接路由（确保 Hysteria 连接不走 VPN）
	r.logger.Debug("Adding direct route to server", "server", r.serverIP, "gateway", gateway)
	if err := r.runCmd("route", "add", r.serverIP, "mask", "255.255.255.255", gateway, "metric", "1"); err != nil {
		r.logger.Warn("Failed to add server route (may already exist)", "error", err)
	} else {
		r.serverRoutes = append(r.serverRoutes, r.serverIP)
	}

	// 4. 添加 VPN 路由 (0.0.0.0/1 和 128.0.0.0/1 覆盖默认路由)
	r.logger.Debug("Adding VPN routes (IPv4)", "interface_index", ifIndex)

	// Windows route add 需要指定接口索引才能绑定到正确的 TUN
	if ifIndex != "" {
		if err := r.runCmd("route", "add", "0.0.0.0", "mask", "128.0.0.0", r.tunGateway, "metric", "5", "if", ifIndex); err != nil {
			return fmt.Errorf("failed to add route 0.0.0.0/1: %w", err)
		}
		if err := r.runCmd("route", "add", "128.0.0.0", "mask", "128.0.0.0", r.tunGateway, "metric", "5", "if", ifIndex); err != nil {
			return fmt.Errorf("failed to add route 128.0.0.0/1: %w", err)
		}
	} else {
		// Fallback: 不指定接口（可能绑定到错误接口）
		if err := r.runCmd("route", "add", "0.0.0.0", "mask", "128.0.0.0", r.tunGateway, "metric", "5"); err != nil {
			return fmt.Errorf("failed to add route 0.0.0.0/1: %w", err)
		}
		if err := r.runCmd("route", "add", "128.0.0.0", "mask", "128.0.0.0", r.tunGateway, "metric", "5"); err != nil {
			return fmt.Errorf("failed to add route 128.0.0.0/1: %w", err)
		}
	}

	// 5. 添加 IPv6 路由
	if r.tunDevice != "" {
		r.logger.Debug("Adding VPN routes (IPv6)", "device", r.tunDevice)
		// Windows IPv6 路由：使用接口名称
		r.runCmd("netsh", "interface", "ipv6", "add", "route", "::/1", r.tunDevice, "metric=5")
		r.runCmd("netsh", "interface", "ipv6", "add", "route", "8000::/1", r.tunDevice, "metric=5")
	}

	r.configured = true
	r.logger.Info("VPN routes configured successfully")
	return nil
}

// getInterfaceIndex 获取 Windows 网络接口索引
func (r *RouteManager) getInterfaceIndex(ifName string) (string, error) {
	// 使用 netsh 获取接口信息
	cmd := exec.Command("netsh", "interface", "ip", "show", "interface")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, ifName) {
			fields := strings.Fields(line)
			if len(fields) >= 1 {
				// 第一个字段是接口索引
				return fields[0], nil
			}
		}
	}

	return "", fmt.Errorf("interface %s not found", ifName)
}

// cleanupWindows Windows 路由恢复
func (r *RouteManager) cleanupWindows() error {
	var errs []error

	// 1. 删除 VPN 路由
	r.logger.Debug("Removing VPN routes")
	if err := r.runCmd("route", "delete", "0.0.0.0", "mask", "128.0.0.0"); err != nil {
		errs = append(errs, err)
	}
	if err := r.runCmd("route", "delete", "128.0.0.0", "mask", "128.0.0.0"); err != nil {
		errs = append(errs, err)
	}

	// 删除 IPv6 路由
	if r.tunDevice != "" {
		r.runCmd("netsh", "interface", "ipv6", "delete", "route", "::/1", r.tunDevice)
		r.runCmd("netsh", "interface", "ipv6", "delete", "route", "8000::/1", r.tunDevice)
	}

	// 2. 删除服务器直接路由
	for _, route := range r.serverRoutes {
		r.logger.Debug("Removing server route", "route", route)
		if err := r.runCmd("route", "delete", route); err != nil {
			errs = append(errs, err)
		}
	}

	r.configured = false
	r.routesAdded = nil
	r.serverRoutes = nil

	if len(errs) > 0 {
		r.logger.Warn("Some routes could not be removed", "errors", errs)
	} else {
		r.logger.Info("Original routes restored")
	}

	return nil
}

// getDefaultGatewayWindows 获取 Windows 默认网关
func (r *RouteManager) getDefaultGatewayWindows() (string, error) {
	cmd := exec.Command("route", "print", "0.0.0.0")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		// 寻找 0.0.0.0 开头的行
		if len(fields) >= 3 && fields[0] == "0.0.0.0" {
			// 格式: 0.0.0.0  0.0.0.0  网关  接口  跃点
			return fields[2], nil
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
