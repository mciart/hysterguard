// Package tunnel - DNS 管理模块
package tunnel

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// DNSManager DNS 管理器
type DNSManager struct {
	logger      *slog.Logger
	dnsServers  []string
	originalDNS map[string][]string // 保存原始 DNS 配置 (网络服务 -> DNS 列表)
	configured  bool
}

// NewDNSManager 创建 DNS 管理器
func NewDNSManager(servers []string, logger *slog.Logger) *DNSManager {
	return &DNSManager{
		logger:      logger,
		dnsServers:  servers,
		originalDNS: make(map[string][]string),
	}
}

// Setup 配置 DNS
func (d *DNSManager) Setup() error {
	if len(d.dnsServers) == 0 {
		d.logger.Debug("No DNS servers configured, skipping DNS setup")
		return nil
	}

	d.logger.Info("Setting up DNS servers", "servers", d.dnsServers)

	switch runtime.GOOS {
	case "darwin":
		return d.setupDarwin()
	case "linux":
		return d.setupLinux()
	case "windows":
		return d.setupWindows()
	default:
		d.logger.Warn("DNS configuration not supported on this platform")
		return nil
	}
}

// Teardown 恢复原始 DNS
func (d *DNSManager) Teardown() error {
	if !d.configured {
		return nil
	}

	d.logger.Info("Restoring original DNS settings")

	switch runtime.GOOS {
	case "darwin":
		return d.teardownDarwin()
	case "linux":
		return d.teardownLinux()
	case "windows":
		return d.teardownWindows()
	default:
		return nil
	}
}

// setupDarwin macOS DNS 配置
func (d *DNSManager) setupDarwin() error {
	// 获取所有网络服务
	services, err := d.getNetworkServices()
	if err != nil {
		return fmt.Errorf("failed to get network services: %w", err)
	}

	for _, service := range services {
		// 保存原始 DNS
		originalDNS, err := d.getDNS(service)
		if err == nil {
			d.originalDNS[service] = originalDNS
		}

		// 设置新 DNS
		d.logger.Debug("Setting DNS for service", "service", service)
		args := []string{"-setdnsservers", service}
		args = append(args, d.dnsServers...)
		if err := d.runCmd("networksetup", args...); err != nil {
			d.logger.Warn("Failed to set DNS for service", "service", service, "error", err)
			continue
		}
	}

	d.configured = true
	d.logger.Info("DNS configured successfully")
	return nil
}

// teardownDarwin macOS DNS 恢复
func (d *DNSManager) teardownDarwin() error {
	for service, originalDNS := range d.originalDNS {
		d.logger.Debug("Restoring DNS for service", "service", service)

		var args []string
		if len(originalDNS) == 0 || (len(originalDNS) == 1 && originalDNS[0] == "Empty") {
			// 如果原来没有配置 DNS，设置为空（使用 DHCP）
			args = []string{"-setdnsservers", service, "Empty"}
		} else {
			args = []string{"-setdnsservers", service}
			args = append(args, originalDNS...)
		}

		if err := d.runCmd("networksetup", args...); err != nil {
			d.logger.Warn("Failed to restore DNS for service", "service", service, "error", err)
		}
	}

	d.configured = false
	d.originalDNS = make(map[string][]string)
	d.logger.Info("DNS settings restored")
	return nil
}

// getNetworkServices 获取 macOS 网络服务列表
func (d *DNSManager) getNetworkServices() ([]string, error) {
	cmd := exec.Command("networksetup", "-listallnetworkservices")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var services []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// 跳过第一行（标题）和带 * 的禁用服务
		if line != "" && !strings.HasPrefix(line, "*") && !strings.Contains(line, "denotes") {
			services = append(services, line)
		}
	}
	return services, nil
}

// getDNS 获取当前 DNS 设置
func (d *DNSManager) getDNS(service string) ([]string, error) {
	cmd := exec.Command("networksetup", "-getdnsservers", service)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var servers []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.Contains(line, "There aren't") {
			servers = append(servers, line)
		}
	}

	if len(servers) == 0 {
		return []string{"Empty"}, nil
	}
	return servers, nil
}

// hasResolvectl 检测系统是否支持 resolvectl
func (d *DNSManager) hasResolvectl() bool {
	_, err := exec.LookPath("resolvectl")
	return err == nil
}

// setupLinux Linux DNS 配置
// 优先使用 resolvectl (systemd-resolved)，回退到 resolv.conf
func (d *DNSManager) setupLinux() error {
	// 检测是否支持 resolvectl
	if d.hasResolvectl() {
		d.logger.Debug("Using resolvectl for DNS configuration")
		return d.setupLinuxResolvectl()
	}

	d.logger.Debug("Using resolv.conf for DNS configuration")
	return d.setupLinuxResolvconf()
}

// setupLinuxResolvectl 使用 resolvectl 配置 DNS
func (d *DNSManager) setupLinuxResolvectl() error {
	// 获取默认网络接口
	ifName := "hysterguard0" // 默认使用 TUN 接口名

	// 设置 DNS
	for _, server := range d.dnsServers {
		if err := d.runCmd("resolvectl", "dns", ifName, server); err != nil {
			d.logger.Warn("Failed to set DNS via resolvectl", "server", server, "error", err)
		}
	}

	// 设置为默认 DNS 路由（将所有 DNS 查询路由到此接口）
	if err := d.runCmd("resolvectl", "default-route", ifName, "yes"); err != nil {
		d.logger.Warn("Failed to set default DNS route", "error", err)
	}

	d.originalDNS["method"] = []string{"resolvectl"}
	d.configured = true
	d.logger.Info("DNS configured successfully via resolvectl")
	return nil
}

// setupLinuxResolvconf 使用 resolv.conf 配置 DNS（回退方案）
func (d *DNSManager) setupLinuxResolvconf() error {
	// 备份原始 resolv.conf
	original, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		d.logger.Warn("Failed to read original resolv.conf", "error", err)
	} else {
		d.originalDNS["resolv.conf"] = []string{string(original)}
	}

	// 生成新的 resolv.conf
	var content strings.Builder
	content.WriteString("# Generated by HysterGuard\n")
	for _, server := range d.dnsServers {
		content.WriteString(fmt.Sprintf("nameserver %s\n", server))
	}

	// 写入 resolv.conf
	if err := os.WriteFile("/etc/resolv.conf", []byte(content.String()), 0644); err != nil {
		return fmt.Errorf("failed to write resolv.conf: %w", err)
	}

	d.originalDNS["method"] = []string{"resolvconf"}
	d.configured = true
	d.logger.Info("DNS configured successfully via resolv.conf")
	return nil
}

// teardownLinux Linux DNS 恢复
func (d *DNSManager) teardownLinux() error {
	method := "resolvconf"
	if methods, ok := d.originalDNS["method"]; ok && len(methods) > 0 {
		method = methods[0]
	}

	if method == "resolvectl" {
		// 使用 resolvectl 恢复：重置 DNS 设置
		d.runCmd("resolvectl", "revert", "hysterguard0")
		d.logger.Info("DNS settings restored via resolvectl")
	} else {
		// 恢复 resolv.conf
		if original, ok := d.originalDNS["resolv.conf"]; ok && len(original) > 0 {
			if err := os.WriteFile("/etc/resolv.conf", []byte(original[0]), 0644); err != nil {
				d.logger.Warn("Failed to restore resolv.conf", "error", err)
			}
		}
		d.logger.Info("DNS settings restored via resolv.conf")
	}

	d.configured = false
	d.originalDNS = make(map[string][]string)
	return nil
}

// setupWindows Windows DNS 配置 (使用 netsh)
func (d *DNSManager) setupWindows() error {
	// 获取所有网络接口并设置 DNS
	// 主要针对 VPN 接口设置 DNS
	d.logger.Debug("Configuring DNS on Windows")

	// 设置主 DNS 和备用 DNS
	if len(d.dnsServers) > 0 {
		// 设置主 DNS
		if err := d.runCmd("netsh", "interface", "ip", "set", "dns",
			"hysterguard0", "static", d.dnsServers[0], "primary"); err != nil {
			d.logger.Warn("Failed to set primary DNS", "error", err)
		}

		// 添加备用 DNS
		for i := 1; i < len(d.dnsServers); i++ {
			// 只添加 IPv4 DNS
			if !strings.Contains(d.dnsServers[i], ":") {
				if err := d.runCmd("netsh", "interface", "ip", "add", "dns",
					"hysterguard0", d.dnsServers[i], "index="+fmt.Sprintf("%d", i+1)); err != nil {
					d.logger.Warn("Failed to add secondary DNS", "error", err)
				}
			}
		}

		// 添加 IPv6 DNS
		for _, server := range d.dnsServers {
			if strings.Contains(server, ":") {
				if err := d.runCmd("netsh", "interface", "ipv6", "add", "dnsservers",
					"hysterguard0", server); err != nil {
					d.logger.Warn("Failed to add IPv6 DNS", "error", err)
				}
			}
		}
	}

	d.configured = true
	d.logger.Info("DNS configured successfully")
	return nil
}

// teardownWindows Windows DNS 恢复
func (d *DNSManager) teardownWindows() error {
	// 将 DNS 设置回 DHCP
	d.runCmd("netsh", "interface", "ip", "set", "dns", "hysterguard0", "dhcp")
	d.runCmd("netsh", "interface", "ipv6", "set", "dnsservers", "hysterguard0", "dhcp")

	d.configured = false
	d.logger.Info("DNS settings restored")
	return nil
}

// runCmd 执行命令
func (d *DNSManager) runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %s - %s", name, args, err, string(output))
	}
	return nil
}
