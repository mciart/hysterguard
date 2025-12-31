// Package tunnel 提供 Hysteria + WireGuard 组合隧道功能
package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/hysterguard/hysterguard/internal/config"
)

// Status 隧道状态
type Status int

const (
	StatusDisconnected Status = iota
	StatusConnecting
	StatusConnected
	StatusError
)

func (s Status) String() string {
	switch s {
	case StatusDisconnected:
		return "disconnected"
	case StatusConnecting:
		return "connecting"
	case StatusConnected:
		return "connected"
	case StatusError:
		return "error"
	default:
		return "unknown"
	}
}

// Tunnel 组合隧道接口
type Tunnel interface {
	// Start 启动隧道
	Start(ctx context.Context) error
	// Stop 停止隧道
	Stop() error
	// Status 获取隧道状态
	Status() Status
	// Wait 等待隧道关闭
	Wait() <-chan struct{}
}

// UDPTransport UDP 传输接口（供 WireGuard 使用）
type UDPTransport interface {
	// ReadFrom 从传输层读取数据
	ReadFrom(b []byte) (n int, addr net.Addr, err error)
	// WriteTo 向传输层写入数据
	WriteTo(b []byte, addr net.Addr) (n int, err error)
	// Close 关闭传输层
	Close() error
	// LocalAddr 本地地址
	LocalAddr() net.Addr
}

// ClientTunnel 客户端隧道实现
type ClientTunnel struct {
	config *config.ClientConfig
	logger *slog.Logger

	mu     sync.RWMutex
	status Status
	done   chan struct{}

	// 组件
	hysteriaRelay *HysteriaUDPRelay
	wgDevice      *WireGuardDevice
	routeManager  *RouteManager
	dnsManager    *DNSManager
}

// NewClientTunnel 创建客户端隧道
func NewClientTunnel(cfg *config.ClientConfig, logger *slog.Logger) (*ClientTunnel, error) {
	if logger == nil {
		logger = slog.Default()
	}

	return &ClientTunnel{
		config: cfg,
		logger: logger,
		status: StatusDisconnected,
		done:   make(chan struct{}),
	}, nil
}

// Start 启动客户端隧道
func (t *ClientTunnel) Start(ctx context.Context) error {
	t.mu.Lock()
	if t.status == StatusConnecting || t.status == StatusConnected {
		t.mu.Unlock()
		return fmt.Errorf("tunnel already running")
	}
	t.status = StatusConnecting
	t.mu.Unlock()

	t.logger.Info("Starting HysterGuard tunnel",
		"server", t.config.Hysteria.Server,
	)

	// 步骤 1: 建立 Hysteria 连接
	t.logger.Debug("Connecting to Hysteria server...")
	hyRelay, err := NewHysteriaUDPRelay(t.config, t.logger)
	if err != nil {
		t.setStatus(StatusError)
		return fmt.Errorf("failed to create Hysteria relay: %w", err)
	}
	t.hysteriaRelay = hyRelay

	if err := hyRelay.Connect(ctx); err != nil {
		t.setStatus(StatusError)
		return fmt.Errorf("failed to connect to Hysteria server: %w", err)
	}
	t.logger.Info("Hysteria connection established")

	// 步骤 2: 启动 WireGuard（使用 Hysteria 作为传输层）
	t.logger.Debug("Starting WireGuard device...")
	wgDevice, err := NewWireGuardDevice(t.config, hyRelay, t.logger)
	if err != nil {
		hyRelay.Close()
		t.setStatus(StatusError)
		return fmt.Errorf("failed to create WireGuard device: %w", err)
	}
	t.wgDevice = wgDevice

	if err := wgDevice.Start(); err != nil {
		hyRelay.Close()
		t.setStatus(StatusError)
		return fmt.Errorf("failed to start WireGuard device: %w", err)
	}

	// 获取实际的 TUN 设备名称
	tunDeviceName := wgDevice.GetTUNName()

	t.logger.Info("WireGuard device started",
		"tun", tunDeviceName,
		"address", t.config.TUN.Address.IPv4,
	)

	// 步骤 3: 配置路由（将流量导向 VPN）
	// 提取 TUN 网关地址
	tunGateway := "10.10.0.1" // 默认网关
	ipv4 := t.config.TUN.Address.IPv4
	if idx := len(ipv4) - 1; idx > 0 {
		// 从 10.10.0.2/24 提取 10.10.0.1
		parts := ipv4
		if slashIdx := len(ipv4); slashIdx > 0 {
			for i := len(ipv4) - 1; i >= 0; i-- {
				if ipv4[i] == '/' {
					parts = ipv4[:i]
					break
				}
			}
		}
		// 替换最后一个数字为 1
		for i := len(parts) - 1; i >= 0; i-- {
			if parts[i] == '.' {
				tunGateway = parts[:i+1] + "1"
				break
			}
		}
	}

	t.routeManager = NewRouteManager(t.config.Hysteria.Server, tunGateway, tunDeviceName, t.logger)
	if err := t.routeManager.Setup(); err != nil {
		t.logger.Warn("Failed to configure routes automatically", "error", err)
		t.logger.Info("You may need to configure routes manually")
	}

	// 步骤 4: 配置 DNS
	if len(t.config.TUN.DNS.Servers) > 0 {
		t.dnsManager = NewDNSManager(t.config.TUN.DNS.Servers, t.logger)
		if err := t.dnsManager.Setup(); err != nil {
			t.logger.Warn("Failed to configure DNS automatically", "error", err)
		}
	}

	t.setStatus(StatusConnected)
	t.logger.Info("HysterGuard tunnel established successfully")

	return nil
}

// Stop 停止隧道
func (t *ClientTunnel) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusDisconnected {
		return nil
	}

	t.logger.Info("Stopping HysterGuard tunnel...")

	var errs []error

	// 先恢复 DNS（在关闭路由之前）
	if t.dnsManager != nil {
		if err := t.dnsManager.Teardown(); err != nil {
			errs = append(errs, fmt.Errorf("failed to restore DNS: %w", err))
		}
		t.dnsManager = nil
	}

	// 恢复路由（在关闭 WireGuard 之前）
	if t.routeManager != nil {
		if err := t.routeManager.Teardown(); err != nil {
			errs = append(errs, fmt.Errorf("failed to restore routes: %w", err))
		}
		t.routeManager = nil
	}

	// 停止 WireGuard
	if t.wgDevice != nil {
		if err := t.wgDevice.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("failed to stop WireGuard: %w", err))
		}
		t.wgDevice = nil
	}

	// 关闭 Hysteria
	if t.hysteriaRelay != nil {
		if err := t.hysteriaRelay.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close Hysteria: %w", err))
		}
		t.hysteriaRelay = nil
	}

	t.status = StatusDisconnected
	close(t.done)

	if len(errs) > 0 {
		return fmt.Errorf("errors during shutdown: %v", errs)
	}

	t.logger.Info("HysterGuard tunnel stopped")
	return nil
}

// Status 获取状态
func (t *ClientTunnel) Status() Status {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.status
}

// Wait 等待隧道关闭
func (t *ClientTunnel) Wait() <-chan struct{} {
	return t.done
}

func (t *ClientTunnel) setStatus(s Status) {
	t.mu.Lock()
	t.status = s
	t.mu.Unlock()
}
