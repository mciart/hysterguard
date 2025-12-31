// Package tunnel - Hysteria UDP 中继模块
package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/hysterguard/hysterguard/internal/config"
)

// HysteriaUDPRelay Hysteria UDP 中继
// 将 UDP 流量通过 Hysteria 隧道转发
type HysteriaUDPRelay struct {
	config *config.ClientConfig
	logger *slog.Logger

	hyClient client.Client
	udpConn  client.HyUDPConn

	mu        sync.RWMutex
	closed    atomic.Bool
	unhealthy atomic.Bool  // 标记连接是否不健康
	errCount  atomic.Int32 // 连续错误计数
}

const maxConsecutiveErrors = 5 // 连续错误阈值

// NewHysteriaUDPRelay 创建 Hysteria UDP 中继
func NewHysteriaUDPRelay(cfg *config.ClientConfig, logger *slog.Logger) (*HysteriaUDPRelay, error) {
	return &HysteriaUDPRelay{
		config: cfg,
		logger: logger,
	}, nil
}

// Connect 连接到 Hysteria 服务器
func (r *HysteriaUDPRelay) Connect(ctx context.Context) error {
	r.logger.Debug("Creating Hysteria client configuration")

	// 解析服务器地址
	serverAddr, err := net.ResolveUDPAddr("udp", r.config.Hysteria.Server)
	if err != nil {
		return fmt.Errorf("failed to resolve server address: %w", err)
	}

	// 创建 Hysteria 客户端配置
	hyConfig := &client.Config{
		ServerAddr: serverAddr,
		Auth:       r.config.Hysteria.Auth,
		TLSConfig: client.TLSConfig{
			ServerName:         r.config.Hysteria.SNI,
			InsecureSkipVerify: r.config.Hysteria.Insecure,
		},
		QUICConfig: client.QUICConfig{
			InitialStreamReceiveWindow:     8388608,  // 8MB
			MaxStreamReceiveWindow:         8388608,  // 8MB
			InitialConnectionReceiveWindow: 20971520, // 20MB
			MaxConnectionReceiveWindow:     20971520, // 20MB
			MaxIdleTimeout:                 30 * time.Second,
			KeepAlivePeriod:                10 * time.Second,
		},
	}

	// 解析带宽配置
	if r.config.Hysteria.Bandwidth.Up != "" {
		upBytes, err := parseBandwidth(r.config.Hysteria.Bandwidth.Up)
		if err != nil {
			return fmt.Errorf("failed to parse upload bandwidth: %w", err)
		}
		hyConfig.BandwidthConfig.MaxTx = upBytes
	}
	if r.config.Hysteria.Bandwidth.Down != "" {
		downBytes, err := parseBandwidth(r.config.Hysteria.Bandwidth.Down)
		if err != nil {
			return fmt.Errorf("failed to parse download bandwidth: %w", err)
		}
		hyConfig.BandwidthConfig.MaxRx = downBytes
	}

	// 如果配置了混淆，创建混淆连接工厂
	if r.config.Hysteria.Obfs.Type == "salamander" && r.config.Hysteria.Obfs.Password != "" {
		r.logger.Debug("Using Salamander obfuscation")
		obfuscator, err := obfs.NewSalamanderObfuscator([]byte(r.config.Hysteria.Obfs.Password))
		if err != nil {
			return fmt.Errorf("failed to create obfuscator: %w", err)
		}
		hyConfig.ConnFactory = &obfsConnFactory{
			obfs:       obfuscator,
			serverAddr: serverAddr,
		}
	}

	// 创建并连接 Hysteria 客户端
	r.logger.Debug("Connecting to Hysteria server", "server", r.config.Hysteria.Server)
	hyClient, info, err := client.NewClient(hyConfig)
	if err != nil {
		return fmt.Errorf("failed to create Hysteria client: %w", err)
	}

	r.logger.Info("Hysteria handshake completed",
		"udp_enabled", info.UDPEnabled,
		"tx_rate", info.Tx,
	)

	if !info.UDPEnabled {
		hyClient.Close()
		return fmt.Errorf("server does not support UDP relay")
	}

	// 获取 UDP 连接
	udpConn, err := hyClient.UDP()
	if err != nil {
		hyClient.Close()
		return fmt.Errorf("failed to create UDP session: %w", err)
	}

	r.hyClient = hyClient
	r.udpConn = udpConn

	return nil
}

// ReadFrom 从 Hysteria 隧道读取 UDP 数据
func (r *HysteriaUDPRelay) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	if r.closed.Load() {
		return 0, nil, net.ErrClosed
	}

	data, addrStr, err := r.udpConn.Receive()
	if err != nil {
		return 0, nil, err
	}

	n = copy(b, data)

	// 解析地址
	udpAddr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		return n, nil, err
	}

	return n, udpAddr, nil
}

// WriteTo 向 Hysteria 隧道写入 UDP 数据
func (r *HysteriaUDPRelay) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	if r.closed.Load() {
		return 0, net.ErrClosed
	}

	err = r.udpConn.Send(b, addr.String())
	if err != nil {
		// 增加错误计数
		count := r.errCount.Add(1)
		if count >= maxConsecutiveErrors && !r.unhealthy.Load() {
			r.unhealthy.Store(true)
			r.logger.Warn("Connection marked as unhealthy after consecutive errors", "count", count)
		}
		return 0, err
	}

	// 成功发送，重置错误计数
	r.errCount.Store(0)
	return len(b), nil
}

// Close 关闭中继
func (r *HysteriaUDPRelay) Close() error {
	if r.closed.Swap(true) {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	var errs []error

	if r.udpConn != nil {
		if err := r.udpConn.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if r.hyClient != nil {
		if err := r.hyClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during close: %v", errs)
	}

	return nil
}

// LocalAddr 返回本地地址（占位符）
func (r *HysteriaUDPRelay) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

// udpConnFactory UDP 连接工厂
type udpConnFactory struct{}

func (f *udpConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	// 设置 4MB 缓冲区以提高吞吐量稳定性
	_ = conn.SetReadBuffer(4194304)
	_ = conn.SetWriteBuffer(4194304)
	return conn, nil
}

// obfsConnFactory 带混淆的连接工厂
type obfsConnFactory struct {
	obfs       obfs.Obfuscator
	serverAddr net.Addr
}

func (f *obfsConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	// 设置 4MB 缓冲区以提高吞吐量稳定性
	_ = conn.SetReadBuffer(4194304)
	_ = conn.SetWriteBuffer(4194304)
	return obfs.WrapPacketConn(conn, f.obfs), nil
}

// parseBandwidth 解析带宽字符串（如 "100 mbps"）
func parseBandwidth(s string) (uint64, error) {
	var value float64
	var unit string

	_, err := fmt.Sscanf(s, "%f %s", &value, &unit)
	if err != nil {
		// 尝试不带空格的格式
		_, err = fmt.Sscanf(s, "%f%s", &value, &unit)
		if err != nil {
			return 0, fmt.Errorf("invalid bandwidth format: %s", s)
		}
	}

	multiplier := uint64(1)
	switch unit {
	case "bps", "b":
		multiplier = 1
	case "kbps", "kb", "k":
		multiplier = 1000
	case "mbps", "mb", "m":
		multiplier = 1000 * 1000
	case "gbps", "gb", "g":
		multiplier = 1000 * 1000 * 1000
	default:
		return 0, fmt.Errorf("unknown bandwidth unit: %s", unit)
	}

	return uint64(value) * multiplier / 8, nil // 转换为字节/秒
}

// decodeBase64Key 解码 base64 编码的密钥
func decodeBase64Key(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// unused but may be needed for TLS
var _ = tls.Config{}
