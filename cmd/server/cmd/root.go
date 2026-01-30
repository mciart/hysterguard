// Package cmd 提供服务端 CLI 命令
package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/hysterguard/hysterguard/internal/config"
	"github.com/hysterguard/hysterguard/internal/tunnel"
)

var (
	configFile string
	logLevel   string
)

var rootCmd = &cobra.Command{
	Use:   "hysterguard-server",
	Short: "HysterGuard Server - Hysteria + WireGuard VPN Server",
	Long: `HysterGuard Server combines Hysteria 2 obfuscation with WireGuard encryption.

Hysteria provides the outer QUIC transport layer with Salamander obfuscation,
while WireGuard handles the inner encrypted VPN tunnel.

This is a single all-in-one process. No external ports are used for WireGuard.`,
	RunE: runServer,
}

func init() {
	rootCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "Path to configuration file")
	rootCmd.Flags().StringVarP(&logLevel, "log-level", "l", "info", "Log level (debug, info, warn, error)")
}

// Execute 执行根命令
func Execute() error {
	return rootCmd.Execute()
}

func runServer(cmd *cobra.Command, args []string) error {
	// 设置日志
	level := slog.LevelInfo
	switch logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	logger.Info("Starting HysterGuard Server",
		"version", "0.1.0",
		"config", configFile,
	)

	// 加载配置
	cfg, err := config.LoadServerConfig(configFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// 验证配置
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	logger.Debug("Configuration loaded",
		"listen", cfg.Listen,
		"obfs", cfg.Hysteria.Obfs.Type,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ============ 1. 启动 WireGuard 服务（All-in-One 模式，无端口监听）============
	logger.Info("Starting WireGuard server (all-in-one mode)...")
	wgTunnel, err := tunnel.NewServerTunnel(cfg, logger)
	if err != nil {
		return fmt.Errorf("failed to create WireGuard tunnel: %w", err)
	}

	if err := wgTunnel.Start(ctx); err != nil {
		return fmt.Errorf("failed to start WireGuard tunnel: %w", err)
	}
	defer wgTunnel.Stop()

	// 获取 WireGuard bind
	wgBind := wgTunnel.GetBind()

	// ============ 2. 创建 WireGuard Outbound（连接 Hysteria 和 WireGuard）============
	wgOutbound := NewWireGuardOutbound(wgBind, logger)

	// 设置 WireGuard bind 的发送回调（将 WireGuard 响应发回客户端）
	wgBind.SetSendCallback(wgOutbound.SendToClient)

	// ============ 3. 启动 Hysteria 服务 ============
	logger.Info("Starting Hysteria server...")
	hyServer, err := createHysteriaServer(cfg, wgOutbound, logger)
	if err != nil {
		return fmt.Errorf("failed to create Hysteria server: %w", err)
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("Hysteria server listening", "listen", cfg.Listen)
		if err := hyServer.Serve(); err != nil {
			errCh <- err
		}
	}()

	logger.Info("===============================================")
	logger.Info("HysterGuard Server is now running (All-in-One)")
	logger.Info("  Hysteria (obfuscation): " + cfg.Listen)
	logger.Info("  WireGuard: embedded (no port listening)")
	logger.Info("===============================================")
	logger.Info("Press Ctrl+C to stop")

	// 等待信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// 非阻塞发送，队列满时丢包
	select {
	case sig := <-sigCh:
		logger.Info("Received signal, shutting down", "signal", sig)
	case err := <-errCh:
		logger.Error("Server error", "error", err)
		return err
	case <-ctx.Done():
		logger.Info("Context cancelled")
	}

	// 停止服务
	logger.Info("Shutting down...")
	if err := hyServer.Close(); err != nil {
		logger.Error("Error stopping Hysteria", "error", err)
	}

	logger.Info("HysterGuard Server stopped")
	return nil
}

// createHysteriaServer 创建 Hysteria 服务端
func createHysteriaServer(cfg *config.ServerConfig, outbound server.Outbound, logger *slog.Logger) (server.Server, error) {
	// 加载 TLS 证书
	cert, err := tls.LoadX509KeyPair(cfg.Hysteria.TLS.Cert, cfg.Hysteria.TLS.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	// 创建 UDP 监听
	udpAddr, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve listen address: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on UDP: %w", err)
	}

	// 设置 4MB 缓冲区以防止高负载丢包
	_ = udpConn.SetReadBuffer(4194304)
	_ = udpConn.SetWriteBuffer(4194304)

	// 如果配置了混淆，包装连接
	var packetConn net.PacketConn = udpConn
	if cfg.Hysteria.Obfs.Type == "salamander" && cfg.Hysteria.Obfs.Password != "" {
		logger.Debug("Using Salamander obfuscation")
		obfuscator, err := obfs.NewSalamanderObfuscator([]byte(cfg.Hysteria.Obfs.Password))
		if err != nil {
			udpConn.Close()
			return nil, fmt.Errorf("failed to create obfuscator: %w", err)
		}
		packetConn = obfs.WrapPacketConn(udpConn, obfuscator)
	}

	// 创建服务端配置
	serverConfig := &server.Config{
		QUICConfig: server.QUICConfig{
			InitialStreamReceiveWindow: 8388608,  // 8MB
			MaxStreamReceiveWindow:     8388608,  // 8MB
			MaxConnectionReceiveWindow: 20971520, // 20MB
			MaxIdleTimeout:             30 * time.Second,
		},
		TLSConfig: server.TLSConfig{
			Certificates: []tls.Certificate{cert},
		},
		Conn:                  packetConn,
		Outbound:              outbound,
		IgnoreClientBandwidth: false, // 允许客户端指定带宽（启用 Brutal）
		Authenticator: &simpleAuthenticator{
			password: cfg.Hysteria.Auth,
			logger:   logger,
		},
		EventLogger: &serverEventLogger{logger: logger},
	}

	return server.NewServer(serverConfig)
}

// simpleAuthenticator 简单密码认证器
type simpleAuthenticator struct {
	password string
	logger   *slog.Logger
}

func (a *simpleAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (ok bool, id string) {
	if auth == a.password {
		a.logger.Debug("Authentication successful", "addr", addr.String())
		return true, "user"
	}
	a.logger.Warn("Authentication failed", "addr", addr.String())
	return false, ""
}

// serverEventLogger 服务端事件日志记录器
type serverEventLogger struct {
	logger *slog.Logger
}

func (l *serverEventLogger) Connect(addr net.Addr, id string, tx uint64) {
	l.logger.Info("Client connected", "addr", addr.String(), "id", id, "tx", tx)
}

func (l *serverEventLogger) Disconnect(addr net.Addr, id string, err error) {
	if err != nil {
		l.logger.Info("Client disconnected", "addr", addr.String(), "id", id, "error", err)
	} else {
		l.logger.Info("Client disconnected", "addr", addr.String(), "id", id)
	}
}

func (l *serverEventLogger) TCPRequest(addr net.Addr, id, reqAddr string) {
	l.logger.Debug("TCP request", "addr", addr.String(), "id", id, "target", reqAddr)
}

func (l *serverEventLogger) TCPError(addr net.Addr, id, reqAddr string, err error) {
	l.logger.Warn("TCP error", "addr", addr.String(), "id", id, "target", reqAddr, "error", err)
}

func (l *serverEventLogger) UDPRequest(addr net.Addr, id string, sessionID uint32, reqAddr string) {
	l.logger.Debug("UDP request (WireGuard)", "addr", addr.String(), "id", id, "sessionID", sessionID, "target", reqAddr)
}

func (l *serverEventLogger) UDPError(addr net.Addr, id string, sessionID uint32, err error) {
	l.logger.Warn("UDP error", "addr", addr.String(), "id", id, "sessionID", sessionID, "error", err)
}

// WireGuardOutbound 实现 Hysteria server.Outbound 接口
type WireGuardOutbound struct {
	bind   *tunnel.HysteriaServerBind
	logger *slog.Logger

	mu    sync.RWMutex
	conns map[string]*wireGuardConn
}

// NewWireGuardOutbound 创建 WireGuard Outbound
func NewWireGuardOutbound(bind *tunnel.HysteriaServerBind, logger *slog.Logger) *WireGuardOutbound {
	return &WireGuardOutbound{
		bind:   bind,
		logger: logger,
		conns:  make(map[string]*wireGuardConn),
	}
}

// TCP 实现 TCP 连接（直接连接外部网络）
func (o *WireGuardOutbound) TCP(reqAddr string) (net.Conn, error) {
	// 支持普通 TCP 连接
	return net.Dial("tcp", reqAddr)
}

// UDP 实现 UDP 连接
func (o *WireGuardOutbound) UDP(reqAddr string) (server.UDPConn, error) {
	o.logger.Debug("Creating WireGuard UDP connection", "target", reqAddr)

	conn := &wireGuardConn{
		bind:       o.bind,
		targetAddr: reqAddr,
		recvChan:   make(chan *wgPacket, 16384), // 增大缓冲区，防止丢包
		outbound:   o,
	}

	// 保存连接以便发送响应
	o.mu.Lock()
	o.conns[reqAddr] = conn
	o.mu.Unlock()

	return conn, nil
}

// SendToClient WireGuard bind 的回调，将响应发送回客户端
func (o *WireGuardOutbound) SendToClient(data []byte, endpoint string) error {
	o.mu.RLock()
	conn, ok := o.conns[endpoint]
	o.mu.RUnlock()

	if !ok {
		// 可能连接已关闭
		return nil
	}

	conn.deliverPacket(data)
	return nil
}

// wireGuardConn 实现 server.UDPConn 接口
type wireGuardConn struct {
	bind       *tunnel.HysteriaServerBind
	targetAddr string
	recvChan   chan *wgPacket
	outbound   *WireGuardOutbound
	closed     atomic.Bool // 使用 atomic 代替 mutex 提高性能
}

// wgPacket WireGuard 响应包
// 使用缓冲池减少 GC 压力
type wgPacket struct {
	data []byte  // 实际数据切片
	buf  *[]byte // 缓冲池中的原始缓冲区指针（用于归还）
}

// ReadFrom 读取 WireGuard 响应
func (c *wireGuardConn) ReadFrom(b []byte) (int, string, error) {
	if c.closed.Load() {
		return 0, "", net.ErrClosed
	}

	pkt, ok := <-c.recvChan
	if !ok {
		return 0, "", net.ErrClosed
	}

	n := copy(b, pkt.data)
	// 归还缓冲区到池中
	if pkt.buf != nil {
		tunnel.PutBuffer(pkt.buf)
	}
	return n, c.targetAddr, nil
}

// WriteTo 写入数据到 WireGuard
func (c *wireGuardConn) WriteTo(b []byte, addr string) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}

	// 将数据包投递到 WireGuard bind
	c.bind.DeliverPacket(b, c.targetAddr)
	return len(b), nil
}

// Close 关闭连接
func (c *wireGuardConn) Close() error {
	if c.closed.Swap(true) {
		return nil // 已经关闭过
	}

	// 从 outbound 移除
	c.outbound.mu.Lock()
	delete(c.outbound.conns, c.targetAddr)
	c.outbound.mu.Unlock()

	close(c.recvChan)
	return nil
}

// deliverPacket 投递 WireGuard 响应包
func (c *wireGuardConn) deliverPacket(data []byte) {
	if c.closed.Load() {
		return
	}

	// 从缓冲池获取缓冲区，减少 GC 压力
	buf := tunnel.GetBuffer()
	dataCopy := (*buf)[:len(data)]
	copy(dataCopy, data)

	// 阻塞式发送，不丢包！
	// 如果 channel 满了，等待消费者读取
	// 这对于 BBR/Brutal 拥塞控制至关重要
	select {
	case c.recvChan <- &wgPacket{data: dataCopy, buf: buf}:
	default:
		// Channel 满了，尝试阻塞发送（带超时保护）
		select {
		case c.recvChan <- &wgPacket{data: dataCopy, buf: buf}:
		case <-time.After(100 * time.Millisecond):
			// 超时才丢包，归还缓冲区
			tunnel.PutBuffer(buf)
		}
	}
}
