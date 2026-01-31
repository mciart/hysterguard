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

	// ============ 1. 根据模式启动 WireGuard 服务 ============
	var wgTunnel *tunnel.ServerTunnel
	var wgTarget string

	if cfg.WireGuard.Mode == "local" {
		logger.Info("Starting WireGuard server (local mode)...", "listen", cfg.WireGuard.Listen)
		var err error
		wgTunnel, err = tunnel.NewServerTunnel(cfg, logger)
		if err != nil {
			return fmt.Errorf("failed to create WireGuard tunnel: %w", err)
		}

		if err := wgTunnel.Start(ctx); err != nil {
			return fmt.Errorf("failed to start WireGuard tunnel: %w", err)
		}
		defer wgTunnel.Stop()

		wgTarget = cfg.WireGuard.Target
		logger.Info("WireGuard server started", "listen", cfg.WireGuard.Listen, "target", wgTarget)
	} else {
		// forward 模式：不启动本地 WireGuard，只转发
		wgTarget = cfg.WireGuard.Target
		logger.Info("WireGuard forward mode", "target", wgTarget)
	}

	// ============ 2. 启动 Hysteria 服务（使用默认 Outbound）============
	logger.Info("Starting Hysteria server...")
	hyServer, err := createHysteriaServer(cfg, wgTarget, logger)
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

	// 打印启动信息
	logger.Info("===============================================")
	if cfg.WireGuard.Mode == "local" {
		logger.Info("HysterGuard Server is now running (Local Mode)")
		logger.Info("  Hysteria (obfuscation): " + cfg.Listen)
		logger.Info("  WireGuard listen: " + cfg.WireGuard.Listen)
		logger.Info("  WireGuard target: " + wgTarget)
	} else {
		logger.Info("HysterGuard Server is now running (Forward Mode)")
		logger.Info("  Hysteria (obfuscation): " + cfg.Listen)
		logger.Info("  WireGuard target: " + wgTarget)
	}
	logger.Info("===============================================")
	logger.Info("Press Ctrl+C to stop")

	// 等待信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

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
func createHysteriaServer(cfg *config.ServerConfig, wgTarget string, logger *slog.Logger) (server.Server, error) {
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
		Outbound:              &defaultOutbound{wgTarget: wgTarget, logger: logger},
		IgnoreClientBandwidth: false, // 允许客户端指定带宽（启用 Brutal）
		Authenticator: &simpleAuthenticator{
			password: cfg.Hysteria.Auth,
			logger:   logger,
		},
		EventLogger: &serverEventLogger{logger: logger},
	}

	return server.NewServer(serverConfig)
}

// defaultOutbound 默认 Outbound 实现，使用标准 UDP 代理
type defaultOutbound struct {
	wgTarget string
	logger   *slog.Logger
}

// TCP 实现 TCP 连接
func (o *defaultOutbound) TCP(reqAddr string) (net.Conn, error) {
	return net.Dial("tcp", reqAddr)
}

// UDP 实现 UDP 连接
func (o *defaultOutbound) UDP(reqAddr string) (server.UDPConn, error) {
	// 使用配置的 WireGuard 目标地址
	target := reqAddr
	if reqAddr == "127.0.0.1:51820" || reqAddr == o.wgTarget {
		target = o.wgTarget
	}

	o.logger.Debug("Creating UDP connection", "reqAddr", reqAddr, "target", target)

	// 创建真实的 UDP 连接
	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial UDP: %w", err)
	}

	// 设置缓冲区
	_ = conn.SetReadBuffer(4194304)
	_ = conn.SetWriteBuffer(4194304)

	c := &realUDPConn{
		conn:     conn,
		target:   target,
		recvChan: make(chan []byte, 1024),
		logger:   o.logger,
	}

	// 启动异步读取 goroutine
	go c.readLoop()

	return c, nil
}

// realUDPConn 真实 UDP 连接包装器（异步读取）
type realUDPConn struct {
	conn     *net.UDPConn
	target   string
	recvChan chan []byte
	closed   atomic.Bool
	logger   *slog.Logger
}

// readLoop 异步读取循环
func (c *realUDPConn) readLoop() {
	buf := make([]byte, 2000)
	for !c.closed.Load() {
		n, err := c.conn.Read(buf)
		if err != nil {
			if !c.closed.Load() {
				c.logger.Debug("UDP read error", "error", err)
			}
			return
		}

		// 复制数据
		dataCopy := make([]byte, n)
		copy(dataCopy, buf[:n])

		select {
		case c.recvChan <- dataCopy:
			// 成功入队
		default:
			c.logger.Warn("UDP recv channel full, dropping packet")
		}
	}
}

func (c *realUDPConn) ReadFrom(b []byte) (int, string, error) {
	if c.closed.Load() {
		return 0, "", net.ErrClosed
	}

	// 使用短超时让 Hysteria 能继续处理其他数据
	select {
	case data := <-c.recvChan:
		n := copy(b, data)
		return n, c.target, nil
	case <-time.After(5 * time.Millisecond):
		// 返回空数据，让 Hysteria 继续处理其他方向的数据
		return 0, "", nil
	}
}

func (c *realUDPConn) WriteTo(b []byte, addr string) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.conn.Write(b)
}

func (c *realUDPConn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	close(c.recvChan)
	return c.conn.Close()
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
