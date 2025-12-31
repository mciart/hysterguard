// Package config 提供配置文件解析功能
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// ClientConfig 客户端配置
type ClientConfig struct {
	Hysteria  HysteriaClientConfig `yaml:"hysteria"`
	WireGuard WireGuardConfig      `yaml:"wireguard"`
	TUN       TUNConfig            `yaml:"tun"`
	Log       LogConfig            `yaml:"log"`
}

// ServerConfig 服务端配置
type ServerConfig struct {
	Listen    string                `yaml:"listen"`
	Hysteria  HysteriaServerConfig  `yaml:"hysteria"`
	WireGuard WireGuardServerConfig `yaml:"wireguard"`
	Log       LogConfig             `yaml:"log"`
}

// HysteriaClientConfig Hysteria 客户端配置
type HysteriaClientConfig struct {
	Server    string          `yaml:"server"`
	Auth      string          `yaml:"auth"`
	SNI       string          `yaml:"sni"`
	Insecure  bool            `yaml:"insecure"`
	Obfs      ObfsConfig      `yaml:"obfs"`
	Bandwidth BandwidthConfig `yaml:"bandwidth"`
}

// HysteriaServerConfig Hysteria 服务端配置
type HysteriaServerConfig struct {
	Auth       string           `yaml:"auth"`
	TLS        TLSConfig        `yaml:"tls"`
	Obfs       ObfsConfig       `yaml:"obfs"`
	Masquerade MasqueradeConfig `yaml:"masquerade"`
}

// ObfsConfig 混淆配置
type ObfsConfig struct {
	Type     string `yaml:"type"`
	Password string `yaml:"password"`
}

// BandwidthConfig 带宽配置
type BandwidthConfig struct {
	Up   string `yaml:"up"`
	Down string `yaml:"down"`
}

// TLSConfig TLS 证书配置
type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

// MasqueradeConfig 伪装配置
type MasqueradeConfig struct {
	Type  string                `yaml:"type"`
	Proxy MasqueradeProxyConfig `yaml:"proxy"`
}

// MasqueradeProxyConfig 代理伪装配置
type MasqueradeProxyConfig struct {
	URL         string `yaml:"url"`
	RewriteHost bool   `yaml:"rewrite_host"`
}

// WireGuardConfig WireGuard 客户端配置
type WireGuardConfig struct {
	PrivateKey string     `yaml:"private_key"`
	Peer       PeerConfig `yaml:"peer"`
}

// WireGuardServerConfig WireGuard 服务端配置
type WireGuardServerConfig struct {
	PrivateKey string        `yaml:"private_key"`
	ListenPort int           `yaml:"listen_port"`
	Peers      []PeerConfig  `yaml:"peers"`
	Address    AddressConfig `yaml:"address"`
	PostUp     []string      `yaml:"post_up"`   // 接口启动后执行的命令
	PostDown   []string      `yaml:"post_down"` // 接口关闭前执行的命令
}

// PeerConfig WireGuard 对端配置
type PeerConfig struct {
	PublicKey           string   `yaml:"public_key"`
	AllowedIPs          []string `yaml:"allowed_ips"`
	PersistentKeepalive int      `yaml:"persistent_keepalive"`
}

// TUNConfig TUN 设备配置
type TUNConfig struct {
	Name     string        `yaml:"name"`
	MTU      int           `yaml:"mtu"`
	Address  AddressConfig `yaml:"address"`
	DNS      DNSConfig     `yaml:"dns"`
	PostUp   []string      `yaml:"post_up"`   // 接口启动后执行的命令
	PostDown []string      `yaml:"post_down"` // 接口关闭前执行的命令
}

// DNSConfig DNS 配置
type DNSConfig struct {
	Servers []string `yaml:"servers"` // DNS 服务器地址
}

// AddressConfig IP 地址配置
type AddressConfig struct {
	IPv4 string `yaml:"ipv4"`
	IPv6 string `yaml:"ipv6"`
}

// LogConfig 日志配置
type LogConfig struct {
	Level string `yaml:"level"`
	File  string `yaml:"file"`
}

// LoadClientConfig 加载客户端配置
func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config ClientConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// 设置默认值
	if config.TUN.MTU == 0 {
		config.TUN.MTU = 1280
	}
	if config.TUN.Name == "" {
		config.TUN.Name = "hysterguard0"
	}
	if config.Log.Level == "" {
		config.Log.Level = "info"
	}

	return &config, nil
}

// LoadServerConfig 加载服务端配置
func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config ServerConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// 设置默认值
	if config.Listen == "" {
		config.Listen = ":443"
	}
	if config.WireGuard.ListenPort == 0 {
		config.WireGuard.ListenPort = 51820
	}
	if config.Log.Level == "" {
		config.Log.Level = "info"
	}

	return &config, nil
}

// Validate 验证客户端配置
func (c *ClientConfig) Validate() error {
	if c.Hysteria.Server == "" {
		return fmt.Errorf("hysteria.server is required")
	}
	if c.Hysteria.Auth == "" {
		return fmt.Errorf("hysteria.auth is required")
	}
	if c.WireGuard.PrivateKey == "" {
		return fmt.Errorf("wireguard.private_key is required")
	}
	if c.WireGuard.Peer.PublicKey == "" {
		return fmt.Errorf("wireguard.peer.public_key is required")
	}
	return nil
}

// Validate 验证服务端配置
func (c *ServerConfig) Validate() error {
	if c.Hysteria.Auth == "" {
		return fmt.Errorf("hysteria.auth is required")
	}
	if c.Hysteria.TLS.Cert == "" || c.Hysteria.TLS.Key == "" {
		return fmt.Errorf("hysteria.tls.cert and hysteria.tls.key are required")
	}
	if c.WireGuard.PrivateKey == "" {
		return fmt.Errorf("wireguard.private_key is required")
	}
	return nil
}

// ParseDuration 解析持续时间字符串
func ParseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	return time.ParseDuration(s)
}
