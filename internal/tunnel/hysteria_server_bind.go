// Package tunnel - 服务端 Hysteria-WireGuard 绑定
package tunnel

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"
)

// HysteriaServerBind 实现服务端的 WireGuard Bind 接口
// 直接通过内存通道接收来自 Hysteria 的数据包，无需 UDP 端口
type HysteriaServerBind struct {
	mu sync.RWMutex

	// 接收队列
	recvChan chan *serverPacket

	// 发送回调（用于将响应发送回 Hysteria）
	sendCallback func(data []byte, endpoint string) error

	closed atomic.Bool
}

// serverPacket 服务端数据包
// 使用缓冲池来减少 GC 压力
type serverPacket struct {
	data     []byte  // 实际数据切片（长度为实际数据大小）
	buf      *[]byte // 缓冲池中的原始缓冲区指针（用于归还）
	endpoint string  // 客户端地址标识
}

// ServerEndpoint 服务端端点实现
type ServerEndpoint struct {
	addr string
}

func (e *ServerEndpoint) ClearSrc()           {}
func (e *ServerEndpoint) SrcToString() string { return "" }
func (e *ServerEndpoint) DstToString() string { return e.addr }
func (e *ServerEndpoint) DstToBytes() []byte  { return []byte(e.addr) }
func (e *ServerEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (e *ServerEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

// NewHysteriaServerBind 创建服务端绑定
func NewHysteriaServerBind() *HysteriaServerBind {
	return &HysteriaServerBind{
		recvChan: make(chan *serverPacket, 4096), // 增大缓冲队列，防止突发流量丢包
		closed:   atomic.Bool{},
	}
}

// SetSendCallback 设置发送回调
func (b *HysteriaServerBind) SetSendCallback(callback func(data []byte, endpoint string) error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sendCallback = callback
}

// DeliverPacket 从 Hysteria 投递数据包到 WireGuard
func (b *HysteriaServerBind) DeliverPacket(data []byte, clientAddr string) {
	if b.closed.Load() {
		return
	}

	// 从缓冲池获取缓冲区，减少 GC 压力
	buf := GetBuffer()
	dataCopy := (*buf)[:len(data)]
	copy(dataCopy, data)

	b.mu.RLock()
	ch := b.recvChan
	b.mu.RUnlock()

	if ch == nil {
		PutBuffer(buf) // 归还缓冲区
		return
	}

	// 使用 select 避免在已关闭的 channel 上阻塞
	select {
	case ch <- &serverPacket{
		data:     dataCopy,
		buf:      buf,
		endpoint: clientAddr,
	}:
	default:
		// 队列满或已关闭，丢弃包并归还缓冲区
		PutBuffer(buf)
	}
}

// Open 实现 Bind.Open
func (b *HysteriaServerBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	// 重新创建 channel（如果之前被关闭）
	if b.recvChan == nil {
		b.recvChan = make(chan *serverPacket, 4096)
	}
	b.closed.Store(false)
	ch := b.recvChan
	b.mu.Unlock()

	recvFunc := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		if b.closed.Load() {
			return 0, net.ErrClosed
		}

		// 1. 阻塞读取第一个包
		pkt, ok := <-ch
		if !ok {
			return 0, net.ErrClosed
		}

		n = copy(packets[0], pkt.data)
		sizes[0] = n
		eps[0] = &ServerEndpoint{addr: pkt.endpoint}
		// 归还缓冲区
		if pkt.buf != nil {
			PutBuffer(pkt.buf)
		}
		count := 1

		// 2. 尝试非阻塞读取更多包 (Batch Processing)
		for count < len(packets) {
			select {
			case pkt, ok := <-ch:
				if !ok {
					return count, nil
				}
				n = copy(packets[count], pkt.data)
				sizes[count] = n
				eps[count] = &ServerEndpoint{addr: pkt.endpoint}
				// 归还缓冲区
				if pkt.buf != nil {
					PutBuffer(pkt.buf)
				}
				count++
			default:
				// 通道空了，直接返回已读取的包
				return count, nil
			}
		}

		return count, nil
	}

	return []conn.ReceiveFunc{recvFunc}, 0, nil
}

// Close 实现 Bind.Close
func (b *HysteriaServerBind) Close() error {
	if b.closed.Swap(true) {
		return nil
	}

	b.mu.Lock()
	if b.recvChan != nil {
		close(b.recvChan)
		b.recvChan = nil
	}
	b.mu.Unlock()

	return nil
}

// SetMark 实现 Bind.SetMark
func (b *HysteriaServerBind) SetMark(mark uint32) error {
	return nil
}

// Send 实现 Bind.Send（发送响应回 Hysteria）
func (b *HysteriaServerBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if b.closed.Load() {
		return net.ErrClosed
	}

	serverEp, ok := ep.(*ServerEndpoint)
	if !ok {
		return fmt.Errorf("unexpected endpoint type: %T", ep)
	}

	b.mu.RLock()
	callback := b.sendCallback
	b.mu.RUnlock()

	if callback == nil {
		return fmt.Errorf("send callback not set")
	}

	for _, buf := range bufs {
		if err := callback(buf, serverEp.addr); err != nil {
			return err
		}
	}

	return nil
}

// ParseEndpoint 实现 Bind.ParseEndpoint
func (b *HysteriaServerBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return &ServerEndpoint{addr: s}, nil
}

// BatchSize 实现 Bind.BatchSize
func (b *HysteriaServerBind) BatchSize() int {
	return conn.IdealBatchSize
}
