// Package tunnel - 缓冲区池，用于减少高吞吐场景下的 GC 压力
package tunnel

import "sync"

// DefaultBufferSize 默认缓冲区大小 (64KB，足够容纳最大 UDP 包)
const DefaultBufferSize = 65535

// bufferPool 全局缓冲区池
var bufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, DefaultBufferSize)
		return &buf
	},
}

// GetBuffer 从池中获取缓冲区
// 返回的是指向切片的指针，以便归还时不会逃逸
func GetBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

// PutBuffer 归还缓冲区到池中
// 确保缓冲区足够大且重置为原始容量
func PutBuffer(buf *[]byte) {
	if buf == nil {
		return
	}
	// 检查容量是否足够（防止用户传入小缓冲区）
	if cap(*buf) < DefaultBufferSize {
		return
	}
	// 重置切片长度为完整容量
	*buf = (*buf)[:DefaultBufferSize]
	bufferPool.Put(buf)
}

// GetBufferWithSize 从池中获取指定大小的缓冲区切片
// 返回的切片长度为 size，但底层容量仍为 DefaultBufferSize
func GetBufferWithSize(size int) *[]byte {
	buf := GetBuffer()
	if size > 0 && size <= DefaultBufferSize {
		*buf = (*buf)[:size]
	}
	return buf
}
