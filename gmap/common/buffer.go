package common

import (
	"bytes"
	"sync"
)

type Buffer struct {
	buf   *bytes.Buffer
	mutex sync.Mutex
}

func NewBuffer() *Buffer {
	return &Buffer{
		buf: bytes.NewBuffer(nil),
	}
}

func (p *Buffer) Write(content []byte, length int) int {
	if content == nil || length <= 0 {
		return -1
	}

	p.mutex.Lock()
	p.buf.Write(content[:length-1])
	p.mutex.Unlock()

	return len(content)
}

func (p *Buffer) Read() ([]byte, int) {
	result := make([]byte, 0)
	var length int
	p.mutex.Lock()
	result = append(result, p.buf.Bytes()...)
	length = len(result)
	p.mutex.Unlock()

	return result, length
}
