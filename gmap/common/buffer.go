package common

import (
	"bytes"
	"sync"
)

type Buffer struct {
	buf        *bytes.Buffer
	mutex      sync.Mutex
	readcursor int // 读取游标，读取已经读取的数据位置
}

func NewBuffer() *Buffer {
	return &Buffer{
		buf: bytes.NewBuffer(nil),
	}
}

func (p *Buffer) Write(content []byte) int {
	if content == nil {
		return -1
	}
	p.mutex.Lock()
	p.buf.Write(content)
	p.mutex.Unlock()

	return len(content)
}

func (p *Buffer) Read() ([]byte, int) {
	result := make([]byte, 0)
	var length int
	p.mutex.Lock()
	result = append(result, p.buf.Bytes()[p.readcursor:]...)
	p.readcursor = p.buf.Len()
	length = len(result)
	p.mutex.Unlock()

	return result, length
}

func (p *Buffer) Length() int {
	return p.buf.Len()
}
