package sock

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

const (
	ProtocolType_TCP = iota
	ProtocolType_UDP
)

type BaseDialer struct {
	ProtocolType int
	IsTLS        bool // tls连接
	Dialer       net.Dialer
	IP           net.IP
	IPnet        *net.IPNet
	Port         uint16
	Conn         net.Conn
	TlsConn      *tls.Conn
	// 数据返回回调
	// 参数
	// 传递的数据
	// 返回结果类型
	HandleData  func([]byte, int) //
	Signal      chan int          // 信号
	StateError  chan error
	ConnTimeout time.Duration
	ReadTimeout time.Duration
	CacheSize   int           // 接收数据的缓存大小
	IsBlockMode bool          // 是否阻塞模式 阻塞模式的情况下，数据处理是阻塞处理的, 不会分出协程
	RecvedBuf   *bytes.Buffer // 接收到的数据buf
}

const (
	Signal_RecvFinished = iota + 1
)

func NewBaseDialer(protocoltype int, isTLS bool) *BaseDialer {
	return &BaseDialer{
		ProtocolType: protocoltype,
		IsTLS:        isTLS,
		TlsConn:      nil,
		ConnTimeout:  10 * time.Second,
		ReadTimeout:  10 * time.Second,
		Dialer:       net.Dialer{},
		Signal:       make(chan int),
		StateError:   make(chan error, 1000),
		CacheSize:    10240,
		RecvedBuf:    bytes.NewBuffer([]byte{}),
	}
}

func (p *BaseDialer) SetConnTimeout(msecond int64) {
	p.ConnTimeout = time.Duration(msecond) * time.Millisecond
	p.Dialer.Timeout = p.ConnTimeout
}

func (p *BaseDialer) SetReadTimeout(msecond int64) {
	p.ReadTimeout = time.Duration(msecond) * time.Millisecond
}

func (p *BaseDialer) SetIP(ip string) error {
	var err error
	p.IP, p.IPnet, err = net.ParseCIDR(ip)
	if err != nil {
		p.IP = net.ParseIP(ip)
		err = nil
	}
	return err
}

func (p *BaseDialer) SetPort(port uint16) {
	p.Port = port
}

func (p *BaseDialer) SetCacheSize(size int) {
	p.CacheSize = size
}

func (p *BaseDialer) SetTlsFlag(flag bool) {
	p.IsTLS = flag
}

func (p *BaseDialer) GetRecvedBuf() []byte {
	return p.RecvedBuf.Bytes()
}

func (p *BaseDialer) Send(buf []byte) (int, error) {
	if p.Conn == nil {
		return 0, errors.New("")
	}
	var count int
	var err error
	if p.ProtocolType == ProtocolType_TCP && p.IsTLS {
		if p.TlsConn != nil {
			count, err = p.TlsConn.Write(buf)
		} else {
			return 0, errors.New("tls failed")
		}
	} else {
		count, err = p.Conn.Write(buf)
	}

	return count, err
}

func (p *BaseDialer) Dial(bOnlyConnectTest bool) error {
	var err error
	if p.ProtocolType == ProtocolType_TCP {
		// golang 在这个地方是真垃圾
		p.Conn, err = p.Dialer.Dial("tcp", p.IP.String()+":"+strconv.FormatInt(int64(p.Port), 10))
		if err == nil && !bOnlyConnectTest {
			if p.ReadTimeout > 0 {
				p.Conn.SetReadDeadline(time.Now().Add(p.ReadTimeout))
			} else {
				p.Conn.SetReadDeadline(time.Time{}) // 不限制
			}
		} else {
			return err
		}

		if p.IsTLS {
			p.TlsConn = tls.Client(p.Conn, &tls.Config{
				InsecureSkipVerify: true,
			})
			err = p.TlsConn.Handshake()
			if err == nil {
				return nil
			} else {
				p.TlsConn = nil
				return err
			}
		}
	} else if p.ProtocolType == ProtocolType_UDP {
		p.Conn, err = p.Dialer.Dial("udp", p.IP.String()+":"+strconv.FormatInt(int64(p.Port), 10))
		if err == nil && p.ReadTimeout > 0 {
			p.Conn.SetReadDeadline(time.Now().Add(p.ReadTimeout))
		}
	} else {
		err = errors.New("protocol type error")
	}

	return err
}

func (p *BaseDialer) Close() {
	if p.ProtocolType == ProtocolType_TCP && p.IsTLS {
		p.TlsConn.Close()
		p.Conn.Close()
	} else {
		p.Conn.Close()
	}
}

func (p *BaseDialer) Listen() error {
	if p.Conn == nil {
		return errors.New("don't connect a server")
	}

	go func() {
		if p.ProtocolType == ProtocolType_TCP && p.IsTLS {
			for {
				buf := make([]byte, p.CacheSize)
				n, err := p.TlsConn.Read(buf)
				if err != nil {
					if n > 0 {
						p.RecvedBuf.Write(buf[:n])
						if p.HandleData != nil {
							if p.IsBlockMode {
								p.HandleData(buf, n)
							} else {
								go p.HandleData(buf, n)
							}

						}
					}

					if err == io.EOF {
						p.Signal <- Signal_RecvFinished
					} else {
						p.StateError <- err
					}
					return
				}
				if n > 0 {
					p.RecvedBuf.Write(buf[:n])
					if p.HandleData != nil {
						if p.IsBlockMode {
							p.HandleData(buf, n)
						} else {
							go p.HandleData(buf, n)
						}
					}
				} else {
					p.Signal <- Signal_RecvFinished
					return
				}
			}
		} else {
			for {
				buf := make([]byte, p.CacheSize)
				n, err := p.Conn.Read(buf)
				if err != nil {
					if n > 0 {
						p.RecvedBuf.Write(buf[:n])
						if p.HandleData != nil {
							if p.IsBlockMode {
								p.HandleData(buf, n)
							} else {
								go p.HandleData(buf, n)
							}
						}
					}
					if err.Error() == "EOF" {
						p.Signal <- Signal_RecvFinished
					} else {
						p.StateError <- err
					}
					return
				}
				if n > 0 {
					p.RecvedBuf.Write(buf[:n])
					if p.HandleData != nil {
						if p.IsBlockMode {
							p.HandleData(buf, n)
						} else {
							go p.HandleData(buf, n)
						}
					}
				} else {
					p.Signal <- Signal_RecvFinished
					return
				}
			}
		}

	}()

	return nil
}

// golang的错误处理返回详细信息简直是垃圾
func (p *BaseDialer) Wait() error {
	var err error
	select {
	case val := <-p.Signal:
		switch val {
		case Signal_RecvFinished:
			return errors.New("RecvFinished")
		}
	case err = <-p.StateError:
		var opErr *net.OpError
		if errors.As(err, &opErr) {
			// 进一步检查具体的错误类型
			var syscallError *os.SyscallError
			var DNSError *net.DNSError
			switch {
			case errors.As(opErr.Err, &syscallError), errors.As(opErr.Err, &DNSError):
				break
			default:
				err = nil
			}
		}
	}

	return err
}

// golang的错误处理返回详细信息简直是垃圾
func (p *BaseDialer) WaitTimeout(t time.Duration) error {
	var err error
	select {
	case val := <-p.Signal:
		switch val {
		case Signal_RecvFinished:
			return errors.New("RecvFinished")
		}
	case err = <-p.StateError:
		var opErr *net.OpError
		if errors.As(err, &opErr) {
			// 进一步检查具体的错误类型
			var syscallError *os.SyscallError
			var DNSError *net.DNSError
			switch {
			case errors.As(opErr.Err, &syscallError), errors.As(opErr.Err, &DNSError):
				break
			default:
				err = nil
			}
		}
	case <-time.After(t):
		err = errors.New("timeout")
	}

	return err
}
