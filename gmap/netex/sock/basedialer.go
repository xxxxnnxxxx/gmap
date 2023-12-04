package sock

import (
	"Gmap/gmap/log"
	"crypto/tls"
	"errors"
	"io"
	"net"
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
	HandleData   func([]byte, int) error // 接收数据回调
	Signal       chan int                // 信号
	StateError   chan error
	ConnTimeout  time.Duration
	ReadTimeout  time.Duration
	CacheSize    int // 接收数据的缓存大小
}

const (
	Signal_RecvFinished = iota + 1
)

func NewBaseDialer(protocoltype int, isTLS bool) *BaseDialer {
	return &BaseDialer{
		ProtocolType: protocoltype,
		IsTLS:        isTLS,
		TlsConn:      nil,
		ConnTimeout:  2 * time.Second,
		ReadTimeout:  10 * time.Second,
		Dialer:       net.Dialer{},
		Signal:       make(chan int),
		StateError:   make(chan error),
		CacheSize:    10240,
	}
}

func (p *BaseDialer) SetConnTimeout(seconds float64) {
	p.ConnTimeout = time.Duration(seconds * float64(time.Second))
	p.Dialer.Timeout = p.ConnTimeout
}

func (p *BaseDialer) SetReadTimeout(seconds float64) {
	p.ReadTimeout = time.Duration(seconds * float64(time.Second))
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
		//p.Conn, err = net.DialTCP("tcp", nil, &net.TCPAddr{
		//	IP:   p.IP,
		//	Port: int(p.Port),
		//})
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

func (p *BaseDialer) StartRecv() error {
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
						if p.HandleData != nil {
							go p.HandleData(buf, n)
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
					if p.HandleData != nil {
						go p.HandleData(buf, n)
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
						if p.HandleData != nil {
							go p.HandleData(buf, n)
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
					if p.HandleData != nil {
						go p.HandleData(buf, n)
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

func (p *BaseDialer) Wait() {
	select {
	case val := <-p.Signal:
		switch val {
		case Signal_RecvFinished:
			log.Logger.Info("RecvFinished")
		}
	case err := <-p.StateError:
		log.Logger.Error(err)
	}
}
