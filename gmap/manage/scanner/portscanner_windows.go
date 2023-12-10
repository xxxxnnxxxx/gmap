//go:build windows
// +build windows

package scanner

import (
	"Gmap/gmap/log"
	"Gmap/gmap/netex/rawsock"
	"Gmap/gmap/netex/sock"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// 普通的tcp连接测试
func TCPConnectProbe(entity *ScanTargetEntity) int {
	var ret int
	var waitFinished sync.WaitGroup

	for _, item := range entity.TargetPort {
		pp := item // 必须，要不在循环过程中item地址不能传递给下一层
		waitFinished.Add(1)
		go func(group *sync.WaitGroup) {
			defer group.Done()
			// 指向 Port 结构主体
			pPort := pp
			var times int
			var timeout time.Duration
			timeout = entity.Timeout
			btcp := sock.NewBaseDialer(sock.ProtocolType_TCP, false)
			btcp.HandleData = func(data []byte, n int) {
				fmt.Println(string(data))
			}
			btcp.SetIP(entity.IP.String())
			btcp.SetPort(pPort.Val)
			times = entity.NumOfAttempts // 尝试次数
		begin:
			btcp.SetConnTimeout(int64(timeout))
			err := btcp.Dial(true)
			if err != nil {
				var s *net.OpError
				switch {
				case errors.As(err, &s):
					var m *os.SyscallError
					switch {
					case errors.As(s.Err, &m):
						var v syscall.Errno
						if errors.As(m.Err, &v) {
							// 区分不同的错误，后续处理相关的返回信息
							switch v {
							case windows.WSAECONNABORTED:
								ret = PortState_Closed
							case windows.WSAETIMEDOUT:
								ret = PortState_Closed
							case windows.WSAECONNREFUSED:
								ret = PortState_Closed
							default:
								ret = PortState_Closed
							}
						}
					default:
						ret = PortState_Closed
					}
				default:
					ret = PortState_Closed
				}

				if ret == PortState_Closed && times > 1 {
					times = times - 1
					timeout = timeout * 2
					goto begin
				}

				pPort.Lock.Lock()
				pPort.State = ret
				pPort.Lock.Unlock()
				return
			} else {
				btcp.Close()
				pPort.Lock.Lock()
				pPort.State = PortState_Open
				pPort.Lock.Unlock()
				return
			}
		}(&waitFinished)

	}

	waitFinished.Wait()

	return PortState_Unknown
}

func TCPSynProbe(entity *ScanTargetEntity) int {
	if len(entity.Nexthops) == 0 {
		log.Logger.Error("not found nexthop info")
		return -1
	}

	processor := NewSimplePacketProcessor2(
		rawsock.SocketType_STREAM,
		entity,
		func(port *Port) {

		},
	)
	processor.SetTimeout(2)
	processor.Initialize()
	processor.Do()
	processor.Wait()

	return PortState_Unknown
}
