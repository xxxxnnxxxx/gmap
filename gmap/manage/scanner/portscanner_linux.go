// go:build linux
// +build:linux
package scanner

import (
	"Gmap/gmap/log"
	"Gmap/gmap/netex/rawsock"
	"sync"
)

func TCPConnectProbe(entity *ScanTargetEntity) int {
	var ret int
	var waitFinished sync.WaitGroup

	for _, item := range entity.TargetPort {
		pp := item // 必须，要不在循环过程中item地址不能传递给下一层
		waitFinished.Add(1)
		go func(group *sync.WaitGroup) {
			defer group.Done()
			// 指向 Port 结构主体

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
