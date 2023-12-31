/*
以下主要用于扫描的简单sock处理，用于方便和加快处置速度
上面的sock主要用于开发通用的tcp/udp的通讯开发，满足通用性处理
*/

package scanner

import (
	"Gmap/gmap/log"
	"Gmap/gmap/netex/device"
	"Gmap/gmap/netex/rawsock"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type SimplePacketProcessor struct {
	handle        *pcap.Handle
	Wg            sync.WaitGroup
	Done          chan struct{}
	deviceLnkName string
	toseconds     time.Duration // 设置超时
	finishedcount int32         // 完成个数

	scanEntity *ScanTargetEntity
	sourcePort uint16
	sourceIP   net.IP
	sourceMAC  net.HardwareAddr
	dstIP      net.IP
	nexthopMAC net.HardwareAddr // 下一跳总是网关的MAC地址

	lockPortList    sync.Mutex
	portList        map[uint16]*Port // 端口列表
	countOfPortList int32
	countOfFinished int32 // 保留端口已经结束的个数
	ScanState       int32 // 是否完成
	socketType      int

	lock_latestTime sync.RWMutex
	latestTime      time.Time // 记录最后一次获取数据的时间
	countOfRetry    int32     // 尝试次数

	ResultCallback func(port *Port)
}

func NewSimplePacketProcessor(socketType int,
	dstIP net.IP, nexthopMAC net.HardwareAddr,
	sourceIP net.IP, sourceMAC net.HardwareAddr, sourcePort uint16,
	portList []*Port,
	deviceLnkName string,
	resultCallback func(port *Port)) *SimplePacketProcessor {

	instance := &SimplePacketProcessor{
		socketType:     socketType,
		Done:           make(chan struct{}, 10), // 这个地方可以多分配几个信号量，不用的地方可以不处理
		deviceLnkName:  deviceLnkName,
		dstIP:          dstIP,
		nexthopMAC:     nexthopMAC,
		sourceIP:       sourceIP,
		sourceMAC:      sourceMAC,
		sourcePort:     sourcePort,
		portList:       make(map[uint16]*Port),
		ResultCallback: resultCallback,
		latestTime:     time.Time{},
		ScanState:      ScannerState_Stop,
	}

	for _, item := range portList {
		instance.portList[item.Val] = item
	}

	instance.countOfPortList = int32(len(instance.portList))

	return instance
}

func NewSimplePacketProcessor2(socketType int,
	entity *ScanTargetEntity,
	resultCallback func(port *Port)) *SimplePacketProcessor {
	instance := &SimplePacketProcessor{
		socketType:     socketType,
		Done:           make(chan struct{}, 10), // 这个地方可以多分配几个信号量，不用的地方可以不处理
		deviceLnkName:  entity.Nexthops[0].Route.II.DevLinkSymbol,
		dstIP:          entity.IP,
		nexthopMAC:     entity.Nexthops[0].MAC,
		sourceIP:       entity.Nexthops[0].Route.II.Addrs[0].ToIP(),
		sourceMAC:      entity.Nexthops[0].Route.II.MAC,
		sourcePort:     uint16(rawsock.GeneratePort()),
		portList:       make(map[uint16]*Port),
		ResultCallback: resultCallback,
	}

	// 回环的情况下，目的地址和源地址一样
	if entity.IsLoopback {
		instance.sourceIP = entity.IP
	}

	// 指向实体
	instance.scanEntity = entity

	for _, item := range entity.TargetPort {
		instance.portList[item.Val] = item
	}

	instance.countOfPortList = int32(len(instance.portList))

	return instance
}

func (p *SimplePacketProcessor) Initialize() error {
	// 打开设备
	handle, err := device.OpenPcapDevice(p.deviceLnkName)
	if err != nil {
		return err
	}

	p.handle = handle

	p.Wg.Add(1)

	return nil
}

func (p *SimplePacketProcessor) SetTimeout(toseconds time.Duration) {
	p.toseconds = toseconds
}

// 性能问题？？？
func (p *SimplePacketProcessor) IsContiansPort(port uint16) *Port {
	p.lockPortList.Lock()
	pport, ok := p.portList[port]
	if !ok {
		p.lockPortList.Unlock()
		return nil
	}
	p.lockPortList.Unlock()
	pport.Entry()
	defer pport.Leave()
	if pport.IsFinished || pport.State != PortState_Unknown {
		return nil
	}

	return pport
}

func (p *SimplePacketProcessor) HandleProcess() error {
	if p.handle == nil {
		return errors.New("please open the device.")
	}
	// p.Wg.Add(1)
	go func() {
		// defer wg.Done()
		packetSource := gopacket.NewPacketSource(p.handle, p.handle.LinkType()) // layers.LayerTypeEthernet
		packetSource.Lazy = true
		packetSource.NoCopy = false
		packetSource.DecodeStreamsAsDatagrams = true
		for {
			stream, err := packetSource.NextPacket()
			if err == io.EOF {
				return
			}
			//select {
			//case stream := <-packetSource.Packets():
			// 判断是否完成所有的端口扫描
			count := atomic.LoadInt32(&p.countOfFinished)
			if count == p.countOfPortList {
				return
			}

			// 判断扫描器状态
			scanState := atomic.LoadInt32(&p.ScanState)
			if scanState == ScannerState_Stop || scanState == ScannerState_Terminated {
				return
			}

			packet := stream
			if packet == nil {
				continue
			}

			go func() {
				// 判断是否完成所有的端口扫描
				count := atomic.LoadInt32(&p.countOfFinished)
				if count == p.countOfPortList {
					// 扫描完成直接返回
					// p.Close()
					return
				}

				scanState := atomic.LoadInt32(&p.ScanState)
				if scanState == ScannerState_Stop || scanState == ScannerState_Terminated {
					return
				}

				var iplayer gopacket.Layer
				// var ip net.IPAddr
				var srcIP net.IP
				var dstIP net.IP
				iplayer = packet.Layer(layers.LayerTypeIPv4)
				if iplayer == nil {
					iplayer = packet.Layer(layers.LayerTypeIPv6)
					if iplayer == nil {
						return
					}
					ip, ok := iplayer.(*layers.IPv6)
					if !ok {
						return
					}
					srcIP = ip.SrcIP
					dstIP = ip.DstIP
				} else {
					ip, ok := iplayer.(*layers.IPv4)
					if !ok {
						return
					}
					srcIP = ip.SrcIP
					dstIP = ip.DstIP
				}
				// 只直接目的地址为当前IP地址的数据
				if !(dstIP.Equal(p.sourceIP) && srcIP.Equal(p.dstIP)) {
					return
				}

				// 区分协议
				switch p.socketType {
				case rawsock.SocketType_STREAM:
					tcplayer := packet.Layer(layers.LayerTypeTCP)
					if tcplayer == nil {
						return
					}

					tcp, ok := tcplayer.(*layers.TCP)
					if !ok {
						return
					}

					var pCurrentPort *Port
					pCurrentPort = p.IsContiansPort(uint16(tcp.SrcPort))
					if pCurrentPort == nil || tcp.DstPort != layers.TCPPort(pCurrentPort.SrcPort) {
						return
					}

					atomic.AddInt32(&p.countOfFinished, 1)

					if tcp.SYN && tcp.ACK {
						pCurrentPort.Entry()
						pCurrentPort.State = PortState_Open
						pCurrentPort.IsFinished = true
						pCurrentPort.Leave()
					} else if tcp.RST && tcp.ACK {
						pCurrentPort.Entry()
						pCurrentPort.State = PortState_Closed
						pCurrentPort.IsFinished = true
						pCurrentPort.Leave()
					} else {
						pCurrentPort.Entry()
						pCurrentPort.State = PortState_Unknown
						pCurrentPort.IsFinished = true
						pCurrentPort.Leave()
					}

					// 这个地方也是判断是否完成了所有的端口扫描
					count = atomic.LoadInt32(&p.countOfFinished)
					if count == p.countOfPortList {
						// 扫描完成直接返回
						// p.Close()
						return
					}

					// 更新时间
					p.lock_latestTime.Lock()
					p.latestTime = time.Now()
					p.lock_latestTime.Unlock()

					if p.ResultCallback != nil {
						go p.ResultCallback(pCurrentPort)
					}

				case rawsock.SocketType_DGRAM:
					udplayer := packet.Layer(layers.LayerTypeUDP)
					if udplayer == nil {
						return
					}

					udp, ok := udplayer.(*layers.UDP)
					if !ok {
						return
					}

					if udp.DstPort != layers.UDPPort(p.sourcePort) {
						return
					}
				}
			}()
			//case <-p.Done:
			//	return
			//}
		}
	}()
	return nil
}

func (p *SimplePacketProcessor) GenerateTCPPackage(srcIP net.IP,
	srcMac net.HardwareAddr,
	dstIP net.IP,
	dstMac net.HardwareAddr,
	srcPort uint16,
	dstPort uint16,
	tcp_signal int,
	seq uint32,
	ack uint32,
	options []layers.TCPOption,
	payload []byte,
	isLoopback bool) ([]byte, error) {

	// eth layer
	ethernet := &layers.Ethernet{}
	ethernet.EthernetType = 0x800
	ethernet.DstMAC = dstMac
	ethernet.SrcMAC = srcMac

	// 判断ip类型
	if dstIP.To4() != nil && srcIP.To4() != nil {
		// ip layer
		ipv4 := &layers.IPv4{}
		ipv4.Version = 4
		ipv4.Protocol = layers.IPProtocolTCP
		ipv4.SrcIP = srcIP
		ipv4.DstIP = dstIP
		//ipv4.Length = 20
		ipv4.TTL = 255

		// tcp layer
		tcp := &layers.TCP{}
		tcp.SrcPort = layers.TCPPort(srcPort)
		tcp.DstPort = layers.TCPPort(dstPort)
		tcp.Window = 1024
		if tcp_signal&rawsock.TCP_SIGNAL_ACK > 0 {
			tcp.ACK = true
		}
		if tcp_signal&rawsock.TCP_SIGNAL_SYN > 0 {
			tcp.SYN = true
		}
		if tcp_signal&rawsock.TCP_SIGNAL_FIN > 0 {
			tcp.FIN = true
		}
		if tcp_signal&rawsock.TCP_SIGNAL_RST > 0 {
			tcp.RST = true
		}
		if tcp_signal&rawsock.TCP_SIGNAL_URG > 0 {
			tcp.URG = true
		}
		if tcp_signal&rawsock.TCP_SIGNAL_PSH > 0 {
			tcp.PSH = true
		}
		tcp.Seq = seq
		tcp.Ack = ack
		tcp.Options = append(tcp.Options, options...)
		tcp.SetNetworkLayerForChecksum(ipv4)

		// options
		opts := gopacket.SerializeOptions{}
		opts.ComputeChecksums = true
		opts.FixLengths = true

		buf := gopacket.NewSerializeBuffer()
		if p.scanEntity.Nexthops[0].IsLoopback {
			loopbackLayer := &layers.Loopback{}
			loopbackLayer.Family = layers.ProtocolFamilyIPv4
			err := gopacket.SerializeLayers(buf, opts, loopbackLayer, ipv4, tcp, gopacket.Payload(payload))
			if err != nil {
				return nil, err
			}
		} else {
			err := gopacket.SerializeLayers(buf, opts, ethernet, ipv4, tcp, gopacket.Payload(payload))
			if err != nil {
				return nil, err
			}
		}

		return buf.Bytes(), nil
	} else if dstIP.To16() != nil && srcIP.To16() != nil {
		// ip layer
		ipv6 := &layers.IPv6{}
		ipv6.Version = 4
		ipv6.NextHeader = layers.IPProtocolTCP
		ipv6.SrcIP = srcIP
		ipv6.DstIP = dstIP
		//ipv4.Length = 20
		ipv6.HopLimit = 255

		// tcp layer
		tcp := &layers.TCP{}
		tcp.SrcPort = layers.TCPPort(srcPort)
		tcp.DstPort = layers.TCPPort(dstPort)
		tcp.Window = 1024
		if tcp_signal&rawsock.TCP_SIGNAL_ACK > 0 {
			tcp.ACK = true
		}
		if tcp_signal&rawsock.TCP_SIGNAL_SYN > 0 {
			tcp.SYN = true
		}
		if tcp_signal&rawsock.TCP_SIGNAL_FIN > 0 {
			tcp.FIN = true
		}
		if tcp_signal&rawsock.TCP_SIGNAL_RST > 0 {
			tcp.RST = true
		}
		if tcp_signal&rawsock.TCP_SIGNAL_URG > 0 {
			tcp.URG = true
		}
		if tcp_signal&rawsock.TCP_SIGNAL_PSH > 0 {
			tcp.PSH = true
		}
		tcp.Seq = seq
		tcp.Ack = ack
		tcp.Options = append(tcp.Options, options...)
		tcp.SetNetworkLayerForChecksum(ipv6)

		// options
		opts := gopacket.SerializeOptions{}
		opts.ComputeChecksums = true
		opts.FixLengths = true

		buf := gopacket.NewSerializeBuffer()
		if p.scanEntity.Nexthops[0].IsLoopback {
			loopbackLayer := &layers.Loopback{}
			loopbackLayer.Family = layers.ProtocolFamilyIPv6Linux
			err := gopacket.SerializeLayers(buf, opts, loopbackLayer, ipv6, tcp, gopacket.Payload(payload))
			if err != nil {
				return nil, err
			}
		} else {
			err := gopacket.SerializeLayers(buf, opts, ethernet, ipv6, tcp, gopacket.Payload(payload))
			if err != nil {
				return nil, err
			}
		}

		return buf.Bytes(), nil
	}

	return nil, errors.New("ip error")
}

func (p *SimplePacketProcessor) sendSyn(port *Port) (bool, error) {
	var targetPort uint16
	port.Lock.Lock()
	if port.IsFinished == true {
		port.Lock.Unlock()
		return false, nil
	}

	port.AttmptNum++
	targetPort = port.Val
	port.STime = time.Now()
	port.Lock.Unlock()

	option_mss := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xb4},
	}

	options := make([]layers.TCPOption, 0)
	options = append(options, option_mss)

	// 根据当前的消息类型判断处理方式
	sendBuf, err := p.GenerateTCPPackage(p.sourceIP,
		p.sourceMAC,
		p.dstIP,
		p.nexthopMAC,
		port.SrcPort,
		targetPort,
		rawsock.TCP_SIGNAL_SYN,
		0,
		0,
		options,
		nil,
		false)
	if err != nil {
		log.Logger.Info("GenerateTCPPackage error")
		return false, err
	}

	device.SendBuf(p.handle, sendBuf)
	return true, nil
}

func (p *SimplePacketProcessor) splitePortlistForSend() [][]*Port {
	result := make([][]*Port, 0)

	tmpArray := make([]*Port, 0)
	for _, item := range p.portList {
		tmpArray = append(tmpArray, item)
	}

	var countarray int
	var countofperarray int

	if len(tmpArray) <= 5000 {
		countarray = 1
	} else if len(tmpArray) > 5000 && len(tmpArray) <= 10000 {
		// 分为2个组
		countarray = 3
	} else if len(tmpArray) > 10000 && len(tmpArray) <= 20000 {
		// 分为4组
		countarray = 5
	} else if len(tmpArray) > 20000 && len(tmpArray) <= 30000 {
		countarray = 7
	} else if len(tmpArray) > 30000 && len(tmpArray) <= 40000 {
		countarray = 9
	} else if len(tmpArray) > 40000 && len(tmpArray) <= 50000 {
		countarray = 11
	} else if len(tmpArray) > 50000 {
		countarray = 13
	}

	countofperarray = len(tmpArray) / countarray

	n := 1
	index := 0
	tmp := make([]*Port, 0)
	for {
		if index >= len(tmpArray) {
			break
		}
		tmp = append(tmp, tmpArray[index])
		index++
		if n < countarray {
			if index >= n*countofperarray {
				n++
				result = append(result, tmp)
				tmp = make([]*Port, 0)
				continue
			}
		} else if n == countarray {
			if index >= len(tmpArray) {
				result = append(result, tmp)
				break
			}
		}

	}

	return result
}

// 对端口扫描只扫描两次
func (p *SimplePacketProcessor) Do() error {
	defer p.Wg.Done()
	if len(p.portList) == 0 {
		return errors.New("not found scanned ports")
	}
	p.ScanState = ScannerState_Running //初始化扫描状态
	p.HandleProcess()                  // 增加监听
	count := 0
	for {
		//countOfFinished := atomic.LoadInt32(&p.countOfFinished)
		//if countOfFinished == p.countOfPortList {
		//	p.Close()
		//	break
		//}
		countofSended := 0
		var srcPort uint16 = 0
		if count == 1 {
			srcPort = uint16(rawsock.GeneratePort())
		} else if count > 1 {
			p.Close()
			break
		}
		for _, port := range p.portList {
			if count == 1 {
				port.SrcPort = srcPort
			}
			bret, _ := p.sendSyn(port)
			if bret {
				countofSended++
			}
		}

		// 一个都没有发送出去，说明已经完成
		// 那么直接退出发送程序
		if countofSended == 0 {
			p.Close()
			break
		}

		//
		beginTime := time.Now()
		for {
			var latestTime time.Time
			p.lock_latestTime.Lock()
			latestTime = p.latestTime
			p.lock_latestTime.Unlock()

			if latestTime.IsZero() {
				time.Sleep(2 * time.Millisecond)
				if time.Now().Sub(beginTime).Milliseconds() > 1000 {
					break
				}
				continue
			}

			if time.Now().Sub(latestTime).Milliseconds() > 1000 {
				if count == 1 {
					p.Close()
					return nil
				} else if count == 0 {
					break
				}
			} else { // 小于时间
				countOfFinished := atomic.LoadInt32(&p.countOfFinished)
				if countOfFinished == p.countOfPortList {
					p.Close()
					break
				} else {
					continue
				}
			}
		}
		count++
	}
	return nil
}

func (p *SimplePacketProcessor) Close() {
	atomic.StoreInt32(&p.ScanState, ScannerState_Stop)
	p.handle.Close()
	// p.Done <- struct{}{}
}

func (p *SimplePacketProcessor) Wait() {
	p.Wg.Wait()
}
