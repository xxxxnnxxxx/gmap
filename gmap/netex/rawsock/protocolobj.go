package rawsock

import (
	"Gmap/gmap/common"
	"Gmap/gmap/netex/device"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	IFObtainType_IP = iota
	IFObtainType_DeviceLnkName
)

const (
	PCAP_IF_LOOPBACK                         = 0x00000001 /* interface is loopback */
	PCAP_IF_UP                               = 0x00000002 /* interface is up */
	PCAP_IF_RUNNING                          = 0x00000004 /* interface is running */
	PCAP_IF_WIRELESS                         = 0x00000008 /* interface is wireless (*NOT* necessarily Wi-Fi!) */
	PCAP_IF_CONNECTION_STATUS                = 0x00000030 /* connection status: */
	PCAP_IF_CONNECTION_STATUS_UNKNOWN        = 0x00000000 /* unknown */
	PCAP_IF_CONNECTION_STATUS_CONNECTED      = 0x00000010 /* connected */
	PCAP_IF_CONNECTION_STATUS_DISCONNECTED   = 0x00000020 /* disconnected */
	PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE = 0x00000030 /* not applicable */
)

type AdapterInfo struct {
	Flag       uint32 // 接口类型
	MTU        int    // 最大传输单元
	IsLoopback bool
	DevName    string
	MAC        net.HardwareAddr
	Addrs      []device.IPAddress
}

type ProtocolObject struct {
	SocketType int // 数据类型
	DevHandle  *device.DeviceHandle
	Ifs        []pcap.Interface // 所有的接口信息
	AdapterInfo

	Wg      sync.WaitGroup
	timeout time.Duration
	//
	originSocket    *Socket // 初始化本地信息
	lock_SocketList sync.Mutex
	TCPSocketsList  map[string]*Socket // 保存所有的连接的socket
	UDPSocketsList  map[string]*Socket

	accpetStack *common.Stack
}

func NewProtocolObject(socketType int) *ProtocolObject {

	instance := &ProtocolObject{
		SocketType:     socketType,
		DevHandle:      device.NewDeviceHandle(),
		Ifs:            make([]pcap.Interface, 0),
		timeout:        2 * time.Second,
		originSocket:   nil,
		TCPSocketsList: make(map[string]*Socket),
		UDPSocketsList: make(map[string]*Socket),
		accpetStack:    common.NewStack(),
	}
	instance.AdapterInfo.Addrs = make([]device.IPAddress, 0)
	instance.AdapterInfo.MAC = make(net.HardwareAddr, 0)
	return instance
}

// connect and send
func (p *ProtocolObject) SetTimeout(timeout time.Duration) {
	p.timeout = timeout
}

// 参数说明
// iftype 获取接口的方式
// IFObtainType_IP  指定接口目前的IP,
// IFObtainType_DevlnkName 指定接口的lnk名称（windows下为符号连接)
// param 就是根据不同类型传递的不同数据
// pcap打开设备需要执行一个设备连接符号，这么做的目的是方便传递
// 没有直接指定MAC地址的原因是，不能直接获取到MAC地址
func (p *ProtocolObject) InitAdapter(iftype int, param string) error {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}
	p.Ifs = append(p.Ifs, ifs...)
	var deviceLnkName string
	var flag uint32
	IPs := make([]pcap.InterfaceAddress, 0)
	for _, item := range p.Ifs {
		switch iftype {
		case IFObtainType_IP:
			for _, ip := range item.Addresses {
				if ip.IP.String() == param {
					deviceLnkName = item.Name
					flag = item.Flags
					IPs = append(IPs, ip)
				}
			}
		case IFObtainType_DeviceLnkName:
			if item.Name == param {
				deviceLnkName = param
				flag = item.Flags
				IPs = append(IPs, item.Addresses...)
			}

		}
	}

	if len(deviceLnkName) == 0 {
		return errors.New("not found adapter")
	}

	if flag&PCAP_IF_UP == 0 {
		return errors.New("invailed adapter")
	}

	p.AdapterInfo.Flag = flag
	if flag&PCAP_IF_LOOPBACK > 0 {
		p.AdapterInfo.IsLoopback = true
	}

	for _, item := range IPs {
		var ipa device.IPAddress
		netipAddr, err := netip.ParseAddr(item.IP.String())
		if err != nil {
			continue
		}
		ipa.IP = netipAddr
		ipa.NetmaskBits, _ = item.Netmask.Size()
		p.AdapterInfo.Addrs = append(p.AdapterInfo.Addrs, ipa)
	}

	p.AdapterInfo.DevName = deviceLnkName

	// 打开设备
	if flag&PCAP_IF_LOOPBACK > 0 {
		p.DevHandle.IsLoopback = true
	} else {
		p.DevHandle.IsLoopback = false
	}

	err = p.DevHandle.Open(p.AdapterInfo.DevName)
	if err != nil {
		return err
	}
	// 获取mac地址
	// 获取设备的硬件地址（MAC 地址）
	// 获取链路层数据
	if p.DevHandle.IsLoopback == false {
		packetSource := gopacket.NewPacketSource(p.DevHandle.Handle, layers.LayerTypeEthernet)
		packetSource.Lazy = true
		packetSource.NoCopy = false
		packetSource.DecodeStreamsAsDatagrams = true
		for {
			stream, err := packetSource.NextPacket()
			if err == io.EOF {
				continue
			}
			packet := stream
			if packet == nil {
				continue
			}
			var iplayer gopacket.Layer
			// var ip net.IPAddr
			var srcIP net.IP
			var dstIP net.IP
			iplayer = packet.Layer(layers.LayerTypeIPv4)
			if iplayer == nil {
				iplayer = packet.Layer(layers.LayerTypeIPv6)
				if iplayer == nil {
					continue
				}
				ip, ok := iplayer.(*layers.IPv6)
				if !ok {
					continue
				}
				srcIP = ip.SrcIP
				dstIP = ip.DstIP
			} else {
				ip, ok := iplayer.(*layers.IPv4)
				if !ok {
					continue
				}
				srcIP = ip.SrcIP
				dstIP = ip.DstIP
			}

			var eth *layers.Ethernet
			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethLayer != nil {
				var ok bool
				eth, ok = ethLayer.(*layers.Ethernet)
				if !ok {
					continue
				}
			} else {
				continue
			}

			if dstIP.Equal(net.ParseIP(p.AdapterInfo.Addrs[0].IP.String())) {
				p.AdapterInfo.MAC = eth.DstMAC
				break
			} else if srcIP.Equal(net.ParseIP(p.AdapterInfo.Addrs[0].IP.String())) {
				p.AdapterInfo.MAC = eth.SrcMAC
				break
			}

		}
	} else { // 在回环的情况下，不需要特别获取MAC地址,因为栈帧不存在以太网层

	}

	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println(err)
	}
	for _, item := range interfaces {
		if strings.ToLower(item.HardwareAddr.String()) == strings.ToLower(p.AdapterInfo.MAC.String()) {
			p.AdapterInfo.MTU = item.MTU
			break
		}
	}

	if p.AdapterInfo.MTU == 0 {
		p.AdapterInfo.MTU = 1200
	}

	return nil
}

func (p *ProtocolObject) Bind(s *Socket) {
	p.originSocket = s
	p.SocketType = p.originSocket.SocketType
	p.originSocket.Handle = p.DevHandle
	p.originSocket.LocalIP = net.ParseIP(p.AdapterInfo.Addrs[0].IP.String())
	p.originSocket.LocalMAC = p.AdapterInfo.MAC //
	p.originSocket.SeqNum = generateRandowSeq()
}

func (p *ProtocolObject) Startup() error {
	if p.originSocket == nil {
		p.originSocket = NewSocket()
		p.originSocket.SocketType = p.SocketType
		p.originSocket.Handle = p.DevHandle
		p.originSocket.LocalIP = net.ParseIP(p.AdapterInfo.Addrs[0].IP.String())
		p.originSocket.LocalMAC = p.AdapterInfo.MAC //
		p.originSocket.SeqNum = generateRandowSeq()
		p.originSocket.LocalPort = uint16(GeneratePort())
	}

	// 启动消息循环，获取消息
	return p.msgLoop()
}

func (p *ProtocolObject) CloseDevice() {
	if p.DevHandle != nil {
		p.DevHandle.Close()
	}
}

func (p *ProtocolObject) CloseAllofSockets() {
	p.lock_SocketList.Lock()
	defer p.lock_SocketList.Unlock()

	if p.SocketType == SocketType_STREAM {
		for _, socket := range p.TCPSocketsList {
			p.Close(socket)
		}
	} else if p.SocketType == SocketType_DGRAM {
		for _, socket := range p.UDPSocketsList {
			p.Close(socket)
		}
	}

}

// 发送
func (p *ProtocolObject) sendBuffer(handle *device.DeviceHandle, bytes []byte) error {
	if handle == nil {
		return errors.New("the handle is empty")
	}

	if len(bytes) == 0 {
		return errors.New("the buffer is empty")
	}

	return device.SendBuf(handle.Handle, bytes)
}

// 得到分包个数
func (p *ProtocolObject) getCountOfSubPacketsForSend(s *Socket, signal int, sizeofpackets int) (int, int) {
	// default tcp
	options := make([]layers.TCPOption, 0)
	switch signal {
	case TCP_SIGNAL_SYN:
		option_mss := layers.TCPOption{
			OptionType:   layers.TCPOptionKindMSS,
			OptionLength: 4,
			OptionData:   []byte{0x05, 0xb4},
		}
		options = append(options, option_mss)
	default:
		option_nop := layers.TCPOption{
			OptionType: layers.TCPOptionKindNop,
		}

		option_nop2 := layers.TCPOption{
			OptionType: layers.TCPOptionKindNop,
		}
		options = append(options, option_nop, option_nop2)
	}

	if s.IsSupportTimestamp {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, s.TsEcho)
		option_timstamp := layers.TCPOption{
			OptionType:   layers.TCPOptionKindTimestamps,
			OptionLength: 10,
		}

		option_timstamp.OptionData = append(option_timstamp.OptionData, getCurrentTimestampBigEndian()...)
		option_timstamp.OptionData = append(option_timstamp.OptionData, buf...)

		options = append(options, option_timstamp)
	}
	// 根据当前的消息类型判断处理方式
	sendBuf, err := GenerateTCPPackage(s.LocalIP,
		s.LocalMAC,
		s.RemoteIP,
		s.Nexthop,
		s.LocalPort,
		s.RemotePort,
		signal,
		s.TCPSock.SeqNum,
		s.TCPSock.AckNum,
		options,
		nil,
		s.Handle.IsLoopback)
	if err != nil {
		return -1, 0
	}

	lenofHeader := len(sendBuf)

	countofprepacket := p.MTU - lenofHeader

	count := sizeofpackets / countofprepacket
	remainder := sizeofpackets % countofprepacket

	if remainder > 0 {
		return count + 1, countofprepacket
	} else {
		return count, countofprepacket
	}
}

// 返回的值为 seq 数据
// 为了后续可以根据数据确认回包的正确性
func (p *ProtocolObject) sendTCPPacket(s *Socket, payload []byte, signal int) (uint32, error) {
	if s.SocketType != SocketType_STREAM {
		return 0, errors.New("not a tcp")
	}

	options := make([]layers.TCPOption, 0)
	switch signal {
	case TCP_SIGNAL_SYN:
		option_mss := layers.TCPOption{
			OptionType:   layers.TCPOptionKindMSS,
			OptionLength: 4,
			OptionData:   []byte{0x05, 0xb4},
		}
		options = append(options, option_mss)
	default:
		option_nop := layers.TCPOption{
			OptionType: layers.TCPOptionKindNop,
		}

		option_nop2 := layers.TCPOption{
			OptionType: layers.TCPOptionKindNop,
		}
		options = append(options, option_nop, option_nop2)
	}

	if s.IsSupportTimestamp {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, s.TsEcho)
		option_timstamp := layers.TCPOption{
			OptionType:   layers.TCPOptionKindTimestamps,
			OptionLength: 10,
		}

		option_timstamp.OptionData = append(option_timstamp.OptionData, getCurrentTimestampBigEndian()...)
		option_timstamp.OptionData = append(option_timstamp.OptionData, buf...)

		options = append(options, option_timstamp)
	}
	// 根据当前的消息类型判断处理方式
	sendBuf, err := GenerateTCPPackage(s.LocalIP,
		s.LocalMAC,
		s.RemoteIP,
		s.Nexthop,
		s.LocalPort,
		s.RemotePort,
		signal,
		s.TCPSock.SeqNum,
		s.TCPSock.AckNum,
		options,
		payload,
		s.Handle.IsLoopback)
	if err != nil {
		return 0, err
	}

	err = p.sendBuffer(s.Handle, sendBuf)
	if err != nil {
		return 0, err
	}
	// 保存上一个信号
	s.PreSentSignal = signal
	//
	s.PreLenOfSent = uint32(len(payload))
	// 更新序号
	s.UpdateSeqNum()
	// 根据信号，改变套接字状态
	switch signal {
	case TCP_SIGNAL_SYN:
		if s.TCPSock.Status == TS_UNKNOWN {
			s.TCPSock.Status = TCP_SYN_SENT
		}
	case TCP_SIGNAL_SYN | TCP_SIGNAL_ACK:
		if s.TCPSock.Status == TS_UNKNOWN {
			s.TCPSock.Status = TCP_SYN_RECV
		}
	case TCP_SIGNAL_ACK:
		if s.TCPSock.Status == TCP_SYN_SENT {
			s.TCPSock.Status = TCP_ESTABLISHED
		} else if s.TCPSock.Status == TCP_FIN_WAIT2 {
			s.TCPSock.Status = TCP_TIME_WAIT
		} else if s.TCPSock.Status == TCP_FIN_WAIT1 {
			s.TCPSock.Status = TCP_FIN_WAIT2
		}
	case TCP_SIGNAL_FIN | TCP_SIGNAL_ACK:
		if s.TCPSock.Status == TCP_FIN_WAIT2 {
			s.TCPSock.Status = TCP_TIME_WAIT
		}
	case TCP_SIGNAL_FIN:
		// change status
		if s.TCPSock.Status == TCP_CLOSE_WAIT {
			s.TCPSock.Status = TCP_LAST_ACK
		} else if s.TCPSock.Status == TCP_ESTABLISHED {
			s.TCPSock.Status = TCP_FIN_WAIT1
		}
	}

	return s.SeqNum, err
}

func (p *ProtocolObject) sendUDPPacket(s *Socket, payload []byte) error {
	return nil
}

func (p *ProtocolObject) msgLoop() error {
	if p.DevHandle == nil {
		return errors.New("please open the device.")
	}

	p.Wg.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		packetSource := gopacket.NewPacketSource(p.DevHandle.Handle, p.DevHandle.Handle.LinkType())
		packetSource.Lazy = true
		packetSource.NoCopy = false
		packetSource.DecodeStreamsAsDatagrams = true
		for {
			stream, err := packetSource.NextPacket()
			if err == io.EOF {
				return
			}
			func() {
				packet := stream
				if packet == nil {
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

				acceptSock := NewSocket()
				acceptSock.Handle = p.DevHandle
				acceptSock.SocketType = p.SocketType
				switch p.SocketType {
				case SocketType_STREAM:
					tcplayer := packet.Layer(layers.LayerTypeTCP)
					if tcplayer == nil {
						return
					}

					tcp, ok := tcplayer.(*layers.TCP)
					if !ok {
						return
					}

					// 如果目的不是本地的端口和本地的IP则直接返回
					if uint16(tcp.DstPort) != p.originSocket.LocalPort || !dstIP.Equal(p.originSocket.LocalIP) {
						return
					}

					// 这个地方
					if p.originSocket.RemoteIP != nil && p.originSocket.RemotePort > 0 {
						if uint16(tcp.SrcPort) != p.originSocket.RemotePort && !dstIP.Equal(p.originSocket.RemoteIP) {
							return
						}
					}

					var loopback *layers.Loopback
					var eth *layers.Ethernet

					ethLayer := packet.Layer(layers.LayerTypeEthernet)
					if ethLayer != nil {
						eth, ok = ethLayer.(*layers.Ethernet)
						if !ok {
							return
						}
						acceptSock.Nexthop = append(acceptSock.Nexthop, eth.SrcMAC...)
					} else {
						loopbackLayer := packet.Layer(layers.LayerTypeLoopback)
						loopback, ok = loopbackLayer.(*layers.Loopback)
						if !ok {
							return
						}
						acceptSock.Handle.IsLoopback = true
						acceptSock.Family = loopback.Family
					}

					// 远端地址信息
					acceptSock.RemoteIP = append(acceptSock.RemoteIP, srcIP...)
					acceptSock.RemotePort = uint16(tcp.SrcPort)
					// 本地信息
					acceptSock.LocalIP = append(acceptSock.LocalIP, dstIP...)
					acceptSock.LocalPort = uint16(tcp.DstPort)

					// 如果是非回环的地址，则直接拷贝目的MAC地址到本地MAC地址
					if !acceptSock.Handle.IsLoopback {
						acceptSock.LocalMAC = append(acceptSock.LocalMAC, eth.DstMAC...)
					}

					// 序号
					acceptSock.TCPSock.RecvedAckNum = tcp.Ack
					acceptSock.TCPSock.RecvedSeqNum = tcp.Seq
					// 状态
					acceptSock.TCPSock.FIN = tcp.FIN
					acceptSock.TCPSock.ACK = tcp.ACK
					acceptSock.TCPSock.CWR = tcp.CWR
					acceptSock.TCPSock.ECE = tcp.ECE
					acceptSock.TCPSock.PSH = tcp.PSH
					acceptSock.TCPSock.SYN = tcp.SYN
					acceptSock.TCPSock.NS = tcp.NS
					acceptSock.TCPSock.URG = tcp.URG
					acceptSock.TCPSock.RST = tcp.RST

					acceptSock.Options = append(acceptSock.Options, tcp.Options...)
					acceptSock.LenOfRecved = uint32(len(tcp.Payload)) // 接收数据的长度
					acceptSock.RecvedPayload = append(acceptSock.RecvedPayload, tcp.Payload...)
				case SocketType_DGRAM:
					udplayer := packet.Layer(layers.LayerTypeUDP)
					if udplayer == nil {
						return
					}

					udp, ok := udplayer.(*layers.UDP)
					if !ok {
						return
					}

					if uint16(udp.DstPort) != p.originSocket.LocalPort && !dstIP.Equal(p.originSocket.LocalIP) {
						return
					}

					ethLayer := packet.Layer(layers.LayerTypeEthernet)
					var eth *layers.Ethernet
					if ethLayer != nil {
						eth, ok = ethLayer.(*layers.Ethernet)
					} else {
						loopbackLayer := packet.Layer(layers.LayerTypeLoopback)
						loopback, ok := loopbackLayer.(*layers.Loopback)
						if !ok {
							return
						}
						acceptSock.Handle.IsLoopback = true
						acceptSock.Family = loopback.Family
					}

					acceptSock.RemoteIP = append(acceptSock.RemoteIP, srcIP...)
					acceptSock.RemotePort = uint16(udp.SrcPort)
					acceptSock.LocalIP = append(acceptSock.LocalIP, dstIP...)
					acceptSock.LocalPort = uint16(udp.DstPort)
					acceptSock.LocalMAC = append(acceptSock.LocalMAC, eth.DstMAC...)

					acceptSock.RecvedPayload = append(acceptSock.RecvedPayload, udp.Payload...)
				}

				go p.protocolStackHandle(acceptSock)
			}()
		}
	}(&p.Wg)

	return nil
}

func (p *ProtocolObject) tcpsignalHandle(s *Socket, buf []byte) (int, error) {
	var tcp_signal int
	if s.SocketType == SocketType_STREAM {

		if s.TCPSock.SYN {
			tcp_signal |= TCP_SIGNAL_SYN
		}
		if s.TCPSock.RST {
			tcp_signal |= TCP_SIGNAL_RST
		}
		if s.TCPSock.ACK {
			tcp_signal |= TCP_SIGNAL_ACK
		}
		if s.TCPSock.FIN {
			tcp_signal |= TCP_SIGNAL_FIN
		}
		if s.TCPSock.URG {
			tcp_signal |= TCP_SIGNAL_URG
		}
		if s.TCPSock.PSH {
			tcp_signal |= TCP_SIGNAL_PSH
		}
	} else {
		return 0, errors.New("no info")
	}
	return tcp_signal, nil
}

func (p *ProtocolObject) protocolStackHandle(s *Socket) error {
	var pSock *Socket = nil
	if s.SocketType == SocketType_STREAM {
		// 处理信号
		var tcp_signal int
		if s.TCPSock.SYN {
			tcp_signal |= TCP_SIGNAL_SYN
		}
		if s.TCPSock.RST {
			tcp_signal |= TCP_SIGNAL_RST
		}
		if s.TCPSock.ACK {
			tcp_signal |= TCP_SIGNAL_ACK
		}
		if s.TCPSock.FIN {
			tcp_signal |= TCP_SIGNAL_FIN
		}
		if s.TCPSock.URG {
			tcp_signal |= TCP_SIGNAL_URG
		}
		if s.TCPSock.PSH {
			tcp_signal |= TCP_SIGNAL_PSH
		}

		sock, ok := p.IsInBufferSockets(s)
		if ok {
			sock.Lock.Lock()
			pSock = sock
			pSock.RecvedSeqNum = s.RecvedSeqNum
			pSock.RecvedAckNum = s.RecvedAckNum
			pSock.LenOfRecved = s.LenOfRecved
			pSock.RecvedPayload = append(pSock.RecvedPayload, s.RecvedPayload...)
			pSock.PreRecvedSignal = tcp_signal // 当前接收到的信号
			sock.Lock.Unlock()
		} else {
			if tcp_signal != TCP_SIGNAL_SYN {
				return errors.New("must be TPC_SIGNAL_SYN when the socket is not in the list")
			}
			pSock = p.originSocket.Clone()
			pSock.RecvedSeqNum = s.RecvedSeqNum
			pSock.RecvedAckNum = s.RecvedAckNum
			pSock.RemoteIP = s.RemoteIP
			pSock.RemotePort = s.RemotePort
			pSock.Nexthop = s.Nexthop
			pSock.LenOfRecved = s.LenOfRecved
			pSock.RecvedPayload = append(pSock.RecvedPayload, s.RecvedPayload...)
			pSock.PreRecvedSignal = tcp_signal // 当前接收到的信号
			p.Append(pSock)
		}

		pSock.Lock.Lock()
		defer pSock.Lock.Unlock()

		if pSock.PreRecvedSignal != TCP_SIGNAL_SYN {
			if pSock.SeqNum != pSock.RecvedAckNum {
				return errors.New("check ack error")
			}
		}

		pSock.UpdateAckNum()

		switch tcp_signal {
		case TCP_SIGNAL_SYN:
			if !ok {
				p.sendTCPPacket(pSock, nil, TCP_SIGNAL_ACK|TCP_SIGNAL_SYN)
			}
		case TCP_SIGNAL_SYN | TCP_SIGNAL_ACK:
			if ok {
				if pSock.TCPSock.Status == TCP_SYN_SENT {
					p.sendTCPPacket(pSock, nil, TCP_SIGNAL_ACK)
				}
			}
		case TCP_SIGNAL_FIN | TCP_SIGNAL_ACK: // 还有一种可能是附带数据的情况,比如fin|psh|ack, 所以在这个地方，需要处理数据
			if ok {
				if pSock.TCPSock.Status == TCP_ESTABLISHED {
					p.sendTCPPacket(pSock, nil, TCP_SIGNAL_ACK)
				}
			}
		case TCP_SIGNAL_FIN | TCP_SIGNAL_PSH | TCP_SIGNAL_ACK:
			if pSock.TCPSock.Status == TCP_ESTABLISHED {
				// 处理数据
				if len(pSock.RecvedPayload) > 0 {
					pSock.DataBuf.Write(s.RecvedPayload)
				}
				// 已经建立了连接
				p.sendTCPPacket(pSock, nil, TCP_SIGNAL_ACK)

				// 数据
			}
		case TCP_SIGNAL_PSH | TCP_SIGNAL_ACK:
			if ok {
				if pSock.TCPSock.Status == TCP_ESTABLISHED {
					// 处理数据
					if len(pSock.RecvedPayload) > 0 {
						pSock.DataBuf.Write(s.RecvedPayload)
					}
					// 已经建立了连接
					p.sendTCPPacket(pSock, nil, TCP_SIGNAL_ACK)
				}
			}
		case TCP_SIGNAL_ACK:
			if ok {
				if pSock.TCPSock.Status == TCP_SYN_RECV {
					// 已经发送的Syn+Ack
					pSock.TCPSock.Status = TCP_ESTABLISHED
					p.accpetStack.Push(pSock)
				} else if pSock.TCPSock.Status == TCP_ESTABLISHED {
					// 已经建立连接，则可能接收到数据
					pSock.DataBuf.Write(s.RecvedPayload)
				} else if pSock.TCPSock.Status == TCP_FIN_WAIT1 {
					pSock.TCPSock.Status = TCP_FIN_WAIT2
				} else if pSock.TCPSock.Status == TCP_FIN_WAIT2 {
					pSock.TCPSock.Status = TCP_TIME_WAIT
					// 启动定时器
					TimerCall(0, 2*MSL, func() {
						if pSock.Status == TCP_TIME_WAIT {
							return
						} else if pSock.Status == TCP_FIN_WAIT2 {
							pSock.Status = TCP_CLOSE
						}
					})
				} else if pSock.TCPSock.Status == TCP_TIME_WAIT {
					pSock.TCPSock.Status = TCP_CLOSE
				} else if pSock.TCPSock.Status == TCP_LAST_ACK {
					pSock.TCPSock.Status = TCP_CLOSE
				}
			}

		case TCP_SIGNAL_FIN:
			if ok {
				if pSock.TCPSock.Status == TCP_ESTABLISHED {
					p.sendTCPPacket(pSock, nil, TCP_SIGNAL_ACK)
				}
			}
		}

		// 更新acknum
		pSock.UpdateAckNum()

		// 触发通知回调
		if pSock != nil {
			isNotify := pSock.IsTriggerNotify.Load()
			if pSock.NotifyCallback != nil && isNotify {
				pSock.NotifyCallback()
			}
		}
	} else if pSock.SocketType == SocketType_DGRAM {

	}

	return nil
}

func (p *ProtocolObject) Append(s *Socket) {
	flag := fmt.Sprintf("%v:%v", s.RemoteIP.String(), s.RemotePort)
	p.lock_SocketList.Lock()
	if p.SocketType == SocketType_STREAM {
		p.TCPSocketsList[flag] = s
	} else if p.SocketType == SocketType_DGRAM {
		p.TCPSocketsList[flag] = s
	}
	p.lock_SocketList.Unlock()
}

func (p *ProtocolObject) RemoveSockFromList(s *Socket) {
	flag := fmt.Sprintf("%v:%v", s.RemoteIP.String(), s.RemotePort)
	p.lock_SocketList.Lock()
	if p.SocketType == SocketType_STREAM {
		p.TCPSocketsList[flag] = nil
	} else if p.SocketType == SocketType_DGRAM {
		p.UDPSocketsList[flag] = nil
	}
	p.lock_SocketList.Unlock()
}

func (p *ProtocolObject) IsInBufferSockets(s *Socket) (*Socket, bool) {
	flag := fmt.Sprintf("%v:%v", s.RemoteIP.String(), s.RemotePort)
	ret, ok := p.TCPSocketsList[flag]
	if ok {
		return ret, true
	}
	return nil, false
}

func (p *ProtocolObject) Wait() {
	p.Wg.Wait()
}

// socket 功能模拟
// -----------------

func (p *ProtocolObject) Connect(targetIP net.IP, targetPort uint16, nexthopMAC net.HardwareAddr) (*Socket, error) {
	if p.originSocket == nil {
		return nil, errors.New("not bind socket")
	}

	if p.SocketType != SocketType_STREAM {
		return nil, errors.New("not TCP_STREAM")
	}
	wg := new(sync.WaitGroup)
	wg.Add(1)
	ret := -1
	p.originSocket.Lock.Lock()
	p.originSocket.RemoteIP = targetIP
	p.originSocket.RemotePort = targetPort
	p.originSocket.Nexthop = append(p.originSocket.Nexthop, nexthopMAC...)
	p.originSocket.IsTriggerNotify.Store(true)
	p.originSocket.NotifyCallback = func() {
		isNotifiy := p.originSocket.IsTriggerNotify.Load()
		if p.originSocket.Status == TCP_ESTABLISHED && isNotifiy {
			p.originSocket.IsTriggerNotify.Store(false)
			ret = 1
			wg.Done()
		}
	}
	p.originSocket.Lock.Unlock()

	// 压入列表
	p.lock_SocketList.Lock()
	flag := fmt.Sprintf("%v:%v", p.originSocket.RemoteIP.String(), p.originSocket.RemotePort)
	p.TCPSocketsList[flag] = p.originSocket
	p.lock_SocketList.Unlock()
	// 设置
	p.originSocket.Lock.Lock()
	_, err := p.sendTCPPacket(p.originSocket, nil, TCP_SIGNAL_SYN)
	if err != nil {
		return nil, err
	}
	p.originSocket.TCPSock.Status = TCP_SYN_SENT
	p.originSocket.Lock.Unlock()
	common.WaitTimeout(wg, p.timeout)
	if ret == -1 {
		return nil, errors.New("time out")
	}

	return p.originSocket, nil
}

func (p *ProtocolObject) Accept() (*Socket, error) {
	var result *Socket = nil

	for {
		entity := p.accpetStack.Pop()
		if entity != nil {
			if acceptSocket, ok := entity.(*Socket); ok {
				result = acceptSocket
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	return result, nil
}

func (p *ProtocolObject) Recv(s *Socket, result *[]byte) int {
	if result == nil {
		return -1
	}
	lenofresult := 0
	for {
		if s.SocketType == SocketType_STREAM {
			if s.TCPSock.Status == TCP_CLOSE {
				break
			}
			if s.DataBuf.Length() > 0 {
				*result, lenofresult = s.DataBuf.Read()
				break
			}
		} else if s.SocketType == SocketType_DGRAM {

		}

		runtime.Gosched()
	}
	return lenofresult
}

func (p *ProtocolObject) Send(s *Socket, payload []byte) int {
	if s == nil || len(payload) == 0 {
		return -1
	}
	if s.SocketType == SocketType_STREAM && s.TCPSock.Status == TCP_ESTABLISHED {
		count, countofprepacket := p.getCountOfSubPacketsForSend(s, len(payload), TCP_SIGNAL_PSH|TCP_SIGNAL_ACK)
		i := 0
		for {
			if i >= count {
				break
			}
			ret := -1
			wg := new(sync.WaitGroup)
			wg.Add(1)
			var pSeqnum *uint32
			buf := make([]byte, 0)
			if len(payload)-i*countofprepacket < countofprepacket {
				buf = append(buf, payload[i*countofprepacket:]...)
			} else {
				buf = append(buf, payload[i*countofprepacket:i*countofprepacket+countofprepacket]...)
			}

			s.Lock.Lock()
			s.IsTriggerNotify.Store(true)
			s.NotifyCallback = func() {
				isNotify := s.IsTriggerNotify.Load()
				if s.PreSentSignal == TCP_SIGNAL_PSH|TCP_SIGNAL_ACK &&
					s.PreRecvedSignal == TCP_SIGNAL_ACK && isNotify &&
					s.SeqNum == *pSeqnum {
					if s.SeqNum == s.RecvedAckNum {
						ret = len(payload)
						wg.Done()
					}
					s.IsTriggerNotify.Store(false)
				}
			}
			s.Lock.Unlock()
			seqnum, err := p.sendTCPPacket(s, payload, TCP_SIGNAL_PSH|TCP_SIGNAL_ACK)
			if err != nil {
				s.SetLastError(err)
				return -1
			}
			pSeqnum = &seqnum

			common.WaitTimeout(wg, p.timeout)

			if ret == len(payload) {
				s.SetLastError(nil)
			} else if ret <= 0 {
				s.SetLastError(errors.New("send data failed"))
				return ret
			}
		}

	} else if s.SocketType == SocketType_DGRAM {
		p.Sendto(s, payload)
	}

	return -1
}

func (p *ProtocolObject) Sendto(s *Socket, payload []byte) error {
	return nil
}

func (p *ProtocolObject) Close(s *Socket) int {
	p.sendTCPPacket(s, nil, TCP_SIGNAL_FIN|TCP_SIGNAL_ACK)
	return -1
}
