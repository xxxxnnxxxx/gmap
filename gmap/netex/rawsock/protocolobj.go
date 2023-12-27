package rawsock

import (
	"Gmap/gmap/log"
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
	"sync"
	"time"
)

const (
	IFObtainType_IP = iota
	IFObtainType_DeviceLnkName
)

const (
	// InterfaceFlagUp 表示接口是启用的。
	InterfaceFlagUp uint32 = 1 << iota
	// InterfaceFlagBroadcast 表示接口支持广播。
	InterfaceFlagBroadcast
	// InterfaceFlagLoopback 表示接口是回环接口。
	InterfaceFlagLoopback
	// InterfaceFlagPointToPoint 表示接口是点对点连接。
	InterfaceFlagPointToPoint
	// InterfaceFlagMulticast 表示接口支持多播。
	InterfaceFlagMulticast
)

type ProtocolObject struct {
	DevHandle  *device.DeviceHandle
	Ifs        []pcap.Interface      // 所有的接口信息
	II         *device.InterfaceInfo // 网络接口信息
	SocketType int                   // 数据类型

	Wg         sync.WaitGroup
	Timeout    time.Duration // 设置监听时间 Listen的时间
	Done       chan struct{}
	Callback   func(*Socket, []byte) error // 数据回调
	IsAsServer bool                        // 是否作为服务

	//
	OriginSocket *Socket // 初始化本地信息

	lock_SocketList sync.Mutex
	TCPSocketsList  map[string]*Socket // 保存所有的连接的socket
	UDPSocketsList  map[string]*Socket

	AcceptSocket  chan *Socket
	msg           chan int
	deviceLnkName string
}

func NewProtocolObjectByLnkName(socketType int) *ProtocolObject {

	instance := &ProtocolObject{
		SocketType:     socketType,
		DevHandle:      device.NewDeviceHandle(),
		Ifs:            make([]pcap.Interface, 0),
		Done:           make(chan struct{}),
		OriginSocket:   nil,
		AcceptSocket:   make(chan *Socket),
		TCPSocketsList: make(map[string]*Socket),
		UDPSocketsList: make(map[string]*Socket),
		msg:            make(chan int),
	}

	return instance
}

// 枚举所有的接口信息
func (p *ProtocolObject) enumAllofInterfaces() error {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}
	p.Ifs = append(p.Ifs, ifs...)
	return nil
}

// 参数说明
// iftype 获取接口的方式
// IFObtainType_IP  指定接口目前的IP,
// IFObtainType_DevlnkName 指定接口的lnk名称（windows下为符号连接)
// param 就是根据不同类型传递的不同数据
// pcap打开设备需要执行一个设备连接符号，这么做的目的是方便传递
// 没有直接指定MAC地址的原因是，不能直接获取到MAC地址
func (p *ProtocolObject) InitAdapter(iftype int, param string) error {
	err := p.enumAllofInterfaces()
	if err != nil {
		return err
	}
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
			}

		}
	}

	if len(deviceLnkName) == 0 {
		return errors.New("not found adapter")
	}

	if flag&InterfaceFlagUp == 0 {
		return errors.New("invailed adapter")
	}

	// 填充当前接口信息
	if p.II == nil {
		p.II = device.NewInterfaceInfo()
	}

	if flag&InterfaceFlagLoopback > 0 {
		p.II.IfType |= device.IF_TYPE_SOFTWARE_LOOPBACK
	}

	if flag&InterfaceFlagUp > 0 {
		p.II.OperStatus = 1 // up state
	}

	for _, item := range IPs {
		var ipa device.IPAddress
		netipAddr, err := netip.ParseAddr(item.IP.String())
		if err != nil {
			continue
		}
		ipa.IP = netipAddr
		ipa.NetmaskBits, _ = item.Netmask.Size()
		p.II.Addrs = append(p.II.Addrs, ipa)
	}

	p.II.DevLinkSymbol = deviceLnkName

	// 打开设备
	if flag&InterfaceFlagLoopback > 0 {
		p.DevHandle.IsLoopback = true
	} else {
		p.DevHandle.IsLoopback = false
	}

	err = p.DevHandle.Open(p.deviceLnkName)
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
		packet, err := packetSource.NextPacket()
		if err != nil {
			return err
		}
		// 从数据包中获取源 MAC 地址
		macLayer := packet.LinkLayer()
		if macLayer == nil {
			p.DevHandle.Handle.Close()
			return errors.New("obtain mac address failed")
		}
	} else { // 在回环的情况下，不需要特别获取MAC地址,因为栈帧不存在以太网层

	}

	return nil
}

func (p *ProtocolObject) InitOriginSocket(port uint16) {
	p.OriginSocket = NewSocket()
	p.OriginSocket.SocketType = p.SocketType
	p.OriginSocket.Handle = p.DevHandle
	p.OriginSocket.Nexthop = p.II.MAC
	if port == 0 {
		p.OriginSocket.LocalIP = net.ParseIP(p.II.Addrs[0].IP.String())
		p.OriginSocket.LocalPort = uint16(GeneratePort())
	}
}

func (p *ProtocolObject) Startup() error {
	if p.OriginSocket == nil {
		return errors.New("not initialize originsocket")
	}

	// 启动消息循环，获取消息
	return p.recvLoopback()
}

func (p *ProtocolObject) CloseDevice() {
	if p.DevHandle != nil {
		p.DevHandle.Close()
	}
}

func (p *ProtocolObject) CloseAllOfConnectedTCPSocket() {
	for _, socket := range p.TCPSocketsList {
		p.Close(socket, nil)
	}
}

func (p *ProtocolObject) SetCallback(f func(*Socket, []byte) error) {
	p.Callback = f
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

func (p *ProtocolObject) recvLoopback() error {
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
			packet := stream
			if packet == nil {
				continue
			}
			go func() {
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
					if uint16(tcp.DstPort) != p.OriginSocket.LocalPort && !dstIP.Equal(p.OriginSocket.LocalIP) {
						return
					}

					// 分配socket信息
					acceptSock.SetSocketType(p.SocketType)
					//
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
					acceptSock.TCPSock.Ack = tcp.Ack
					acceptSock.TCPSock.Seq = tcp.Seq
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
					acceptSock.Payload = append(acceptSock.Payload, tcp.Payload...)
				case SocketType_DGRAM:
					udplayer := packet.Layer(layers.LayerTypeUDP)
					if udplayer == nil {
						return
					}

					udp, ok := udplayer.(*layers.UDP)
					if !ok {
						return
					}

					if uint16(udp.DstPort) != p.OriginSocket.LocalPort && !dstIP.Equal(p.OriginSocket.LocalIP) {
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

					acceptSock.Payload = append(acceptSock.Payload, udp.Payload...)
				}

				// 临时测试，实际应用会转发消息到目的程序
				if p.Callback != nil {
					go p.Callback(acceptSock, nil)
				} else {
					go p.protocolStackHandle(acceptSock)
				}
			}()
		}
	}(&p.Wg)

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

func (p *ProtocolObject) IsInAcceptSockets(s *Socket) (*Socket, bool) {
	flag := fmt.Sprintf("%v:%v", s.RemoteIP.String(), s.RemotePort)
	ret, ok := p.TCPSocketsList[flag]
	if ok {
		return ret, true
	}
	return nil, false
}

// 发起连接
func (p *ProtocolObject) SendSyn(s *Socket, payload []byte) error {
	option_mss := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0x04},
	}

	option_scale := layers.TCPOption{
		OptionType:   layers.TCPOptionKindWindowScale,
		OptionLength: 3,
		OptionData:   []byte{0x08},
	}

	option_nop := layers.TCPOption{
		OptionType: layers.TCPOptionKindNop,
	}

	option_sack_permitted := layers.TCPOption{
		OptionType:   layers.TCPOptionKindSACKPermitted,
		OptionLength: 2,
	}

	options := make([]layers.TCPOption, 0)
	options = append(options, option_mss, option_scale, option_nop, option_sack_permitted)

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
		TCP_SIGNAL_SYN,
		s.TCPSock.Ack,
		s.TCPSock.Seq+1,
		options,
		payload,
		s.Handle.IsLoopback)
	if err != nil {
		log.Logger.Info("GenerateTCPPackage error")
		return err
	}

	err = p.sendBuffer(s.Handle, sendBuf)
	return err
}

// 连接反馈
func (p *ProtocolObject) SendSynAck(s *Socket, payload []byte) error {

	option_mss := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0x04},
	}

	option_scale := layers.TCPOption{
		OptionType:   layers.TCPOptionKindWindowScale,
		OptionLength: 3,
		OptionData:   []byte{0x08},
	}

	option_nop := layers.TCPOption{
		OptionType: layers.TCPOptionKindNop,
	}

	option_sack_permitted := layers.TCPOption{
		OptionType:   layers.TCPOptionKindSACKPermitted,
		OptionLength: 2,
	}

	options := make([]layers.TCPOption, 0)
	options = append(options, option_mss, option_scale, option_nop, option_sack_permitted)

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
		TCP_SIGNAL_ACK|TCP_SIGNAL_SYN,
		s.TCPSock.Ack,
		s.TCPSock.Seq+1,
		options,
		payload,
		s.Handle.IsLoopback)
	if err != nil {
		log.Logger.Info("GenerateTCPPackage error")
		return err
	}

	err = p.sendBuffer(s.Handle, sendBuf)
	return err
}

func (p *ProtocolObject) Sendto(s *Socket, payload []byte) error {
	return nil
}

func (p *ProtocolObject) SendAck(s *Socket, payload []byte) error {

	option_nop := layers.TCPOption{
		OptionType: layers.TCPOptionKindNop,
	}

	option_nop2 := layers.TCPOption{
		OptionType: layers.TCPOptionKindNop,
	}

	options := make([]layers.TCPOption, 0)
	options = append(options, option_nop, option_nop2)

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
		TCP_SIGNAL_ACK,
		s.TCPSock.Ack,
		s.TCPSock.Seq+1,
		options,
		payload,
		s.Handle.IsLoopback)
	if err != nil {
		return err
	}

	err = p.sendBuffer(s.Handle, sendBuf)
	return err
}

func (p *ProtocolObject) SendPshAck(acceptSock *Socket, payload []byte) error {

	option_nop := layers.TCPOption{
		OptionType: layers.TCPOptionKindNop,
	}

	option_nop2 := layers.TCPOption{
		OptionType: layers.TCPOptionKindNop,
	}

	options := make([]layers.TCPOption, 0)
	options = append(options, option_nop, option_nop2)

	if acceptSock.IsSupportTimestamp {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, acceptSock.TsEcho)
		option_timstamp := layers.TCPOption{
			OptionType:   layers.TCPOptionKindTimestamps,
			OptionLength: 10,
		}

		option_timstamp.OptionData = append(option_timstamp.OptionData, getCurrentTimestampBigEndian()...)
		option_timstamp.OptionData = append(option_timstamp.OptionData, buf...)

		options = append(options, option_timstamp)
	}
	// 根据当前的消息类型判断处理方式
	sendBuf, err := GenerateTCPPackage(acceptSock.LocalIP,
		acceptSock.LocalMAC,
		acceptSock.RemoteIP,
		acceptSock.Nexthop,
		acceptSock.LocalPort,
		acceptSock.RemotePort,
		TCP_SIGNAL_ACK|TCP_SIGNAL_PSH,
		acceptSock.TCPSock.Ack,
		acceptSock.TCPSock.Seq+1,
		options,
		payload,
		acceptSock.Handle.IsLoopback)
	if err != nil {
		return err
	}

	p.sendBuffer(acceptSock.Handle, sendBuf)
	return nil
}

func (p *ProtocolObject) SendFinAck(s *Socket, payload []byte) error {
	option_nop := layers.TCPOption{
		OptionType: layers.TCPOptionKindNop,
	}

	option_nop2 := layers.TCPOption{
		OptionType: layers.TCPOptionKindNop,
	}

	options := make([]layers.TCPOption, 0)
	options = append(options, option_nop, option_nop2)

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
		TCP_SIGNAL_ACK|TCP_SIGNAL_FIN,
		s.TCPSock.Ack,
		s.TCPSock.Seq+1,
		options,
		payload,
		s.Handle.IsLoopback)
	if err != nil {
		return err
	}

	// change status
	if s.TCPSock.Status == TCP_CLOSE_WAIT {
		s.TCPSock.Status = TCP_LAST_ACK
	} else if s.TCPSock.Status == TCP_ESTABLISHED {
		s.TCPSock.Status = TCP_FIN_WAIT1
	}

	err = p.sendBuffer(s.Handle, sendBuf)
	return err
}

func (p *ProtocolObject) tcpsignalHandle(acceptSock *Socket, buf []byte) (int, error) {
	var tcp_signal int
	if acceptSock.SocketType == SocketType_STREAM {

		if acceptSock.TCPSock.SYN {
			tcp_signal |= TCP_SIGNAL_SYN
		}
		if acceptSock.TCPSock.RST {
			tcp_signal |= TCP_SIGNAL_RST
		}
		if acceptSock.TCPSock.ACK {
			tcp_signal |= TCP_SIGNAL_ACK
		}
		if acceptSock.TCPSock.FIN {
			tcp_signal |= TCP_SIGNAL_FIN
		}
		if acceptSock.TCPSock.URG {
			tcp_signal |= TCP_SIGNAL_URG
		}
		if acceptSock.TCPSock.PSH {
			tcp_signal |= TCP_SIGNAL_PSH
		}
	} else {
		return 0, errors.New("no info")
	}
	return tcp_signal, nil
}

func (p *ProtocolObject) protocolStackHandle(acceptSock *Socket) error {
	if acceptSock.SocketType == SocketType_STREAM {
		// 处理信号
		var tcp_signal int
		if acceptSock.TCPSock.SYN {
			tcp_signal |= TCP_SIGNAL_SYN
		}
		if acceptSock.TCPSock.RST {
			tcp_signal |= TCP_SIGNAL_RST
		}
		if acceptSock.TCPSock.ACK {
			tcp_signal |= TCP_SIGNAL_ACK
		}
		if acceptSock.TCPSock.FIN {
			tcp_signal |= TCP_SIGNAL_FIN
		}
		if acceptSock.TCPSock.URG {
			tcp_signal |= TCP_SIGNAL_URG
		}
		if acceptSock.TCPSock.PSH {
			tcp_signal |= TCP_SIGNAL_PSH
		}

		switch tcp_signal {
		case TCP_SIGNAL_SYN:
			_, ok := p.IsInAcceptSockets(acceptSock)
			if !ok {
				p.Append(acceptSock)
				p.SendSynAck(acceptSock, nil)
				acceptSock.TCPSock.Status = TCP_SYN_RECV
			}
		case TCP_SIGNAL_SYN | TCP_SIGNAL_ACK:
			_, ok := p.IsInAcceptSockets(acceptSock)
			if !ok {
				//if p.IsInOrigin(acceptSock.RemoteIP, acceptSock.RemotePort) {
				//	p.Append(acceptSock)
				//	p.SendAck(acceptSock, nil)
				//	acceptSock.TCPSock.Status = TCP_ESTABLISHED
				//}
			}
		case TCP_SIGNAL_FIN | TCP_SIGNAL_ACK:
			sock, ok := p.IsInAcceptSockets(acceptSock)
			if ok {
				if sock.IsSupportTimestamp {
					sock.TsEcho = acceptSock.GetTsEcho() // bigendian
				}
				if sock.TCPSock.Status == TCP_ESTABLISHED {
					sock.TCPSock.Status = TCP_CLOSE_WAIT
					p.SendAck(sock, nil)
				}
			}
			p.SendAck(acceptSock, nil)
		case TCP_SIGNAL_PSH | TCP_SIGNAL_ACK:
			sock, ok := p.IsInAcceptSockets(acceptSock)
			if ok {
				if sock.TCPSock.Status == TCP_ESTABLISHED {
					// 处理数据
					if len(acceptSock.Payload) > 0 {
						sock.databuf.Write(acceptSock.Payload, len(acceptSock.Payload))
						sock.msg <- SocketMsg_RecvData
					}
					// 已经建立了连接
					p.SendAck(sock, nil)
					// 数据

				}
			}
			// p.SendAck(acceptSock, nil)
		case TCP_SIGNAL_ACK:
			//
			sock, ok := p.IsInAcceptSockets(acceptSock)
			if ok {
				if sock.TCPSock.Status == TCP_SYN_RECV {
					// 已经发送的Syn+Ack
					sock.TCPSock.Status = TCP_ESTABLISHED
					p.AcceptSocket <- sock
				} else if sock.TCPSock.Status == TCP_ESTABLISHED {
					// 已经建立连接，则可能接收到数据
					sock.databuf.Write(acceptSock.Payload, len(acceptSock.Payload))
					sock.msg <- SocketMsg_RecvData
				} else if sock.TCPSock.Status == TCP_FIN_WAIT1 {
					sock.TCPSock.Status = TCP_FIN_WAIT2
				} else if sock.TCPSock.Status == TCP_FIN_WAIT2 {
					sock.TCPSock.Status = TCP_TIME_WAIT
					// 启动定时器
					TimerCall(0, 2*MSL, func() {
						if acceptSock.Status == TCP_TIME_WAIT {
							return
						} else if acceptSock.Status == TCP_FIN_WAIT2 {
							acceptSock.Status = TCP_CLOSE
						}
					})
				} else if sock.TCPSock.Status == TCP_TIME_WAIT {
					sock.TCPSock.Status = TCP_CLOSE
				} else if sock.TCPSock.Status == TCP_LAST_ACK {
					sock.TCPSock.Status = TCP_CLOSE
				}
			}
		}
	} else if acceptSock.SocketType == SocketType_DGRAM {
		if len(acceptSock.Payload) > 0 {
			go func() {
				p.AcceptSocket <- acceptSock
			}()
		}
	}

	return nil
}

func (p *ProtocolObject) Wait() {
	p.Wg.Wait()
}

// socket 功能模拟
// -----------------

func (p *ProtocolObject) Connect(targetIP net.IP, targetPort uint16, nexthopMAC net.HardwareAddr) (*Socket, error) {
	if p.SocketType != SocketType_STREAM {
		return nil, errors.New("not TCP_STREAM")
	}
	p.OriginSocket.Lock.Lock()
	p.OriginSocket.RemoteIP = targetIP
	p.OriginSocket.RemotePort = targetPort
	p.OriginSocket.Nexthop = append(p.OriginSocket.Nexthop, nexthopMAC...)
	p.OriginSocket.Lock.Unlock()

	// 压入列表
	p.lock_SocketList.Lock()
	flag := fmt.Sprintf("%v:%v", p.OriginSocket.RemoteIP.String(), p.OriginSocket.RemotePort)
	p.TCPSocketsList[flag] = p.OriginSocket
	p.lock_SocketList.Unlock()
	// 设置

	err := p.SendSyn(p.OriginSocket, nil)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (p *ProtocolObject) Accept() (*Socket, error) {
	var result *Socket = nil
	select {
	case sock := <-p.AcceptSocket:
		result = sock
	case msg := <-p.msg:
		switch msg {
		case SocketMsg_Closed:
			return nil, errors.New("the socket is closed")
		}
	}

	return result, nil
}

func (p *ProtocolObject) Recv(s *Socket, result *[]byte) int {
	if result == nil {
		return -1
	}
loop:
	select {
	case msg := <-s.msg:
		switch msg {
		case SocketMsg_RecvData:
			*result = append(*result, s.Payload...)
			break loop
		case SocketMsg_Closed:
			return 0
		}
	}
	return len(*result)
}

func (p *ProtocolObject) Send(s *Socket, payload []byte) int {
	if s == nil {
		return -1
	}

	if s.SocketType == SocketType_STREAM && s.TCPSock.Status == TCP_ESTABLISHED {
		p.SendPshAck(s, payload)
	} else if s.SocketType == SocketType_DGRAM {
		p.Sendto(s, payload)
	}
	return -1
}

func (p *ProtocolObject) Close(s *Socket, payload []byte) int {
	p.SendFinAck(s, payload)
	p.RemoveSockFromList(s)
	return -1
}
