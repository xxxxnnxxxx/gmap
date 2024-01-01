package rawsock

import (
	"Gmap/gmap/common"
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

	Wg         sync.WaitGroup
	Timeout    time.Duration // 设置监听时间 Listen的时间
	Done       chan struct{}
	Callback   func(*Socket, []byte) error // 数据回调
	IsAsServer bool                        // 是否作为服务

	//
	originSocket *Socket // 初始化本地信息

	lock_SocketList sync.Mutex
	TCPSocketsList  map[string]*Socket // 保存所有的连接的socket
	UDPSocketsList  map[string]*Socket

	accpetStack *common.Stack
}

func NewProtocolObjectByLnkName(socketType int) *ProtocolObject {

	instance := &ProtocolObject{
		SocketType:     socketType,
		DevHandle:      device.NewDeviceHandle(),
		Ifs:            make([]pcap.Interface, 0),
		Done:           make(chan struct{}),
		originSocket:   nil,
		TCPSocketsList: make(map[string]*Socket),
		UDPSocketsList: make(map[string]*Socket),
		accpetStack:    common.NewStack(),
	}
	instance.AdapterInfo.Addrs = make([]device.IPAddress, 0)
	instance.AdapterInfo.MAC = make(net.HardwareAddr, 0)
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

		fmt.Println(p.AdapterInfo.MAC.String())

	} else { // 在回环的情况下，不需要特别获取MAC地址,因为栈帧不存在以太网层

	}

	return nil
}

func (p *ProtocolObject) BindSocket(port uint16) {
	p.originSocket = NewSocket()
	p.originSocket.SocketType = p.SocketType
	p.originSocket.Handle = p.DevHandle
	p.originSocket.LocalIP = net.ParseIP(p.AdapterInfo.Addrs[0].IP.String())
	p.originSocket.LocalMAC = p.AdapterInfo.MAC // 赋值原视频
	if port == 0 {
		p.originSocket.LocalPort = uint16(GeneratePort())
	} else {
		p.originSocket.LocalPort = port
	}
}

func (p *ProtocolObject) Startup() error {
	if p.originSocket == nil {
		return errors.New("not initialize originsocket")
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
					if uint16(tcp.DstPort) != p.originSocket.LocalPort && !dstIP.Equal(p.originSocket.LocalIP) {
						return
					}

					// 这个地方
					p.originSocket.Lock.Lock()
					if p.originSocket.RemoteIP != nil && p.originSocket.RemotePort > 0 {
						if uint16(tcp.SrcPort) != p.originSocket.RemotePort && !dstIP.Equal(p.originSocket.RemoteIP) {
							p.originSocket.Lock.Unlock()
							return
						}
						p.originSocket.Lock.Unlock()
					} else {
						p.originSocket.Lock.Unlock()
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

					acceptSock.Payload = append(acceptSock.Payload, udp.Payload...)
				}

				// 临时测试，实际应用会转发消息到目的程序
				//if p.Callback != nil {
				//	go p.Callback(acceptSock, nil)
				//} else {
				//	go p.protocolStackHandle(acceptSock)
				//}
				p.protocolStackHandle(acceptSock)
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

func (p *ProtocolObject) IsInBufferSockets(s *Socket) (*Socket, bool) {
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
		OptionData:   []byte{0x05, 0xb4},
	}

	//option_scale := layers.TCPOption{
	//	OptionType:   layers.TCPOptionKindWindowScale,
	//	OptionLength: 3,
	//	OptionData:   []byte{0x08},
	//}
	//
	//option_nop := layers.TCPOption{
	//	OptionType: layers.TCPOptionKindNop,
	//}
	//
	//option_sack_permitted := layers.TCPOption{
	//	OptionType:   layers.TCPOptionKindSACKPermitted,
	//	OptionLength: 2,
	//}

	options := make([]layers.TCPOption, 0)
	options = append(options, option_mss)

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

		switch tcp_signal {
		case TCP_SIGNAL_SYN:
			_, ok := p.IsInBufferSockets(s)
			if !ok {
				pSock = s // 加入的Socket结构地址
				p.Append(pSock)
				p.SendSynAck(pSock, nil)
				pSock.Lock.Lock()
				pSock.Seq++
				pSock.TCPSock.Status = TCP_SYN_RECV
				pSock.Lock.Unlock()
			} else {

			}
		case TCP_SIGNAL_SYN | TCP_SIGNAL_ACK:
			sock, ok := p.IsInBufferSockets(s)
			if !ok {
				pSock = s // 加入的Socket结构地址
				p.Append(pSock)
				p.SendAck(pSock, nil)
				pSock.Lock.Lock()
				pSock.TCPSock.Status = TCP_ESTABLISHED
				pSock.Lock.Unlock()
			} else {
				if sock.TCPSock.Status == TCP_SYN_SENT {
					pSock = sock
					p.SendAck(pSock, nil)
					pSock.Lock.Lock()
					pSock.TCPSock.Status = TCP_ESTABLISHED
					pSock.Lock.Unlock()
				}
			}
		case TCP_SIGNAL_FIN | TCP_SIGNAL_ACK:
			sock, ok := p.IsInBufferSockets(s)
			if ok {
				pSock = sock // 加入的Socket结构地址
				pSock.Lock.Lock()
				if pSock.IsSupportTimestamp {
					pSock.TsEcho = s.GetTsEcho() // bigendian
				}
				if pSock.TCPSock.Status == TCP_ESTABLISHED {
					pSock.TCPSock.Status = TCP_CLOSE_WAIT
					p.SendAck(pSock, nil)
				}
				pSock.Lock.Unlock()
			}
			p.SendAck(s, nil)
		case TCP_SIGNAL_PSH | TCP_SIGNAL_ACK:
			sock, ok := p.IsInBufferSockets(s)
			if ok {
				pSock = sock // 加入的Socket结构地址
				pSock.Lock.Lock()
				if sock.TCPSock.Status == TCP_ESTABLISHED {
					// 处理数据
					if len(s.Payload) > 0 {
						sock.databuf.Write(s.Payload, len(s.Payload))
						sock.msg <- SocketMsg_RecvData
					}
					// 已经建立了连接
					p.SendAck(sock, nil)
					// 数据
				}
				pSock.Lock.Unlock()
			}
			// p.SendAck(acceptSock, nil)
		case TCP_SIGNAL_ACK:
			//
			sock, ok := p.IsInBufferSockets(s)
			if ok {
				pSock = sock // 加入的Socket结构地址
				pSock.Lock.Lock()
				if sock.TCPSock.Status == TCP_SYN_RECV {
					// 已经发送的Syn+Ack
					sock.TCPSock.Status = TCP_ESTABLISHED
					// p.AcceptSocket <- sock
					p.accpetStack.Push(pSock)
				} else if sock.TCPSock.Status == TCP_ESTABLISHED {
					// 已经建立连接，则可能接收到数据
					sock.databuf.Write(s.Payload, len(s.Payload))
					sock.msg <- SocketMsg_RecvData
				} else if sock.TCPSock.Status == TCP_FIN_WAIT1 {
					sock.TCPSock.Status = TCP_FIN_WAIT2
				} else if sock.TCPSock.Status == TCP_FIN_WAIT2 {
					sock.TCPSock.Status = TCP_TIME_WAIT
					// 启动定时器
					TimerCall(0, 2*MSL, func() {
						if s.Status == TCP_TIME_WAIT {
							pSock.Lock.Unlock()
							return
						} else if s.Status == TCP_FIN_WAIT2 {
							s.Status = TCP_CLOSE
						}
					})
				} else if sock.TCPSock.Status == TCP_TIME_WAIT {
					sock.TCPSock.Status = TCP_CLOSE
				} else if sock.TCPSock.Status == TCP_LAST_ACK {
					sock.TCPSock.Status = TCP_CLOSE
				}
				pSock.Lock.Unlock()
			}
		}
	} else if s.SocketType == SocketType_DGRAM {

	}

	// 触发通知回调
	if pSock != nil {
		isNotify := pSock.IsTriggerNotify.Load()
		if s.NotifyCallback != nil && isNotify {
			s.NotifyCallback()
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
	if p.originSocket == nil {
		return nil, errors.New("not bind socket")
	}

	if p.SocketType != SocketType_STREAM {
		return nil, errors.New("not TCP_STREAM")
	}
	wg := new(sync.WaitGroup)
	wg.Add(1)
	p.originSocket.Lock.Lock()
	p.originSocket.RemoteIP = targetIP
	p.originSocket.RemotePort = targetPort
	p.originSocket.Nexthop = append(p.originSocket.Nexthop, nexthopMAC...)
	p.originSocket.IsTriggerNotify.Store(true)
	p.originSocket.NotifyCallback = func() {
		isNotifiy := p.originSocket.IsTriggerNotify.Load()
		if p.originSocket.Status == TCP_ESTABLISHED && isNotifiy {
			p.originSocket.IsTriggerNotify.Store(false)
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
	err := p.SendSyn(p.originSocket, nil)
	if err != nil {
		return nil, err
	}
	p.originSocket.TCPSock.Status = TCP_SYN_SENT
	p.originSocket.Lock.Unlock()

	wg.Wait() // 等待连接完成

	return nil, nil
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
