package rawsock

import (
	"Gmap/gmap/common"
	"Gmap/gmap/log"
	"Gmap/gmap/netex/device"
	"encoding/binary"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"io"
	"net"
	"sync"
	"time"
)

// 协议类型
const (
	SocketType_STREAM int = iota + 1
	SocketType_DGRAM
)

// TCP首部标记
const (
	TCP_SIGNAL_FIN = 0x01
	TCP_SIGNAL_SYN = 0x02
	TCP_SIGNAL_RST = 0x04
	TCP_SIGNAL_PSH = 0x08
	TCP_SIGNAL_ACK = 0x10
	TCP_SIGNAL_URG = 0x20
)

// tcp状态
const (
	TS_UNKNOWN      int = iota
	TCP_ESTABLISHED     // 连接建立：数据传送在进行
	TCP_SYN_SENT        // 已发送SYN:等待ACK
	TCP_SYN_RECV        // 已发送SYN+ACK: 等待ACK
	TCP_FIN_WAIT1       // 第一个FIN 已发送：等待ACK
	TCP_FIN_WAIT2       // 对第一个FIN 的ACK已收到：等待第二个FIN
	TCP_TIME_WAIT       // 收到第二个FIN, 已发送ACK: 等待2MSL超时
	TCP_CLOSE           // 没有连接
	TCP_CLOSE_WAIT      // 收到第一个FIN , 已发送ACK:等待应用程序关闭
	TCP_LAST_ACK        // 收到第二个FIN, 已发送ACK: 等待2MSL超时
	TCP_LISTEN          // 收到了被动打开：等待 SYN
	TCP_CLOSING         /* Now a valid state */ // 双发都已经决定同时关闭

	TCP_MAX_STATES /* Leave at the end! */
)

// tcp 状态字符串
var TCPStatusInfoMap = map[int]string{
	TCP_ESTABLISHED: "Estableshed",
	TCP_SYN_SENT:    "SynSent",
	TCP_SYN_RECV:    "SynRecv",
	TCP_FIN_WAIT1:   "FinWait1",
	TCP_FIN_WAIT2:   "FinWait2",
	TCP_TIME_WAIT:   "TimeWait",
	TCP_CLOSE:       "Close",
	TCP_CLOSE_WAIT:  "CloseWait",
	TCP_LAST_ACK:    "LastACK",
	TCP_LISTEN:      "Listening",
	TCP_CLOSING:     "Closing",
}

// socket 消息
// 主要用于控制接受数据使用
const (
	SocketMsg_Unknow int = iota
	SocketMsg_RecvData
	SocketMsg_Closed
)

// 最大报文段寿命
var MSL int = 30

func TimerCall(interval int, count int, callback func()) {
	for i := 0; i < count; i++ {
		timer := time.NewTimer(time.Duration(interval) * time.Second)
		<-timer.C
		go callback()
	}
}

func getCurrentTimestampBigEndian() []byte {
	now := time.Now()
	ts := now.Unix()

	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, uint32(ts))

	return result
}

// 生成随机端口
// 来自nmap 的源码
/*
#define PRIME_32K 32261
//Change base_port to a new number in a safe port range that is unlikely to
//     conflict with nearby past or future invocations of ultra_scan.
static u16 increment_base_port() {
static u16 g_base_port = 33000 + get_random_uint() % PRIME_32K;
	g_base_port = 33000 + (g_base_port - 33000 + 256) % PRIME_32K;
	return g_base_port;
}
*/
const PRIME_32K int = 32261

func GeneratePort() int {
	base_port := 33000 + int(common.GenerateRandomUint())%PRIME_32K
	base_port = 33000 + (base_port-33000+256)%PRIME_32K

	return base_port
}

type TCPSock struct {
	// TCP 信息
	Seq                                        uint32
	Ack                                        uint32
	DataOffset                                 uint8
	FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS bool
	Options                                    []layers.TCPOption
	IsSupportTimestamp                         bool   // 是否支持时间戳
	TsEcho                                     uint32 // 时间戳相关
	MSS                                        uint16 // 最大报文长度
	WinSize                                    uint16 // 窗口大小
}

type UDPSock struct {
	Length uint16
}

type Socket struct {
	SocketType int // 数据类型

	RemoteIP   net.IP // 连接来源的IP
	RemotePort uint16 // 远程端口号

	LocalIP   net.IP
	LocalMAC  net.HardwareAddr
	LocalPort uint16

	Nexthop *device.NexthopInfo
	Handle  *device.DeviceHandle

	Payload []byte
	TCPSock
	UDPSock // 保留

	TCPStatus int // 保留状态
	databuf   *common.Buffer
	msg       chan int
}

func NewSocket() *Socket {
	result := &Socket{
		Payload:   make([]byte, 0),
		TCPStatus: TS_UNKNOWN, // 初始化为0, UDP的情况下忽略此字段
		databuf:   common.NewBuffer(),
		msg:       make(chan int),
		Nexthop:   device.NewNexthopInfo(),
	}

	result.Options = make([]layers.TCPOption, 0)
	return result
}

func (p *Socket) Clone() *Socket {
	return nil
}

func (p *Socket) SetSocketType(socketType int) {
	p.SocketType = socketType
}

func (p *Socket) SetLocalMAC(localMAC net.HardwareAddr) {
	p.LocalMAC = localMAC
}

func (p *Socket) SetLocalIP(localIP net.IP) {
	p.LocalIP = localIP
}

func (p *Socket) GetSocketType() int {
	return p.SocketType
}

func (p *Socket) GetTsEcho() uint32 {
	var result uint32
	for _, option := range p.Options {
		if option.OptionType == layers.TCPOptionKindTimestamps {
			result = binary.BigEndian.Uint32(option.OptionData[7:])
			break
		}
	}

	return result
}

func (p *Socket) GenerateFlag() int64 {
	return int64(p.RemotePort)
}

func (p *Socket) PrintState() {
	info, ok := TCPStatusInfoMap[p.TCPStatus]
	if !ok {
		return
	}
	log.Logger.Info(info)
}

func GenerateTCPPackage(srcIP net.IP,
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
		if tcp_signal&TCP_SIGNAL_ACK > 0 {
			tcp.ACK = true
		}
		if tcp_signal&TCP_SIGNAL_SYN > 0 {
			tcp.SYN = true
		}
		if tcp_signal&TCP_SIGNAL_FIN > 0 {
			tcp.FIN = true
		}
		if tcp_signal&TCP_SIGNAL_RST > 0 {
			tcp.RST = true
		}
		if tcp_signal&TCP_SIGNAL_URG > 0 {
			tcp.URG = true
		}
		if tcp_signal&TCP_SIGNAL_PSH > 0 {
			tcp.PSH = true
		}
		tcp.Seq = seq
		tcp.Ack = ack
		tcp.Payload = append(tcp.Payload, payload...)
		tcp.Options = append(tcp.Options, options...)
		tcp.SetNetworkLayerForChecksum(ipv4)

		// options
		opts := gopacket.SerializeOptions{}
		opts.ComputeChecksums = true
		opts.FixLengths = true

		buf := gopacket.NewSerializeBuffer()
		if isLoopback {
			loopbackLayer := &layers.Loopback{}
			loopbackLayer.Family = layers.ProtocolFamilyIPv4
			err := gopacket.SerializeLayers(buf, opts, loopbackLayer, ipv4, tcp)
			if err != nil {
				return nil, err
			}
		} else {
			// eth layer
			ethernet := &layers.Ethernet{}
			ethernet.EthernetType = 0x800
			ethernet.DstMAC = dstMac
			ethernet.SrcMAC = srcMac
			err := gopacket.SerializeLayers(buf, opts, ethernet, ipv4, tcp)
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
		if tcp_signal&TCP_SIGNAL_ACK > 0 {
			tcp.ACK = true
		}
		if tcp_signal&TCP_SIGNAL_SYN > 0 {
			tcp.SYN = true
		}
		if tcp_signal&TCP_SIGNAL_FIN > 0 {
			tcp.FIN = true
		}
		if tcp_signal&TCP_SIGNAL_RST > 0 {
			tcp.RST = true
		}
		if tcp_signal&TCP_SIGNAL_URG > 0 {
			tcp.URG = true
		}
		if tcp_signal&TCP_SIGNAL_PSH > 0 {
			tcp.PSH = true
		}
		tcp.Seq = seq
		tcp.Ack = ack
		tcp.Payload = append(tcp.Payload, payload...)
		tcp.Options = append(tcp.Options, options...)
		tcp.SetNetworkLayerForChecksum(ipv6)

		// options
		opts := gopacket.SerializeOptions{}
		opts.ComputeChecksums = true
		opts.FixLengths = true

		buf := gopacket.NewSerializeBuffer()
		if isLoopback {
			loopbackLayer := &layers.Loopback{}
			loopbackLayer.Family = layers.ProtocolFamilyIPv6BSD
			err := gopacket.SerializeLayers(buf, opts, loopbackLayer, ipv6, tcp)
			if err != nil {
				return nil, err
			}
		} else {
			// eth layer
			ethernet := &layers.Ethernet{}
			ethernet.EthernetType = 0x800
			ethernet.DstMAC = dstMac
			ethernet.SrcMAC = srcMac
			err := gopacket.SerializeLayers(buf, opts, ethernet, ipv6, tcp)
			if err != nil {
				return nil, err
			}
		}

		return buf.Bytes(), nil
	}

	return nil, errors.New("ip error")
}

func GenerateUDPPackage(srcIP net.IP,
	srcMac net.HardwareAddr,
	dstIP net.IP,
	dstMac net.HardwareAddr,
	srcPort uint16,
	dstPort uint16,
	payload []byte,
	isLoopback bool) ([]byte, error) {

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

		// udp layer
		udp := &layers.UDP{}
		udp.SrcPort = layers.UDPPort(srcPort)
		udp.DstPort = layers.UDPPort(dstPort)
		udp.Payload = append(udp.Payload, payload...)

		udp.SetNetworkLayerForChecksum(ipv4)

		// options
		opts := gopacket.SerializeOptions{}
		opts.ComputeChecksums = true
		opts.FixLengths = true

		buf := gopacket.NewSerializeBuffer()
		if isLoopback {
			loopbackLayer := &layers.Loopback{}
			loopbackLayer.Family = layers.ProtocolFamilyIPv4
			err := gopacket.SerializeLayers(buf, opts, loopbackLayer, ipv4, udp)
			if err != nil {
				return nil, err
			}
		} else {
			// eth layer
			ethernet := &layers.Ethernet{}
			ethernet.EthernetType = 0x800
			ethernet.DstMAC = dstMac
			ethernet.SrcMAC = srcMac
			err := gopacket.SerializeLayers(buf, opts, ethernet, ipv4, udp)

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
		udp := &layers.UDP{}
		udp.SrcPort = layers.UDPPort(srcPort)
		udp.DstPort = layers.UDPPort(dstPort)
		udp.Payload = append(udp.Payload, payload...)

		udp.SetNetworkLayerForChecksum(ipv6)

		// options
		opts := gopacket.SerializeOptions{}
		opts.ComputeChecksums = true
		opts.FixLengths = true

		buf := gopacket.NewSerializeBuffer()
		if isLoopback {
			loopbackLayer := &layers.Loopback{}
			loopbackLayer.Family = layers.ProtocolFamilyIPv4
			err := gopacket.SerializeLayers(buf, opts, loopbackLayer, ipv6, udp)
			if err != nil {
				return nil, err
			}
		} else {
			// eth layer
			ethernet := &layers.Ethernet{}
			ethernet.EthernetType = 0x800
			ethernet.DstMAC = dstMac
			ethernet.SrcMAC = srcMac
			err := gopacket.SerializeLayers(buf, opts, ethernet, ipv6, udp)

			if err != nil {
				return nil, err
			}
		}
		return buf.Bytes(), nil
	}

	return nil, errors.New("")
}

type ProtocolObject struct {
	DevHandle  *device.DeviceHandle
	SocketType int // 数据类型
	Wg         sync.WaitGroup
	Timeout    time.Duration // 设置监听时间 Listen的时间
	Done       chan struct{}
	Callback   func(*Socket, []byte) error // 数据回调

	IsAsServer bool      // 是否作为服务
	Origins    []*Socket // 初始化本地信息

	AcceptSocket chan *Socket

	TCPSocketsList map[uint16]*Socket // 保存所有的连接的socket
	UDPSocketsList map[uint16]*Socket

	cacheSockes_mutx sync.Mutex
	msg              chan int
	deviceLnkName    string
}

func NewProtocolObjectByLnkName(socketType int, deviceLnkName string) *ProtocolObject {

	instance := &ProtocolObject{
		SocketType:     socketType,
		DevHandle:      device.NewDeviceHandle(),
		Done:           make(chan struct{}),
		Origins:        make([]*Socket, 0),
		AcceptSocket:   make(chan *Socket),
		TCPSocketsList: make(map[uint16]*Socket),
		UDPSocketsList: make(map[uint16]*Socket),
		msg:            make(chan int),
		deviceLnkName:  deviceLnkName,
	}

	return instance
}

// 初始化
func (p *ProtocolObject) InitializeByDevLnkName() error {
	err := p.DevHandle.Open(p.deviceLnkName)
	if err != nil {
		return err
	}

	return err
}

func (p *ProtocolObject) CreateSock(ip net.IP, port uint16) (*Socket, error) {
	socket := NewSocket()

	return socket, nil
}

func (p *ProtocolObject) Startup() error {
	err := p.InitializeByDevLnkName()
	if err != nil {
		return err
	}
	err = p.recvLoopback()
	return err
}

// 是否在本地源信息节点中
func (p *ProtocolObject) IsInOriginsByIP(ip net.IP) bool {
	for _, item := range p.Origins {
		if item.LocalIP.Equal(ip) {
			return true
		}
	}

	return false
}

func (p *ProtocolObject) IsInOriginsByPort(port uint16) bool {
	for _, item := range p.Origins {
		if item.LocalPort == port {
			return true
		}
	}

	return false
}

func (p *ProtocolObject) IsInOrigin(ip net.IP, port uint16) bool {
	for _, item := range p.Origins {
		if item.RemoteIP.Equal(ip) && item.RemotePort == port {
			return true
		}
	}

	return false
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
				// 只直接目的地址为当前IP地址的数据
				if !p.IsInOriginsByIP(dstIP) {
					return
				}

				acceptSock := NewSocket()
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

					if !p.IsInOriginsByPort(uint16(tcp.DstPort)) {
						return
					}

					// 分配socket信息
					acceptSock.SetSocketType(p.SocketType)
					if acceptSock.Nexthop == nil {
						acceptSock.Nexthop = device.NewNexthopInfo()
					}
					//
					var loopback *layers.Loopback
					var eth *layers.Ethernet

					ethLayer := packet.Layer(layers.LayerTypeEthernet)
					if ethLayer != nil {
						eth, ok = ethLayer.(*layers.Ethernet)
						if !ok {
							return
						}
						acceptSock.Nexthop.MAC = append(acceptSock.Nexthop.MAC, eth.SrcMAC...)
					} else {
						loopbackLayer := packet.Layer(layers.LayerTypeLoopback)
						loopback, ok = loopbackLayer.(*layers.Loopback)
						if !ok {
							return
						}
						acceptSock.Nexthop.IsLoopback = true
						acceptSock.Nexthop.Family = loopback.Family
					}

					// 远端地址信息
					acceptSock.RemoteIP = append(acceptSock.RemoteIP, srcIP...)
					acceptSock.RemotePort = uint16(tcp.SrcPort)
					// 本地信息
					acceptSock.LocalIP = append(acceptSock.LocalIP, dstIP...)
					acceptSock.LocalPort = uint16(tcp.DstPort)

					// 如果是非回环的地址，则直接拷贝目的MAC地址到本地MAC地址
					if !acceptSock.Nexthop.IsLoopback {
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

					if !p.IsInOriginsByPort(uint16(udp.DstPort)) {
						return
					}

					ethLayer := packet.Layer(layers.LayerTypeEthernet)
					var eth *layers.Ethernet
					if ethLayer != nil {
						eth, ok = ethLayer.(*layers.Ethernet)
					}

					acceptSock.SetSocketType(p.SocketType)
					acceptSock.RemoteIP = append(acceptSock.RemoteIP, srcIP...)
					acceptSock.RemotePort = uint16(udp.SrcPort)
					if acceptSock.Nexthop == nil {
						acceptSock.Nexthop = device.NewNexthopInfo()
					}
					acceptSock.Nexthop.MAC = append(acceptSock.Nexthop.MAC)
					acceptSock.LocalIP = append(acceptSock.LocalIP, dstIP...)
					acceptSock.LocalMAC = append(acceptSock.LocalMAC, eth.DstMAC...)
					acceptSock.LocalPort = uint16(udp.DstPort)

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

func (p *ProtocolObject) Append(acceptSock *Socket) {
	p.cacheSockes_mutx.Lock()
	p.TCPSocketsList[acceptSock.RemotePort] = acceptSock
	p.cacheSockes_mutx.Unlock()
}

func (p *ProtocolObject) RemoveSockFromCache(acceptSock *Socket) {
	p.cacheSockes_mutx.Lock()
	p.TCPSocketsList[acceptSock.RemotePort] = nil
	p.cacheSockes_mutx.Unlock()
}

func (p *ProtocolObject) IsInAcceptSockets(flag uint16) (*Socket, bool) {
	ret, ok := p.TCPSocketsList[flag]
	if ok {
		return ret, true
	}
	return nil, false
}

// 发起连接
func (p *ProtocolObject) SendSyn(acceptSock *Socket, payload []byte) error {
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
		acceptSock.Nexthop.MAC,
		acceptSock.LocalPort,
		acceptSock.RemotePort,
		TCP_SIGNAL_SYN,
		acceptSock.TCPSock.Ack,
		acceptSock.TCPSock.Seq+1,
		options,
		payload,
		acceptSock.Nexthop.IsLoopback)
	if err != nil {
		log.Logger.Info("GenerateTCPPackage error")
		return err
	}

	p.sendBuffer(acceptSock.Handle, sendBuf)
	return nil
}

// 连接反馈
func (p *ProtocolObject) SendSynAck(acceptSock *Socket, payload []byte) error {

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
		acceptSock.Nexthop.MAC,
		acceptSock.LocalPort,
		acceptSock.RemotePort,
		TCP_SIGNAL_ACK|TCP_SIGNAL_SYN,
		acceptSock.TCPSock.Ack,
		acceptSock.TCPSock.Seq+1,
		options,
		payload,
		acceptSock.Nexthop.IsLoopback)
	if err != nil {
		log.Logger.Info("GenerateTCPPackage error")
		return err
	}

	p.sendBuffer(acceptSock.Handle, sendBuf)
	return nil
}

func (p *ProtocolObject) Sendto(accpetSock *Socket, payload []byte) error {
	return nil
}

func (p *ProtocolObject) SendAck(acceptSock *Socket, payload []byte) error {

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
		acceptSock.Nexthop.MAC,
		acceptSock.LocalPort,
		acceptSock.RemotePort,
		TCP_SIGNAL_ACK,
		acceptSock.TCPSock.Ack,
		acceptSock.TCPSock.Seq+1,
		options,
		payload,
		acceptSock.Nexthop.IsLoopback)
	if err != nil {
		return err
	}

	p.sendBuffer(acceptSock.Handle, sendBuf)
	return nil
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
		acceptSock.Nexthop.MAC,
		acceptSock.LocalPort,
		acceptSock.RemotePort,
		TCP_SIGNAL_ACK|TCP_SIGNAL_PSH,
		acceptSock.TCPSock.Ack,
		acceptSock.TCPSock.Seq+1,
		options,
		payload,
		acceptSock.Nexthop.IsLoopback)
	if err != nil {
		return err
	}

	p.sendBuffer(acceptSock.Handle, sendBuf)
	return nil
}

func (p *ProtocolObject) SendFinAck(acceptSock *Socket, payload []byte) error {
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
		acceptSock.Nexthop.MAC,
		acceptSock.LocalPort,
		acceptSock.RemotePort,
		TCP_SIGNAL_ACK|TCP_SIGNAL_FIN,
		acceptSock.TCPSock.Ack,
		acceptSock.TCPSock.Seq+1,
		options,
		payload,
		acceptSock.Nexthop.IsLoopback)
	if err != nil {
		return err
	}

	// change status
	if acceptSock.TCPStatus == TCP_CLOSE_WAIT {
		acceptSock.TCPStatus = TCP_LAST_ACK
	} else if acceptSock.TCPStatus == TCP_ESTABLISHED {
		acceptSock.TCPStatus = TCP_FIN_WAIT1
	}

	p.sendBuffer(acceptSock.Handle, sendBuf)
	return nil
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
			_, ok := p.IsInAcceptSockets(acceptSock.RemotePort)
			if !ok {
				p.Append(acceptSock)
				p.SendSynAck(acceptSock, nil)
				acceptSock.TCPStatus = TCP_SYN_RECV
			}
		case TCP_SIGNAL_SYN | TCP_SIGNAL_ACK:
			_, ok := p.IsInAcceptSockets(acceptSock.RemotePort)
			if !ok {
				if p.IsInOrigin(acceptSock.RemoteIP, acceptSock.RemotePort) {
					p.Append(acceptSock)
					p.SendAck(acceptSock, nil)
					acceptSock.TCPStatus = TCP_ESTABLISHED
				}
			}
		case TCP_SIGNAL_FIN | TCP_SIGNAL_ACK:
			sock, ok := p.IsInAcceptSockets(acceptSock.RemotePort)
			if ok {
				if sock.IsSupportTimestamp {
					sock.TsEcho = acceptSock.GetTsEcho() // bigendian
				}
				if sock.TCPStatus == TCP_ESTABLISHED {
					sock.TCPStatus = TCP_CLOSE_WAIT
					p.SendAck(sock, nil)
				}
			}
			p.SendAck(acceptSock, nil)
		case TCP_SIGNAL_PSH | TCP_SIGNAL_ACK:
			sock, ok := p.IsInAcceptSockets(acceptSock.RemotePort)
			if ok {
				if sock.TCPStatus == TCP_ESTABLISHED {
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
			sock, ok := p.IsInAcceptSockets(acceptSock.RemotePort)
			if ok {
				if sock.TCPStatus == TCP_SYN_RECV {
					// 已经发送的Syn+Ack
					sock.TCPStatus = TCP_ESTABLISHED
					p.AcceptSocket <- sock
				} else if sock.TCPStatus == TCP_ESTABLISHED {
					// 已经建立连接，则可能接收到数据
					sock.databuf.Write(acceptSock.Payload, len(acceptSock.Payload))
					sock.msg <- SocketMsg_RecvData
				} else if sock.TCPStatus == TCP_FIN_WAIT1 {
					sock.TCPStatus = TCP_FIN_WAIT2
				} else if sock.TCPStatus == TCP_FIN_WAIT2 {
					sock.TCPStatus = TCP_TIME_WAIT
					// 启动定时器
					TimerCall(0, 2*MSL, func() {
						if acceptSock.TCPStatus == TCP_TIME_WAIT {
							return
						} else if acceptSock.TCPStatus == TCP_FIN_WAIT2 {
							acceptSock.TCPStatus = TCP_CLOSE
						}
					})
				} else if sock.TCPStatus == TCP_TIME_WAIT {
					sock.TCPStatus = TCP_CLOSE
				} else if sock.TCPStatus == TCP_LAST_ACK {
					sock.TCPStatus = TCP_CLOSE
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
//
//

func (p *ProtocolObject) Connect(targetIP net.IP, targetPort uint16) error {
	return nil
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

func (p *ProtocolObject) Recv(acceptSock *Socket, result *[]byte) int {
	if result == nil {
		return -1
	}
loop:
	select {
	case msg := <-acceptSock.msg:
		switch msg {
		case SocketMsg_RecvData:
			*result = append(*result, acceptSock.Payload...)
			break loop
		case SocketMsg_Closed:
			return 0
		}
	}
	return len(*result)
}

func (p *ProtocolObject) Send(acceptSock *Socket, payload []byte) int {
	if acceptSock == nil {
		return -1
	}

	if acceptSock.SocketType == SocketType_STREAM && acceptSock.TCPStatus == TCP_ESTABLISHED {
		p.SendPshAck(acceptSock, payload)
	} else if acceptSock.SocketType == SocketType_DGRAM {
		p.Sendto(acceptSock, payload)
	}
	return -1
}

func (p *ProtocolObject) Close(acceptSock *Socket, payload []byte) int {
	p.SendFinAck(acceptSock, payload)
	p.RemoveSockFromCache(acceptSock)
	return -1
}
