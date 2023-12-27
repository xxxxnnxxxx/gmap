package rawsock

import (
	"Gmap/gmap/common"
	"Gmap/gmap/log"
	"Gmap/gmap/netex/device"
	"encoding/binary"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
	Status int // TCP状态
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
	Lock       sync.RWMutex
	Family     layers.ProtocolFamily
	SocketType int // 数据类型
	Handle     *device.DeviceHandle

	RemoteIP   net.IP // 连接来源的IP
	RemotePort uint16 // 远程端口号
	Nexthop    net.HardwareAddr

	LocalIP   net.IP
	LocalPort uint16
	LocalMAC  net.HardwareAddr

	TCPSock
	UDPSock // 保留
	Payload []byte

	// 是否自动回复, 在接收到数据信息后，如果是自动，会自动处理接受到的消息
	// 比如收到Syn直接回复Syn/Ack,
	// 这个操作点，主要是返回给上一级的操作，如果不存在NotifyCallback函数
	// 那么这个是否自动回复不起作用，默认自动回复
	IsAutoReply    bool
	NotifyCallback func()

	databuf *common.Buffer
	msg     chan int
	Err     error
}

func NewSocket() *Socket {
	result := &Socket{
		Payload:        make([]byte, 0),
		databuf:        common.NewBuffer(),
		msg:            make(chan int),
		NotifyCallback: nil,
		IsAutoReply:    true,
	}
	result.TCPSock.Status = TS_UNKNOWN
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
	info, ok := TCPStatusInfoMap[p.TCPSock.Status]
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
