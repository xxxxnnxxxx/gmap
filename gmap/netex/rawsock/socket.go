package rawsock

import (
	"Gmap/gmap/common"
	"Gmap/gmap/netex/device"
	"encoding/binary"
	"github.com/google/gopacket/layers"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
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

func generateRandowSeq() uint32 {
	// 使用当前时间的纳秒级别时间戳作为种子
	rand.Seed(time.Now().UnixNano())

	// 生成一个随机的 uint32 整数
	randomUint32 := rand.Uint32()

	return randomUint32
}

type TCPSock struct {
	Status int // TCP状态
	// TCP 信息
	SeqNum                                     uint32 // 顺序号
	AckNum                                     uint32 // 确认序列号
	RecvedSeqNum                               uint32 // 接收到的顺序号
	RecvedAckNum                               uint32 // 确认序列号
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
	UDPSock             // 保留
	PreLenOfSent uint32 // 上一个发送的数据包长度

	LenOfRecved   uint32 // 接收的数据包长度
	RecvedPayload []byte

	// 通知回调，触发通知
	IsTriggerNotify atomic.Bool
	NotifyCallback  func()

	databuf *common.Buffer
	msg     chan int
	Err     error
}

func NewSocket() *Socket {
	result := &Socket{
		RecvedPayload:  make([]byte, 0),
		databuf:        common.NewBuffer(),
		msg:            make(chan int),
		NotifyCallback: nil,
	}
	result.TCPSock.Status = TS_UNKNOWN
	result.Options = make([]layers.TCPOption, 0)
	return result
}

func (p *Socket) Clone() *Socket {

	return nil
}

// 更新序列号
func (p *Socket) UpdateNum() {
	if p.SocketType == SocketType_DGRAM {
		if p.PreLenOfSent == 0 {
			p.SeqNum++
		} else {
			p.SeqNum += p.PreLenOfSent
		}

		if p.LenOfRecved == 0 {
			p.AckNum = p.RecvedSeqNum + 1
		} else {
			p.AckNum = p.RecvedSeqNum + p.LenOfRecved
		}
	} else if p.SocketType == SocketType_DGRAM {
	}

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
