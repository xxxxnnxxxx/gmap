package scanner

import (
	"Gmap/gmap/functions/nmap_service_probe"
	"Gmap/gmap/netex/device"
	"net"
	"strconv"
	"sync"
	"time"
)

// 端口扫描参数
type Port struct {
	Lock           sync.RWMutex
	PortType       int    // 端口类型 PortType_TCP/PortType_UDP
	SrcPort        uint16 // 源端口
	Val            uint16
	State          int
	NmapSeviceInfo []*nmap_service_probe.NmapServiceNode
	SrvInfo        []string
	IsFinished     bool      // 是否完成端口扫描
	AttmptNum      int       // 尝试次数，
	STime          time.Time // 最近一次发送请求时间
}

func NewPort() *Port {
	return &Port{
		SrvInfo:        make([]string, 0),
		NmapSeviceInfo: make([]*nmap_service_probe.NmapServiceNode, 0),
	}
}

func (p *Port) Entry() {
	p.Lock.Lock()
}

func (p *Port) Leave() {
	p.Lock.Unlock()
}

func (p *Port) SetVal(val uint16) {
	p.Lock.Lock()
	p.Val = val
	p.Lock.Unlock()
}

func (p *Port) SetState(state int) {
	p.Lock.Lock()
	p.State = state
	p.Lock.Unlock()
}

func (p *Port) AddSrv(srv string) {
	p.Lock.Lock()
	p.SrvInfo = append(p.SrvInfo, srv)
	p.Lock.Unlock()
}

func (p *Port) ToPortTypeString() string {
	switch p.PortType {
	case PortType_TCP:
		return "tcp"
	case PortType_UDP:
		return "udp"
	default:
		return "tcp"
	}
}

func (p *Port) ToPortValString() string {
	return strconv.Itoa(int(p.Val))
}

func (p *Port) ToStateString() string {
	switch p.State {
	case PortState_Unknown:
		return "Unknown"
	case PortState_Open:
		return "Open"
	case PortState_Closed:
		return "Closed"
	case PortState_Filtered:
		return "Filtered"
	}

	return "Unknown"
}

// 根据协议和频度返回NmapServiceNode中的名称
func (p *Port) ToNSServiceName() string {
	var radio float64
	srvname := ""

	for _, item := range p.NmapSeviceInfo {
		floatvar, err := strconv.ParseFloat(item.Radio, 64)
		if err != nil {
			continue
		}

		if floatvar >= radio {
			radio = floatvar
			srvname = item.ServiceName
		}
	}

	return srvname
}

type ScanTargetEntity struct {
	CurrentLevel       int    // 当前level
	CurrentScannerType int    // 当前的扫描类型
	PortScanType       int    // 扫描的端口方法(syn, tcp connect, udp)
	From               string // uid 来自哪个扫描插件

	IP         net.IP                // 指向的IP
	TargetPort []*Port               // 扫描目标端口信息
	Nexthops   []*device.NexthopInfo // 下一跳信息
	Timeout    time.Duration         // 设置扫描超时时间（秒)

	NumOfAttempts int // 尝试次数 默认情况尝试3次
}

func NewScanTargetEntity() *ScanTargetEntity {
	return &ScanTargetEntity{
		CurrentLevel:  0,
		IP:            make(net.IP, 0),
		TargetPort:    make([]*Port, 0),
		Timeout:       2,
		NumOfAttempts: 2,
	}
}

// 获取扫描主体的下一跳信息
func (p *ScanTargetEntity) GetNexthopInfo() []*device.NexthopInfo {
	return p.Nexthops
}

func (p *ScanTargetEntity) ScanTypeString() string {
	switch p.PortScanType {
	case ScannerType_PortScan:
		return "PortScan"
	case ScannerType_SrvDetection:
		return "Service Detection"
	case ScannerType_WebVulnScan:
		return "Web Scan"
	default:
		return "Unknown"
	}
}