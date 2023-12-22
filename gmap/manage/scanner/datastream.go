package scanner

import (
	"Gmap/gmap/functions/nmap_service_probe"
	"Gmap/gmap/netex/device"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// 端口扫描参数
type Port struct {
	Lock            sync.RWMutex                          `json:"-"`
	PortType        int                                   `json:"Type"` // 端口类型 PortType_TCP/PortType_UDP
	SrcPort         uint16                                `json:"-"`    // 源端口
	Val             uint16                                `json:"Port"`
	State           int                                   `json:"State"`
	NmapSeviceInfo  []*nmap_service_probe.NmapServiceNode `json:"-"`
	NmapServiceName string                                `json:"servicename"`
	VersionInfo     []string                              `json:"version"`
	IsFinished      bool                                  `json:"-"` // 是否完成端口扫描
	AttmptNum       int                                   `json:"-"` // 尝试次数，
	STime           time.Time                             `json:"-"` // 最近一次发送请求时间
}

func NewPort() *Port {
	return &Port{
		VersionInfo:    make([]string, 0),
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
	p.VersionInfo = append(p.VersionInfo, srv)
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

	info := fmt.Sprintf("port:%v, state:%v", p.Val, p.State)
	fmt.Println(info)
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
		if p.PortType == PortType_TCP {
			if item.Protocol == "tcp" {
				if floatvar >= radio {
					radio = floatvar
					srvname = item.ServiceName
				}
			}
		} else if p.PortType == PortType_UDP {
			if item.Protocol == "udp" {
				if floatvar >= radio {
					radio = floatvar
					srvname = item.ServiceName
				}
			}
		}
	}

	return srvname
}

func (p *Port) ToVersionInfo() string {
	var result string
	for _, item := range p.VersionInfo {
		result += item + "/"
	}
	if len(result) > 1 {
		if result[len(result)-1] == '/' {
			result = result[:len(result)-1]
		}
	}

	return result
}

type NCResultItem struct {
	ID     string
	Target string
	Result string
}

type ScanTargetEntity struct {
	CurrentLevel       int    // 当前level
	CurrentScannerType int    // 当前的扫描类型
	PortScanType       int    // 扫描的端口方法(syn, tcp connect, udp)
	From               string // uid 来自哪个扫描插件

	TargetURL  string                // 执行的url, 当nuclei的时候起作用
	IP         net.IP                // 指向的IP
	IsUp       bool                  // 是否
	IsLoopback bool                  // 是否回环
	TargetPort []*Port               // 扫描目标端口信息
	Nexthops   []*device.NexthopInfo // 下一跳信息
	Timeout    time.Duration         // 设置扫描超时时间（秒)

	// 主要针对nuclei扫描
	Templates []string // 模板
	NCResults []NCResultItem

	NumOfAttempts int // 尝试次数 默认情况尝试3次
}

func NewScanTargetEntity() *ScanTargetEntity {
	return &ScanTargetEntity{
		CurrentLevel:  0,
		IP:            make(net.IP, 0),
		TargetPort:    make([]*Port, 0),
		Timeout:       2,
		NumOfAttempts: 2,
		IsLoopback:    false,
		Templates:     make([]string, 0),
		NCResults:     make([]NCResultItem, 0),
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
	case ScannerType_NucleiScan:
		return "Nuclei Scan"
	default:
		return "Unknown"
	}
}
