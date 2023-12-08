package device

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

type IPAddress struct {
	IP          netip.Addr
	NetmaskBits int // 子网掩码位数
}

func (p *IPAddress) ToIP() net.IP {
	return net.ParseIP(p.IP.String())
}

// 网络接口的数据结构
type InterfaceInfo struct {
	Family        uint16
	DevName       string // 设备名称
	DevFullName   string // 设备全名
	DevLinkSymbol string // 设备连接符号
	Addrs         []IPAddress
	DNSAddr       []IPAddress
	GateWayAddrs  []IPAddress
	NetmashBits   uint16 // 子网掩码
	IfIndex       uint32 // 网卡接口索引
	IPv6IfIndex   uint32 // IPv6
	IfType        uint32 // 接口类型，Loopback也在这个地方
	IPAAFlags     uint32 // 一组指定适配器各种设置的标志。
	OperStatus    uint32 // 表示是否启用了网卡
	DeviceStartup bool   // 如果设备可用就表示True
	MTU           uint32 // 网络接口MTU大小
	MAC           []byte // 网卡的MAC地址
}

func NewInterfaceInfo() *InterfaceInfo {
	return &InterfaceInfo{
		MAC:     make([]byte, 0),
		Addrs:   make([]IPAddress, 0),
		DNSAddr: make([]IPAddress, 0),
	}
}

func (p *InterfaceInfo) ToStringAddrs() string {
	var result string

	for _, addr := range p.Addrs {
		result = result + addr.IP.String() + ","
	}

	if result[len(result)-1:] == "," {
		result = result[0 : len(result)-1]
	}

	return result
}

func (p *InterfaceInfo) MACString() string {
	if len(p.MAC) != 6 {
		return ""
	}

	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		p.MAC[0],
		p.MAC[1],
		p.MAC[2],
		p.MAC[3],
		p.MAC[4],
		p.MAC[5])
}

// 把当前接口转化为下一跳结构
func (p *InterfaceInfo) ToNewNexthopInfo(dstIP net.IP) ([]*NexthopInfo, error) {
	if Global_InterfacesInfo == nil ||
		Global_RouteInfoTable == nil ||
		Global_ArpTable == nil {
		return nil, errors.New("not initialize Global Variable")
	}

	result := make([]*NexthopInfo, 0) // 记录下一跳信息

	// Loopback地址
	if dstIP.String() == "127.0.0.1" {
		np := &NexthopInfo{
			IsLoopback: true,
		}
		result = append(result, np)

		return result, nil
	}
	// 判断是否为IPv4
	bIPv4 := true
	if dstIP.To4() == nil {
		bIPv4 = false
	}

	// 是否发现相同子域的路由信息
	var samesubmainroute *RouteInfoNode

	for _, item := range Global_RouteInfoTable {
		if bIPv4 && item.Family == 2 { // IPv4
			if item.DestAddr == netip.IPv4Unspecified() {
				continue
			}

			ipdst := net.IPv4(item.DestAddr.As4()[0],
				item.DestAddr.As4()[1],
				item.DestAddr.As4()[2],
				item.DestAddr.As4()[3])
			bSameSubmain := IsSameSubnetIPv4(dstIP, ipdst, item.NetmaskToIP())
			if bSameSubmain { // 相同子网，直连的情况
				samesubmainroute = item
				break
			}
		} else if !bIPv4 && item.Family == 23 { // IPv6

		}
	}

	if bIPv4 && samesubmainroute != nil {
		np := NewNexthopInfo()
		bFind := false
		// 如果是通一个子网下的，那么查找地址表，是否有对应的mac地址
		for _, arp := range Global_ArpTable {
			if dstIP.String() == arp.Item.ToIPv4Str() {
				np.IP = dstIP
				np.MAC = append(np.MAC, arp.Item.MACAddress[:]...)
				np.Route = samesubmainroute
				np.IsDirection = true
				bFind = true
				break
			}
		}
		if !bFind {
			nexthopMACaddr, err := SendARPIPv4(dstIP, samesubmainroute.II.IfIndex, 5)
			if err != nil {
				return nil, errors.New("not find mac address")
			}
			np.IP = dstIP
			np.MAC = nexthopMACaddr
			np.Route = samesubmainroute
			np.IsDirection = false
		}

		result = append(result, np)
	} else if bIPv4 && samesubmainroute == nil {
		// 不同子网下的
		// 不同的子网，我们可以通过网关来查找相关的MAC地址，
		// 首先要得到出网的路由，得到出网的网关地址，然后通过地址表查找相关的内容
		outboundRoute, err := GetOutboundRouteInfo()
		if err != nil {
			return nil, errors.New("not found outbound route info")
		}
		for _, ob := range outboundRoute {
			if ob.Family != 2 {
				continue
			}

			np := &NexthopInfo{}

			for _, at := range Global_ArpTable {
				if ob.GateWayAddr.String() == at.Item.ToIPv4Str() {
					np.IP = dstIP
					np.MAC = append(np.MAC, at.Item.MACAddress[:]...)
					np.Route = ob
					np.IsDirection = false
					result = append(result, np)
					break
				}
			}
		}
	}
	return result, nil
}

// 定义网络接口类型
const (
	IF_TYPE_OTHER              = 1
	IF_TYPE_ETHERNET_CSMACD    = 6
	IF_TYPE_ISO88025_TOKENRING = 9
	IF_TYPE_PPP                = 23
	IF_TYPE_SOFTWARE_LOOPBACK  = 24
	IF_TYPE_ATM                = 37
	IF_TYPE_IEEE80211          = 71
	IF_TYPE_TUNNEL             = 131
	IF_TYPE_IEEE1394           = 144
)

// 路由信息节点
// 包括路由信息, 网络接口地址，
type RouteInfoNode struct {
	Family      uint16 // AF_XX
	DestAddr    netip.Addr
	GateWayAddr netip.Addr
	NetmaskBits uint8          // 子网掩码
	Loopback    bool           // 是否回环地址
	II          *InterfaceInfo // 接口信息
}

func NewRouteInfoNode() *RouteInfoNode {
	return &RouteInfoNode{
		Loopback: false,
	}
}

func (p *RouteInfoNode) NetMaskAddr() netip.Addr {

	var result netip.Addr
	// AF_INET
	if p.Family == 2 && p.NetmaskBits <= 32 {
		if p.NetmaskBits == 0 {
			return netip.IPv4Unspecified()
		}
		var b [4]byte
		// 比如强制转化为int型，
		// 否则后续处理，可能造成整数溢出
		n1 := int(p.NetmaskBits / 8)
		n2 := int(p.NetmaskBits % 8)

		// 满值情况
		// 如果不设置值，这个地方造成整数溢出
		var i int
		for i = int(n1 - 1); i >= 0; i-- {
			b[3-i] = 0xFF
		}
		if n1 < 4 {
			b[3-n1] = 0xFF << (8 - n2)
		}

		ip := fmt.Sprintf("%v.%v.%v.%v", b[3], b[2], b[1], b[0])

		result, _ = netip.ParseAddr(ip)

		return result
	}

	// AF_INET6
	if p.Family == 23 && p.NetmaskBits <= 128 {

	}

	return result
}

func (p *RouteInfoNode) NetmaskToIP() net.IP {
	var result net.IP
	// AF_INET
	if p.Family == 2 && p.NetmaskBits <= 32 {
		if p.NetmaskBits == 0 {
			return net.IPv4(netip.IPv4Unspecified().As4()[0],
				netip.IPv4Unspecified().As4()[1],
				netip.IPv4Unspecified().As4()[2],
				netip.IPv4Unspecified().As4()[3])
		}
		var b [4]byte
		// 比如强制转化为int型，
		// 否则后续处理，可能造成整数溢出
		n1 := int(p.NetmaskBits / 8)
		n2 := int(p.NetmaskBits % 8)

		// 满值情况
		// 如果不设置值，这个地方造成整数溢出
		var i int
		for i = int(n1 - 1); i >= 0; i-- {
			b[3-i] = 0xFF
		}
		if n1 < 4 {
			b[3-n1] = 0xFF << (8 - n2)
		}

		ip := fmt.Sprintf("%v.%v.%v.%v", b[3], b[2], b[1], b[0])

		result = net.ParseIP(ip)

		return result
	}

	// AF_INET6
	if p.Family == 23 && p.NetmaskBits <= 128 {

	}

	return result
}

// Arp 条目类型
const (
	ArpType_Other   = 1 // 其他
	ArpType_Invalid = 2 // 无效或是被移除
	ArpType_Dynamic = 3 // 动态分配
	ArpType_Static  = 4 // 静态分配
)

type ArpItem struct {
	IfType     uint32 // ARP的状态，
	IPAddress  [4]byte
	MACAddress [6]byte
}

func (p *ArpItem) ToIPv4Str() string {
	return fmt.Sprintf("%v.%v.%v.%v", p.IPAddress[0], p.IPAddress[1], p.IPAddress[2], p.IPAddress[3])
}

func (p *ArpItem) ToMacAddrStr() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		p.MACAddress[0],
		p.MACAddress[1],
		p.MACAddress[2],
		p.MACAddress[3],
		p.MACAddress[4],
		p.MACAddress[5])
}

func (p *ArpItem) Type() string {
	if p.IfType == ArpType_Static {
		return "Static"
	} else if p.IfType == ArpType_Dynamic {
		return "Dynamic"
	} else {
		return "Other"
	}
}

type ArpTable struct {
	Item ArpItem
	II   *InterfaceInfo
}

type NexthopInfo struct {
	IP          net.IP
	MAC         net.HardwareAddr
	Route       *RouteInfoNode
	IsDirection bool // 是否直连
	IsLoopback  bool // 是否回环
}

func NewNexthopInfo() *NexthopInfo {
	return &NexthopInfo{
		IP:          make(net.IP, 0),
		MAC:         make(net.HardwareAddr, 0),
		IsDirection: false,
		IsLoopback:  false,
	}
}

func (p *NexthopInfo) Print() {
	header := fmt.Sprintf("%-20v   %-20v", "IP address", "Mac address")
	fmt.Println(header)
	if p.MAC == nil {
		p.MAC = bytes.Repeat([]byte{0x00}, 6)
	}

	if p.IP == nil {
		p.IP = bytes.Repeat([]byte{0x00}, 4)
	}
	info := fmt.Sprintf("%-20v   %02x:%02x:%02x:%02x:%02x:%02x",
		p.IP.String(), p.MAC[0], p.MAC[1], p.MAC[2], p.MAC[3], p.MAC[4], p.MAC[5])
	fmt.Println(info)

}

// 得到所有的网络接口信息
var Global_InterfacesInfo []*InterfaceInfo

// 全局的路由信息表
var Global_RouteInfoTable []*RouteInfoNode

// 全局地址映射表
var Global_ArpTable []ArpTable

func PrintInterfaceInfo() {
	if Global_InterfacesInfo == nil {
		return
	}
	for _, intf := range Global_InterfacesInfo {
		fmt.Println("------------------------------------")
		info := fmt.Sprintf("接口名称：%-30v\nIP地址：%-30v\r\nMac地址：%-30v\r\n连接地址：%-30v\n接口索引：%-30v\r\n接口类型：%-30v",
			intf.DevName, intf.ToStringAddrs(), intf.MACString(), intf.DevLinkSymbol, intf.IfIndex, intf.IfType)
		fmt.Println(info)
	}

}

// 打印arp地址表
func PrintArpTables() {
	if Global_ArpTable != nil {
		header := fmt.Sprintf("%-20v   %-20v   %-20v   %-20v   %-20v",
			"IP Address", "Mac Address", "Interface Name", "Interface Index", "Type")
		fmt.Println(header)
		for _, arp := range Global_ArpTable {
			info := fmt.Sprintf("%-20v   %-20v   %-20v   %-20v   %-20v",
				arp.Item.ToIPv4Str(), arp.Item.ToMacAddrStr(), arp.II.DevName, arp.II.IfIndex, arp.Item.Type())
			fmt.Println(info)
		}
	}
}

// 打印路由表
func PrintRouteTables() {
	if Global_RouteInfoTable != nil {
		ipv4routes := make([]*RouteInfoNode, 0)
		ipv6routes := make([]*RouteInfoNode, 0)
		for _, route := range Global_RouteInfoTable {
			if route.II == nil {
				if route.Loopback {
					if route.Family == 2 {
						ipv4routes = append(ipv4routes)
					}

					if route.Family == 23 {
						ipv6routes = append(ipv6routes)
					}
				}
			}
			if route.II != nil {
				if route.II.Family == 2 {
					ipv4routes = append(ipv4routes, route)
				}

				if route.II.Family == 23 {
					ipv6routes = append(ipv6routes, route)
				}
			}
		}

		fmt.Println("IPv4 Route-------------------------------------")
		header := fmt.Sprintf("%-20v   %-20v   %-20v   %-20v",
			"Destion Address", "Netmask", "Gateway Address", "Interface Address")
		fmt.Println(header)
		for _, route := range ipv4routes {
			info := fmt.Sprintf("%-20v  %-20v   %-20v  %-20v",
				route.DestAddr.String(), route.NetMaskAddr(), route.GateWayAddr.String(), route.II.ToStringAddrs())

			fmt.Println(info)
		}

		fmt.Println("IPV6 Route-------------------------------------")
	}
}

// 得到出网接口信息
func GetOutboundInterfaceInfo() ([]*InterfaceInfo, error) {

	result := make([]*InterfaceInfo, 0)
	if Global_RouteInfoTable != nil {
		for _, route := range Global_RouteInfoTable {
			if route.Family == 2 && route.DestAddr == netip.IPv4Unspecified() {
				result = append(result, route.II)
			} else if route.Family == 23 && route.DestAddr == netip.IPv6Unspecified() {
				result = append(result, route.II)
			}
		}
	} else {
		return result, errors.New("Global_RouteInfoTable is empty")
	}

	return result, nil
}

func GetOutboundRouteInfo() ([]*RouteInfoNode, error) {
	result := make([]*RouteInfoNode, 0)
	if Global_RouteInfoTable != nil {
		for _, route := range Global_RouteInfoTable {
			if route.Family == 2 && route.DestAddr == netip.IPv4Unspecified() {
				result = append(result, route)
			} else if route.Family == 23 && route.DestAddr == netip.IPv6Unspecified() {
				result = append(result, route)
			}
		}
	} else {
		return result, errors.New("Global_RouteInfoTable is empty")
	}

	return result, nil
}

// 通过指定接口，获取出网路由信息
func GetOutboundRouteInfoByII(ii *InterfaceInfo) ([]*RouteInfoNode, error) {
	result := make([]*RouteInfoNode, 0)
	if Global_RouteInfoTable != nil {
		for _, route := range Global_RouteInfoTable {
			if route.Family == 2 && route.DestAddr == netip.IPv4Unspecified() {
				if ii.MACString() == route.II.MACString() {
					result = append(result, route)
				}
			} else if route.Family == 23 && route.DestAddr == netip.IPv6Unspecified() {
				if ii.MACString() == route.II.MACString() {
					result = append(result, route)
				}
			}
		}
	} else {
		return result, errors.New("Global_RouteInfoTable is empty")
	}

	return result, nil
}

func GetInterfaceInfoByIndex(index uint32) *InterfaceInfo {
	var result *InterfaceInfo = nil
	if Global_InterfacesInfo == nil {
		return result
	}
	for _, item := range Global_InterfacesInfo {
		if item.IfIndex == index {
			result = item
			break
		}
	}

	return result
}

func IsSameSubnetIPv4(current net.IP, dst net.IP, mask net.IP) bool {

	var buf [4]byte

	currentIPv4 := current.To4()
	maskIPv4 := mask.To4()
	dstIPv4 := dst.To4()

	buf[0] = currentIPv4[0] & maskIPv4[0]
	buf[1] = currentIPv4[1] & maskIPv4[1]
	buf[2] = currentIPv4[2] & maskIPv4[2]
	buf[3] = currentIPv4[3] & maskIPv4[3]

	if dstIPv4[0] == buf[0] &&
		dstIPv4[1] == buf[1] &&
		dstIPv4[2] == buf[2] &&
		dstIPv4[3] == buf[3] {
		return true
	} else {
		return false
	}
}
