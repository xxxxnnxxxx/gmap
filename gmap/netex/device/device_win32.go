//go:build windows

package device

import (
	"errors"
	"golang.org/x/sys/windows"
	"net"
	"net/netip"
)

func GetArpTablesIPv4(intf *InterfaceInfo) ([]ArpTable, error) {
	err := InitARPLib()
	if err != nil {
		return nil, err
	}

	_, err = InitSNMPLib()
	if err != nil {
		return nil, err
	}

	data, err := GetEntries(intf)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func GetMacAddress(dstIP string) (net.HardwareAddr, error) {
	err := InitARPLib()
	if err != nil {
		return nil, err
	}

	ret, err := GetMacAddrWinIPv4(dstIP)

	return ret, err

}

// 设备全局初始化
func DeviceGlobalInit() error {

	// 初始化全局网络接口表
	// Interface Tables
	var err error
	Global_InterfacesInfo, err = GetAllofInterfacesInfor()
	if err != nil {
		Global_InterfacesInfo = nil
		return err
	}

	// ArpTables
	// 保存测试结果
	result := make([]ArpTable, 0)
	if Global_InterfacesInfo == nil {
		return errors.New("the Global_InterfacesInfo is empty")
	}

	for _, intf := range Global_InterfacesInfo {
		if intf.Family != windows.AF_INET {
			continue
		}
		arpTabls, err := GetArpTablesIPv4(intf)
		if err == nil {
			result = append(result, arpTabls...)
		}
	}

	// 整理arp地址表，通过类型过滤
	for _, item := range result {
		if item.Item.IfType == ArpType_Dynamic ||
			item.Item.IfType == ArpType_Static {
			Global_ArpTable = append(Global_ArpTable, item)
		}
	}

	// Route Tables
	rt, err := GetRouteInfoTable()
	if err != nil {
		return err
	}
	// 整理数据
	for _, item := range rt {
		if item.II != nil {
			if (item.II.IfType == IF_TYPE_ETHERNET_CSMACD ||
				item.II.IfType == IF_TYPE_IEEE80211 ||
				item.II.IfType == IF_TYPE_SOFTWARE_LOOPBACK) && item.II.DeviceStartup {
				Global_RouteInfoTable = append(Global_RouteInfoTable, item)
			}
		}
	}
	return nil
}

// 给定一个IP获取网卡接口信息和下一跳的MAC地址
func GetInterfaceNameAndNextHopMac(dstIP net.IP) ([]*NexthopInfo, error) {
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
	// 判断是否能找到同样的IP
	for _, item := range Global_RouteInfoTable {
		if item.DestAddr.String() == dstIP.String() {
			samesubmainroute = item
			// 如果是在路由表中找到相同的IP,基本确定回环，直接给本机发消息

			for _, addr := range samesubmainroute.II.Addrs {
				if addr.IP.String() == dstIP.String() {
					np := NewNexthopInfo()
					np.IP = dstIP
					np.MAC = append(np.MAC, samesubmainroute.II.MAC...)
					np.Route = samesubmainroute
					np.IsDirection = true
					np.IsLoopback = true

					result = append(result, np)
					return result, nil
				}
			}

			break
		}
	}
	if samesubmainroute == nil {
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

				}
			} else if !bIPv4 && item.Family == 23 { // IPv6

			}
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
