//go:build windows

package device

import (
	"errors"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"net/netip"
)

// 获取本地网卡信息
func GetInterfaces(af uint16) ([]*winipcfg.IPAdapterAddresses, error) {
	interfaces, err := winipcfg.GetAdaptersAddresses(winipcfg.AddressFamily(af), winipcfg.GAAFlagDefault)
	if err != nil {
		return nil, err
	}

	return interfaces, nil
}

func FindIntefaceInfo(af uint16, ifIndex uint32) (*InterfaceInfo, error) {
	for _, item := range Global_InterfacesInfo {
		if item.Family == af && item.IfIndex == ifIndex {
			return item, nil
		}
	}

	return nil, errors.New("Not found")
}

// 获取所有的或有节点表
func GetRouteInfoTable() ([]*RouteInfoNode, error) {
	// 通过API获取系统路由信息
	routeTables, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return nil, errors.New("get the route table failed")
	}

	result := make([]*RouteInfoNode, 0)

	for _, route := range routeTables {
		rin := NewRouteInfoNode()
		// Family
		rin.Family = uint16(route.DestinationPrefix.RawPrefix.Family)
		// 网络目标地址
		rin.DestAddr = route.DestinationPrefix.Prefix().Addr()
		// 网关地址
		rin.GateWayAddr = route.NextHop.Addr()
		// 掩码
		rin.NetmaskBits = route.DestinationPrefix.PrefixLength

		//
		interfaceInfo, err := FindIntefaceInfo(rin.Family, route.InterfaceIndex)
		if err != nil {
			rin.II = nil
		} else {
			//
			rin.II = interfaceInfo
			// 是否回环
			if rin.II.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
				rin.Loopback = true
			}

		}

		result = append(result, rin)

	}

	return result, nil
}
func GetAllofInterfacesInfor() ([]*InterfaceInfo, error) {

	result := make([]*InterfaceInfo, 0)
	// AF_INET
	interfaces, err := GetInterfaces(windows.AF_INET)
	if err == nil {
		for _, intf := range interfaces {
			interfaceInfo := NewInterfaceInfo()
			interfaceInfo.Family = windows.AF_INET
			interfaceInfo.IfIndex = intf.IfIndex
			interfaceInfo.DevName = intf.FriendlyName()
			interfaceInfo.DevFullName = intf.AdapterName()
			interfaceInfo.IfType = uint32(intf.IfType)         // 当前网络接口类型，LoopBack也是在这个地方标记的
			interfaceInfo.OperStatus = uint32(intf.OperStatus) // 保存当前的状态
			interfaceInfo.MTU = intf.MTU
			interfaceInfo.IPAAFlags = uint32(intf.Flags)

			//检查设备的可用状态
			if intf.OperStatus&winipcfg.IfOperStatusUp > 0 {
				interfaceInfo.DeviceStartup = true
			} else {
				interfaceInfo.DeviceStartup = false
			}
			// 获取所有的相关的IP地址
			pUnicastAddr := intf.FirstUnicastAddress
			for {
				if pUnicastAddr == nil {
					break
				}
				netipAddr, err := netip.ParseAddr(pUnicastAddr.Address.IP().String())
				if err != nil {
					pUnicastAddr = pUnicastAddr.Next
				} else {
					ipaddr := IPAddress{
						IP:          netipAddr,
						NetmaskBits: int(pUnicastAddr.OnLinkPrefixLength),
					}
					interfaceInfo.Addrs = append(interfaceInfo.Addrs, ipaddr)
				}
				pUnicastAddr = pUnicastAddr.Next
			}
			// 通过PCAP获取设备的连接符号
			if len(interfaceInfo.Addrs) > 0 {
				devLinkSymbol, err := GetUsedNetInterfaceDeviceLnkNameByIP(interfaceInfo.Addrs[0].IP.AsSlice())
				if err != nil {
					interfaceInfo.DevLinkSymbol = interfaceInfo.DevFullName
				} else {
					interfaceInfo.DevLinkSymbol = devLinkSymbol
				}
			} else {
				interfaceInfo.DevLinkSymbol = interfaceInfo.DevFullName
			}

			// 获取所有的DNS服务器
			pDNSAddrs := intf.FirstDNSServerAddress
			for {
				if pDNSAddrs == nil {
					break
				}
				netipAddr, err := netip.ParseAddr(pDNSAddrs.Address.IP().String())
				if err != nil {
					pDNSAddrs = pDNSAddrs.Next
				} else {
					ipaddr := IPAddress{
						IP: netipAddr,
					}
					interfaceInfo.DNSAddr = append(interfaceInfo.Addrs, ipaddr)
				}
				pDNSAddrs = pDNSAddrs.Next
			}
			// 保留MAC地址
			interfaceInfo.MAC = append(interfaceInfo.MAC, intf.PhysicalAddress()...)

			//
			result = append(result, interfaceInfo)
		}
	}

	// AF_INET6
	interfaces, err = GetInterfaces(windows.AF_INET6)
	if err == nil {
		for _, intf := range interfaces {
			interfaceInfo := NewInterfaceInfo()
			interfaceInfo.Family = windows.AF_INET6
			interfaceInfo.IfIndex = intf.IPv6IfIndex
			interfaceInfo.DevName = intf.FriendlyName()
			interfaceInfo.DevFullName = intf.AdapterName()
			interfaceInfo.IfType = uint32(intf.IfType)         // 当前网络接口类型，LoopBack也是在这个地方标记的
			interfaceInfo.OperStatus = uint32(intf.OperStatus) // 保存当前的状态
			interfaceInfo.MTU = intf.MTU
			interfaceInfo.IPAAFlags = uint32(intf.Flags)

			//检查设备的可用状态
			if intf.OperStatus&winipcfg.IfOperStatusUp > 0 {
				interfaceInfo.DeviceStartup = true
			} else {
				interfaceInfo.DeviceStartup = false
			}
			// 获取所有的相关的IP地址
			pUnicastAddr := intf.FirstUnicastAddress
			for {
				if pUnicastAddr == nil {
					break
				}
				netipAddr, err := netip.ParseAddr(pUnicastAddr.Address.IP().String())
				if err != nil {
					pUnicastAddr = pUnicastAddr.Next
				} else {
					ipaddr := IPAddress{
						IP:          netipAddr,
						NetmaskBits: int(pUnicastAddr.OnLinkPrefixLength),
					}
					interfaceInfo.Addrs = append(interfaceInfo.Addrs, ipaddr)
				}
				pUnicastAddr = pUnicastAddr.Next
			}
			// 通过PCAP获取设备的连接符号
			if len(interfaceInfo.Addrs) > 0 {
				devLinkSymbol, err := GetUsedNetInterfaceDeviceLnkNameByIP(interfaceInfo.Addrs[0].IP.AsSlice())
				if err != nil {
					interfaceInfo.DevLinkSymbol = interfaceInfo.DevFullName
				} else {
					interfaceInfo.DevLinkSymbol = devLinkSymbol
				}
			} else {
				interfaceInfo.DevLinkSymbol = interfaceInfo.DevFullName
			}

			// 获取所有的DNS服务器
			pDNSAddrs := intf.FirstDNSServerAddress
			for {
				if pDNSAddrs == nil {
					break
				}
				netipAddr, err := netip.ParseAddr(pDNSAddrs.Address.IP().String())
				if err != nil {
					pDNSAddrs = pDNSAddrs.Next
				} else {
					ipaddr := IPAddress{
						IP: netipAddr,
					}
					interfaceInfo.DNSAddr = append(interfaceInfo.Addrs, ipaddr)
				}
				pDNSAddrs = pDNSAddrs.Next
			}
			// 保留MAC地址
			interfaceInfo.MAC = append(interfaceInfo.MAC, intf.PhysicalAddress()...)

			result = append(result, interfaceInfo)
		}
	}
	return result, nil
}
