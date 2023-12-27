//go:build windows

package rawsock

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	MIB_IPFORWARD_TYPE_DIRECT = 3
	MIB_IPPROTO_NETMGMT       = 2
	MIB_IPFORWARD_INFO_SIZE   = 24
)

type MIB_IPFORWARD_ROW2 struct {
	InterfaceLuid       uint64
	InterfaceIndex      uint32
	DestinationPrefix   net.IPNet
	NextHop             net.IP
	SitePrefixLength    uint8
	ValidLifetime       uint32
	PreferredLifetime   uint32
	Metric              uint32
	Protocol            uint32
	Loopback            bool
	AutoconfigureActive bool
	Immortal            bool
	Origin              uint32
}

var (
	modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procGetBestRoute2 = modiphlpapi.NewProc("GetBestRoute2")
)

func getBestRoute2(destination net.IP) (net.IP, error) {
	var row MIB_IPFORWARD_ROW2
	row.DestinationPrefix.IP = destination

	ret, _, _ := procGetBestRoute2.Call(
		uintptr(unsafe.Pointer(&row)),
	)
	if ret != 0 {
		return nil, fmt.Errorf("GetBestRoute2 failed with error code %d", ret)
	}

	return row.NextHop, nil
}

func getDefaultGatewayIP() (net.IP, error) {
	return getBestRoute2(net.IPv4(8, 8, 8, 8))
}
