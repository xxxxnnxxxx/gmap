//go:build windows

package device

import "C"
import (
	"Gmap/gmap/common"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"net"
	"net/netip"
	"path"
	"syscall"
	"unsafe"
)

var globalModuleOfArpLib *windows.DLL
var getInitSNMPLib *windows.Proc
var getGetEntries *windows.Proc
var getMacAddr *windows.Proc

func InitARPLib() error {
	// get the current
	currentDir, err := common.GetCurrentDir()
	if err != nil {
		return err
	}

	pathOfArpDll := path.Join(currentDir, "arp.dll")

	if globalModuleOfArpLib == nil {
		modarp, err := windows.LoadDLL(pathOfArpDll)
		if err != nil {
			return err
		}
		globalModuleOfArpLib = modarp
	}

	if getInitSNMPLib == nil {
		getInitSNMPLib, err = globalModuleOfArpLib.FindProc("InitSNMPLib")
		if err != nil {
			globalModuleOfArpLib.Release()
			return err
		}
	}

	if getGetEntries == nil {
		getGetEntries, err = globalModuleOfArpLib.FindProc("GetEntries")
		if err != nil {
			globalModuleOfArpLib.Release()
			return err
		}
	}

	return nil
}

func InitSNMPLib() (bool, error) {
	r0, _, err := syscall.SyscallN(getInitSNMPLib.Addr())
	if r0 != 1 {
		return false, fmt.Errorf("InitSNMPLib failed: %v", err)
	}
	return true, nil
}

func GetEntries(intf *InterfaceInfo) ([]ArpTable, error) {
	var arpItems [256]ArpItem
	r0, _, err := syscall.SyscallN(getGetEntries.Addr(), uintptr(unsafe.Pointer(&arpItems)), 256, uintptr(intf.IfIndex))
	if r0 == 0 {
		return nil, fmt.Errorf("InitSNMPLib failed: %v", err)
	}

	result := make([]ArpTable, r0)
	for i := 0; i < int(r0); i++ {
		// 去掉回环的信息
		if intf.IfType == IF_TYPE_SOFTWARE_LOOPBACK ||
			!intf.DeviceStartup {
			continue
		}

		at := ArpTable{
			Item: arpItems[i],
			II:   intf,
		}
		result = append(result, at)
	}

	return result, nil
}

func GetMacAddrWinIPv4(dstIP string) (net.HardwareAddr, error) {
	if getMacAddr == nil {
		return nil, errors.New("not found the proc address of the function. ")
	}
	var mac [7]byte
	lenofmac := 7
	ip, err := netip.ParseAddr(dstIP)
	if err != nil {
		return nil, err
	}
	b := C.CString(ip.String())
	r0, _, _ := syscall.SyscallN(getMacAddr.Addr(), windows.AF_INET,
		uintptr(unsafe.Pointer(b)),
		uintptr(len(ip.String())),
		uintptr(unsafe.Pointer(&mac)),
		uintptr(unsafe.Pointer(&lenofmac)))
	if r0 != 0 {
		return nil, fmt.Errorf("GetMacAddr failed: the error code: %v ", r0)
	}

	return net.HardwareAddr(mac[:]), nil
}
