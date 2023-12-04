package device

import (
	"Gmap/gmap/common"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"runtime"
	"sync"
	"time"
)

/*
waitTime: 等待的秒数
*/
func SendARPIPv4(dstIP net.IP, ifindex uint32, waitTime int) ([]byte, error) {

	// 通过原IP找到原
	var intf *InterfaceInfo
	intf = GetInterfaceInfoByIndex(ifindex)
	if intf == nil {
		return nil, errors.New("not found interface")
	}

	sourceIP := net.ParseIP(intf.Addrs[0].IP.String())

	// pcap打开设备
	handle, err := OpenPcapDevice(intf.DevLinkSymbol)
	if err != nil {
		return nil, err
	}
	defer ClosePcapHandle(handle)

	var waitPacket sync.WaitGroup
	waitPacket.Add(1)
	bGetMAC := false
	dstMAC := make([]byte, 0)
	// 监听
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			// 解析ARP响应
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer != nil {
				arp, _ := arpLayer.(*layers.ARP)
				if arp.Operation == layers.ARPReply && net.IP(arp.DstProtAddress).Equal(sourceIP) {
					bGetMAC = true
					dstMAC = append(dstMAC, arp.SourceHwAddress...)
					break
				}
			}
		}
	}(&waitPacket)
	runtime.Gosched()
	// 组装
	// eth layer
	ethernet := &layers.Ethernet{}
	ethernet.EthernetType = layers.EthernetTypeARP
	ethernet.DstMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	ethernet.SrcMAC = intf.MAC
	// arp layer
	arplayer := &layers.ARP{}
	arplayer.AddrType = layers.LinkTypeEthernet
	arplayer.Protocol = layers.EthernetTypeIPv4
	arplayer.HwAddressSize = 6
	arplayer.ProtAddressSize = 4
	arplayer.SourceHwAddress = intf.MAC
	arplayer.SourceProtAddress = append(arplayer.SourceProtAddress, intf.Addrs[0].IP.AsSlice()...)
	arplayer.DstHwAddress = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	arplayer.DstProtAddress = dstIP.To4()
	arplayer.Operation = layers.ARPRequest

	opts := gopacket.SerializeOptions{}
	opts.ComputeChecksums = false
	opts.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, opts, ethernet, arplayer)
	if err != nil {
		return nil, err
	}
	for i := 0; i < 5; i++ {
		err = SendBuf(handle, buffer.Bytes())
		if err != nil {
			return nil, err
		}
		time.Sleep(1 * time.Second)
		if bGetMAC {
			break
		}
	}
	if waitTime == 0 {
		waitTime = 5
	}
	if !bGetMAC {
		common.WaitTimeout(&waitPacket, time.Duration(waitTime)*time.Second)
	}

	if bGetMAC {
		//fmt.Println(dstMAC)
	} else {
		return nil, errors.New("not get the mac address")
	}

	return dstMAC, nil
}
