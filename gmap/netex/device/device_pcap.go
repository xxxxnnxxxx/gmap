package device

import (
	"Gmap/gmap/log"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway"
	"net"
	"sync"
	"time"
)

func OpenPcapDevice(deviceLnkName string) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(deviceLnkName, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	return handle, nil
}

func OpenPcapDevice2(deviceLnkName string) (*pcap.Handle, error) {
	inactive, err := pcap.NewInactiveHandle(deviceLnkName)
	if err != nil {
		return nil, err
	}
	defer inactive.CleanUp()

	err = inactive.SetBufferSize(1024 * 1024 * 10)
	if err != nil {
		return nil, err
	}
	handle, err := inactive.Activate() // after this, inactive is no longer valid
	if err != nil {
		return nil, err
	}

	return handle, nil
}

func ClosePcapHandle(handle *pcap.Handle) {
	if handle == nil {
		return
	}

	handle.Close()
}

func SendBuf(handle *pcap.Handle, buf []byte) error {
	err := handle.WritePacketData(buf)
	return err
}

func GetUsedNetInterfaceDeviceLnkNameByIP(usedIP net.IP) (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Logger.Fatal(err)
	}

	var deviceLnkName string = ""
	for _, device := range devices {

		for _, address := range device.Addresses {
			if address.IP.String() == usedIP.String() {
				deviceLnkName = device.Name
			}
		}
	}

	if len(deviceLnkName) == 0 {
		return "", errors.New("not found a avaliable device.")
	}

	return deviceLnkName, nil
}

// 获取出站IP
func GetOutboundIPandMac() (net.IP, net.HardwareAddr, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, nil, err
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipnet.Contains(localAddr.IP) {
				return localAddr.IP, iface.HardwareAddr, nil
			}
		}
	}
	return nil, nil, fmt.Errorf("No suitable network interface found")
}

// 得到网关的MAC地址
// 一般所有的请求包，eth层都
func GetGatewayIPandMac(handle *pcap.Handle) (net.IP, net.HardwareAddr, error) {
	gatewayip, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, nil, err
	}

	// 获取网关的IP地址
	timeout := 10 * time.Second
	wg := sync.WaitGroup{}
	var mac net.HardwareAddr
	go GetMacAddrFromPacketByIP(&wg, timeout, handle, gatewayip, &mac)
	conn, err := net.DialTimeout("tcp4", gatewayip.To4().String()+":1", 1*time.Second)
	if err == nil {
		defer conn.Close()
	}
	wg.Wait()

	return gatewayip, mac, nil
}

func GetMacAddrFromPacketByIP(wg *sync.WaitGroup, timeout time.Duration, handle *pcap.Handle, dstIP net.IP, mac *net.HardwareAddr) error {
	if wg == nil || handle == nil || mac == nil {
		return errors.New("arguments error")
	}

	wg.Add(1)
	defer wg.Done()

	timeoutch := time.After(timeout)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case packet := <-packetSource.Packets():
			iplayer := packet.Layer(layers.LayerTypeIPv4)
			if iplayer == nil {
				continue
			}

			ip, ok := iplayer.(*layers.IPv4)
			if !ok {
				continue
			}

			if !ip.DstIP.Equal(dstIP) {
				continue
			}

			tcplayer := packet.Layer(layers.LayerTypeTCP)
			if tcplayer == nil {
				continue
			}

			_, ok = tcplayer.(*layers.TCP)
			if !ok {
				continue
			}

			// eth层
			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethLayer == nil {
				continue
			}
			eth, ok := ethLayer.(*layers.Ethernet)
			if !ok {
				continue
			}

			*mac = eth.DstMAC
			return nil

		case <-timeoutch:
			log.Logger.Fatal("ARP request timed out")
		}
	}
}
