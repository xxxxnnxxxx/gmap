package rawsock

import (
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
)

func GenerateTCPPackage(srcIP net.IP,
	srcMac net.HardwareAddr,
	dstIP net.IP,
	dstMac net.HardwareAddr,
	srcPort uint16,
	dstPort uint16,
	tcp_signal int,
	seq uint32,
	ack uint32,
	options []layers.TCPOption,
	payload []byte,
	isLoopback bool) ([]byte, error) {

	// 判断ip类型
	if dstIP.To4() != nil && srcIP.To4() != nil {
		// ip layer
		ipv4 := &layers.IPv4{}
		ipv4.Version = 4
		ipv4.Protocol = layers.IPProtocolTCP
		ipv4.SrcIP = srcIP
		ipv4.DstIP = dstIP
		//ipv4.Length = 20
		ipv4.TTL = 255

		// tcp layer
		tcp := &layers.TCP{}
		tcp.SrcPort = layers.TCPPort(srcPort)
		tcp.DstPort = layers.TCPPort(dstPort)
		tcp.Window = 1024
		if tcp_signal&TCP_SIGNAL_ACK > 0 {
			tcp.ACK = true
		}
		if tcp_signal&TCP_SIGNAL_SYN > 0 {
			tcp.SYN = true
		}
		if tcp_signal&TCP_SIGNAL_FIN > 0 {
			tcp.FIN = true
		}
		if tcp_signal&TCP_SIGNAL_RST > 0 {
			tcp.RST = true
		}
		if tcp_signal&TCP_SIGNAL_URG > 0 {
			tcp.URG = true
		}
		if tcp_signal&TCP_SIGNAL_PSH > 0 {
			tcp.PSH = true
		}
		tcp.Seq = seq
		tcp.Ack = ack
		tcp.Options = append(tcp.Options, options...)
		tcp.SetNetworkLayerForChecksum(ipv4)

		// options
		opts := gopacket.SerializeOptions{}
		opts.ComputeChecksums = true
		opts.FixLengths = true

		buf := gopacket.NewSerializeBuffer()
		if isLoopback {
			loopbackLayer := &layers.Loopback{}
			loopbackLayer.Family = layers.ProtocolFamilyIPv4
			err := gopacket.SerializeLayers(buf, opts, loopbackLayer, ipv4, tcp, gopacket.Payload(payload))
			if err != nil {
				return nil, err
			}
		} else {
			// eth layer
			ethernet := &layers.Ethernet{}
			ethernet.EthernetType = 0x800
			ethernet.DstMAC = dstMac
			ethernet.SrcMAC = srcMac
			err := gopacket.SerializeLayers(buf, opts, ethernet, ipv4, tcp, gopacket.Payload(payload))
			if err != nil {
				return nil, err
			}
		}

		return buf.Bytes(), nil
	} else if dstIP.To16() != nil && srcIP.To16() != nil {
		// ip layer
		ipv6 := &layers.IPv6{}
		ipv6.Version = 4
		ipv6.NextHeader = layers.IPProtocolTCP
		ipv6.SrcIP = srcIP
		ipv6.DstIP = dstIP
		//ipv4.Length = 20
		ipv6.HopLimit = 255

		// tcp layer
		tcp := &layers.TCP{}
		tcp.SrcPort = layers.TCPPort(srcPort)
		tcp.DstPort = layers.TCPPort(dstPort)
		tcp.Window = 1024
		if tcp_signal&TCP_SIGNAL_ACK > 0 {
			tcp.ACK = true
		}
		if tcp_signal&TCP_SIGNAL_SYN > 0 {
			tcp.SYN = true
		}
		if tcp_signal&TCP_SIGNAL_FIN > 0 {
			tcp.FIN = true
		}
		if tcp_signal&TCP_SIGNAL_RST > 0 {
			tcp.RST = true
		}
		if tcp_signal&TCP_SIGNAL_URG > 0 {
			tcp.URG = true
		}
		if tcp_signal&TCP_SIGNAL_PSH > 0 {
			tcp.PSH = true
		}
		tcp.Seq = seq
		tcp.Ack = ack
		tcp.Payload = append(tcp.Payload, payload...)
		tcp.Options = append(tcp.Options, options...)
		tcp.SetNetworkLayerForChecksum(ipv6)

		// options
		opts := gopacket.SerializeOptions{}
		opts.ComputeChecksums = true
		opts.FixLengths = true

		buf := gopacket.NewSerializeBuffer()
		if isLoopback {
			loopbackLayer := &layers.Loopback{}
			loopbackLayer.Family = layers.ProtocolFamilyIPv6BSD
			err := gopacket.SerializeLayers(buf, opts, loopbackLayer, ipv6, tcp, gopacket.Payload(payload))
			if err != nil {
				return nil, err
			}
		} else {
			// eth layer
			ethernet := &layers.Ethernet{}
			ethernet.EthernetType = 0x800
			ethernet.DstMAC = dstMac
			ethernet.SrcMAC = srcMac
			err := gopacket.SerializeLayers(buf, opts, ethernet, ipv6, tcp)
			if err != nil {
				return nil, err
			}
		}

		return buf.Bytes(), nil
	}

	return nil, errors.New("ip error")
}

func GenerateUDPPackage(srcIP net.IP,
	srcMac net.HardwareAddr,
	dstIP net.IP,
	dstMac net.HardwareAddr,
	srcPort uint16,
	dstPort uint16,
	payload []byte,
	isLoopback bool) ([]byte, error) {

	// 判断ip类型
	if dstIP.To4() != nil && srcIP.To4() != nil {
		// ip layer
		ipv4 := &layers.IPv4{}
		ipv4.Version = 4
		ipv4.Protocol = layers.IPProtocolTCP
		ipv4.SrcIP = srcIP
		ipv4.DstIP = dstIP
		//ipv4.Length = 20
		ipv4.TTL = 255

		// udp layer
		udp := &layers.UDP{}
		udp.SrcPort = layers.UDPPort(srcPort)
		udp.DstPort = layers.UDPPort(dstPort)
		udp.Payload = append(udp.Payload, payload...)

		udp.SetNetworkLayerForChecksum(ipv4)

		// options
		opts := gopacket.SerializeOptions{}
		opts.ComputeChecksums = true
		opts.FixLengths = true

		buf := gopacket.NewSerializeBuffer()
		if isLoopback {
			loopbackLayer := &layers.Loopback{}
			loopbackLayer.Family = layers.ProtocolFamilyIPv4
			err := gopacket.SerializeLayers(buf, opts, loopbackLayer, ipv4, udp)
			if err != nil {
				return nil, err
			}
		} else {
			// eth layer
			ethernet := &layers.Ethernet{}
			ethernet.EthernetType = 0x800
			ethernet.DstMAC = dstMac
			ethernet.SrcMAC = srcMac
			err := gopacket.SerializeLayers(buf, opts, ethernet, ipv4, udp)

			if err != nil {
				return nil, err
			}
		}

		return buf.Bytes(), nil
	} else if dstIP.To16() != nil && srcIP.To16() != nil {
		// ip layer
		ipv6 := &layers.IPv6{}
		ipv6.Version = 4
		ipv6.NextHeader = layers.IPProtocolTCP
		ipv6.SrcIP = srcIP
		ipv6.DstIP = dstIP
		//ipv4.Length = 20
		ipv6.HopLimit = 255

		// tcp layer
		udp := &layers.UDP{}
		udp.SrcPort = layers.UDPPort(srcPort)
		udp.DstPort = layers.UDPPort(dstPort)
		udp.Payload = append(udp.Payload, payload...)

		udp.SetNetworkLayerForChecksum(ipv6)

		// options
		opts := gopacket.SerializeOptions{}
		opts.ComputeChecksums = true
		opts.FixLengths = true

		buf := gopacket.NewSerializeBuffer()
		if isLoopback {
			loopbackLayer := &layers.Loopback{}
			loopbackLayer.Family = layers.ProtocolFamilyIPv4
			err := gopacket.SerializeLayers(buf, opts, loopbackLayer, ipv6, udp)
			if err != nil {
				return nil, err
			}
		} else {
			// eth layer
			ethernet := &layers.Ethernet{}
			ethernet.EthernetType = 0x800
			ethernet.DstMAC = dstMac
			ethernet.SrcMAC = srcMac
			err := gopacket.SerializeLayers(buf, opts, ethernet, ipv6, udp)

			if err != nil {
				return nil, err
			}
		}
		return buf.Bytes(), nil
	}

	return nil, errors.New("")
}
