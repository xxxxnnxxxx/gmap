package scanner

import (
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"net"
	"os"
	"time"
)

func PingTest(dstIP string) (bool, error) {
	// 目标地址
	targetAddr, err := net.ResolveIPAddr("ip4", dstIP)
	bIPv6 := false
	if err != nil {
		targetAddr, err = net.ResolveIPAddr("ipv6", dstIP)
		if err != nil {
			return false, err
		} else {
			bIPv6 = true
		}
	}

	// 创建 ICMP Socket
	var conn *icmp.PacketConn
	if bIPv6 {
		conn, err = icmp.ListenPacket("ip6:ipv6-icmp", "::")
		if err != nil {
			return false, err
		}
	} else {
		conn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			return false, err
		}
	}

	defer conn.Close()

	// 准备 ICMP Echo Request
	var echoRequest icmp.Message
	if bIPv6 {
		echoRequest = icmp.Message{
			Type: ipv6.ICMPTypeEchoReply,
			Code: 0,
			Body: &icmp.Echo{
				ID:   os.Getpid() & 0xffff,
				Seq:  1,
				Data: []byte("ok"),
			},
		}
	} else {
		echoRequest = icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   os.Getpid() & 0xffff,
				Seq:  1,
				Data: []byte("ok"),
			},
		}
	}

	// 将 ICMP Echo Request 序列化为字节
	echoRequestBytes, err := echoRequest.Marshal(nil)
	if err != nil {
		return false, err
	}

	// 发送 ICMP Echo Request
	_, err = conn.WriteTo(echoRequestBytes, targetAddr)
	if err != nil {
		return false, err
	}

	timeout := time.Now().Add(1 * time.Second)
	if err = conn.SetReadDeadline(timeout); err != nil {
		return false, err
	}

	// 接收 ICMP Echo Reply
	replyBuffer := make([]byte, 15000)
	_, _, err = conn.ReadFrom(replyBuffer)
	if err != nil {
		return false, err
	}

	reply, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), replyBuffer)
	if err != nil {
		return false, err
	}

	/*
		const (
			ICMPTypeEchoReply              ICMPType = 0  // Echo Reply
			ICMPTypeDestinationUnreachable ICMPType = 3  // Destination Unreachable
			ICMPTypeRedirect               ICMPType = 5  // Redirect
			ICMPTypeEcho                   ICMPType = 8  // Echo
			ICMPTypeRouterAdvertisement    ICMPType = 9  // Router Advertisement
			ICMPTypeRouterSolicitation     ICMPType = 10 // Router Solicitation
			ICMPTypeTimeExceeded           ICMPType = 11 // Time Exceeded
			ICMPTypeParameterProblem       ICMPType = 12 // Parameter Problem
			ICMPTypeTimestamp              ICMPType = 13 // Timestamp
			ICMPTypeTimestampReply         ICMPType = 14 // Timestamp Reply
			ICMPTypePhoturis               ICMPType = 40 // Photuris
			ICMPTypeExtendedEchoRequest    ICMPType = 42 // Extended Echo Request
			ICMPTypeExtendedEchoReply      ICMPType = 43 // Extended Echo Reply
		)
	*/

	switch reply.Type {
	case ipv4.ICMPTypeDestinationUnreachable,
		ipv4.ICMPTypeRouterAdvertisement,
		ipv4.ICMPTypeRedirect,
		ipv6.ICMPTypeRedirect,
		ipv6.ICMPTypeDestinationUnreachable,
		ipv6.ICMPTypeRouterAdvertisement:
		return false, nil
	default:
		return true, nil
	}
}
