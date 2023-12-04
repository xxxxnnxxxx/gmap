package scanner

import (
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"net"
	"os"
)

func DetectActive(dstIP string) (bool, error) {
	// 目标地址
	targetAddr, err := net.ResolveIPAddr("ip4", dstIP)
	if err != nil {
		return false, err
	}

	// 创建 ICMP Socket
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// 准备 ICMP Echo Request
	echoRequest := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("ok"),
		},
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

	// 接收 ICMP Echo Reply
	replyBuffer := make([]byte, 1500)
	_, _, err = conn.ReadFrom(replyBuffer)
	if err != nil {
		return false, err
	}

	reply, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), replyBuffer)
	if err != nil {
		fmt.Println("Error parsing ICMP message:", err)
		os.Exit(1)
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
	case ipv4.ICMPTypeDestinationUnreachable, ipv4.ICMPTypeRouterAdvertisement, ipv4.ICMPTypeRedirect:
		return false, nil
	default:
		return true, nil
	}
}
