package main

import "fmt"
import "Gmap/gmap/netex/rawsock"

func main() {
	tcpserver := rawsock.NewProtocolObject(rawsock.SocketType_STREAM)
	err := tcpserver.InitAdapter(rawsock.IFObtainType_DeviceLnkName, "\\Device\\NPF_{D50F087F-49E2-4423-B22F-DA7F46D42394}")
	if err != nil {
		fmt.Println(err)
		return
	}
	socket := rawsock.CreateSocket(rawsock.SocketType_STREAM, 55555)
	tcpserver.Bind(socket)
	err = tcpserver.Startup()
	if err != nil {
		fmt.Println(err)
		tcpserver.CloseAllofSockets()
		tcpserver.CloseDevice()
		return
	}

	client, err := tcpserver.Accept()
	if err != nil {
		fmt.Println(err)
		tcpserver.CloseAllofSockets()
		tcpserver.CloseDevice()
		return
	}

	var result []byte
	recvLen := tcpserver.Recv(client, &result)
	if recvLen == -1 {
		fmt.Println("连接已经断开")
	}
	fmt.Println(string(result))
	ret := tcpserver.Send(client, []byte("hello,world"))
	if ret == -1 {
		fmt.Println(client.GetLastError())
		return
	}

	fmt.Println("发送成功")

}
