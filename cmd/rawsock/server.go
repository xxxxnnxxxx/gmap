package main

import (
	"Gmap/gmap/common"
	"fmt"
	"os"
	"path"
)
import "Gmap/gmap/netex/rawsock"

func readarticle() string {
	filepath, err := common.GetCurrentDir()
	if err != nil {
		return ""
	}
	content, err := os.ReadFile(path.Join(filepath, "article.txt"))
	if err != nil {
		return ""
	}
	return string(content)
}

func main() {
	tcpserver := rawsock.NewProtocolObject(rawsock.SocketType_STREAM)
	err := tcpserver.InitAdapter(rawsock.IFObtainType_DeviceLnkName, "\\Device\\NPF_{D50F087F-49E2-4423-B22F-DA7F46D42394}")
	if err != nil {
		fmt.Println(err)
		return
	}
	socket := rawsock.CreateSocket(rawsock.SocketType_STREAM, 8000)
	tcpserver.Bind(socket)
	err = tcpserver.Startup()
	if err != nil {
		fmt.Println(err)
		tcpserver.CloseAllofSockets()
		tcpserver.CloseDevice()
		return
	}

	client, ret := tcpserver.Accept()
	if ret == -1 {
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
	ret = tcpserver.Send(client, []byte("i am server:"+socket.LocalIP.String()+"! hello "+client.RemoteIP.String()))
	if ret == -1 {
		fmt.Println(client.GetLastError())
		return
	}

	fmt.Println("发送成功")

}
