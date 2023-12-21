package main

import "fmt"
import "Gmap/gmap/netex/rawsock"

func main() {
	tcpserver := rawsock.NewProtocolObjectByLnkName(rawsock.SocketType_STREAM, "\\Device\\NPF_{D50F087F-49E2-4423-B22F-DA7F46D42394}")
	tcpserver.CreateSock(nil, 7777)
	tcpserver.Startup()

	for {
		socket, err := tcpserver.Accept()
		if err == nil {
			go func() {
				var buf []byte = nil
				ret := tcpserver.Recv(socket, &buf)
				if ret > 0 {
					fmt.Println(string(buf))
				}
			}()
		}
	}

	tcpserver.Wait()
}
