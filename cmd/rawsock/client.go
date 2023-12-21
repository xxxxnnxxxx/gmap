package main

import (
	"Gmap/gmap/netex/rawsock"
)

func main() {
	client := rawsock.NewProtocolObjectByLnkName(rawsock.SocketType_STREAM, "\\Device\\NPF_{D50F087F-49E2-4423-B22F-DA7F46D42394}")
	client.Wait()
}
