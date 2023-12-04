// go:build linux
// +build:linux
package scanner

func TCPConnectProbe(ip net.IP, port uint16, timeout float64) int {
	return 0
}

func TCPConnectPorbeByTLS(ip net.IP, port uint16, timeout time.Duration) int {
	return 0
}

func UDPProbe(ip net.IP, port uint16) int {
	return 0
}
