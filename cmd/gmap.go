package main

import (
	"Gmap/gmap/common"
	"Gmap/gmap/log"
	"Gmap/gmap/manage"
	"Gmap/gmap/manage/scanner"
	"Gmap/gmap/netex/device"
	"flag"
	"os"
)

func test() {

}

func main() {
	var target string
	var isSrvDetection bool
	var szport string
	var sS, sT, sU bool
	var timeout float64
	var c1, c2, c3, c4, c5 bool
	var arp, route bool
	var ifindex uint // 指定索引
	var pif bool
	var isDectivePing bool // 执行ping

	flag.BoolVar(&sS, "sS", false, "SYN port scan")
	flag.BoolVar(&sT, "sT", false, "TCP connect port scan")
	flag.BoolVar(&sU, "sU", false, "UDP port scan")
	flag.BoolVar(&isDectivePing, "sN", false, "Ping detective hosts")
	flag.BoolVar(&isSrvDetection, "sV", false, "Service Detection")
	flag.StringVar(&szport, "p", "", "port list")
	flag.StringVar(&target, "t", "", "input a target, formats: 192.168.1.1/24 or 192.168.1.1,192.168.1.2 or 192.168.1.1")
	flag.Float64Var(&timeout, "to", 2, "timeout per probe (seconds")
	flag.BoolVar(&c1, "c1", true, "try 1")
	flag.BoolVar(&c2, "c2", false, "try 2")
	flag.BoolVar(&c3, "c3", false, "try 3")
	flag.BoolVar(&c4, "c4", false, "try 4")
	flag.BoolVar(&c5, "c5", false, "try 5")
	flag.BoolVar(&arp, "arp", false, "print arp table")
	flag.BoolVar(&route, "route", false, "print route table")
	flag.UintVar(&ifindex, "if", 0, "a interface index for the scanner")
	flag.BoolVar(&pif, "pif", false, "print interface info")

	flag.Parse()

	if arp == true {
		device.DeviceGlobalInit()
		device.PrintArpTables()
		return
	}

	if route == true {
		device.DeviceGlobalInit()
		device.PrintRouteTables()
		return
	}

	if pif == true {
		device.DeviceGlobalInit()
		device.PrintInterfaceInfo()
		return
	}

	probeManager := manage.NewProbeManager()
	if len(common.TrimEx(target)) == 0 || len(common.TrimEx(szport)) == 0 {
		log.Logger.Error("please a target and ports")
		os.Exit(1)
	}

	probeManager.PrintBanner()

	// 超时时间
	probeManager.Timeout = timeout
	// 尝试次数
	if c1 {
		probeManager.NumOfAttempts = 1
	}
	if c2 {
		probeManager.NumOfAttempts = 2
	}
	if c3 {
		probeManager.NumOfAttempts = 3
	}
	if c4 {
		probeManager.NumOfAttempts = 4
	}
	if c5 {
		probeManager.NumOfAttempts = 5
	}
	// Port scan
	if sS {
		probeManager.ScanType = scanner.ScanType_Syn
	}

	if sT {
		probeManager.ScanType = scanner.ScanType_TCPConn
	}

	if sU {
		probeManager.ScanType = scanner.ScanType_UDP
	}

	if sS && sT && sU == false {
		log.Logger.Error("please select a scan type.")
		os.Exit(1)
	}

	if isSrvDetection {
		probeManager.IsSrvDetective = isSrvDetection
	}

	// 端口
	probeManager.Ports = append(probeManager.Ports, common.Splite_Port(szport)...)
	// 分析targets
	ips := common.GetIPsFromString(target)
	if len(ips) == 0 {
		log.Logger.Error("please input a vaild target")
		os.Exit(1)
	}
	// 指定接口索引
	probeManager.Ifindex = uint32(ifindex)
	// 初始化
	probeManager.Initialize(ips)
	// 执行
	probeManager.Do()
	//
	probeManager.Wait()

	// 打印结果
	probeManager.PrintResult()
}
