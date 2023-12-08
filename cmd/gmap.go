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

func main() {
	var target string
	//var isSrvDetection bool
	var szport string
	var sS, sT bool
	// var timeout float64
	var arp, route bool
	var ifindex int // 指定索引
	var pif bool
	var isPingtestNo bool // 执行ping
	var outputpath string

	flag.BoolVar(&sS, "sS", false, "SYN扫描")
	flag.BoolVar(&sT, "sT", false, "TCP连接扫描")
	flag.BoolVar(&isPingtestNo, "Pn", false, "禁止ping探活")
	// flag.BoolVar(&isSrvDetection, "sV", false, "服务探测")
	flag.StringVar(&szport, "p", "", "指定扫描端口列表")
	flag.StringVar(&target, "t", "", "输入扫描目标, 格式: 192.168.1.1/24 or 192.168.1.1,192.168.1.2 or 192.168.1.1")
	// flag.Float64Var(&timeout, "to", 2, "超时时间（秒）")
	flag.BoolVar(&arp, "arp", false, "打印arp地址表")
	flag.BoolVar(&route, "route", false, "打印路由表")
	flag.IntVar(&ifindex, "if", -1, "指定扫描所使用的网络出口")
	flag.BoolVar(&pif, "pif", false, "打印网络接口信息")
	flag.StringVar(&outputpath, "o", "", "输出到json文件")

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
		log.Logger.Error("请输入目标和端口")
		os.Exit(1)
	}

	// 保存端口和目标的参数
	probeManager.ArgumentTarget = target
	probeManager.ArgumentPorts = szport

	probeManager.PrintBanner()

	// 超时时间
	// probeManager.Timeout = timeout
	// Port scan
	if sS {
		probeManager.ScanType = scanner.ScanType_Syn
	}

	if sT {
		probeManager.ScanType = scanner.ScanType_TCPConn
	}

	//if sU {
	//	probeManager.ScanType = scanner.ScanType_UDP
	//}

	if sS == false && sT == false {
		log.Logger.Error("请选择一个扫描类型(SYN/TCP connect)")
		os.Exit(1)
	}

	//if isSrvDetection {
	//	probeManager.IsSrvDetective = isSrvDetection
	//}

	// 输出路径
	if len(outputpath) > 0 {
		probeManager.OutputPath = outputpath
	}

	// 是否ping测试
	probeManager.IsPingTest = !isPingtestNo
	// 端口
	probeManager.Ports = append(probeManager.Ports, common.Splite_Port(szport)...)
	// 分析targets
	ips := common.GetIPsFromString(target)
	if len(ips) == 0 {
		log.Logger.Error("请输入一个有效的目标")
		os.Exit(1)
	}
	// 指定接口索引

	probeManager.Ifindex = ifindex
	// 初始化
	probeManager.Initialize(ips)
	// 执行
	probeManager.Do()
	//
	probeManager.Wait()

	if len(probeManager.OutputPath) > 0 {
		r2j, err := probeManager.Result2JSON()
		if err != nil {
			log.Logger.Error(err)
		}

		_, err = common.WriteFile(probeManager.OutputPath, []byte(r2j))
		if err != nil {
			log.Logger.Error(err)
		}
	}

	// 打印结果
	probeManager.PrintResult()
}
