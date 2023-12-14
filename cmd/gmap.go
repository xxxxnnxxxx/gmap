package main

import (
	"Gmap/gmap/common"
	"Gmap/gmap/log"
	"Gmap/gmap/manage"
	"Gmap/gmap/manage/scanner"
	"Gmap/gmap/netex/device"
	"github.com/felixge/fgprof"
	opt "github.com/pborman/getopt/v2"
	"net/http"
	_ "net/http/pprof"
	"os"
)

func monitor() {
	http.Handle("/debug/fgprof", fgprof.Handler())
	log.Logger.Fatal(http.ListenAndServe(":9090", nil))

}
func main() {
	var szport string

	s := opt.Bool('s', "端口扫描类")
	S := opt.Bool('S', "SYN 扫描")
	T := opt.Bool('T', "Connect 连接扫描")
	V := opt.Bool('V', "探测服务版本")
	P := opt.Bool('P', "ping 探活")
	n := opt.Bool('n', "否定操作")
	port := opt.String('p', "", "指定端口列表")
	printArp := opt.BoolLong("print-arp", 'a', "", "打印arp列表")
	printRoute := opt.BoolLong("print-route", 'r', "", "打印路由表")
	ifindex := opt.IntLong("interface-index", 'i', -1, "指定网络接口索引")
	printInterface := opt.BoolLong("print-interface", 'e', "", "打印网络接口信息")
	outputpath := opt.StringLong("output", 'o', "", "指定输出文件路径")

	opt.Parse()

	szport = *port

	// go monitor()

	if *printArp == true {
		device.DeviceGlobalInit()
		device.PrintArpTables()
		return
	}

	if *printRoute == true {
		device.DeviceGlobalInit()
		device.PrintRouteTables()
		return
	}

	if *printInterface == true {
		device.DeviceGlobalInit()
		device.PrintInterfaceInfo()
		return
	}

	probeManager := manage.NewProbeManager()
	if len(opt.Args()) == 0 {
		log.Logger.Error("请输入目标")
		os.Exit(1)
	}

	if len(common.TrimEx(szport)) == 0 {
		log.Logger.Error("请输入要扫描的端口列表")
		os.Exit(1)
	}

	// 保存端口和目标的参数
	probeManager.ArgumentTarget = opt.Args()[0]
	probeManager.ArgumentPorts = szport

	probeManager.PrintBanner()

	if *s {
		if *S == false && *T == false {
			log.Logger.Error("请选择一个扫描类型(SYN/TCP connect)")
			os.Exit(1)
		}
	} else {
		log.Logger.Error("请指定sS/sT端口扫描方式")
		os.Exit(1)
	}

	// Port scan
	if *s && *S {
		probeManager.ScanType = scanner.ScanType_Syn
	}

	if *s && *T {
		probeManager.ScanType = scanner.ScanType_TCPConn
	}

	// 加载服务探测
	if *s && *V {
		probeManager.IsSrvProbe = true
	} else {
		probeManager.IsSrvProbe = false
	}

	// 输出路径
	if len(*outputpath) > 0 {
		probeManager.OutputPath = *outputpath
	}

	// 是否ping测试
	if *P && *n {
		probeManager.IsPingTest = false
	} else {
		probeManager.IsPingTest = true
	}

	// 端口
	probeManager.Ports = append(probeManager.Ports, common.Splite_Port(szport)...)
	// 分析targets
	ips := common.GetIPsFromString(opt.Args()[0])
	if len(ips) == 0 {
		log.Logger.Error("请输入一个有效的目标")
		os.Exit(1)
	}
	// 指定接口索引

	probeManager.Ifindex = *ifindex
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
