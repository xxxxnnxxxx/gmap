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
	s := opt.Bool('s', "扫描")
	S := opt.Bool('S', "扫描——SYN方式 端口扫描")
	T := opt.Bool('T', "扫描——TCP Connect方式 端口扫描")
	V := opt.Bool('V', "探测服务版本")
	P := opt.Bool('P', "ping 探活")
	n := opt.Bool('n', "否定操作")
	szport := opt.String('p', "", "指定端口列表, 形如: 80,443 或 1-1000")
	ifindex := opt.IntLong("interface-index", 'i', -1, "指定网络接口索引")
	outputpath := opt.StringLong("output", 'o', "", "指定输出文件路径")
	printArp := opt.BoolLong("print-arp", 'a', "", "打印arp列表")
	printRoute := opt.BoolLong("print-route", 'r', "", "打印路由表")
	printInterface := opt.BoolLong("print-interface", 'e', "", "打印网络接口信息")

	opt.Parse()

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

	//if len(common.TrimEx(*szport)) == 0 {
	//	log.Logger.Error("请输入要扫描的端口列表")
	//	os.Exit(1)
	//}

	// 保存端口和目标的参数
	probeManager.ArgumentTarget = opt.Args()[0]
	probeManager.ArgumentPorts = *szport

	probeManager.PrintBanner()

	if *s {
		if *S == false && *T == false && *V == false {
			log.Logger.Error("请选择一个扫描类型(SYN/TCP connect)")
			os.Exit(1)
		}

		if *S {
			probeManager.ScanType = scanner.ScanType_Syn
		} else if *T {
			probeManager.ScanType = scanner.ScanType_TCPConn
		} else if *V {
			probeManager.ScanType = scanner.ScanType_Syn
			probeManager.IsSrvProbe = true
		} else {
			log.Logger.Error("指定扫描类型")
			os.Exit(1)
		}
	} else {
		log.Logger.Error("请指定sS/sT/sV端口扫描方式")
		os.Exit(1)
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
	if len(*szport) > 0 {
		probeManager.Ports = append(probeManager.Ports, common.Splite_Port(*szport)...)
	}
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
