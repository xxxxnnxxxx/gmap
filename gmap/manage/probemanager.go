package manage

import (
	"Gmap/gmap/common"
	"Gmap/gmap/functions/nmap_service_probe"
	"Gmap/gmap/log"
	"Gmap/gmap/manage/scanner"
	"Gmap/gmap/netex/device"
	"Gmap/gmap/netex/rawsock"
	"errors"
	"fmt"
	"github.com/panjf2000/ants/v2"
	"net"
	"os"
	"os/signal"
	"path"
	"sync"
	"syscall"
	"time"
)

type TargetIP struct {
	IP       net.IP
	IsUp     bool // 是否活跃
	Nexthops []*device.NexthopInfo
}

func NewTargetIP() *TargetIP {
	return &TargetIP{
		Nexthops: make([]*device.NexthopInfo, 0),
	}
}

type Target struct {
	IP            string          `json:"ip"`             // IP地址
	IsUp          bool            `json:"isup"`           // 是否在线
	OpenPorts     []*scanner.Port `json:"open-ports"`     // 开放端口
	FilteredPorts []*scanner.Port `json:"filtered-ports"` // 过滤端口
	ClosedPorts   []*scanner.Port `json:"closed-ports"`   // 关闭端口
}

type ResultSet struct {
	StartTime   time.Time `json:"StartTime"` // 启动时间
	EndTime     time.Time `json:"EndTime"`   // 结束时间
	PortScanned []uint16  `json:"ports"`     // 被扫描的端口，扫描参数
	Targets     []*Target `json:"Targets"`   // 目标
}

type ProbeManager struct {
	ScanType       int      // 端口扫描类型
	IsSrvDetective bool     // 服务探测库，目前只有nmap
	Ports          []uint16 // 端口列表
	Entities       []*scanner.ScanTargetEntity
	IsPingTest     bool // 是否ping测试, 默认探活
	CountOfHostup  int  // 在线主机个数

	MaxLevel      int                // 最大层级
	MaxTaskPool   int                // 最大任务个数
	Timeout       float64            // 超时时间
	NumOfAttempts int                // 尝试次数
	WgWorker      sync.WaitGroup     // 同步
	ResultSet     *common.Stack      // 结果池
	TaskPool      *ants.PoolWithFunc // 例程池函数
	NotifyChannel chan *scanner.ScannerMSG

	// scanner
	Scanners map[int][]scanner.IScanner // 扫描插件 int的索引是按层级作为索引的， 索引的起始为1，
	// performance
	cpucorecount int // cpu核心数量
	//
	Ifindex int                   // interface index
	II      *device.InterfaceInfo // 接口信息
	//
	startTime time.Time // 启动时间
	//
	OutputPath string // 输出路径
}

func NewProbeManager() *ProbeManager {
	return &ProbeManager{
		ScanType:      scanner.ScanType_TCPConn,
		Ports:         make([]uint16, 0),
		MaxTaskPool:   0, // 默认的最大的任务分割为10
		ResultSet:     common.NewStack(),
		Scanners:      make(map[int][]scanner.IScanner),
		IsPingTest:    true,
		NumOfAttempts: 2, // 默认值
		Timeout:       2,
	}
}

func (p *ProbeManager) SetMaxTaskPool(count int) {
	p.MaxTaskPool = count
}

func (p *ProbeManager) GetCountOfScanners() int {
	if len(p.Scanners) == 0 {
		return 0
	}

	count := 0
	for _, v := range p.Scanners {
		count += len(v)
	}

	return count
}

func (p *ProbeManager) Initialize(IPs []net.IP) error {
	// 初始化全局信息表
	currentDir, err := common.GetCurrentDir()
	if err != nil {
		return errors.New("get the current directionary failed")
	}
	nmapServicePath := path.Join(currentDir, "data", "nmap-services")

	err = nmap_service_probe.LoadNmapSerivce(nmapServicePath)
	if err != nil {
		return err
	}

	// 初始化设备
	if p.ScanType == scanner.ScanType_Syn {
		//// 初始化全局路由表和地址映射表
		device.DeviceGlobalInit()
	}
	// 根据指定的网络接口索引，接口信息结构
	if p.Ifindex > 0 {
		p.II = device.GetInterfaceInfoByIndex(uint32(p.Ifindex))
	}

	//
	// 整理
	// 在这个地方单独处理原因就是需要对扫描得端口和目标进行下一跳处理
	tps, err := p.IPtoTargetIP(IPs)
	if err != nil {
		return err
	}

	// 根据参数，创建扫描示例
	// 端口扫描
	if p.ScanType == 0 {
		return errors.New("Don't set the method of portscan")
	} else {
		p.MaxLevel = p.MaxLevel + 1
		scanner := scanner.NewPortScanner()
		scanner.SetLevel(p.MaxLevel)
		scanner.SetUID(common.GenerateUniqueStr())
		scanner.SetProcCallback(p.Distibition)
		scanner.SetTimeoutPerProbe(p.Timeout)
		scanner.SetAttemptTimes(p.NumOfAttempts)
		scanner.SetMsgCallback(p.HandleMsg)
		scanner.SetNotifyChannel(&p.NotifyChannel)
		p.Scanners[p.MaxLevel] = append(p.Scanners[p.MaxLevel], scanner)
	}
	// 服务探测
	if p.IsSrvDetective {
		p.MaxLevel = p.MaxLevel + 1
		scanner := scanner.NewSrvDetectiveScan()
		scanner.SetLevel(p.MaxLevel)
		scanner.SetUID(common.GenerateUniqueStr())
		scanner.SetProcCallback(p.Distibition)
		scanner.SetTimeoutPerProbe(p.Timeout)
		scanner.SetAttemptTimes(p.NumOfAttempts)
		scanner.SetMsgCallback(p.HandleMsg)
		scanner.SetNotifyChannel(&p.NotifyChannel)
		p.Scanners[p.MaxLevel] = append(p.Scanners[p.MaxLevel], scanner)
	}

	// 这个地方根据扫描器个数，通知
	p.NotifyChannel = make(chan *scanner.ScannerMSG, p.GetCountOfScanners())
	// 填充参数
	// 每个IP作为一单元进行分配
	p.Entities = append(p.Entities, p.spliteTask(tps)...)
	countOfTasks := len(p.Entities)

	for k, v := range p.Scanners {
		for _, scanner := range v {
			// 设置每个扫描器要执行的任务总数
			// 这个目的是为了方便一直等待任务的到来，要处理所有的数据
			scanner.SetCountOfTasks(countOfTasks)
			// 把数压入第一个层级的数据参数执行栈中
			if k == 1 {
				scanner.PutDataSet(p.Entities)
			}
		}
	}

	// 调整并发的运行性能
	p.cpucorecount = common.GetCPUCoreCount()
	common.SetGOMAXPROCS(p.cpucorecount)
	// 最大的任务量默认设置为cpu核心数量
	if p.MaxTaskPool == 0 {
		p.MaxTaskPool = p.cpucorecount
	}

	return nil
}

func (p *ProbeManager) IPtoTargetIP(IPs []net.IP) ([]*TargetIP, error) {
	if len(IPs) == 0 {
		return nil, errors.New("")
	}
	result := make([]*TargetIP, 0)
	for _, ip := range IPs {
		targetIP := NewTargetIP()
		if p.IsPingTest {
			bPT, _ := scanner.PingTest(ip.String())
			if bPT {
				targetIP.IsUp = true
				p.CountOfHostup++
			} else {
				targetIP.IsUp = false
			}
		}

		if p.ScanType == scanner.ScanType_Syn {
			// np, err := device.GetNexthopByIP(ip)
			np, err := device.GetNexthopByIPandInterface(ip, p.II)
			if err != nil {
				continue
			}
			targetIP.Nexthops = append(targetIP.Nexthops, np...)
		}

		targetIP.IP = ip
		result = append(result, targetIP)
	}

	return result, nil
}

// 分割任务
func (p *ProbeManager) spliteTask(targetIPs []*TargetIP) []*scanner.ScanTargetEntity {
	result := make([]*scanner.ScanTargetEntity, 0)
	srcPort := uint16(rawsock.GeneratePort())
	for _, targetIP := range targetIPs {
		if p.ScanType == scanner.ScanType_Syn {
			ste := scanner.NewScanTargetEntity()
			ste.CurrentLevel = 1
			// 初始化扫描实体的IP和下一跳地址
			ste.IP = append(ste.IP, targetIP.IP...)
			ste.IsUp = targetIP.IsUp
			ste.Nexthops = append(ste.Nexthops, targetIP.Nexthops...)
			ste.PortScanType = p.ScanType
			ste.NumOfAttempts = p.NumOfAttempts
			for _, item := range p.Ports {
				pPort := scanner.NewPort()
				pPort.SrcPort = srcPort
				pPort.Val = item
				pPort.PortType = scanner.PortType_TCP
				pPort.State = scanner.PortState_Unknown
				pPort.NmapSeviceInfo = append(pPort.NmapSeviceInfo, nmap_service_probe.GetNmapServiceNode(int(item))...)
				pPort.NmapServiceName = pPort.ToNSServiceName()
				ste.TargetPort = append(ste.TargetPort, pPort)
			}

			result = append(result, ste)
		} else {
			step := 10
			if len(p.Ports)/step <= 50 {
				step = 2
			} else if len(p.Ports)/step > 50 && len(p.Ports)/step <= 200 {
				step = 5
			} else if len(p.Ports)/step > 200 {
				step = 20
			}
			startPoint := 0
			endPoint := step
			for {
				if startPoint >= len(p.Ports) {
					break
				}
				ste := scanner.NewScanTargetEntity()
				ste.CurrentLevel = 1
				// 初始化扫描实体的IP和下一跳地址
				ste.IP = append(ste.IP, targetIP.IP...)
				ste.IsUp = targetIP.IsUp
				ste.Nexthops = append(ste.Nexthops, targetIP.Nexthops...)
				ste.NumOfAttempts = p.NumOfAttempts
				ste.PortScanType = p.ScanType
				if len(p.Ports) < endPoint {
					endPoint = len(p.Ports)
				}

				for _, item := range p.Ports[startPoint:endPoint] {
					pPort := scanner.NewPort()
					pPort.SrcPort = srcPort
					pPort.Val = item
					pPort.PortType = scanner.PortType_TCP
					pPort.State = scanner.PortState_Unknown
					pPort.NmapSeviceInfo = append(pPort.NmapSeviceInfo, nmap_service_probe.GetNmapServiceNode(int(item))...)
					pPort.NmapServiceName = pPort.ToNSServiceName()
					ste.TargetPort = append(ste.TargetPort, pPort)
				}

				result = append(result, ste)

				startPoint = startPoint + step
				endPoint = endPoint + step

			}
		}

	}

	return result
}

// 扫描探测处理
func (p *ProbeManager) Do() {
	// 处理中断信号
	signalProcess := func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		for s := range ch {
			switch s {
			case syscall.SIGINT, syscall.SIGTERM:
				p.Close()
			}
		}
	}
	go signalProcess()
	// 记录启动时间
	p.startTime = time.Now()

	// 遍历所有的扫描器，并启动等待操作
	for k, _ := range p.Scanners {
		for _, scanner := range p.Scanners[k] {
			p.WgWorker.Add(1)
			go func() {
				err := scanner.Ready()
				if err != nil {
					log.Logger.Error(scanner.GetScannerName(), err)
					p.WgWorker.Done()
					return
				}
				err = scanner.Run(&p.WgWorker)
				if err != nil {
					log.Logger.Error(err)
				}
			}()

		}
	}
}

func (p *ProbeManager) Wait() {
	p.WgWorker.Wait()
}

func (p *ProbeManager) Close() {
	for k, _ := range p.Scanners {
		for _, scanner := range p.Scanners[k] {
			scanner.Terminate()
		}
	}
}

func (p *ProbeManager) WaitTimeout(period time.Duration) error {
	ret, err := common.WaitTimeout(&p.WgWorker, period)
	if ret == false {
		log.Logger.Error(err)
		return err
	}

	return nil
}

func (p *ProbeManager) HandleMsg(msg *scanner.ScannerMSG) {
	return
}

func (p *ProbeManager) Distibition(entity *scanner.ScanTargetEntity) {

	sublevel := p.MaxLevel - entity.CurrentLevel
	if sublevel == 0 {
		p.ResultSet.Push(entity)
	} else if sublevel > 0 {
		entity.CurrentLevel += 1
		for _, scanner := range p.Scanners[entity.CurrentLevel] {
			scanner.Push(entity)
		}
	} else {
		log.Logger.Error("the level is wrong.")
	}

}

func (p *ProbeManager) PrintBanner() {
	flag := `
  ________                       
 /  _____/  _____ _____  ______  
/   \  ___ /     \\__  \ \____ \ 
\    \_\  \  Y Y  \/ __ \|  |_> >
 \______  /__|_|  (____  /   __/ 
        \/      \/     \/|__|   
`
	fmt.Println(flag)
	formattedTime := time.Now().Format("2006-1-2  15:04:05")
	fmt.Println("Starting Gmap at ", formattedTime)
}

func (p *ProbeManager) PrintResult() {
	sets := make(map[string][]*scanner.Port)
	for _, entity := range p.Entities {
		for _, item := range entity.TargetPort {
			_, ok := sets[entity.IP.String()]
			if !ok {
				sets[entity.IP.String()] = make([]*scanner.Port, 0)
			}

			sets[entity.IP.String()] = append(sets[entity.IP.String()], item)
		}
	}
	for k, v := range sets {
		fmt.Println("---------------------------------------")
		top := fmt.Sprintf(": %-20v", k)
		fmt.Println(top)
		header := fmt.Sprintf("%-15v %-10v %-20v", "PROT", "STATE", "SERVICE")
		fmt.Println(header)
		var countofClosed int
		var countofFiltered int
		for _, item := range v {
			if item.State == scanner.PortState_Closed {
				countofClosed++
				continue
			} else if item.State == scanner.PortState_Filtered || item.State == scanner.PortState_Unknown {
				countofFiltered++
				continue
			}
			var info string
			info = fmt.Sprintf("%-15v %-10v %-20v",
				item.ToPortValString()+"/"+item.ToPortTypeString(),
				item.ToStateString(),
				item.ToNSServiceName())
			fmt.Println(info)
		}

		// 打印结尾
		bottom := fmt.Sprintf("\n:%v ports are closed  %v ports are filtered", countofClosed, countofFiltered)
		fmt.Println(bottom)
	}

	end := fmt.Sprintf("\nGmap done: %v IP address (%v host up) scanned in %v seconds",
		len(sets),
		p.CountOfHostup,
		time.Now().Sub(p.startTime).Seconds())

	fmt.Println(end)
}

// 结果输出为json
func (p *ProbeManager) Result2JSON() (string, error) {
	resultSet := &ResultSet{
		Targets: make([]*Target, 0),
	}

	resultSet.StartTime = p.startTime
	resultSet.EndTime = time.Now()
	resultSet.PortScanned = append(resultSet.PortScanned, p.Ports...)

	tmpContainer := make(map[string]*Target)

	for _, item := range p.Entities {
		_, ok := tmpContainer[item.IP.String()]
		if !ok {
			tmpContainer[item.IP.String()] = &Target{
				OpenPorts:     make([]*scanner.Port, 0),
				FilteredPorts: make([]*scanner.Port, 0),
				ClosedPorts:   make([]*scanner.Port, 0),
			}

			tmpContainer[item.IP.String()].IP = item.IP.String()
			tmpContainer[item.IP.String()].IsUp = item.IsUp
		}
		for _, tp := range item.TargetPort {
			switch tp.State {
			case scanner.PortState_Open:
				tmpContainer[item.IP.String()].OpenPorts = append(tmpContainer[item.IP.String()].OpenPorts, tp)
			case scanner.PortState_Filtered, scanner.PortState_Unknown:
				tmpContainer[item.IP.String()].FilteredPorts = append(tmpContainer[item.IP.String()].FilteredPorts, tp)
			case scanner.PortState_Closed:
				tmpContainer[item.IP.String()].FilteredPorts = append(tmpContainer[item.IP.String()].FilteredPorts, tp)
			}
		}
	}

	for _, item := range tmpContainer {
		resultSet.Targets = append(resultSet.Targets, item)
	}

	return common.ToJsonEncodeStruct(resultSet), nil
}
