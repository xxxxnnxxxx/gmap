package srvprobe

import (
	"Gmap/gmap/common"
	"Gmap/gmap/functions/nmap_service_probe"
	"Gmap/gmap/log"
	"Gmap/gmap/manage/scanner"
	"errors"
	"fmt"
	"github.com/panjf2000/ants/v2"
	"net"
	"path"
	"sync"
	"time"
)

// 服务探测扫描
type SrvDetectiveScan struct {
	DetectiveType int // 扫描类型

	ProcCallback  func(result *scanner.ScanTargetEntity) // 处理回调
	MsgCallback   func(msg *scanner.ScannerMSG)          // 消息回调
	notifyChannel *chan *scanner.ScannerMSG

	level        int                // 层级号
	uid          string             // 当前层级唯一编号
	taskStack    *common.Stack      // 任务栈
	taskPool     *ants.PoolWithFunc // 例程池函数
	timeout      float64            // 每次探测时间
	attemptTimes int                // 尝试次数
	maxTaskPool  int                // 最大任务池
	countOfTasks int                // 任务个数
	state        int                // 状态 0 close 1 running 2 terminated

	nsp *nmap_service_probe.NmapServiceProbe // nmap 扫描数据库
}

func NewSrvDetectiveScan() *SrvDetectiveScan {
	return &SrvDetectiveScan{
		taskStack:   common.NewStack(),
		maxTaskPool: 20, // 默认值
		state:       0,  // 0 表示不在运行
		nsp:         nmap_service_probe.NewNmapServiceProbe(),
	}
}

func (p *SrvDetectiveScan) PutDataSet(dataset []*scanner.ScanTargetEntity) {
	for _, item := range dataset {
		p.Push(item)
	}
}

func (p *SrvDetectiveScan) Push(data interface{}) {
	p.taskStack.Push(data)
}

func (p *SrvDetectiveScan) SetProcCallback(f func(entity *scanner.ScanTargetEntity)) {
	p.ProcCallback = f
}
func (p *SrvDetectiveScan) SetMsgCallback(f func(msg *scanner.ScannerMSG)) {
	p.MsgCallback = f
}

func (p *SrvDetectiveScan) SetNotifyChannel(c *chan *scanner.ScannerMSG) {
	p.notifyChannel = c
}
func (p *SrvDetectiveScan) SetMaxTaskPool(count int) {
	p.maxTaskPool = count
}

func (p *SrvDetectiveScan) SetCountOfTasks(count int) {
	p.countOfTasks = count
}

// 每次探测时间
func (p *SrvDetectiveScan) SetTimeoutPerProbe(t float64) {
	p.timeout = t
}

func (p *SrvDetectiveScan) SetAttemptTimes(count int) {
	p.attemptTimes = count
}

func (p *SrvDetectiveScan) Ready() error {
	err := p.createTaskPool()
	if err != nil {
		return err
	}

	err = p.loadNmapServiceProbeLib()
	if err != nil {
		return err
	}

	return nil
}

func (p *SrvDetectiveScan) Run(wg *sync.WaitGroup) error {
	defer wg.Done()
	log.Logger.Info("srvprobe is running.")
	p.state = scanner.ScannerState_Running // 运行状态
	for {
		reqTask := p.taskStack.Pop()
		if reqTask != nil {
			if entity, ok := reqTask.(*scanner.ScanTargetEntity); ok {
				p.countOfTasks-- // 每次减少要执行的任务总数
				_ = p.taskPool.Invoke(entity)
			}
		}

		if p.state == scanner.ScannerState_Stop {
			if p.taskPool.Running() > 0 {
				time.Sleep(10 * time.Millisecond)
			} else {
				break
			}
		} else if p.state == scanner.ScannerState_Running {
			if p.taskPool.Running() > 0 { // 这个地方可能存在问题，导致后面没有栈可能暂时没有任务，然后没有处理就已经退出了
				time.Sleep(10 * time.Millisecond)
			} else {
				if p.countOfTasks > 0 {
					continue
				} else {
					p.state = scanner.ScannerState_Stop
					break
				}
			}
		} else if p.state == scanner.ScannerState_Terminated {
			if p.MsgCallback != nil {
				msg := &scanner.ScannerMSG{
					MSG:   p.state,
					Level: p.GetLevel(),
				}
				p.MsgCallback(msg)
			}

			return errors.New("the scanner is terminated")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if p.MsgCallback != nil {
		msg := &scanner.ScannerMSG{
			MSG:   p.state,
			Level: p.GetLevel(),
		}
		p.MsgCallback(msg)
	}
	log.Logger.Info("srvprobe is stopped")
	return nil
}

func (p *SrvDetectiveScan) Close() {
	p.state = scanner.ScannerState_Stop
}

func (p *SrvDetectiveScan) Terminate() {
	p.state = 2
}

func (p *SrvDetectiveScan) GetState() int {
	return p.state
}

// 属性
func (p *SrvDetectiveScan) GetScanType() int {
	return scanner.ScannerType_SrvDetection
}
func (p *SrvDetectiveScan) GetLevel() int {
	return p.level
}

func (p *SrvDetectiveScan) SetLevel(level int) {
	p.level = level
}

func (p *SrvDetectiveScan) GetUID() string {
	return p.uid
}

func (p *SrvDetectiveScan) SetUID(uid string) {
	p.uid = uid
}

func (p *SrvDetectiveScan) GetScannerName() string {
	return "ServiceDetective"
}

func (p *SrvDetectiveScan) worker(param interface{}) {
	ste, ok := param.(*scanner.ScanTargetEntity)
	if ok {
		if ste.CurrentLevel&p.level > 0 {
			info := fmt.Sprintf("service is probing: %v", ste.IP.String())
			log.Logger.Info(info)
			// TODO: 在这个地方探测各种相关的服务内容
			p.detectiveService(ste)
			info = fmt.Sprintf("service is end: %v", ste.IP.String())
			log.Logger.Info(info)
		}

	}
}

// 创建任务执行池
func (p *SrvDetectiveScan) createTaskPool() error {
	// 创建工作池
	var err error
	p.taskPool, err = ants.NewPoolWithFunc(p.maxTaskPool, p.worker) //
	if err != nil {
		log.Logger.Error(err)
		return err
	}
	return nil
}

// 记载nmap 服务探测库
func (p *SrvDetectiveScan) loadNmapServiceProbeLib() error {
	currentDir, err := common.GetCurrentDir()
	if err != nil {
		return err
	}
	_, err = p.nsp.LoadNmapServiceProbes(path.Join(currentDir, "data", "nmap-service-probes"))
	if err != nil {
		return err
	}

	// 整理所有的端口和节点对应
	p.nsp.ArrangeProbeNodes()
	return nil
}

// 根据扫描实体，探测相关的服务
func (p *SrvDetectiveScan) detectiveService(entity *scanner.ScanTargetEntity) error {
	// 得到所有的有效端口
	portsOpened := make([]*scanner.Port, 0)
	for _, port := range entity.TargetPort {
		if port.PortType == scanner.PortType_TCP && port.State == scanner.PortState_Open {
			portsOpened = append(portsOpened, port)
		}
	}

	// 根据端口和协议，获取所有的
	wait := new(sync.WaitGroup)
	for _, item := range portsOpened {
		wait.Add(1)
		pPort := item
		go p.srvprobeHandle(wait, entity.IP, pPort)
	}

	wait.Wait()
	return nil
}

func (p *SrvDetectiveScan) srvprobeHandle(wg *sync.WaitGroup, ip net.IP, port *scanner.Port) error {
	defer wg.Done()
	if port == nil {
		return errors.New("port is empty")
	}
	_, ok := p.nsp.PortsToNodes[port.Val]
	if ok {
		for _, item := range p.nsp.PortsToNodes[port.Val] {
			srvinfo, err := item.Method.Method(item, port.PortType, false, ip.String(), port.Val)
			if err == nil {
				if len(srvinfo) > 0 {
					port.SrvInfo = append(port.SrvInfo, srvinfo...)
					break
				} else {
					continue
				}
			}
		}
	}

	_, ok = p.nsp.SSLPortsToNodes[port.Val]
	if ok {
		for _, item := range p.nsp.SSLPortsToNodes[port.Val] {
			srvinfo, err := item.Method.Method(item, port.PortType, true, ip.String(), port.Val)
			if err == nil {
				if len(srvinfo) > 0 {
					port.SrvInfo = append(port.SrvInfo, srvinfo...)
					break
				} else {
					continue
				}
			}
		}
	}

	return nil
}
