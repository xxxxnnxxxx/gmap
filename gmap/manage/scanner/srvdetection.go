package scanner

import (
	"Gmap/gmap/common"
	"Gmap/gmap/functions/nmap_service_probe"
	"Gmap/gmap/log"
	"errors"
	"github.com/panjf2000/ants/v2"
	"path"
	"sync"
	"time"
)

// 服务探测扫描
type SrvDetectiveScan struct {
	DetectiveType int // 扫描类型

	ProcCallback  func(result *ScanTargetEntity) // 处理回调
	MsgCallback   func(msg *ScannerMSG)          // 消息回调
	notifyChannel *chan *ScannerMSG

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
		maxTaskPool: 10, // 默认值
		state:       0,  // 0 表示不在运行
	}
}

func (p *SrvDetectiveScan) PutDataSet(dataset []*ScanTargetEntity) {
	for _, item := range dataset {
		p.Push(item)
	}
}

func (p *SrvDetectiveScan) Push(data interface{}) {
	p.taskStack.Push(data)
}

func (p *SrvDetectiveScan) SetProcCallback(f func(entity *ScanTargetEntity)) {
	p.ProcCallback = f
}
func (p *SrvDetectiveScan) SetMsgCallback(f func(msg *ScannerMSG)) {
	p.MsgCallback = f
}

func (p *SrvDetectiveScan) SetNotifyChannel(c *chan *ScannerMSG) {
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
	log.Logger.Info("ServiceDetective is running.")
	defer wg.Done()
	p.state = ScannerState_Running // 运行状态
	for {
		reqTask := p.taskStack.Pop()
		if reqTask != nil {
			if entity, ok := reqTask.(*ScanTargetEntity); ok {
				p.countOfTasks-- // 每次减少要执行的任务总数
				_ = p.taskPool.Invoke(entity)
			}
		}

		if p.state == ScannerState_Stop {
			wgTaskPool := new(sync.WaitGroup)
			wgTaskPool.Add(1)
			go func(group *sync.WaitGroup) {
				defer group.Done()
				for {
					if p.taskPool.Running() > 0 {
						time.Sleep(50 * time.Millisecond)
					} else {
						break
					}
				}
			}(wgTaskPool)

			wgTaskPool.Wait()
		} else if p.state == ScannerState_Running {
			if p.taskPool.Running() > 0 { // 这个地方可能存在问题，导致后面没有栈可能暂时没有任务，然后没有处理就已经退出了
				time.Sleep(50 * time.Millisecond)
			} else {
				if p.countOfTasks > 0 {
					continue
				} else {
					p.state = ScannerState_Stop
					break
				}
			}
		} else if p.state == ScannerState_Terminated {
			if p.MsgCallback != nil {
				msg := &ScannerMSG{
					MSG:   p.state,
					Level: p.GetLevel(),
				}
				p.MsgCallback(msg)
			}
			return errors.New("the scanner is terminated")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if p.MsgCallback != nil {
		msg := &ScannerMSG{
			MSG:   p.state,
			Level: p.GetLevel(),
		}
		p.MsgCallback(msg)
	}
	log.Logger.Info("ServiceDetective is stopped.")
	return nil
}

func (p *SrvDetectiveScan) Close() {
	p.state = 0
}

func (p *SrvDetectiveScan) Terminate() {
	p.state = 2
}

func (p *SrvDetectiveScan) GetState() int {
	return p.state
}

// 属性
func (p *SrvDetectiveScan) GetScanType() int {
	return ScannerType_SrvDetection
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
	ste, ok := param.(*ScanTargetEntity)
	if ok {
		if ste.CurrentLevel&p.level > 0 {
			var waitSubTask sync.WaitGroup
			waitSubTask.Add(1)
			go func(waits *sync.WaitGroup) {
				defer waits.Done()

			}(&waitSubTask)

			waitSubTask.Wait()
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
	nsp := nmap_service_probe.NewNmapServiceProbe()
	currentDir, err := common.GetCurrentDir()
	if err != nil {
		return err
	}
	_, err = nsp.LoadNmapServiceProbes(path.Join(currentDir, "data", "nmap-service-probes"))
	if err != nil {
		return err
	}

	return nil
}

// 根据扫描实体，探测相关的服务
func (p *SrvDetectiveScan) detectiveService(entity *ScanTargetEntity) error {
	// 得到所有的有效端口
	portsOpened := make([]*Port, 0)
	for _, port := range entity.TargetPort {
		if port.PortType == PortType_TCP && port.State == PortState_Open {
			portsOpened = append(portsOpened, port)
		}
	}

	// 根据端口和协议，获取所有的
	return nil
}
