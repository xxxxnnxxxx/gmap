package scanner

import (
	"Gmap/gmap/common"
	"Gmap/gmap/log"
	"errors"
	"fmt"
	"github.com/panjf2000/ants/v2"
	"sync"
	"time"
)

type PortScan struct {
	ScanType int // 扫描类型

	ProcCallback  func(result *ScanTargetEntity) // 处理回调
	MsgCallback   func(msg *ScannerMSG)          // 消息回调
	notifyChannel *chan *ScannerMSG

	level        int                // 层级号
	uid          string             // 当前层级唯一编号
	taskStack    *common.Stack      // 任务栈
	taskPool     *ants.PoolWithFunc // 例程池函数
	timeout      float64            // 每次探测时间
	attemptTimes int                // 尝试次数
	maxTaskPool  int                // 子任务个数， 当多个端口扫描的情况下
	countOfTasks int                // 任务总数
	state        int                // 状态 0 close 1 running 2 terminated

	startTime time.Time // 启动时间
}

func NewPortScanner() *PortScan {
	return &PortScan{
		taskStack:   common.NewStack(),
		maxTaskPool: 50, // 默认值
		state:       0,  // 0 表示不在运行
	}
}

func (p *PortScan) PutDataSet(dataset []*ScanTargetEntity) {
	for _, item := range dataset {
		p.Push(item)
	}
}

func (p *PortScan) Push(data interface{}) {
	p.taskStack.Push(data)
}

// 设置处理过程回调
func (p *PortScan) SetProcCallback(f func(entity *ScanTargetEntity)) {
	p.ProcCallback = f
}

func (p *PortScan) SetMsgCallback(f func(msg *ScannerMSG)) {
	p.MsgCallback = f
}

func (p *PortScan) SetNotifyChannel(c *chan *ScannerMSG) {
	p.notifyChannel = c
}

func (p *PortScan) SetMaxTaskPool(count int) {
	p.maxTaskPool = count
}

// 设置任务总数
func (p *PortScan) SetCountOfTasks(count int) {
	p.countOfTasks = count
}

// 每次探测时间
func (p *PortScan) SetTimeoutPerProbe(t float64) {
	p.timeout = t
}

func (p *PortScan) SetAttemptTimes(count int) {
	p.attemptTimes = count
}

func (p *PortScan) Ready() error {
	err := p.createTaskPool()
	if err != nil {
		return err
	}

	return nil
}

// 启动
func (p *PortScan) Run(wg *sync.WaitGroup) error {
	log.Logger.Info("PortScan is running.")
	defer wg.Done()
	p.state = ScannerState_Running // 运行状态
	for {
		reqTask := p.taskStack.Pop()
		if reqTask != nil {
			if entity, ok := reqTask.(*ScanTargetEntity); ok {
				p.countOfTasks--
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
						time.Sleep(10 * time.Millisecond)
					} else {
						break
					}
				}
			}(wgTaskPool)

			wgTaskPool.Wait()
		} else if p.state == ScannerState_Running {
			if p.taskPool.Running() > 0 { // 这个地方可能存在问题，导致后面没有栈可能暂时没有任务，然后没有处理就已经退出了
				time.Sleep(10 * time.Millisecond)
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
		time.Sleep(10 * time.Millisecond)
	}
	if p.MsgCallback != nil {
		msg := &ScannerMSG{
			MSG:   p.state,
			Level: p.GetLevel(),
		}
		p.MsgCallback(msg)
	}
	log.Logger.Info("PortScan is stopped.")
	return nil
}

// 关闭
func (p *PortScan) Close() {
	p.state = ScannerState_Stop
}

func (p *PortScan) Terminate() {
	p.state = 2
}

func (p *PortScan) GetScanType() int {
	return ScannerType_PortScan
}

func (p *PortScan) GetLevel() int {
	return p.level
}

func (p *PortScan) SetLevel(level int) {
	p.level = level
}

func (p *PortScan) GetUID() string {
	return p.uid
}

func (p *PortScan) GetState() int {
	return p.state
}

func (p *PortScan) SetUID(uid string) {
	p.uid = uid
}

func (p *PortScan) GetScannerName() string {
	return "PortScanner"
}

func (p *PortScan) worker(param interface{}) {
	ste, ok := param.(*ScanTargetEntity)
	if ok {
		if ste.CurrentLevel&p.level > 0 && ste.Nexthops != nil {
			info := fmt.Sprintf("port scanning: %v", ste.IP.String())
			log.Logger.Info(info)
			var waitSubTask sync.WaitGroup
			waitSubTask.Add(1)
			go func(waits *sync.WaitGroup) {
				defer waits.Done()
				switch ste.PortScanType {
				case ScanType_TCPConn:
					p.sendTCPConnectionProbe(ste)
				case ScanType_Syn:
					p.sendTCPSynProbe(ste)
				}
			}(&waitSubTask)

			waitSubTask.Wait()
			info = fmt.Sprintf("port end: %v", ste.IP.String())
			log.Logger.Info(info)
		}

	}
}

// 创建任务执行池
func (p *PortScan) createTaskPool() error {
	// 创建工作池
	var err error
	p.taskPool, err = ants.NewPoolWithFunc(p.maxTaskPool, p.worker) //
	if err != nil {
		log.Logger.Error(err)
		return err
	}
	return nil
}

// TCP 连接扫描
func (p *PortScan) sendTCPConnectionProbe(entity *ScanTargetEntity) {
	if entity == nil {
		return
	}

	TCPConnectProbe(entity)

	go p.ProcCallback(entity)
}

// TCP SYN扫描
func (p *PortScan) sendTCPSynProbe(entity *ScanTargetEntity) {
	if entity == nil {
		return
	}

	TCPSynProbe(entity)

	go p.ProcCallback(entity)
}

func (p *PortScan) sendUDPProbe(entity *ScanTargetEntity) {
	if entity == nil {
		return
	}

}
