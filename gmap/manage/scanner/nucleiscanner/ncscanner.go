package nucleiscanner

import (
	"Gmap/gmap/common"
	"Gmap/gmap/log"
	"Gmap/gmap/manage/scanner"
	"errors"
	"fmt"
	"github.com/panjf2000/ants/v2"
	"sync"
	"time"
)

type NucleiScanner struct {
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
}

func (p *NucleiScanner) PutDataSet(dataset []*scanner.ScanTargetEntity) {
	for _, item := range dataset {
		p.Push(item)
	}
}

func (p *NucleiScanner) Push(data interface{}) {
	p.taskStack.Push(data)
}

func (p *NucleiScanner) SetProcCallback(f func(entity *scanner.ScanTargetEntity)) {
	p.ProcCallback = f
}
func (p *NucleiScanner) SetMsgCallback(f func(msg *scanner.ScannerMSG)) {
	p.MsgCallback = f
}

func (p *NucleiScanner) SetNotifyChannel(c *chan *scanner.ScannerMSG) {
	p.notifyChannel = c
}
func (p *NucleiScanner) SetMaxTaskPool(count int) {
	p.maxTaskPool = count
}

func (p *NucleiScanner) SetCountOfTasks(count int) {
	p.countOfTasks = count
}

// 每次探测时间
func (p *NucleiScanner) SetTimeoutPerProbe(t float64) {
	p.timeout = t
}

func (p *NucleiScanner) SetAttemptTimes(count int) {
	p.attemptTimes = count
}

func (p *NucleiScanner) Ready() error {
	err := p.createTaskPool()
	if err != nil {
		return err
	}

	return nil
}

func (p *NucleiScanner) Run(wg *sync.WaitGroup) error {
	defer wg.Done()
	log.Logger.Info("NucleiScan is running.")
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

			return errors.New("the NucleiScan is terminated")
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
	log.Logger.Info("NucleiScan is stopped")
	return nil
}

func (p *NucleiScanner) Close() {
	p.state = scanner.ScannerState_Stop
}

func (p *NucleiScanner) Terminate() {
	p.state = 2
}

func (p *NucleiScanner) GetState() int {
	return p.state
}

// 属性
func (p *NucleiScanner) GetScanType() int {
	return scanner.ScannerType_NucleiScan
}
func (p *NucleiScanner) GetLevel() int {
	return p.level
}

func (p *NucleiScanner) SetLevel(level int) {
	p.level = level
}

func (p *NucleiScanner) GetUID() string {
	return p.uid
}

func (p *NucleiScanner) SetUID(uid string) {
	p.uid = uid
}

func (p *NucleiScanner) GetScannerName() string {
	return "NucleiScanner"
}

func (p *NucleiScanner) worker(param interface{}) {
	ste, ok := param.(*scanner.ScanTargetEntity)
	if ok {
		if ste.CurrentLevel&p.level > 0 {
			info := fmt.Sprintf("service probe is probing: %v", ste.IP.String())
			log.Logger.Info(info)
			// TODO: 在这个地方探测各种相关的服务内容
			p.detectiveInfo(ste)

			info = fmt.Sprintf("service probe is end: %v", ste.IP.String())
			log.Logger.Info(info)
		}

	}
}

// 创建任务执行池
func (p *NucleiScanner) createTaskPool() error {
	// 创建工作池
	var err error
	p.taskPool, err = ants.NewPoolWithFunc(p.maxTaskPool, p.worker) //
	if err != nil {
		log.Logger.Error(err)
		return err
	}
	return nil
}

func (p *NucleiScanner) detectiveInfo(entity *scanner.ScanTargetEntity) error {
	return nil
}
