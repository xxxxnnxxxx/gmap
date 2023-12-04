package scanner

import (
	"sync"
)

// 扫描类型
// 端口扫描，服务扫描等
const (
	ScannerType_PortScan     = 1 // 端口扫描
	ScannerType_SrvDetection = 2 // 服务探测
	ScannerType_WebVulnScan  = 4 // Web漏洞扫描
)

// 扫描器状态
const (
	ScannerState_Stop = iota
	ScannerState_Running
	ScannerState_Terminated
)

// 端口的状态
const (
	PortState_Unknown = iota
	PortState_Open
	PortState_Closed
	PortState_Filtered
	PortState_Ignored
)

const (
	PortType_TCP = iota
	PortType_UDP
	PortType_SCP // scp也是基于tcp基础上的一套协议
)

// 端口扫描的类型
const (
	ScanType_Unknown = iota
	ScanType_TCPConn // tcp 连接扫描
	ScanType_Syn     // SYN扫描
	ScanType_UDP     // UDP 扫描
)

const (
	ScannerMSG_Unknown = iota
	ScannerMSG_Start
	ScannerMSG_Running
	ScannerMSG_Finished
)

// 扫描器通知结构
type ScannerMSG struct {
	MSG   int // 消息类型
	Level int // 扫描器层级

}

/*
扫描接口
*/
type IScanner interface {
	PutDataSet([]*ScanTargetEntity)                 // 放入数据集合
	Push(interface{})                               // 单独压入到数据栈
	SetProcCallback(func(entity *ScanTargetEntity)) // 处理过程回调
	SetMsgCallback(func(msg *ScannerMSG))           // 设置消息回调
	SetNotifyChannel(nc *chan *ScannerMSG)          // 设置获取接收通知的通道
	SetMaxTaskPool(int)                             // 设置任务池最大数
	SetCountOfTasks(int)                            // 设置任务总数
	SetTimeoutPerProbe(float64)                     // 设置最大超时时间， 比如每次尝试连接探测的最大超时时间
	SetAttemptTimes(int)                            // 尝试次数
	Ready() error                                   // 准备
	Run(*sync.WaitGroup) error                      // 处理事务
	Close()                                         // 关闭
	Terminate()                                     // 终止

	// 属性
	GetState() int          // 获取扫描器状态
	GetScanType() int       // 获取扫描类型，根据这个类型，对应的不同的参数数据
	GetLevel() int          // 得到当前扫描的层级
	SetLevel(int)           // 设置层级
	GetScannerName() string // 获取扫描器的名字
	GetUID() string         // 得到当前扫描模块的唯一序列
	SetUID(string)          // 设置序列号
}
