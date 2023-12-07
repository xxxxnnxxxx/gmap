package manage

type Option struct {
	Name   string
	HasArg int
	Flag   string
	Val    int
}

// 分析参数
func (p *ProbeManager) ParseOptions() error {
	return nil
}
