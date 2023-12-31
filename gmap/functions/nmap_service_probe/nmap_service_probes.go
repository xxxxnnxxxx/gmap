package nmap_service_probe

import (
	"Gmap/gmap/common"
	"bufio"
	"encoding/hex"
	"errors"
	"github.com/dlclark/regexp2"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 探测协议
const (
	ProbeProtocol_TCP int = 0
	ProbeProtocol_UDP int = 1
)

type Exclude struct {
	UDPPort []uint16
	TCPPort []uint16
}

func NewExclude() *Exclude {
	return &Exclude{
		UDPPort: make([]uint16, 0),
		TCPPort: make([]uint16, 0),
	}
}

func (p *Exclude) Analyze(script string) error {
	if len(script) == 0 {
		return nil
	}
	rules := strings.Split(script, ",")
	for _, rule := range rules {
		if len(rule) >= 2 {
			switch rule[:2] {
			case "T:":
				p.TCPPort = append(p.TCPPort, common.Splite_Port(rule[3:])...)
			case "U:":
				p.UDPPort = append(p.UDPPort, common.Splite_Port(rule[3:])...)
			default:
				ps, err := strconv.Atoi(rule)
				if err == nil {
					p.TCPPort = append(p.TCPPort, uint16(ps))
					p.UDPPort = append(p.UDPPort, uint16(ps))
				}
			}
		} else {
			ps, err := strconv.Atoi(rule)
			if err == nil {
				p.TCPPort = append(p.TCPPort, uint16(ps))
				p.UDPPort = append(p.UDPPort, uint16(ps))
			}
		}
	}
	return nil
}

func (p *Exclude) ContainPortInTCP(port uint16) bool {
	return false
}

func (p *Exclude) ContainPortInUDP(port uint16) bool {
	return false
}

// Probe 节点
type NmapServiceProbeNode struct {
	Protocol    int    // 协议
	Probename   string // 探测名称
	Probestring string // 探测字符串
	Method      *ProbeMethod

	Tcpwrappedms int //
	Totalwaitms  int
	Rarity       int8     // 稀有度指令大致对应于该探测器返回有用结果的频率。
	Ports        []uint16 // 端口
	SSLPorts     []uint16

	Matchs     []*MatchMethod
	Fallback1  *Fallback // 当当前的探测没有匹配的情况下，则顺序执行这个回退，查找匹配
	NoPlayload bool      // ???
}

func NewProbeNode() *NmapServiceProbeNode {
	return &NmapServiceProbeNode{
		Ports:      make([]uint16, 0),
		Matchs:     make([]*MatchMethod, 0),
		Fallback1:  NewFallback(),
		NoPlayload: false,
	}
}

// 字符串转码
func (p *NmapServiceProbeNode) stringUnescape(escape string) string {
	result := make([]byte, 0)
	i := 0
	for {
		if i >= len(escape) {
			break
		}

		if escape[i] == '\\' {
			i++
			switch escape[i] {
			case '0':
				result = append(result, '\x00')
				i++
			case 'a':
				result = append(result, '\a')
				i++
			case 'b':
				result = append(result, '\b')
				i++
			case 'f':
				result = append(result, '\f')
				i++
			case 'n':
				result = append(result, '\n')
				i++
			case 'r':
				result = append(result, '\r')
				i++
			case 't':
				result = append(result, '\t')
				i++
			case 'x':
				i++
				if i >= len(escape) || i+1 > len(escape) {
					return ""
				}
				b, err := hex.DecodeString(escape[i : i+2])
				if err != nil {
					return ""
				}

				result = append(result, b...)
				i += 2
			default:
				if escape[i] >= '0' && escape[i] <= '9' {
					return ""
				}
				result = append(result, escape[i])
				i++
			}
		} else {
			result = append(result, escape[i])
			i++
		}
	}

	return string(result)
}

func (p *NmapServiceProbeNode) Analyze(script string) error {
	rules, err := common.Splite_Space(script, 3)
	if err != nil {
		return err
	}
	// protocol
	switch rules[0] {
	case "TCP":
		p.Protocol = ProbeProtocol_TCP
	case "UDP":
		p.Protocol = ProbeProtocol_UDP
	default:
		return errors.New("probe script error")
	}
	// probename
	p.Probename = rules[1]
	p.Method = GetProbeMethod(p.Probename)
	// probestring
	var begin = 2
	var end = 0
	if len(rules[2]) == 3 {
		p.Probestring = ""
		return nil
	} else {
		for i := 2; i < len(rules[2]); i++ {
			if rules[2][i] == '|' {
				end = i
				break
			}
		}
		p.Probestring = p.stringUnescape(rules[2][begin:end])
	}

	// 探测字符串需要转码

	// no-payloed
	if end < len(rules[2]) {
		nopayload := common.TrimEx(rules[2][end+1:])
		if nopayload == "no-payload" {
			p.NoPlayload = true
		} else {
			p.NoPlayload = false
		}
	}

	return nil
}

// 匹配信息
func (p *NmapServiceProbeNode) Match(content string) ([]string, error) {

	result := make([]string, 0)
	for _, item := range p.Matchs {
		bMatch, ms, bSoftmatch, err := item.Match(content)
		if err != nil {
			return nil, err
		}

		if bMatch {
			result = append(result, ms...)
			if bSoftmatch {
				continue
			} else {
				break
			}
		}
	}

	return result, nil
}

// fallback
type Fallback struct {
	FallbackNames      []string // 命令行
	FallbackProbeNodes []*NmapServiceProbeNode
}

func NewFallback() *Fallback {
	return &Fallback{
		FallbackNames:      make([]string, 0),
		FallbackProbeNodes: make([]*NmapServiceProbeNode, 0),
	}
}

func (p *Fallback) Analyze(script string) error {
	names := strings.Split(script, ",")
	p.FallbackNames = append(p.FallbackNames, names...)
	return nil
}

// 匹配节点
/*
match 和 softmatch 通过7.94 的代码发现目前处理格式相同
*/
type MatchMethod struct {
	IsSoftMatch   bool            // 是否为软匹配
	ServiceName   string          // 服务名称
	Pattern       string          // 正则表达式
	RegCompile    *regexp2.Regexp // 编译好的正则表达式
	IsContainerRN bool            // 在“.”中包含换行符 /s
	IsIgnoreCase  bool            // 是否忽略大小写 /i
	VersionInfos  []*VersionInfo  // 版本信息
}

func NewMatchMethod(issoftmatch bool) *MatchMethod {
	return &MatchMethod{
		IsSoftMatch:  issoftmatch,
		VersionInfos: make([]*VersionInfo, 0),
		RegCompile:   nil,
	}
}

// 得到匹配组
func (p *MatchMethod) getMatchArray(format string) ([]int, error) {
	regsz := `\$\d+`
	reg, err := regexp2.Compile(regsz, 0)
	if err != nil {
		return nil, err
	}
	// 匹配超时时间
	reg.MatchTimeout = 200 * time.Millisecond
	result := make([]int, 0)
	match, err := reg.FindStringMatch(format)
	for match != nil {
		pos, err := strconv.Atoi(match.String()[1:])
		if err != nil {
			continue
		}
		result = append(result, pos)
		match, _ = reg.FindNextMatch(match)
	}

	return result, nil
}

// 返回值：
// 是否匹配成功，匹配到的数据， 是否软匹配，返回错误
func (p *MatchMethod) Match(content string) (bool, []string, bool, error) {
	var err error
	if p.RegCompile == nil {
		return false, nil, p.IsSoftMatch, err
	}

	result := make([]string, 0)
	match, err := p.RegCompile.FindStringMatch(content)
	if err != nil {
		return false, nil, p.IsSoftMatch, err
	}

	if match == nil {
		return false, nil, p.IsSoftMatch, nil
	}

	versioninfo := ""
	for _, item := range p.VersionInfos {
		switch item.InfoType {
		case 'p':
			versioninfo += item.Description + " "
		case 'v', 'i', 'd', 'h', 'o':
			regsz := `\$\d+`
			reg, err := regexp2.Compile(regsz, 0)
			if err != nil {
				continue
			}
			// 设置匹配超时时间
			reg.MatchTimeout = 200 * time.Millisecond
			marray := make([]int, 0)
			m, err := reg.FindStringMatch(item.Description)
			if m == nil {
				versioninfo += item.Description
				continue
			}
			for m != nil {
				pos, err := strconv.Atoi(m.String()[1:])
				if err != nil {
					break
				}
				marray = append(marray, pos)
				m, _ = reg.FindNextMatch(m)
			}

			gps := match.Groups()
			if len(gps) != len(marray)+1 {
				continue
			}
			var ssss string
			ssss = item.Description
			for _, pos := range marray {
				tem, err := reg.Replace(ssss, gps[pos].Captures[0].String(), 0, 1)
				if err == nil {
					ssss = tem
				}
			}

			versioninfo += ssss
		}
	}
	if len(versioninfo) == 0 {
		return false, nil, p.IsSoftMatch, nil
	}
	result = append(result, versioninfo)
	return true, result, p.IsSoftMatch, nil
}

func (p *MatchMethod) Analyze(script string) error {
	rules, err := common.Splite_Space(script, 2)
	if err != nil {
		return err
	}
	// service
	p.ServiceName = rules[0]
	// get match
	mscript := common.TrimEx(rules[1])
	var splitchar byte = 0x00
	var seg bool = false
	script_content := make([]byte, 0)
	var tag uint16 // 初始这个值可以为m匹配的信息
	for i := 0; i < len(mscript); i++ {
		if (mscript[i] == 'm' ||
			mscript[i] == 'p' ||
			mscript[i] == 'v' ||
			mscript[i] == 'i' ||
			mscript[i] == 'h' ||
			mscript[i] == 'o' ||
			mscript[i] == 'd') && !seg {
			if i+1 < len(mscript) {
				splitchar = mscript[i+1]
				seg = true
				tag = uint16(mscript[i])
				i = i + 1

			}
		} else if mscript[i] == 'c' && !seg {
			if i+4 < len(mscript) {
				if mscript[i:i+4] == "cpe:" {
					splitchar = mscript[i+4]
					seg = true
					tag = 0xff << 8
					i = i + 4
				}
			}
		} else if mscript[i] == splitchar {
			if tag == 'm' {
				if i+1 < len(mscript) {
					if mscript[i+1] == 's' {
						p.IsContainerRN = true
						i = i + 1
					} else if mscript[i+1] == 'i' {
						p.IsIgnoreCase = true
						i = i + 1
					}
				}
			} else if (tag & 0xff00) == 0xff {
				if i+1 < len(mscript) {
					if mscript[i+1] == 'a' {
						tag = tag + 1
					} else if mscript[i+1] == 'o' {
						tag = tag + 2
					} else if mscript[i+1] == 'h' {
						tag = tag + 3
					}
				}
			}

			seg = false
			versioninfo := NewVersionInfo()
			if tag == 'm' {
				p.Pattern = string(script_content)
			} else if tag == 'p' || tag == 'v' || tag == 'i' || tag == 'h' ||
				tag == 'o' || tag == 'd' || (tag&0xff00) == 0xff {
				versioninfo.InfoType = tag
				versioninfo.Description = string(script_content)
				p.VersionInfos = append(p.VersionInfos, versioninfo)
			}
			script_content = make([]byte, 0)

		} else if mscript[i] == ' ' && !seg {
			continue
		} else if seg {
			script_content = append(script_content, mscript[i])
		}
	}

	// 初始化正则表达式
	var regOption regexp2.RegexOptions = 0
	if p.IsContainerRN {
		regOption |= regexp2.Singleline
	}
	if p.IsIgnoreCase {
		regOption |= regexp2.IgnoreCase
	}
	p.RegCompile, err = regexp2.Compile(p.Pattern, regOption)
	if err != nil {
		return err
	}
	p.RegCompile.MatchTimeout = 50 * time.Millisecond

	return nil
}

// 版本信息
// 类型信息包括如下：
/*
p/vendorproductname/
	包括供应商名称和服务名称，格式为“ Sun Solaris rexecd ”、“ ISC BIND named ”或 “ Apache httpd ”。
v/version/
	应用程序版本“数字”，可能包含非数字字符，甚至多个单词。
i/info/
	立即可用且可能有用的各种进一步信息。
	示例包括 X 服务器是否对未经身份验证的连接开放，或者 SSH 服务器的协议号。
h/hostname/
	服务提供的主机名（如果有）。
	这对于 SMTP 和 POP3 等协议很常见，并且很有用，因为这些主机名可能用于内部网络或与直接的反向 DNS 响应不同。
o/operatingsystem/
	运行服务的操作系统。
	这可能与基于 Nmap IP 堆栈的操作系统检测报告的操作系统不同。
	例如，目标 IP 可能是一个 Linux 机器，它使用网络地址转换将请求转发到 DMZ 中的 Microsoft IIS 服务器。在这种情况下，
	堆栈操作系统检测应将操作系统报告为 Linux，而服务检测将端口 80 报告为 Windows。
d/devicetype/
	运行服务的设备类型，如 “打印服务器”或“网络摄像头”之类的字符串。某些服务会公开此信息，并且可以在更多情况下推断出来。
	例如，HP-ChaiServer Web 服务器仅在打印机上运行。有关设备类型的完整列表，请参阅“设备类型”部分。
cpe:/cpename/[a]
	服务某些方面的 CPE 名称。这可以多次使用；
	可以想象，不仅能够识别服务（cpe:/a名称），还能够识别操作系统（cpe:/o名称）和硬件平台（cpe:/h名称）。
	尾部斜杠不是 CPE 语法的一部分，但包含它是为了匹配其他字段的格式。有关 CPE 的更多信息，请参阅“通用平台枚举 (CPE)”部分。
*/

type VersionInfo struct {
	InfoType    uint16
	Description string
}

func NewVersionInfo() *VersionInfo {
	return &VersionInfo{}
}

type NmapServiceProbe struct {
	DataPath string
	// data
	ExcludeInfo     *Exclude
	ProbeNodes      []*NmapServiceProbeNode
	PortsToNodes    map[uint16]([]*NmapServiceProbeNode)
	SSLPortsToNodes map[uint16]([]*NmapServiceProbeNode)
	currentProbe    *NmapServiceProbeNode
}

func NewNmapServiceProbe() *NmapServiceProbe {
	return &NmapServiceProbe{
		ExcludeInfo:     NewExclude(),
		ProbeNodes:      make([]*NmapServiceProbeNode, 0),
		PortsToNodes:    make(map[uint16][]*NmapServiceProbeNode),
		SSLPortsToNodes: make(map[uint16][]*NmapServiceProbeNode),
	}
}

func (p *NmapServiceProbe) LoadNmapServiceProbes(nspPath string) (int, error) {
	if !common.IsFileExist(nspPath) {
		return 0, errors.New("not found the nmap service probes file.")
	}

	// load file
	fi, err := os.Open(nspPath)
	if err != nil {
		return 0, err
	}

	defer fi.Close()

	br := bufio.NewReader(fi)
	wg := sync.WaitGroup{}
loop:
	for {
		a, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}

		//
		line_data := string(a)
		if len(line_data) == 0 || line_data[0] == '#' {
			continue
		}

		// decomposition
		decompose_body, err := common.Splite_Space(common.TrimEx(line_data), 2)
		if err != nil {
			return 0, err
		}
		if len(decompose_body) < 2 {
			return 0, errors.New("splite string error")
		}

		switch common.TrimEx(decompose_body[0]) {
		case "Exclude":
			wg.Add(1)
			func(wg *sync.WaitGroup) {
				defer wg.Done()
				common.SafeRunner(p.ExcludeInfo.Analyze, decompose_body[1])
			}(&wg)
		case "Probe":
			probeNode := NewProbeNode()
			p.ProbeNodes = append(p.ProbeNodes, probeNode)
			p.currentProbe = probeNode
			wg.Add(1)
			func(wg *sync.WaitGroup) {
				defer wg.Done()
				common.SafeRunner(probeNode.Analyze, decompose_body[1])
			}(&wg)
		case "match":
			match := NewMatchMethod(false)
			p.currentProbe.Matchs = append(p.currentProbe.Matchs, match)
			wg.Add(1)
			func(wg *sync.WaitGroup) {
				defer wg.Done()
				common.SafeRunner(match.Analyze, decompose_body[1])
			}(&wg)
		case "softmatch":
			softwarematch := NewMatchMethod(true)
			p.currentProbe.Matchs = append(p.currentProbe.Matchs, softwarematch)
			wg.Add(1)
			func(wg *sync.WaitGroup) {
				defer wg.Done()
				common.SafeRunner(softwarematch.Analyze, decompose_body[1])
			}(&wg)
		case "rarity":
			rarity, err := strconv.Atoi(decompose_body[1])
			if err != nil {
				log.Error("nmap service probe file format error")
				break loop
			}
			p.currentProbe.Rarity = int8(rarity)
		case "ports":
			port_list := strings.Split(decompose_body[1], ",")
			if len(port_list) > 0 {
				for _, item := range port_list {
					// like 32750-32810
					rs := strings.Split(item, "-")
					if len(rs) == 2 {
						begin, err := strconv.Atoi(rs[0])
						if err != nil {
							continue
						}
						end, err := strconv.Atoi(rs[1])
						if err != nil {
							continue
						}
						for i := begin; i <= end; i++ {
							p.currentProbe.Ports = append(p.currentProbe.Ports, uint16(i))
						}
					} else if len(rs) == 1 {
						if len(rs[0]) == 0 {
							continue
						}
						port, err := strconv.Atoi(common.TrimEx(rs[0]))
						if err != nil || port > 65535 {
							continue
						}
						p.currentProbe.Ports = append(p.currentProbe.Ports, uint16(port))
					}

				}
			}
		case "sslports":
			sslport_list := strings.Split(decompose_body[1], ",")
			if len(sslport_list) > 0 {
				for _, item := range sslport_list {
					// like 32750-32810
					rs := strings.Split(item, "-")
					if len(rs) == 2 {
						begin, err := strconv.Atoi(rs[0])
						if err != nil {
							continue
						}
						end, err := strconv.Atoi(rs[1])
						if err != nil {
							continue
						}
						for i := begin; i <= end; i++ {
							p.currentProbe.SSLPorts = append(p.currentProbe.SSLPorts, uint16(i))
						}
					} else if len(rs) == 1 {
						if len(rs[0]) == 0 {
							continue
						}
						port, err := strconv.Atoi(common.TrimEx(rs[0]))
						if err != nil || port > 65535 {
							continue
						}
						p.currentProbe.SSLPorts = append(p.currentProbe.SSLPorts, uint16(port))
					}

				}
			}
		case "totalwaitms":
			tw, err := strconv.Atoi(decompose_body[1])
			if err != nil {
				continue
			}
			p.currentProbe.Totalwaitms = tw
		case "tcpwrappedms":
			twd, err := strconv.Atoi(decompose_body[1])
			if err != nil {
				continue
			}
			p.currentProbe.Tcpwrappedms = twd
		case "fallback":
			fallback := NewFallback()
			p.currentProbe.Fallback1 = fallback
			wg.Add(1)
			func(wg *sync.WaitGroup) {
				defer wg.Done()
				fallback.Analyze(decompose_body[1])
			}(&wg)

		}
	}
	wg.Wait()
	return 0, nil
}

// 通过探测名字找到探测
func (p *NmapServiceProbe) FindProbeNodeByName(probeName string) *NmapServiceProbeNode {
	for _, item := range p.ProbeNodes {
		if item.Probename == probeName {
			return item
		}
	}

	return nil
}

func (p *NmapServiceProbe) InitializeFallback() error {
	for _, item := range p.ProbeNodes {
		if len(item.Fallback1.FallbackNames) > 0 {
			for _, name := range item.Fallback1.FallbackNames {
				item.Fallback1.FallbackProbeNodes = append(item.Fallback1.FallbackProbeNodes, p.FindProbeNodeByName(name))
			}
		}
	}

	return nil
}

func (p *NmapServiceProbe) ArrangeProbeNodes() error {
	if len(p.ProbeNodes) == 0 {
		return errors.New("probenodes is empty")
	}
	for _, item := range p.ProbeNodes {
		for _, port := range item.Ports {
			_, ok := p.PortsToNodes[port]
			if !ok {
				p.PortsToNodes[port] = make([]*NmapServiceProbeNode, 0)
			}
			p.PortsToNodes[port] = append(p.PortsToNodes[port], item)
		}

		for _, port := range item.SSLPorts {
			_, ok := p.SSLPortsToNodes[port]
			if !ok {
				p.SSLPortsToNodes[port] = make([]*NmapServiceProbeNode, 0)
			}
			p.SSLPortsToNodes[port] = append(p.SSLPortsToNodes[port], item)
		}
	}

	return nil
}
