package nmap_service_probe

import (
	"Gmap/gmap/common"
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
)

/*
加载nmap_service文件，保存基本的端口与服务对应信息
*/

type NmapServiceNode struct {
	ServiceName string
	Port        int
	Protocol    string
	Radio       string // 频度
	Comment     string
}

func NewNmapServiceNode() *NmapServiceNode {
	return &NmapServiceNode{}
}

// 加载nmap_service文件
func LoadNmapSerivce(nsPath string) error {
	Global_NmapServices = make([]*NmapServiceNode, 0)
	if !common.IsFileExist(nsPath) {
		return errors.New("not found the nmap service probes file.")
	}

	// load file
	fi, err := os.Open(nsPath)
	if err != nil {
		return err
	}

	defer fi.Close()

	br := bufio.NewReader(fi)
	// wg := sync.WaitGroup{}

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

		// 分析每行的数据
		// 使用\t键进行分割
		nmapServiceNode := NewNmapServiceNode()
		_, err = fmt.Sscanf(line_data, "%127s %v/%15s %31s",
			&nmapServiceNode.ServiceName,
			&nmapServiceNode.Port,
			&nmapServiceNode.Protocol,
			&nmapServiceNode.Radio)
		if err != nil {
			continue
		}

		Global_NmapServices = append(Global_NmapServices, nmapServiceNode)
	}
	return nil
}

func GetNmapServiceNode(port int) []*NmapServiceNode {
	result := make([]*NmapServiceNode, 0)

	if Global_NmapServices == nil {
		return nil
	}

	for _, item := range Global_NmapServices {
		if item.Port == port {
			result = append(result, item)
		}
	}

	return result
}

// 全局保存服务描述表
var Global_NmapServices []*NmapServiceNode
