package scanner

import (
	"fmt"
	"net"
	"net/http"
	"time"
)

// 检查是否是web服务
// timeout 指定超时时间（秒）默认是2秒
// flag参数：
// -1 发送http/https两个请求
// 0 发送http请求
// 1 发送https请求
//
// 返回值
// 0 不是http服务
// 1 http存在
// 2 https存在
// 3 http/https都存在
func CheckHttp(ip net.IP, port uint16, timeout time.Duration, flag int) (int, error) {
	u1 := fmt.Sprintf("http://%v:%v/", ip.String(), port)
	u2 := fmt.Sprintf("https://%v:%v/", ip.String(), port)

	if timeout == 0 {
		timeout = 2
	}
	client := http.Client{
		Timeout: timeout * time.Second,
	}
	bHttp := false
	bHttps := false

	switch flag {
	case -1:
		_, err := client.Head(u1)
		if err != nil {
			bHttp = false
		} else {
			bHttp = true
		}

		_, err = client.Head(u2)
		if err != nil {
			bHttps = false
		} else {
			bHttps = true
		}
		if bHttp && bHttps {
			return 3, nil
		}

		if bHttp {
			return 1, nil
		}

		if bHttps {
			return 2, nil
		}
	case 0:
		_, err := client.Head(u1)
		if err != nil {
			return 0, err
		} else {
			return 1, nil
		}
	case 1:
		_, err := client.Head(u2)
		if err != nil {
			return 0, err
		} else {
			return 2, nil
		}
	}

	return 0, nil
}
