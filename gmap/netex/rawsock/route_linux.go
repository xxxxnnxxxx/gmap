//go:build linux

package rawsock

func getDefaultGatewayIP() (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		// 获取接口信息
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			// 检查IPv4地址
			ipNet, ok := addr.(*net.IPNet)
			if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
				// 查询路由表
				msgs, err := route.FetchRIB(route.RIBTypeRoute, 0)
				if err != nil {
					return nil, err
				}
				defer route.FreeRIB(msgs)

				// 遍历路由表，查找默认路由
				for _, msg := range msgs {
					if msg.Header.Type == route.RTM_ADD || msg.Header.Type == route.RTM_DELETE {
						rtInfo, err := route.ParseRoute(msg)
						if err == nil {
							if rtInfo.Dst == nil {
								// 找到默认路由，返回网关地址
								return rtInfo.Gateway, nil
							}
						}
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("Unable to determine default gateway")
}
