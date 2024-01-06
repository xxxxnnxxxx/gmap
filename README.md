# gmap

## 描述
基于gopacket简单的模拟nmap的功能，目前支持windows下的syn/connect扫描。
(IPv6目前暂不支持)

## 使用

本程序不需要安装，但运行需要winpcap/npcap支持，我们可以到npcap官方网站下载：https://npcap.com/dist/npcap-1.78.exe
或是已经安装了nmap程序或是wireshark，那本地机器说明已经安装了npcap相关驱动。

## 帮助和示例

### 帮助

```shell
 -a, --print-arp    打印arp列表
 -e, --print-interface
                    打印网络接口信息
 -i, --interface-index=value
                    指定网络接口索引 [-1]
 -n                 否定操作
 -o, --output=value
                    指定输出文件路径
 -P                 ping 探活
 -p value           指定端口列表, 形如: 80,443 或 1-1000
 -r, --print-route  打印路由表
 -S                 扫描——TCP SYN方式 端口扫描
 -s                 扫描
 -T                 扫描——TCP Connect方式 端口扫描
 -V                 探测服务版本
```

### 示例

```shell
# syn scan (-sS)
gmap.exe -p1-65535 -sS 192.168.1.3

# connect scan (-sT)
gmap.exe -p1-65535 -sT 192.168.1.3

# service probe (-sV)
gmap.exe -p1-65535 -sV 192.168.1.1/24

# 多网卡的情况下，指定适配器索引
# -i 17 就是指定索引为17的网络适配器
gmap.exe -p1-65535 -sV -i 17 192.168.1.1/24
```
输出：

![image](https://github.com/xxxxnnxxxx/gmap/blob/main/images/synscan.png)


1. 打印网络适配器信息

```shell
gmap.exe --print-interface
```
输出:
```shell
------------------------------------
接口名称：本地连接* 1
IP地址：169.254.172.43
Mac地址：84:5c:f3:4f:19:84
连接地址：\Device\NPF_{6D8F92BF-8858-4AD6-B3E3-254992C17948}
接口索引：12
接口类型：71
------------------------------------
...
```

2. 打印路由信息（暂时只显示IPV4)

```shell
# 目前路由显示信息只是支持IPv4
gmap.exe --print-route
```
输出：
```shell
IPv4 Route-------------------------------------
Destion Address        Netmask                Gateway Address        Interface Address
0.0.0.0               0.0.0.0                192.168.1.1           192.168.1.2
192.168.1.0           255.255.255.0          0.0.0.0               192.168.1.2
192.168.1.2           255.255.255.255        0.0.0.0               192.168.1.2
192.168.1.255         255.255.255.255        0.0.0.0               192.168.1.2
127.0.0.0             255.0.0.0              0.0.0.0               127.0.0.1
127.0.0.1             255.255.255.255        0.0.0.0               127.0.0.1
127.255.255.255       255.255.255.255        0.0.0.0               127.0.0.1
224.0.0.0             240.0.0.0              0.0.0.0               127.0.0.1
224.0.0.0             240.0.0.0              0.0.0.0               192.168.1.2
255.255.255.255       255.255.255.255        0.0.0.0               127.0.0.1
255.255.255.255       255.255.255.255        0.0.0.0               192.168.12
IPV6 Route-------------------------------------
```

3. 打印arp地址表
```shell
gmap.exe --print-arp
```

# netx/rawsock

这个库主要是通过gopacket库模拟了tcp通讯，实现数据传输的功能，`cmd` 目录下 `client.go` 和 `server.go` 就是两个测试程序
。测试这两个程序，是通过python socket模拟服务器和客户端测试的，两个程序都能正常使用。

测试的 `client.py` 代码如下：

```python
import socket
import time

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('192.168.1.3', 8000))

client.send(bytes('i am " + client.getsocketname()[0] + 'hello 192.168.1.3','utf-8'))
from_server = client.recv(4096)
print(str(from_server))
time.sleep(5)
client.close()
```
运行截图如下：

![image](https://github.com/xxxxnnxxxx/gmap/blob/main/images/example_server.png)

### 附加说明

在一些情况下，服务器端可能尝试端口复用，比如说，原有主机有某些程序运行在80端口，你可以在主机上运行此`rawsock`
构造的服务程序，也开启80端口，两个程序启动并不冲突，都可以监听80端口，但正常情况客户端不是 `rawsock` 实现的程序
尝试连接服务器的80端口，是不能正常与 `rawsock` 服务器通讯的，因为首先会连接到原有程序的80端口，那么这个时候，就可以
通过使用 `rawsock` 实现客户端，构造异形的 tcp连接系统，与服务器通讯，注意：服务器端也必须是和客户端同样的规则，比如说，
seq与ack的确认方式改变，这样客户端既不与原有程序连接，又能和 `rawsock` 构造的服务器保持稳定通讯。

以上只是思路，目前没有测试实现，后续有时间会上测试代码。

### 关于代码中的说明

在客户端连接服务器时有函数：

```go
Connect(targetIP net.IP, targetPort uint16, nexthopMAC net.HardwareAddr) (*Socket, error)
```
其中有参数 `nexthopMAC` 这个指定的是下一跳物理地址， 在tcp封包中， 网络接口层 `eth` 需要传递下一跳的物理地址，
在规则中，同一个局域网属于直连，那么下一跳地址就是目标机器的MAC地址，如果是不在同一个局域网，那么这个就是网关的物理地址。
注意： 我们这里排除掉回环的情况(127.0.0.1本地通讯)

这个参数需要手动输入，本身`gmap`其实是可以实现探测的，但使用了本机系统的 api, 这样就不能保证使用 `rawsock` 的简单性，
所以需要手动输入。

