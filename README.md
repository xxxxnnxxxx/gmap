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
