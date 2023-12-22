# gmap

基于gopacket简单的模拟nmap的功能，目前支持windows下的syn/connect扫描

例如：
```shell
# syn scan (-sS)
gmap.exe -p1-65535 -sS 192.168.1.3

# connect scan (-sT)
gmap.exe -p1-65535 -sT 192.168.1.3

# service probe (-sV)
gmap.exe -p1-65535 -sV 192.168.1.1/24
```
输出：

![image](https://github.com/xxxxnnxxxx/gmap/blob/main/images/synscan.png)

## 命令说明

1. 打印接口信息

```shell
gmap.exe --print-interface
```

2. 打印路由信息（暂时只显示IPV4)

```shell
gmap.exe --print-route
```
