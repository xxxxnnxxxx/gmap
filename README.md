# gmap

基于gopacket简单的模拟nmap的功能，目前支持windows下的syn/connect扫描

例如：
```shell
# syn scan
gmap.exe -p 1-65535 -sS -t 192.168.1.3

# connect scan
gmap.exe -p 1-65535 -sT -t 192.168.1.3
```
输出：

![image](https://github.com/xxxxnnxxxx/gmap/blob/main/images/synscan.png)