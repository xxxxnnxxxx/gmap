# gmap

对比nmap, 基于gopacket基础上开发的一套端口和服务扫描程序，目前支持syn/connect扫描。

正式的端口扫描前，去掉了nmap扫描钱的一些预处理操作，比如探活等。

例子：
```shell

gmap.exe -p 1-65535 -sS 192.168.1.3

```