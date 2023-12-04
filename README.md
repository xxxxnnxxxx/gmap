# gmap

基于gopacket简单的模拟nmap的功能，目前支持windows下的syn/connect扫描

例如：
```shell
gmap.exe -p 1-65535 -sS 192.168.1.3
```