package nmap_service_probe

import (
	"Gmap/gmap/netex/sock"

	"fmt"
	"sync"
)

// 获取网络数据
func GetData(protocol int,
	isTLS bool,
	host string,
	port uint16,
	data string,
	timeout int64) (string, error) {
	btcp := sock.NewBaseDialer(protocol, isTLS)
	var content string
	// 注意数据必须等待完成才能返回
	// 因为数据不能很快处理，连接返回后，不一定能获取数据
	// 所以这个地方必须要有个等待返回
	var waitDataHandle sync.WaitGroup
	waitDataHandle.Add(1)
	btcp.HandleData = func(data []byte, n int) {
		defer waitDataHandle.Done()
		content = string(data)
		btcp.Close()
	}

	btcp.SetIP(host)
	btcp.SetPort(port)
	if timeout > 0 {
		btcp.SetConnTimeout(timeout)
		btcp.SetReadTimeout(timeout)
	}

	btcp.Dial(false)
	btcp.Listen()
	btcp.Send([]byte(data))
	err := btcp.Wait()
	waitDataHandle.Wait()

	return content, err
}

func ProbeFunc_NULL(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_NULL")
	return nil, nil
}
func ProbeFunc_GenericLines(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_GenericLines")
	return nil, nil
}
func ProbeFunc_GetRequest(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	content, err := GetData(protocol, isTLS, host, port, pn.Probestring, int64(pn.Totalwaitms))
	if len(content) == 0 {
		return nil, err
	}
	// 匹配内容
	result, err := pn.Match(content)
	if err != nil {
		return nil, err
	}
	return result, nil
}
func ProbeFunc_HTTPOptions(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	content, err := GetData(protocol, isTLS, host, port, pn.Probestring, int64(pn.Totalwaitms))
	if len(content) == 0 {
		return nil, err
	}
	// 匹配内容
	result, err := pn.Match(content)
	if err != nil {
		return nil, err
	}
	return result, nil
}
func ProbeFunc_RTSPRequest(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	content, err := GetData(protocol, isTLS, host, port, pn.Probestring, int64(pn.Totalwaitms))
	if len(content) == 0 {
		return nil, err
	}
	// 匹配内容
	result, err := pn.Match(content)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func ProbeFunc_RPCCheck(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_RPCCheck")
	return nil, nil
}
func ProbeFunc_DNSVersionBindReq(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_DNSVersionBindReq")
	return nil, nil
}
func ProbeFunc_DNSVersionBindReqTCP(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_DNSVersionBindReqTCP")
	return nil, nil
}
func ProbeFunc_DNSStatusRequest(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_DNSStatusRequest")
	return nil, nil
}
func ProbeFunc_DNSStatusRequestTCP(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_DNSStatusRequestTCP")
	return nil, nil
}
func ProbeFunc_NBTStat(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_NBTStat")
	return nil, nil
}
func ProbeFunc_Help(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_Help")
	return nil, nil
}
func ProbeFunc_Hello(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_Hello")
	return nil, nil
}

func ProbeFunc_SSLSessionReq(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_SSLSessionReq")
	return nil, nil
}
func ProbeFunc_TerminalServerCookie(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_TerminalServerCookie")
	return nil, nil
}
func ProbeFunc_TLSSessionReq(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_TLSSessionReq")
	return nil, nil
}
func ProbeFunc_SSLv23SessionReq(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_SSLv23SessionReq")
	return nil, nil
}
func ProbeFunc_SMBProgNeg(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_SMBProgNeg")
	return nil, nil
}
func ProbeFunc_X11Probe(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	content, err := GetData(protocol, isTLS, host, port, pn.Probestring, int64(pn.Totalwaitms))
	if len(content) == 0 {
		return nil, err
	}
	// 匹配内容
	result, err := pn.Match(content)
	if err != nil {
		return nil, err
	}
	return result, nil
}
func ProbeFunc_FourOhFourRequest(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	content, err := GetData(protocol, isTLS, host, port, pn.Probestring, int64(pn.Totalwaitms))
	if len(content) == 0 {
		return nil, err
	}
	// 匹配内容
	result, err := pn.Match(content)
	if err != nil {
		return nil, err
	}
	return result, nil
}
func ProbeFunc_LPDString(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_LPDString")
	return nil, nil
}
func ProbeFunc_LDAPSearchReq(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_LDAPSearchReq")
	return nil, nil
}
func ProbeFunc_LDAPSearchReqUDP(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_LDAPSearchReqUDP")
	return nil, nil
}
func ProbeFunc_LDAPBindReq(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_LDAPBindReq")
	return nil, nil
}
func ProbeFunc_SIPOptions(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_SIPOptions")
	return nil, nil
}

func ProbeFunc_LANDesk_RC(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_LANDesk_RC")
	return nil, nil
}
func ProbeFunc_TerminalServer(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_TerminalServer")
	return nil, nil
}
func ProbeFunc_NCP(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_NCP")
	return nil, nil
}
func ProbeFunc_NotesRPC(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_NotesRPC")
	return nil, nil
}
func ProbeFunc_DistCCD(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_DistCCD")
	return nil, nil
}
func ProbeFunc_JavaRMI(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_JavaRMI")
	return nil, nil
}
func ProbeFunc_Radmin(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_Radmin")
	return nil, nil
}
func ProbeFunc_Sqlping(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_Sqlping")
	return nil, nil
}
func ProbeFunc_NTPRequest(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_NTPRequest")
	return nil, nil
}
func ProbeFunc_NessusTPv12(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_NessusTPv12")
	return nil, nil
}
func ProbeFunc_NessusTPv11(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_NessusTPv11")
	return nil, nil
}
func ProbeFunc_NessusTPv10(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_NessusTPv10")
	return nil, nil
}
func ProbeFunc_SNMPv1public(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_SNMPv1public")
	return nil, nil
}
func ProbeFunc_SNMPv3GetRequest(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_SNMPv3GetRequest")
	return nil, nil
}
func ProbeFunc_WMSRequest(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_WMSRequest")
	return nil, nil
}
func ProbeFunc_oracle_tns(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_oracle_tns")
	return nil, nil
}
func ProbeFunc_xdmcp(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_xdmcp")
	return nil, nil
}
func ProbeFunc_AFSVersionRequest(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_AFSVersionRequest")
	return nil, nil
}
func ProbeFunc_mydoom(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_mydoom")
	return nil, nil
}
func ProbeFunc_WWWOFFLEctrlstat(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_WWWOFFLEctrlstat")
	return nil, nil
}
func ProbeFunc_Verifier(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_Verifier")
	return nil, nil
}
func ProbeFunc_VerifierAdvanced(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_VerifierAdvanced")
	return nil, nil
}
func ProbeFunc_Socks5(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_Socks5")
	return nil, nil
}
func ProbeFunc_Socks4(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_Socks4")
	return nil, nil
}
func ProbeFunc_OfficeScan(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_OfficeScan")
	return nil, nil
}
func ProbeFunc_ms_sql_s(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_ms_sql_s")
	return nil, nil
}
func ProbeFunc_HELP4STOMP(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_HELP4STOMP")
	return nil, nil
}
func ProbeFunc_Memcache(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_Memcache")
	return nil, nil
}
func ProbeFunc_beast2(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_beast2")
	return nil, nil
}
func ProbeFunc_firebird(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_firebird")
	return nil, nil
}
func ProbeFunc_ibm_db2_das(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_ibm_db2_das")
	return nil, nil
}
func ProbeFunc_ibm_db2(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_ibm_db2")
	return nil, nil
}
func ProbeFunc_pervasive_relational(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_pervasive_relational")
	return nil, nil
}
func ProbeFunc_pervasive_btrieve(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_pervasive_btrieve")
	return nil, nil
}
func ProbeFunc_ibm_db2_das_udp(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_ibm_db2_das_udp")
	return nil, nil
}
func ProbeFunc_ajp(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_ajp")
	return nil, nil
}
func ProbeFunc_DNS_SD(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_DNS_SD")
	return nil, nil
}
func ProbeFunc_hp_pjl(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_hp_pjl")
	return nil, nil
}
func ProbeFunc_Citrix(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_Citrix")
	return nil, nil
}
func ProbeFunc_Kerberos(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_Kerberos")
	return nil, nil
}
func ProbeFunc_SqueezeCenter(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_SqueezeCenter")
	return nil, nil
}
func ProbeFunc_afp(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_afp")
	return nil, nil
}
func ProbeFunc_Quake1_server_info(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_Quake1_server_info")
	return nil, nil
}
func ProbeFunc_Quake2_status(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_Quake2_status")
	return nil, nil
}
func ProbeFunc_Quake3_getstatus(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_Quake3_getstatus")
	return nil, nil
}
func ProbeFunc_Quake3_master_getservers(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_Quake3_master_getservers")
	return nil, nil
}
func ProbeFunc_SqueezeCenter_CLI(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_SqueezeCenter_CLI")
	return nil, nil
}
func ProbeFunc_Arucer(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_Arucer")
	return nil, nil
}
func ProbeFunc_serialnumberd(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_serialnumberd")
	return nil, nil
}
func ProbeFunc_dominoconsole(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_dominoconsole")
	return nil, nil
}
func ProbeFunc_informix(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_informix")
	return nil, nil
}
func ProbeFunc_drda(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_drda")
	return nil, nil
}
func ProbeFunc_ibm_mqseries(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_ibm_mqseries")
	return nil, nil
}
func ProbeFunc_apple_iphoto(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_apple_iphoto")
	return nil, nil
}
func ProbeFunc_ZendJavaBridge(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_ZendJavaBridge")
	return nil, nil
}
func ProbeFunc_BackOrifice(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_BackOrifice")
	return nil, nil
}
func ProbeFunc_gkrellm(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_gkrellm")
	return nil, nil
}
func ProbeFunc_metasploit_xmlrpc(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_metasploit_xmlrpc")
	return nil, nil
}
func ProbeFunc_mongodb(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_mongodb")
	return nil, nil
}
func ProbeFunc_sybaseanywhere(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_sybaseanywhere")
	return nil, nil
}
func ProbeFunc_vuze_dht(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_vuze_dht")
	return nil, nil
}
func ProbeFunc_pc_anywhere(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_pc_anywhere")
	return nil, nil
}
func ProbeFunc_pc_duo(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_pc_duo")
	return nil, nil
}
func ProbeFunc_pc_duo_gw(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_pc_duo_gw")
	return nil, nil
}
func ProbeFunc_redis_server(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_redis_server")
	return nil, nil
}
func ProbeFunc_memcached(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_memcached")
	return nil, nil
}
func ProbeFunc_riak_pbc(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_riak_pbc")
	return nil, nil
}
func ProbeFunc_tarantool(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_tarantool")
	return nil, nil
}
func ProbeFunc_couchbase_data(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_couchbase_data")
	return nil, nil
}
func ProbeFunc_epmd(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_epmd")
	return nil, nil
}
func ProbeFunc_vp3(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_vp3")
	return nil, nil
}
func ProbeFunc_kumo_server(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_kumo_server")
	return nil, nil
}
func ProbeFunc_metasploit_msgrpc(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_metasploit_msgrpc")
	return nil, nil
}
func ProbeFunc_svrloc(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_svrloc")
	return nil, nil
}
func ProbeFunc_hazelcast_http(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_hazelcast_http")
	return nil, nil
}
func ProbeFunc_minecraft_ping(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_minecraft_ping")
	return nil, nil
}
func ProbeFunc_erlang_node(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_erlang_node")
	return nil, nil
}
func ProbeFunc_Murmur(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_Murmur")
	return nil, nil
}
func ProbeFunc_Ventrilo(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_Ventrilo")
	return nil, nil
}
func ProbeFunc_teamspeak_tcpquery_ver(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_teamspeak_tcpquery_ver")
	return nil, nil
}
func ProbeFunc_TeamSpeak2(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_TeamSpeak2")
	return nil, nil
}
func ProbeFunc_TeamSpeak3(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_TeamSpeak3")
	return nil, nil
}
func ProbeFunc_xmlsysd(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_xmlsysd")
	return nil, nil
}
func ProbeFunc_FreelancerStatus(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_FreelancerStatus")
	return nil, nil
}
func ProbeFunc_ASE(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_ASE")
	return nil, nil
}
func ProbeFunc_AndroMouse(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_AndroMouse")
	return nil, nil
}
func ProbeFunc_AirHID(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_AirHID")
	return nil, nil
}
func ProbeFunc_NetMotionMobility(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_NetMotionMobility")
	return nil, nil
}
func ProbeFunc_docker(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_docker")
	return nil, nil
}
func ProbeFunc_tor_versions(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_tor_versions")
	return nil, nil
}
func ProbeFunc_TLS_PSK(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_TLS_PSK")
	return nil, nil
}
func ProbeFunc_NJE(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_NJE")
	return nil, nil
}
func ProbeFunc_tn3270(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_tn3270")
	return nil, nil
}
func ProbeFunc_giop(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_giop")
	return nil, nil
}
func ProbeFunc_OpenVPN(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_OpenVPN")
	return nil, nil
}

func ProbeFunc_pcworx(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_pcworx")
	return nil, nil
}
func ProbeFunc_proconos(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_proconos")
	return nil, nil
}
func ProbeFunc_niagara_fox(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_niagara_fox")
	return nil, nil
}
func ProbeFunc_mqtt(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_mqtt")
	return nil, nil
}
func ProbeFunc_ipmi_rmcp(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_ipmi_rmcp")
	return nil, nil
}
func ProbeFunc_coap_request(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_coap_request")
	return nil, nil
}
func ProbeFunc_DTLSSessionReq(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_DTLSSessionReq")
	return nil, nil
}
func ProbeFunc_iperf3(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_iperf3")
	return nil, nil
}
func ProbeFunc_QUIC(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	content, err := GetData(protocol, isTLS, host, port, pn.Probestring, int64(pn.Totalwaitms))
	if len(content) == 0 {
		return nil, err
	}
	// 匹配内容
	result, err := pn.Match(content)
	if err != nil {
		return nil, err
	}
	return result, nil
}
func ProbeFunc_VersionRequest(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_VersionRequest")
	return nil, nil
}
func ProbeFunc_NoMachine(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_NoMachine")
	return nil, nil
}
func ProbeFunc_JMON(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_JMON")
	return nil, nil
}
func ProbeFunc_LibreOfficeImpressSCPair(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_LibreOfficeImpressSCPair")
	return nil, nil
}
func ProbeFunc_ARD(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_ARD")
	return nil, nil
}
func ProbeFunc_LSCP(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_LSCP")
	return nil, nil
}
func ProbeFunc_rotctl(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_rotctl")
	return nil, nil
}
func ProbeFunc_UbiquitiDiscoveryv1(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_UbiquitiDiscoveryv1")
	return nil, nil
}
func ProbeFunc_UbiquitiDiscoveryv2(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_UbiquitiDiscoveryv2")
	return nil, nil
}
func ProbeFunc_SharpTV(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_SharpTV")
	return nil, nil
}
func ProbeFunc_adbConnect(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_adbConnect")
	return nil, nil
}
func ProbeFunc_piholeVersion(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_piholeVersion")
	return nil, nil
}
func ProbeFunc_teamtalk_login(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_teamtalk_login")
	return nil, nil
}
func ProbeFunc_insteonPLM(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_insteonPLM")
	return nil, nil
}
func ProbeFunc_DHCP_INFORM(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_DHCP_INFORM")
	return nil, nil
}
func ProbeFunc_TFTP_GET(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_TFTP_GET")
	return nil, nil
}
func ProbeFunc_ONCRPC_CALL(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_ONCRPC_CALL")
	return nil, nil
}
func ProbeFunc_NTP_REQ(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_NTP_REQ")
	return nil, nil
}
func ProbeFunc_DCERPC_CALL(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_DCERPC_CALL")
	return nil, nil
}
func ProbeFunc_CIFS_NS_UC(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_CIFS_NS_UC")
	return nil, nil
}
func ProbeFunc_CIFS_NS_BC(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_CIFS_NS_BC")
	return nil, nil
}
func ProbeFunc_IKE_MAIN_MODE(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_IKE_MAIN_MODE")
	return nil, nil
}
func ProbeFunc_IPSEC_START(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_IPSEC_START")
	return nil, nil
}
func ProbeFunc_RIPv1(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_RIPv1")
	return nil, nil
}
func ProbeFunc_RMCP_ASF_PING(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_RMCP_ASF_PING")
	return nil, nil
}
func ProbeFunc_OPENVPN_PKI(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_OPENVPN_PKI")
	return nil, nil
}
func ProbeFunc_RADIUS_ACCESS(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_RADIUS_ACCESS")
	return nil, nil
}
func ProbeFunc_L2TP_ICRQ(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_L2TP_ICRQ")
	return nil, nil
}
func ProbeFunc_UPNP_MSEARCH(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_UPNP_MSEARCH")
	return nil, nil
}
func ProbeFunc_NFSPROC_NULL(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_NFSPROC_NULL")
	return nil, nil
}
func ProbeFunc_GPRS_GTPv1(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_GPRS_GTPv1")
	return nil, nil
}
func ProbeFunc_GPRS_GTPv2prime(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_GPRS_GTPv2prime")
	return nil, nil
}
func ProbeFunc_GPRS_GTPv2(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_GPRS_GTPv2")
	return nil, nil
}
func ProbeFunc_STUN_BIND(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_STUN_BIND")
	return nil, nil
}
func ProbeFunc_STD_DISCOVER(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_STD_DISCOVER")
	return nil, nil
}
func ProbeFunc_NAT_PMP_ADDR(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_NAT_PMP_ADDR")
	return nil, nil
}
func ProbeFunc_DNS_SD_QU(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_DNS_SD_QU")
	return nil, nil
}
func ProbeFunc_PCANY_STATUS(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_PCANY_STATUS")
	return nil, nil
}
func ProbeFunc_UT2K_PING(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_UT2K_PING")
	return nil, nil
}
func ProbeFunc_AMANDA_NOOP(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_AMANDA_NOOP")
	return nil, nil
}
func ProbeFunc_WDB_TARGET_PING(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_WDB_TARGET_PING")
	return nil, nil
}
func ProbeFunc_WDB_TARGET_CONNECT(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_WDB_TARGET_CONNECT")
	return nil, nil
}
func ProbeFunc_KADEMLIA_PING(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_KADEMLIA_PING")
	return nil, nil
}
func ProbeFunc_TS3INIT1(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_TS3INIT1")
	return nil, nil
}
func ProbeFunc_MEMCACHED_VERSION(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_MEMCACHED_VERSION")
	return nil, nil
}
func ProbeFunc_STEAM(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_STEAM")
	return nil, nil
}
func ProbeFunc_TRIN00_UNIX_PING(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_TRIN00_UNIX_PING")
	return nil, nil
}
func ProbeFunc_BO_PING(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_BO_PING")
	return nil, nil
}
func ProbeFunc_TRIN00_WIN_PING(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_TRIN00_WIN_PING")
	return nil, nil
}
func ProbeFunc_BECKHOFF_ADS(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	fmt.Println("ProbeFunc_BECKHOFF_ADS")
	return nil, nil
}
