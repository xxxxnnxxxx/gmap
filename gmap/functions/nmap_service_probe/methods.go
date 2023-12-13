package nmap_service_probe

import (
	"Gmap/gmap/netex/sock"
	"errors"
	"time"
)

// 获取网络数据
func GetData(protocol int,
	isTLS bool,
	host string,
	port uint16,
	data string,
	timeout int64) (string, error) {
	btcp := sock.NewBaseDialer(protocol, isTLS)
	btcp.HandleData = func(data []byte, n int) {
		btcp.Close()
	}
	// 1m
	btcp.SetCacheSize(1024 * 1024)
	btcp.SetIP(host)
	btcp.SetPort(port)
	btcp.IsBlockMode = true
	if timeout > 0 {
		btcp.SetConnTimeout(timeout)
		btcp.SetReadTimeout(timeout)
	} else {
		btcp.SetConnTimeout(1000)
		btcp.SetReadTimeout(2000)
	}

	btcp.Dial(false)
	btcp.Listen()
	btcp.Send([]byte(data))
	err := btcp.WaitTimeout(2 * time.Second)
	buf := btcp.GetRecvedBuf()
	if len(buf) == 0 {
		return "", errors.New("don't recved data")
	}
	return string(buf), err
}

func handleProbe(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	content, err := GetData(protocol, isTLS, host, port, pn.Probestring, int64(pn.Totalwaitms))
	if len(content) == 0 {
		return nil, err
	}
	// 匹配内容
	result, err := pn.Match(content)
	if err != nil {
		// 如果没有找到相关的匹配，那么通过fallback查找
		for _, item := range pn.Fallback1.FallbackProbeNodes {
			result, err = item.Match(content)
			if err == nil {
				return result, nil
			}
		}
		return nil, err
	}
	return result, nil
}

func ProbeFunc_NULL(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_GenericLines(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_GetRequest(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_HTTPOptions(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_RTSPRequest(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_RPCCheck(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_DNSVersionBindReq(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_DNSVersionBindReqTCP(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_DNSStatusRequest(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_DNSStatusRequestTCP(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_NBTStat(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_Help(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_Hello(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_SSLSessionReq(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_TerminalServerCookie(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_TLSSessionReq(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_SSLv23SessionReq(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_Kerberos(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_SMBProgNeg(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_X11Probe(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_FourOhFourRequest(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_LPDString(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_LDAPSearchReq(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_LDAPSearchReqUDP(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_LDAPBindReq(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_SIPOptions(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_LANDesk_RC(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_TerminalServer(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_NCP(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_NotesRPC(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_DistCCD(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_JavaRMI(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_Radmin(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_Sqlping(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_NTPRequest(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_NessusTPv12(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_NessusTPv11(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_NessusTPv10(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_SNMPv1public(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_SNMPv3GetRequest(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_WMSRequest(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_oracle_tns(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_xdmcp(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_AFSVersionRequest(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_mydoom(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_WWWOFFLEctrlstat(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_Verifier(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_VerifierAdvanced(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_Socks5(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_Socks4(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_OfficeScan(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_ms_sql_s(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_HELP4STOMP(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_Memcache(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_beast2(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_firebird(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_ibm_db2_das(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_ibm_db2(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_pervasive_relational(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_pervasive_btrieve(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_ibm_db2_das_udp(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_ajp(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_DNS_SD(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_hp_pjl(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_Citrix(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_SqueezeCenter(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_afp(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_Quake1_server_info(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_Quake2_status(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_Quake3_getstatus(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_Quake3_master_getservers(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_SqueezeCenter_CLI(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_Arucer(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_serialnumberd(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_dominoconsole(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_informix(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_drda(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_ibm_mqseries(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_apple_iphoto(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_ZendJavaBridge(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_BackOrifice(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_gkrellm(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_metasploit_xmlrpc(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_mongodb(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_sybaseanywhere(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_vuze_dht(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_pc_anywhere(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_pc_duo(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_pc_duo_gw(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_redis_server(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_memcached(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_riak_pbc(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_tarantool(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_couchbase_data(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_epmd(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_vp3(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_kumo_server(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_metasploit_msgrpc(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_svrloc(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_hazelcast_http(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_minecraft_ping(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_erlang_node(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_Murmur(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_Ventrilo(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_teamspeak_tcpquery_ver(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_TeamSpeak2(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_TeamSpeak3(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_xmlsysd(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_FreelancerStatus(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_ASE(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_AndroMouse(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_AirHID(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_NetMotionMobility(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_docker(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_tor_versions(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_TLS_PSK(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_NJE(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_tn3270(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_giop(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_OpenVPN(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_pcworx(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_proconos(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_niagara_fox(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_mqtt(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_ipmi_rmcp(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_coap_request(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_DTLSSessionReq(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_iperf3(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_QUIC(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_VersionRequest(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_NoMachine(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_JMON(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_LibreOfficeImpressSCPair(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_ARD(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_LSCP(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_rotctl(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_UbiquitiDiscoveryv1(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_UbiquitiDiscoveryv2(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_SharpTV(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_adbConnect(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_piholeVersion(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_teamtalk_login(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_insteonPLM(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_DHCP_INFORM(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_TFTP_GET(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_ONCRPC_CALL(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_NTP_REQ(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_DCERPC_CALL(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_CIFS_NS_UC(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_CIFS_NS_BC(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_IKE_MAIN_MODE(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_IPSEC_START(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_RIPv1(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_RMCP_ASF_PING(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_OPENVPN_PKI(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_RADIUS_ACCESS(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_L2TP_ICRQ(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_UPNP_MSEARCH(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_NFSPROC_NULL(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_GPRS_GTPv1(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_GPRS_GTPv2prime(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_GPRS_GTPv2(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_STUN_BIND(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_STD_DISCOVER(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_NAT_PMP_ADDR(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_DNS_SD_QU(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_PCANY_STATUS(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_UT2K_PING(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_AMANDA_NOOP(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_WDB_TARGET_PING(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_WDB_TARGET_CONNECT(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_KADEMLIA_PING(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_TS3INIT1(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_MEMCACHED_VERSION(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_STEAM(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_TRIN00_UNIX_PING(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_BO_PING(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_TRIN00_WIN_PING(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
func ProbeFunc_BECKHOFF_ADS(pn *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error) {
	return handleProbe(pn, protocol, isTLS, host, port)
}
