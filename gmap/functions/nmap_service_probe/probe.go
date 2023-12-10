package nmap_service_probe

// 探针名称
const (
	ProbeName_NULL                     = "NULL"
	ProbeName_GenericLines             = "GenericLines"
	ProbeName_GetRequest               = "GetRequest"
	ProbeName_HTTPOptions              = "HTTPOptions"
	ProbeName_RTSPRequest              = "RTSPRequest"
	ProbeName_RPCCheck                 = "RPCCheck"
	ProbeName_DNSVersionBindReq        = "DNSVersionBindReq"
	ProbeName_DNSVersionBindReqTCP     = "DNSVersionBindReqTCP"
	ProbeName_DNSStatusRequest         = "DNSStatusRequest"
	ProbeName_DNSStatusRequestTCP      = "DNSStatusRequestTCP"
	ProbeName_NBTStat                  = "NBTStat"
	ProbeName_Help                     = "Help"
	ProbeName_Hello                    = "Hello"
	ProbeName_SSLSessionReq            = "SSLSessionReq"
	ProbeName_TerminalServerCookie     = "TerminalServerCookie"
	ProbeName_TLSSessionReq            = "TLSSessionReq"
	ProbeName_SSLv23SessionReq         = "SSLv23SessionReq"
	ProbeName_Kerberos                 = "Kerberos"
	ProbeName_SMBProgNeg               = "SMBProgNeg"
	ProbeName_X11Probe                 = "X11Probe"
	ProbeName_FourOhFourRequest        = "FourOhFourRequest"
	ProbeName_LPDString                = "LPDString"
	ProbeName_LDAPSearchReq            = "LDAPSearchReq"
	ProbeName_LDAPSearchReqUDP         = "LDAPSearchReqUDP"
	ProbeName_LDAPBindReq              = "LDAPBindReq"
	ProbeName_SIPOptions               = "SIPOptions"
	ProbeName_LANDesk_RC               = "LANDesk-RC"
	ProbeName_TerminalServer           = "TerminalServer"
	ProbeName_NCP                      = "NCP"
	ProbeName_NotesRPC                 = "NotesRPC"
	ProbeName_DistCCD                  = "DistCCD"
	ProbeName_JavaRMI                  = "JavaRMI"
	ProbeName_Radmin                   = "Radmin"
	ProbeName_Sqlping                  = "Sqlping"
	ProbeName_NTPRequest               = "NTPRequest"
	ProbeName_NessusTPv12              = "NessusTPv12"
	ProbeName_NessusTPv11              = "NessusTPv11"
	ProbeName_NessusTPv10              = "NessusTPv10"
	ProbeName_SNMPv1public             = "SNMPv1public"
	ProbeName_SNMPv3GetRequest         = "SNMPv3GetRequest"
	ProbeName_WMSRequest               = "WMSRequest"
	ProbeName_oracle_tns               = "oracle-tns"
	ProbeName_xdmcp                    = "xdmcp"
	ProbeName_AFSVersionRequest        = "AFSVersionRequest"
	ProbeName_mydoom                   = "mydoom"
	ProbeName_WWWOFFLEctrlstat         = "WWWOFFLEctrlstat"
	ProbeName_Verifier                 = "Verifier"
	ProbeName_VerifierAdvanced         = "VerifierAdvanced"
	ProbeName_Socks5                   = "Socks5"
	ProbeName_Socks4                   = "Socks4"
	ProbeName_OfficeScan               = "OfficeScan"
	ProbeName_ms_sql_s                 = "ms-sql-s"
	ProbeName_HELP4STOMP               = "HELP4STOMP"
	ProbeName_Memcache                 = "Memcache"
	ProbeName_beast2                   = "beast2"
	ProbeName_firebird                 = "firebird"
	ProbeName_ibm_db2_das              = "ibm-db2-das"
	ProbeName_ibm_db2                  = "ibm-db2"
	ProbeName_pervasive_relational     = "pervasive-relational"
	ProbeName_pervasive_btrieve        = "pervasive-btrieve"
	ProbeName_ibm_db2_das_udp          = "ibm-db2-das-udp"
	ProbeName_ajp                      = "ajp"
	ProbeName_DNS_SD                   = "DNS-SD"
	ProbeName_hp_pjl                   = "hp-pjl"
	ProbeName_Citrix                   = "Citrix"
	ProbeName_SqueezeCenter            = "SqueezeCenter"
	ProbeName_afp                      = "afp"
	ProbeName_Quake1_server_info       = "Quake1_server_info"
	ProbeName_Quake2_status            = "Quake2_status"
	ProbeName_Quake3_getstatus         = "Quake3_getstatus"
	ProbeName_Quake3_master_getservers = "Quake3_master_getservers"
	ProbeName_SqueezeCenter_CLI        = "SqueezeCenter_CLI"
	ProbeName_Arucer                   = "Arucer"
	ProbeName_serialnumberd            = "serialnumberd"
	ProbeName_dominoconsole            = "dominoconsole"
	ProbeName_informix                 = "informix"
	ProbeName_drda                     = "drda"
	ProbeName_ibm_mqseries             = "ibm-mqseries"
	ProbeName_apple_iphoto             = "apple-iphoto"
	ProbeName_ZendJavaBridge           = "ZendJavaBridge"
	ProbeName_BackOrifice              = "BackOrifice"
	ProbeName_gkrellm                  = "gkrellm"
	ProbeName_metasploit_xmlrpc        = "metasploit-xmlrpc"
	ProbeName_mongodb                  = "mongodb"
	ProbeName_sybaseanywhere           = "sybaseanywhere"
	ProbeName_vuze_dht                 = "vuze-dht"
	ProbeName_pc_anywhere              = "pc-anywhere"
	ProbeName_pc_duo                   = "pc-duo"
	ProbeName_pc_duo_gw                = "pc-duo-gw"
	ProbeName_redis_server             = "redis-server"
	ProbeName_memcached                = "memcached"
	ProbeName_riak_pbc                 = "riak-pbc"
	ProbeName_tarantool                = "tarantool"
	ProbeName_couchbase_data           = "couchbase-data"
	ProbeName_epmd                     = "epmd"
	ProbeName_vp3                      = "vp3"
	ProbeName_kumo_server              = "kumo-server"
	ProbeName_metasploit_msgrpc        = "metasploit-msgrpc"
	ProbeName_svrloc                   = "svrloc"
	ProbeName_hazelcast_http           = "hazelcast-http"
	ProbeName_minecraft_ping           = "minecraft-ping"
	ProbeName_erlang_node              = "erlang-node"
	ProbeName_Murmur                   = "Murmur"
	ProbeName_Ventrilo                 = "Ventrilo"
	ProbeName_teamspeak_tcpquery_ver   = "teamspeak-tcpquery-ver"
	ProbeName_TeamSpeak2               = "TeamSpeak2"
	ProbeName_TeamSpeak3               = "TeamSpeak3"
	ProbeName_xmlsysd                  = "xmlsysd"
	ProbeName_FreelancerStatus         = "FreelancerStatus"
	ProbeName_ASE                      = "ASE"
	ProbeName_AndroMouse               = "AndroMouse"
	ProbeName_AirHID                   = "AirHID"
	ProbeName_NetMotionMobility        = "NetMotionMobility"
	ProbeName_docker                   = "docker"
	ProbeName_tor_versions             = "tor-versions"
	ProbeName_TLS_PSK                  = "TLS-PSK"
	ProbeName_NJE                      = "NJE"
	ProbeName_tn3270                   = "tn3270"
	ProbeName_giop                     = "giop"
	ProbeName_OpenVPN                  = "OpenVPN"
	ProbeName_pcworx                   = "pcworx"
	ProbeName_proconos                 = "proconos"
	ProbeName_niagara_fox              = "niagara-fox"
	ProbeName_mqtt                     = "mqtt"
	ProbeName_ipmi_rmcp                = "ipmi-rmcp"
	ProbeName_coap_request             = "coap-request"
	ProbeName_DTLSSessionReq           = "DTLSSessionReq"
	ProbeName_iperf3                   = "iperf3"
	ProbeName_QUIC                     = "QUIC"
	ProbeName_VersionRequest           = "VersionRequest"
	ProbeName_NoMachine                = "NoMachine"
	ProbeName_JMON                     = "JMON"
	ProbeName_LibreOfficeImpressSCPair = "LibreOfficeImpressSCPair"
	ProbeName_ARD                      = "ARD"
	ProbeName_LSCP                     = "LSCP"
	ProbeName_rotctl                   = "rotctl"
	ProbeName_UbiquitiDiscoveryv1      = "UbiquitiDiscoveryv1"
	ProbeName_UbiquitiDiscoveryv2      = "UbiquitiDiscoveryv2"
	ProbeName_SharpTV                  = "SharpTV"
	ProbeName_adbConnect               = "adbConnect"
	ProbeName_piholeVersion            = "piholeVersion"
	ProbeName_teamtalk_login           = "teamtalk-login"
	ProbeName_insteonPLM               = "insteonPLM"
	ProbeName_DHCP_INFORM              = "DHCP_INFORM"
	ProbeName_TFTP_GET                 = "TFTP_GET"
	ProbeName_ONCRPC_CALL              = "ONCRPC_CALL"
	ProbeName_NTP_REQ                  = "NTP_REQ"
	ProbeName_DCERPC_CALL              = "DCERPC_CALL"
	ProbeName_CIFS_NS_UC               = "CIFS_NS_UC"
	ProbeName_CIFS_NS_BC               = "CIFS_NS_BC"
	ProbeName_IKE_MAIN_MODE            = "IKE_MAIN_MODE"
	ProbeName_IPSEC_START              = "IPSEC_START"
	ProbeName_RIPv1                    = "RIPv1"
	ProbeName_RMCP_ASF_PING            = "RMCP_ASF_PING"
	ProbeName_OPENVPN_PKI              = "OPENVPN_PKI"
	ProbeName_RADIUS_ACCESS            = "RADIUS_ACCESS"
	ProbeName_L2TP_ICRQ                = "L2TP_ICRQ"
	ProbeName_UPNP_MSEARCH             = "UPNP_MSEARCH"
	ProbeName_NFSPROC_NULL             = "NFSPROC_NULL"
	ProbeName_GPRS_GTPv1               = "GPRS_GTPv1"
	ProbeName_GPRS_GTPv2prime          = "GPRS_GTPv2prime"
	ProbeName_GPRS_GTPv2               = "GPRS_GTPv2"
	ProbeName_STUN_BIND                = "STUN_BIND"
	ProbeName_STD_DISCOVER             = "STD_DISCOVER"
	ProbeName_NAT_PMP_ADDR             = "NAT_PMP_ADDR"
	ProbeName_DNS_SD_QU                = "DNS_SD_QU"
	ProbeName_PCANY_STATUS             = "PCANY_STATUS"
	ProbeName_UT2K_PING                = "UT2K_PING"
	ProbeName_AMANDA_NOOP              = "AMANDA_NOOP"
	ProbeName_WDB_TARGET_PING          = "WDB_TARGET_PING"
	ProbeName_WDB_TARGET_CONNECT       = "WDB_TARGET_CONNECT"
	ProbeName_KADEMLIA_PING            = "KADEMLIA_PING"
	ProbeName_TS3INIT1                 = "TS3INIT1"
	ProbeName_MEMCACHED_VERSION        = "MEMCACHED_VERSION"
	ProbeName_STEAM                    = "STEAM"
	ProbeName_TRIN00_UNIX_PING         = "TRIN00_UNIX_PING"
	ProbeName_BO_PING                  = "BO_PING"
	ProbeName_TRIN00_WIN_PING          = "TRIN00_WIN_PING"
	ProbeName_BECKHOFF_ADS             = "BECKHOFF_ADS"
)

type ProbeMethod struct {
	ProbeName string // 探针名称
	Method    func(node *NmapServiceProbeNode, protocol int, isTLS bool, host string, port uint16) ([]string, error)
}

func NewProbeMethod() *ProbeMethod {
	return &ProbeMethod{}
}

var Global_SrvProbeNode = []*ProbeMethod{
	&ProbeMethod{
		ProbeName: ProbeName_NULL,
		Method:    ProbeFunc_NULL,
	},
	&ProbeMethod{
		ProbeName: ProbeName_GenericLines,
		Method:    ProbeFunc_GenericLines,
	},
	&ProbeMethod{
		ProbeName: ProbeName_GetRequest,
		Method:    ProbeFunc_GetRequest,
	},
	&ProbeMethod{
		ProbeName: ProbeName_HTTPOptions,
		Method:    ProbeFunc_HTTPOptions,
	},
	&ProbeMethod{
		ProbeName: ProbeName_RTSPRequest,
		Method:    ProbeFunc_RTSPRequest,
	},
	&ProbeMethod{
		ProbeName: ProbeName_RPCCheck,
		Method:    ProbeFunc_RPCCheck,
	},
	&ProbeMethod{
		ProbeName: ProbeName_DNSVersionBindReq,
		Method:    ProbeFunc_DNSVersionBindReq,
	},
	&ProbeMethod{
		ProbeName: ProbeName_DNSVersionBindReqTCP,
		Method:    ProbeFunc_DNSVersionBindReqTCP,
	},
	&ProbeMethod{
		ProbeName: ProbeName_DNSStatusRequest,
		Method:    ProbeFunc_DNSStatusRequest,
	},
	&ProbeMethod{
		ProbeName: ProbeName_DNSStatusRequestTCP,
		Method:    ProbeFunc_DNSStatusRequestTCP,
	},
	&ProbeMethod{
		ProbeName: ProbeName_NBTStat,
		Method:    ProbeFunc_NBTStat,
	},
	&ProbeMethod{
		ProbeName: ProbeName_Help,
		Method:    ProbeFunc_Help,
	},
	&ProbeMethod{
		ProbeName: ProbeName_Hello,
		Method:    ProbeFunc_Hello,
	},
	&ProbeMethod{
		ProbeName: ProbeName_SSLSessionReq,
		Method:    ProbeFunc_SSLSessionReq,
	},
	&ProbeMethod{
		ProbeName: ProbeName_TerminalServerCookie,
		Method:    ProbeFunc_TerminalServerCookie,
	},
	&ProbeMethod{
		ProbeName: ProbeName_TLSSessionReq,
		Method:    ProbeFunc_TLSSessionReq,
	},
	&ProbeMethod{
		ProbeName: ProbeName_SSLv23SessionReq,
		Method:    ProbeFunc_SSLv23SessionReq,
	},
	&ProbeMethod{
		ProbeName: ProbeName_Kerberos,
		Method:    ProbeFunc_Kerberos,
	},
	&ProbeMethod{
		ProbeName: ProbeName_SMBProgNeg,
		Method:    ProbeFunc_SMBProgNeg,
	},
	&ProbeMethod{
		ProbeName: ProbeName_X11Probe,
		Method:    ProbeFunc_X11Probe,
	},
	&ProbeMethod{
		ProbeName: ProbeName_FourOhFourRequest,
		Method:    ProbeFunc_FourOhFourRequest,
	},
	&ProbeMethod{
		ProbeName: ProbeName_LPDString,
		Method:    ProbeFunc_LPDString,
	},
	&ProbeMethod{
		ProbeName: ProbeName_LDAPSearchReq,
		Method:    ProbeFunc_LDAPSearchReq,
	},
	&ProbeMethod{
		ProbeName: ProbeName_LDAPSearchReqUDP,
		Method:    ProbeFunc_LDAPSearchReqUDP,
	},
	&ProbeMethod{
		ProbeName: ProbeName_LDAPBindReq,
		Method:    ProbeFunc_LDAPBindReq,
	},
	&ProbeMethod{
		ProbeName: ProbeName_SIPOptions,
		Method:    ProbeFunc_SIPOptions,
	},
	&ProbeMethod{
		ProbeName: ProbeName_LANDesk_RC,
		Method:    ProbeFunc_LANDesk_RC,
	},
	&ProbeMethod{
		ProbeName: ProbeName_TerminalServer,
		Method:    ProbeFunc_TerminalServer,
	},
	&ProbeMethod{
		ProbeName: ProbeName_NCP,
		Method:    ProbeFunc_NCP,
	},
	&ProbeMethod{
		ProbeName: ProbeName_NotesRPC,
		Method:    ProbeFunc_NotesRPC,
	},
	&ProbeMethod{
		ProbeName: ProbeName_DistCCD,
		Method:    ProbeFunc_DistCCD,
	},
	&ProbeMethod{
		ProbeName: ProbeName_JavaRMI,
		Method:    ProbeFunc_JavaRMI,
	},
	&ProbeMethod{
		ProbeName: ProbeName_Radmin,
		Method:    ProbeFunc_Radmin,
	},
	&ProbeMethod{
		ProbeName: ProbeName_Sqlping,
		Method:    ProbeFunc_Sqlping,
	},
	&ProbeMethod{
		ProbeName: ProbeName_NTPRequest,
		Method:    ProbeFunc_NTPRequest,
	},
	&ProbeMethod{
		ProbeName: ProbeName_NessusTPv12,
		Method:    ProbeFunc_NessusTPv12,
	},
	&ProbeMethod{
		ProbeName: ProbeName_NessusTPv11,
		Method:    ProbeFunc_NessusTPv11,
	},
	&ProbeMethod{
		ProbeName: ProbeName_NessusTPv10,
		Method:    ProbeFunc_NessusTPv10,
	},
	&ProbeMethod{
		ProbeName: ProbeName_SNMPv1public,
		Method:    ProbeFunc_SNMPv1public,
	},
	&ProbeMethod{
		ProbeName: ProbeName_SNMPv3GetRequest,
		Method:    ProbeFunc_SNMPv3GetRequest,
	},
	&ProbeMethod{
		ProbeName: ProbeName_WMSRequest,
		Method:    ProbeFunc_WMSRequest,
	},
	&ProbeMethod{
		ProbeName: ProbeName_oracle_tns,
		Method:    ProbeFunc_oracle_tns,
	},
	&ProbeMethod{
		ProbeName: ProbeName_xdmcp,
		Method:    ProbeFunc_xdmcp,
	},
	&ProbeMethod{
		ProbeName: ProbeName_AFSVersionRequest,
		Method:    ProbeFunc_AFSVersionRequest,
	},
	&ProbeMethod{
		ProbeName: ProbeName_mydoom,
		Method:    ProbeFunc_mydoom,
	},
	&ProbeMethod{
		ProbeName: ProbeName_WWWOFFLEctrlstat,
		Method:    ProbeFunc_WWWOFFLEctrlstat,
	},
	&ProbeMethod{
		ProbeName: ProbeName_Verifier,
		Method:    ProbeFunc_Verifier,
	},
	&ProbeMethod{
		ProbeName: ProbeName_VerifierAdvanced,
		Method:    ProbeFunc_VerifierAdvanced,
	},
	&ProbeMethod{
		ProbeName: ProbeName_Socks5,
		Method:    ProbeFunc_Socks5,
	},
	&ProbeMethod{
		ProbeName: ProbeName_Socks4,
		Method:    ProbeFunc_Socks4,
	},
	&ProbeMethod{
		ProbeName: ProbeName_OfficeScan,
		Method:    ProbeFunc_OfficeScan,
	},
	&ProbeMethod{
		ProbeName: ProbeName_ms_sql_s,
		Method:    ProbeFunc_ms_sql_s,
	},
	&ProbeMethod{
		ProbeName: ProbeName_HELP4STOMP,
		Method:    ProbeFunc_HELP4STOMP,
	},
	&ProbeMethod{
		ProbeName: ProbeName_Memcache,
		Method:    ProbeFunc_Memcache,
	},
	&ProbeMethod{
		ProbeName: ProbeName_beast2,
		Method:    ProbeFunc_beast2,
	},
	&ProbeMethod{
		ProbeName: ProbeName_firebird,
		Method:    ProbeFunc_firebird,
	},
	&ProbeMethod{
		ProbeName: ProbeName_ibm_db2_das,
		Method:    ProbeFunc_ibm_db2_das,
	},
	&ProbeMethod{
		ProbeName: ProbeName_ibm_db2,
		Method:    ProbeFunc_ibm_db2,
	},
	&ProbeMethod{
		ProbeName: ProbeName_pervasive_relational,
		Method:    ProbeFunc_pervasive_relational,
	},
	&ProbeMethod{
		ProbeName: ProbeName_pervasive_btrieve,
		Method:    ProbeFunc_pervasive_btrieve,
	},
	&ProbeMethod{
		ProbeName: ProbeName_ibm_db2_das_udp,
		Method:    ProbeFunc_ibm_db2_das_udp,
	},
	&ProbeMethod{
		ProbeName: ProbeName_ajp,
		Method:    ProbeFunc_ajp,
	},
	&ProbeMethod{
		ProbeName: ProbeName_DNS_SD,
		Method:    ProbeFunc_DNS_SD,
	},
	&ProbeMethod{
		ProbeName: ProbeName_hp_pjl,
		Method:    ProbeFunc_hp_pjl,
	},
	&ProbeMethod{
		ProbeName: ProbeName_Citrix,
		Method:    ProbeFunc_Citrix,
	},
	&ProbeMethod{
		ProbeName: ProbeName_SqueezeCenter,
		Method:    ProbeFunc_SqueezeCenter,
	},
	&ProbeMethod{
		ProbeName: ProbeName_afp,
		Method:    ProbeFunc_afp,
	},
	&ProbeMethod{
		ProbeName: ProbeName_Quake1_server_info,
		Method:    ProbeFunc_Quake1_server_info,
	},
	&ProbeMethod{
		ProbeName: ProbeName_Quake2_status,
		Method:    ProbeFunc_Quake2_status,
	},
	&ProbeMethod{
		ProbeName: ProbeName_Quake3_getstatus,
		Method:    ProbeFunc_Quake3_getstatus,
	},
	&ProbeMethod{
		ProbeName: ProbeName_Quake3_master_getservers,
		Method:    ProbeFunc_Quake3_master_getservers,
	},
	&ProbeMethod{
		ProbeName: ProbeName_SqueezeCenter_CLI,
		Method:    ProbeFunc_SqueezeCenter_CLI,
	},
	&ProbeMethod{
		ProbeName: ProbeName_Arucer,
		Method:    ProbeFunc_Arucer,
	},
	&ProbeMethod{
		ProbeName: ProbeName_serialnumberd,
		Method:    ProbeFunc_serialnumberd,
	},
	&ProbeMethod{
		ProbeName: ProbeName_dominoconsole,
		Method:    ProbeFunc_dominoconsole,
	},
	&ProbeMethod{
		ProbeName: ProbeName_informix,
		Method:    ProbeFunc_informix,
	},
	&ProbeMethod{
		ProbeName: ProbeName_drda,
		Method:    ProbeFunc_drda,
	},
	&ProbeMethod{
		ProbeName: ProbeName_ibm_mqseries,
		Method:    ProbeFunc_ibm_mqseries,
	},
	&ProbeMethod{
		ProbeName: ProbeName_apple_iphoto,
		Method:    ProbeFunc_apple_iphoto,
	},
	&ProbeMethod{
		ProbeName: ProbeName_ZendJavaBridge,
		Method:    ProbeFunc_ZendJavaBridge,
	},
	&ProbeMethod{
		ProbeName: ProbeName_BackOrifice,
		Method:    ProbeFunc_BackOrifice,
	},
	&ProbeMethod{
		ProbeName: ProbeName_gkrellm,
		Method:    ProbeFunc_gkrellm,
	},
	&ProbeMethod{
		ProbeName: ProbeName_metasploit_xmlrpc,
		Method:    ProbeFunc_metasploit_xmlrpc,
	},
	&ProbeMethod{
		ProbeName: ProbeName_mongodb,
		Method:    ProbeFunc_mongodb,
	},
	&ProbeMethod{
		ProbeName: ProbeName_sybaseanywhere,
		Method:    ProbeFunc_sybaseanywhere,
	},
	&ProbeMethod{
		ProbeName: ProbeName_vuze_dht,
		Method:    ProbeFunc_vuze_dht,
	},
	&ProbeMethod{
		ProbeName: ProbeName_pc_anywhere,
		Method:    ProbeFunc_pc_anywhere,
	},
	&ProbeMethod{
		ProbeName: ProbeName_pc_duo,
		Method:    ProbeFunc_pc_duo,
	},
	&ProbeMethod{
		ProbeName: ProbeName_pc_duo_gw,
		Method:    ProbeFunc_pc_duo_gw,
	},
	&ProbeMethod{
		ProbeName: ProbeName_redis_server,
		Method:    ProbeFunc_redis_server,
	},
	&ProbeMethod{
		ProbeName: ProbeName_memcached,
		Method:    ProbeFunc_memcached,
	},
	&ProbeMethod{
		ProbeName: ProbeName_riak_pbc,
		Method:    ProbeFunc_riak_pbc,
	},
	&ProbeMethod{
		ProbeName: ProbeName_tarantool,
		Method:    ProbeFunc_tarantool,
	},
	&ProbeMethod{
		ProbeName: ProbeName_couchbase_data,
		Method:    ProbeFunc_couchbase_data,
	},
	&ProbeMethod{
		ProbeName: ProbeName_epmd,
		Method:    ProbeFunc_epmd,
	},
	&ProbeMethod{
		ProbeName: ProbeName_vp3,
		Method:    ProbeFunc_vp3,
	},
	&ProbeMethod{
		ProbeName: ProbeName_kumo_server,
		Method:    ProbeFunc_kumo_server,
	},
	&ProbeMethod{
		ProbeName: ProbeName_metasploit_msgrpc,
		Method:    ProbeFunc_metasploit_msgrpc,
	},
	&ProbeMethod{
		ProbeName: ProbeName_svrloc,
		Method:    ProbeFunc_svrloc,
	},
	&ProbeMethod{
		ProbeName: ProbeName_hazelcast_http,
		Method:    ProbeFunc_hazelcast_http,
	},
	&ProbeMethod{
		ProbeName: ProbeName_minecraft_ping,
		Method:    ProbeFunc_minecraft_ping,
	},
	&ProbeMethod{
		ProbeName: ProbeName_erlang_node,
		Method:    ProbeFunc_erlang_node,
	},
	&ProbeMethod{
		ProbeName: ProbeName_Murmur,
		Method:    ProbeFunc_Murmur,
	},
	&ProbeMethod{
		ProbeName: ProbeName_Ventrilo,
		Method:    ProbeFunc_Ventrilo,
	},
	&ProbeMethod{
		ProbeName: ProbeName_teamspeak_tcpquery_ver,
		Method:    ProbeFunc_teamspeak_tcpquery_ver,
	},
	&ProbeMethod{
		ProbeName: ProbeName_TeamSpeak2,
		Method:    ProbeFunc_TeamSpeak2,
	},
	&ProbeMethod{
		ProbeName: ProbeName_TeamSpeak3,
		Method:    ProbeFunc_TeamSpeak3,
	},
	&ProbeMethod{
		ProbeName: ProbeName_xmlsysd,
		Method:    ProbeFunc_xmlsysd,
	},
	&ProbeMethod{
		ProbeName: ProbeName_FreelancerStatus,
		Method:    ProbeFunc_FreelancerStatus,
	},
	&ProbeMethod{
		ProbeName: ProbeName_ASE,
		Method:    ProbeFunc_ASE,
	},
	&ProbeMethod{
		ProbeName: ProbeName_AndroMouse,
		Method:    ProbeFunc_AndroMouse,
	},
	&ProbeMethod{
		ProbeName: ProbeName_AirHID,
		Method:    ProbeFunc_AirHID,
	},
	&ProbeMethod{
		ProbeName: ProbeName_NetMotionMobility,
		Method:    ProbeFunc_NetMotionMobility,
	},
	&ProbeMethod{
		ProbeName: ProbeName_docker,
		Method:    ProbeFunc_docker,
	},
	&ProbeMethod{
		ProbeName: ProbeName_tor_versions,
		Method:    ProbeFunc_tor_versions,
	},
	&ProbeMethod{
		ProbeName: ProbeName_TLS_PSK,
		Method:    ProbeFunc_TLS_PSK,
	},
	&ProbeMethod{
		ProbeName: ProbeName_NJE,
		Method:    ProbeFunc_NJE,
	},
	&ProbeMethod{
		ProbeName: ProbeName_tn3270,
		Method:    ProbeFunc_tn3270,
	},
	&ProbeMethod{
		ProbeName: ProbeName_giop,
		Method:    ProbeFunc_giop,
	},
	&ProbeMethod{
		ProbeName: ProbeName_OpenVPN,
		Method:    ProbeFunc_OpenVPN,
	},
	&ProbeMethod{
		ProbeName: ProbeName_pcworx,
		Method:    ProbeFunc_pcworx,
	},
	&ProbeMethod{
		ProbeName: ProbeName_proconos,
		Method:    ProbeFunc_proconos,
	},
	&ProbeMethod{
		ProbeName: ProbeName_niagara_fox,
		Method:    ProbeFunc_niagara_fox,
	},
	&ProbeMethod{
		ProbeName: ProbeName_mqtt,
		Method:    ProbeFunc_mqtt,
	},
	&ProbeMethod{
		ProbeName: ProbeName_ipmi_rmcp,
		Method:    ProbeFunc_ipmi_rmcp,
	},
	&ProbeMethod{
		ProbeName: ProbeName_coap_request,
		Method:    ProbeFunc_coap_request,
	},
	&ProbeMethod{
		ProbeName: ProbeName_DTLSSessionReq,
		Method:    ProbeFunc_DTLSSessionReq,
	},
	&ProbeMethod{
		ProbeName: ProbeName_iperf3,
		Method:    ProbeFunc_iperf3,
	},
	&ProbeMethod{
		ProbeName: ProbeName_QUIC,
		Method:    ProbeFunc_QUIC,
	},
	&ProbeMethod{
		ProbeName: ProbeName_VersionRequest,
		Method:    ProbeFunc_VersionRequest,
	},
	&ProbeMethod{
		ProbeName: ProbeName_NoMachine,
		Method:    ProbeFunc_NoMachine,
	},
	&ProbeMethod{
		ProbeName: ProbeName_JMON,
		Method:    ProbeFunc_JMON,
	},
	&ProbeMethod{
		ProbeName: ProbeName_LibreOfficeImpressSCPair,
		Method:    ProbeFunc_LibreOfficeImpressSCPair,
	},
	&ProbeMethod{
		ProbeName: ProbeName_ARD,
		Method:    ProbeFunc_ARD,
	},
	&ProbeMethod{
		ProbeName: ProbeName_LSCP,
		Method:    ProbeFunc_LSCP,
	},
	&ProbeMethod{
		ProbeName: ProbeName_rotctl,
		Method:    ProbeFunc_rotctl,
	},
	&ProbeMethod{
		ProbeName: ProbeName_UbiquitiDiscoveryv1,
		Method:    ProbeFunc_UbiquitiDiscoveryv1,
	},
	&ProbeMethod{
		ProbeName: ProbeName_UbiquitiDiscoveryv2,
		Method:    ProbeFunc_UbiquitiDiscoveryv2,
	},
	&ProbeMethod{
		ProbeName: ProbeName_SharpTV,
		Method:    ProbeFunc_SharpTV,
	},
	&ProbeMethod{
		ProbeName: ProbeName_adbConnect,
		Method:    ProbeFunc_adbConnect,
	},
	&ProbeMethod{
		ProbeName: ProbeName_piholeVersion,
		Method:    ProbeFunc_piholeVersion,
	},
	&ProbeMethod{
		ProbeName: ProbeName_teamtalk_login,
		Method:    ProbeFunc_teamtalk_login,
	},
	&ProbeMethod{
		ProbeName: ProbeName_insteonPLM,
		Method:    ProbeFunc_insteonPLM,
	},
	&ProbeMethod{
		ProbeName: ProbeName_DHCP_INFORM,
		Method:    ProbeFunc_DHCP_INFORM,
	},
	&ProbeMethod{
		ProbeName: ProbeName_TFTP_GET,
		Method:    ProbeFunc_TFTP_GET,
	},
	&ProbeMethod{
		ProbeName: ProbeName_ONCRPC_CALL,
		Method:    ProbeFunc_ONCRPC_CALL,
	},
	&ProbeMethod{
		ProbeName: ProbeName_NTP_REQ,
		Method:    ProbeFunc_NTP_REQ,
	},
	&ProbeMethod{
		ProbeName: ProbeName_DCERPC_CALL,
		Method:    ProbeFunc_DCERPC_CALL,
	},
	&ProbeMethod{
		ProbeName: ProbeName_CIFS_NS_UC,
		Method:    ProbeFunc_CIFS_NS_UC,
	},
	&ProbeMethod{
		ProbeName: ProbeName_CIFS_NS_BC,
		Method:    ProbeFunc_CIFS_NS_BC,
	},
	&ProbeMethod{
		ProbeName: ProbeName_IKE_MAIN_MODE,
		Method:    ProbeFunc_IKE_MAIN_MODE,
	},
	&ProbeMethod{
		ProbeName: ProbeName_IPSEC_START,
		Method:    ProbeFunc_IPSEC_START,
	},
	&ProbeMethod{
		ProbeName: ProbeName_RIPv1,
		Method:    ProbeFunc_RIPv1,
	},
	&ProbeMethod{
		ProbeName: ProbeName_RMCP_ASF_PING,
		Method:    ProbeFunc_RMCP_ASF_PING,
	},
	&ProbeMethod{
		ProbeName: ProbeName_OPENVPN_PKI,
		Method:    ProbeFunc_OPENVPN_PKI,
	},
	&ProbeMethod{
		ProbeName: ProbeName_RADIUS_ACCESS,
		Method:    ProbeFunc_RADIUS_ACCESS,
	},
	&ProbeMethod{
		ProbeName: ProbeName_L2TP_ICRQ,
		Method:    ProbeFunc_L2TP_ICRQ,
	},
	&ProbeMethod{
		ProbeName: ProbeName_UPNP_MSEARCH,
		Method:    ProbeFunc_UPNP_MSEARCH,
	},
	&ProbeMethod{
		ProbeName: ProbeName_NFSPROC_NULL,
		Method:    ProbeFunc_NFSPROC_NULL,
	},
	&ProbeMethod{
		ProbeName: ProbeName_GPRS_GTPv1,
		Method:    ProbeFunc_GPRS_GTPv1,
	},
	&ProbeMethod{
		ProbeName: ProbeName_GPRS_GTPv2prime,
		Method:    ProbeFunc_GPRS_GTPv2prime,
	},
	&ProbeMethod{
		ProbeName: ProbeName_GPRS_GTPv2,
		Method:    ProbeFunc_GPRS_GTPv2,
	},
	&ProbeMethod{
		ProbeName: ProbeName_STUN_BIND,
		Method:    ProbeFunc_STUN_BIND,
	},
	&ProbeMethod{
		ProbeName: ProbeName_STD_DISCOVER,
		Method:    ProbeFunc_STD_DISCOVER,
	},
	&ProbeMethod{
		ProbeName: ProbeName_NAT_PMP_ADDR,
		Method:    ProbeFunc_NAT_PMP_ADDR,
	},
	&ProbeMethod{
		ProbeName: ProbeName_DNS_SD_QU,
		Method:    ProbeFunc_DNS_SD_QU,
	},
	&ProbeMethod{
		ProbeName: ProbeName_PCANY_STATUS,
		Method:    ProbeFunc_PCANY_STATUS,
	},
	&ProbeMethod{
		ProbeName: ProbeName_UT2K_PING,
		Method:    ProbeFunc_UT2K_PING,
	},
	&ProbeMethod{
		ProbeName: ProbeName_AMANDA_NOOP,
		Method:    ProbeFunc_AMANDA_NOOP,
	},
	&ProbeMethod{
		ProbeName: ProbeName_WDB_TARGET_PING,
		Method:    ProbeFunc_WDB_TARGET_PING,
	},
	&ProbeMethod{
		ProbeName: ProbeName_WDB_TARGET_CONNECT,
		Method:    ProbeFunc_WDB_TARGET_CONNECT,
	},
	&ProbeMethod{
		ProbeName: ProbeName_KADEMLIA_PING,
		Method:    ProbeFunc_KADEMLIA_PING,
	},
	&ProbeMethod{
		ProbeName: ProbeName_TS3INIT1,
		Method:    ProbeFunc_TS3INIT1,
	},
	&ProbeMethod{
		ProbeName: ProbeName_MEMCACHED_VERSION,
		Method:    ProbeFunc_MEMCACHED_VERSION,
	},
	&ProbeMethod{
		ProbeName: ProbeName_STEAM,
		Method:    ProbeFunc_STEAM,
	},
	&ProbeMethod{
		ProbeName: ProbeName_TRIN00_UNIX_PING,
		Method:    ProbeFunc_TRIN00_UNIX_PING,
	},
	&ProbeMethod{
		ProbeName: ProbeName_BO_PING,
		Method:    ProbeFunc_BO_PING,
	},
	&ProbeMethod{
		ProbeName: ProbeName_TRIN00_WIN_PING,
		Method:    ProbeFunc_TRIN00_WIN_PING,
	},
	&ProbeMethod{
		ProbeName: ProbeName_BECKHOFF_ADS,
		Method:    ProbeFunc_BECKHOFF_ADS,
	},
}

func GetProbeMethod(probeName string) *ProbeMethod {
	for _, item := range Global_SrvProbeNode {
		if item.ProbeName == probeName {
			return item
		}
	}

	return nil
}
