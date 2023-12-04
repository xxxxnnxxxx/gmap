package http

import (
	"ProbeTools/gmap/common"
	"ProbeTools/gmap/log"
	"ProbeTools/gmap/netex/sock"
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	ResponseDataStatus_NotFoundHeaders = iota + 1
	ResponseDataStatus_FoundHeaders
	ResponseDataStatus_DataBodyContinue
	ResponseDataStatus_Finished
)

const (
	HTTP11 = "HTTP/1.1"
	HTTP20 = "HTTP/2.0"
)

const (
	Header_Host            = "Host"
	Header_Content_type    = "content-type"
	Header_User_Agent      = "User-Agent"
	Header_Accept          = "Accept"
	Header_Accept_Encoding = "Accept-Encoding"
	Header_Connection      = "Connection"
	Header_Accept_Language = "Accept-Language"
)

const (
	Default_Header_Content_type_value    = ""
	Default_Headder_User_Agent_value     = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36`
	Default_Header_Accept_value          = `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`
	Default_Header_Accept_Encoding_value = `gzip, deflate, br`
	Default_Header_Accept_Language_value = `zh-CN,zh;q=0.9`
	Default_Header_Connection_value      = "close"
)

const (
	ContentEncoding_Gzip = iota + 1
	ContentEncoding_Deflate
	ContentEncoding_Compress
	ContentEncoding_Br
)

const (
	TransferEncoding_Chunked = iota + 1
	TransferEncoding_Compress
	TransferEncoding_Deflate
	TransferEncoding_Gzip
	TransferEncoding_Identity
)

type Response struct {
	Protocol           string
	Version            string
	StatusCode         int
	StatusMsg          string
	HPBannerLock       sync.Mutex // Protocol Version StatusCode StatusMsg 都属于 Http头部的信息， 例如 HTTP/1.1 200 OK
	ResponseRecvStatus int32      // 0 默认 1 完成header接收 2 完成所有的数据接收

	Headers       map[string]string
	OffsetHeaders int        // 头部所在位置的数据偏移
	HPHeaderLock  sync.Mutex // 处理头部数据的锁 Headers, OffsetHeaders

	OffsetContent   int32  // 数据内容的偏移
	ContentLength   int32  // 数据长度
	Content         string // 数据
	bHasExistLength bool   // 存在长度的，当Transfer-Encoding的情况下，ContentLength是无效的处理，所以在Transfer-Encoding的情况下，忽略长度
	ContentEncoding int
	HPContentLock   sync.Mutex // 处理 OffsetContent, ContentLength 的锁

	bHasTransferEncoding bool
	TransferEncoding     int
}
type HttpEntity struct {
	IsTls           bool
	Url             *url.URL
	IP              net.IP // IP的优先级优于 Url
	Port            uint16
	ProtocolVersion string
	ReqHeaders      map[string]string
	HandleData      func([]byte) error // 数据达到回调
	Response

	dialer       *sock.BaseDialer
	buffer       *common.Buffer
	maxCacheSize int // 最大缓存
	cacheSize    int // 当前缓存长度
}

func NewHttpEntity() *HttpEntity {

	he := &HttpEntity{
		ReqHeaders:      make(map[string]string),
		buffer:          common.NewBuffer(),
		dialer:          sock.NewBaseDialer(sock.ProtocolType_TCP, false),
		ProtocolVersion: HTTP11,
		Response: Response{
			bHasExistLength:      false,
			bHasTransferEncoding: false,
			Headers:              make(map[string]string),
		},
	}
	he.dialer.SetReadTimeout(30)
	he.dialer.HandleData = he.handleTCPData
	he.defaultReqheader()

	return he
}

func (p *HttpEntity) defaultReqheader() {
	p.ReqHeaders[Header_User_Agent] = Default_Headder_User_Agent_value
	p.ReqHeaders[Header_Accept] = Default_Header_Accept_value
	// p.ReqHeaders[Header_Accept_Encoding] = Default_Header_Accept_Encoding_value
	p.ReqHeaders[Header_Connection] = Default_Header_Connection_value
}

func (p *HttpEntity) handleTCPData(buf []byte, length int) error {
	p.buffer.Write(buf, length)
	status := atomic.LoadInt32(&p.ResponseRecvStatus)
	if status == 0 {
		p.analyzeHttpHeaders()
	} else if status == 1 {
		go p.analyzeContent()
	}

	return nil
}

// 处理banner， 形如 HTTP/1.1 200 OK
func (p *HttpEntity) analyzeHttpHeaders() error {
	p.Response.HPHeaderLock.Lock()
	defer p.Response.HPHeaderLock.Unlock()

	status := atomic.LoadInt32(&p.ResponseRecvStatus)
	if status >= 1 {
		return nil
	}

	buf, _ := p.buffer.Read()

	var err error
	httpProtocolLen := bytes.Index(buf, []byte("\r\n\r\n"))
	bannerLen := bytes.Index(buf, []byte("\r\n"))

	if httpProtocolLen == -1 {
		return nil
	}
	// banner
	infos := strings.Split(string(buf[:bannerLen]), " ")
	if len(infos) != 3 {
		return errors.New("")
	}

	// 返回首部
	p.Response.Protocol = infos[0]
	p.Response.StatusCode, err = strconv.Atoi(infos[1])
	if err != nil {
		return err
	}
	p.Response.StatusMsg = infos[2]

	// headers
	szheaders := string(buf[bannerLen+2 : httpProtocolLen])
	headers := strings.Split(szheaders, "\r\n")
	for _, item := range headers {
		item = strings.Trim(item, "\r\n ")
		if len(item) == 0 {
			continue
		}
		kv := strings.SplitN(item, ":", 2)
		p.Response.Headers[kv[0]] = strings.Trim(kv[1], " ")

		// 页面编码
		if strings.ToLower(kv[0]) == "content-encoding" {
			vv := strings.Split(kv[1], ",")
			for _, item := range vv {
				method := strings.ToLower(strings.Trim(item, " "))
				if len(method) == 0 {
					continue
				}

				switch method {
				case "gzip":
					p.ContentEncoding = ContentEncoding_Gzip
				case "compress":
					p.ContentEncoding = ContentEncoding_Compress
				case "deflate":
					p.ContentEncoding = ContentEncoding_Deflate
				case "br":
					p.ContentEncoding = ContentEncoding_Br
				}
			}
		}

		// Content-Length
		if strings.ToLower(kv[0]) == "content-length" {
			p.bHasExistLength = true
			length, err := strconv.Atoi(kv[1])
			if err == nil {
				p.ContentLength = int32(length)
			}
		}

		// Transfer-Encoding
		if strings.ToLower(kv[0]) == "transfer-encoding" {
			vv := strings.Split(kv[1], ",")
			for _, item := range vv {
				method := strings.ToLower(strings.Trim(item, " "))
				if len(method) == 0 {
					continue
				}

				switch method {
				case "chunked":
					p.TransferEncoding = TransferEncoding_Chunked
				case "gzip":
					p.TransferEncoding = TransferEncoding_Gzip
				case "compress":
					p.TransferEncoding = TransferEncoding_Compress
				case "deflate":
					p.TransferEncoding = TransferEncoding_Deflate
				case "identity":
					p.TransferEncoding = TransferEncoding_Identity
				}
			}

			p.bHasTransferEncoding = true
		}
	}

	//
	atomic.StoreInt32(&p.ResponseRecvStatus, 1) // 设置http完成
	atomic.StoreInt32(&p.OffsetContent, int32(httpProtocolLen+4))

	// 解析数据
	go p.analyzeContent()

	return nil
}

// 分析内容
func (p *HttpEntity) analyzeContent() error {
	p.HPContentLock.Lock()
	defer p.HPContentLock.Unlock()

	status := atomic.LoadInt32(&p.ResponseRecvStatus)
	if status != 1 { // 没有发现头的情况下
		return nil
	}

	buf, n := p.buffer.Read()

	// 存在 TransferEncoding情况下
	if p.bHasTransferEncoding {
		fmt.Println(buf[n-1])
		fmt.Println(buf[n-2])
		fmt.Println(buf[n-3])
		fmt.Println(buf[n-4])
		fmt.Println(strconv.Itoa(n - int(p.OffsetContent)))
		if string(buf[n-4:]) == string("\r\n\r\n") {
			// 如果是默认接收到 \r\n\r\n, 则说明接收完成，可以直接处理数据
			// 结束监听
			p.dialer.Close()
		}
	} else {
		if p.bHasExistLength {
			if len(buf)-int(p.OffsetContent) == int(p.ContentLength) {
				p.dialer.Close()

				p.Content = string(buf[p.OffsetContent:])
			}
		}
	}

	return nil
}

// 设置最大缓存长度
func (p *HttpEntity) SetMaxCacheSize(size int) {
	p.maxCacheSize = size
}

func (p *HttpEntity) SetTlsFlag(btls bool) {
	p.IsTls = btls
}

func (p *HttpEntity) SetIP(ip string) {
	p.IP = net.ParseIP(ip)
}

func (p *HttpEntity) SetPort(port uint16) {
	p.Port = port
}

func (p *HttpEntity) SetHeaders(headers map[string]string) error {
	for k, v := range headers {
		p.AddHeaders(k, v)
	}
	return nil
}

func (p *HttpEntity) AddHeaders(key string, value string) error {
	bfindKey := false
	for k, _ := range p.ReqHeaders {
		if strings.ToLower(k) == strings.ToLower(key) {
			p.ReqHeaders[k] = value
			bfindKey = true
			break
		}
	}

	if !bfindKey {
		p.ReqHeaders[key] = value
	}
	return nil
}

func (p *HttpEntity) SetHandleDataCallback(f func([]byte) error) {
	p.HandleData = f
}

func (p *HttpEntity) SetUrl(upath string) error {
	var err error
	p.Url, err = url.Parse(upath)
	if err != nil {
		p.Url = nil
		return err
	}

	// analyze scheme
	scheme := strings.ToLower(p.Url.Scheme)
	switch scheme {
	case "https":
		p.SetTlsFlag(true)
		p.SetPort(443)
	case "http":
		p.SetTlsFlag(false)
		p.SetPort(80)
	}

	// host and port
	hp := strings.Split(p.Url.Host, ":")
	host := ""
	port := ""
	if len(hp) == 1 {
		host = hp[0]
	} else if len(hp) == 2 {
		host = hp[0]
		port = hp[1]
	} else {
		return errors.New("url error")
	}

	ipaddr, err := net.ResolveIPAddr("ip", host)
	if err == nil {
		p.IP = ipaddr.IP
	} else {
		return err
	}

	if port != "" {
		iport, err := strconv.Atoi(port)
		if err != nil {
			return err
		}

		p.SetPort(uint16(iport))
	}

	// path
	if len(p.Url.Path) == 0 {
		p.Url.Path = "/"
	}
	return nil
}

func (p *HttpEntity) SetProtocolVersion(version string) {
	p.ProtocolVersion = version
}

func (p *HttpEntity) HeadersToString() string {
	result := ""
	for k, v := range p.ReqHeaders {
		result = result + k + ":" + v + "\r\n"
	}

	return result
}

func (p *HttpEntity) Send(buf []byte) error {
	p.dialer.SetIP(p.IP.String())
	p.dialer.SetPort(p.Port)
	p.dialer.SetTlsFlag(p.IsTls)
	p.dialer.SetCacheSize(20000)
	p.dialer.Dial(false)
	p.dialer.StartRecv()
	p.dialer.Send(buf)
	p.dialer.Wait()
	return nil
}

func (p *HttpEntity) Get() error {
	if len(p.Url.String()) > 0 { // 存在url的情况下
		p.ReqHeaders["Host"] = p.Url.Host
		first := "GET " + p.Url.Path + " " + p.ProtocolVersion
		szHeaders := p.HeadersToString()
		content := first + "\r\n" + szHeaders + "\r\n"
		log.Logger.Info(content)
		p.Send([]byte(content))

	} else if len(p.IP) > 0 {
		p.Headers["Host"] = p.IP.String()
	} else {
		return errors.New("not found target")
	}
	return nil
}

func (p *HttpEntity) Post() error {
	if len(p.Url.String()) > 0 { // 存在url的情况下
		p.ReqHeaders["Host"] = p.Url.Host
		first := "POST " + p.Url.Path + " " + p.ProtocolVersion
		szHeaders := p.HeadersToString()
		content := first + "\r\n" + szHeaders + "\r\n"
		log.Logger.Info(content)
		p.Send([]byte(content))

	} else if len(p.IP) > 0 {
		p.Headers["Host"] = p.IP.String()
	} else {
		return errors.New("not found target")
	}
	return nil
}
