package urllib

import (
	"net/url"
	"path"
	"regexp"
	"strings"
)

var regexpList = []string{
	`^javascript:`,
	`^mailto:`,
}

func UrlJoin(base *url.URL, arg string) *url.URL {
	if base == nil {
		return nil
	}

	if len(arg) == 0 {
		return base
	}

	// 特殊路径处理
	for _, item := range regexpList {
		re, err := regexp.Compile(item)
		if err == nil {
			data := re.Find([]byte(strings.ToLower(arg)))
			if len(data) > 0 {
				return base
			}
		}
	}

	result, _ := url.Parse(base.String())
	//
	ret, err := url.Parse(arg)
	if err != nil {
		return result
	}

	// 只有存在协议和host字段的情况下，url才是正确的
	if len(ret.Scheme) > 0 && len(ret.Host) > 0 {
		return ret
	}

	// 分析path
	if len(result.Path) == 0 {
		result.Path = "/"
	} else {
		s := strings.Split(result.Path, "/")
		if result.Path[len(result.Path)-1:] != "/" {
			result.Path = "/" + strings.Join(s[:len(s)-1], "/")
		}
	}

	// 如果为根目录的情况下
	if len(arg) > 2 && arg[:2] == "//" {
		u := result.Scheme + ":" + arg
		result, _ = url.Parse(u)
	} else if arg[0] == '/' {
		u := result.Scheme + "://" + result.Host + arg
		result, _ = url.Parse(u)
	} else {
		urlpath := path.Join(result.Path, arg)
		u := result.Scheme + "://" + result.Host + urlpath
		result, _ = url.Parse(u)
	}

	return result
}
