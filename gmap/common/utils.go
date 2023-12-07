package common

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/3th1nk/cidr"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// waitTimeout waits for the waitgroup for the specified max timeout.
// Returns true if waiting timed out.
func WaitTimeout(wg *sync.WaitGroup, timeout time.Duration) (bool, error) {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return true, nil // completed normally
	case <-time.After(timeout):
		return false, errors.New("time out") // timed out
	}
}

func ReadFileAll(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	content, err := ioutil.ReadAll(file)
	if err != nil {
		return "", err
	}

	return string(content), nil
}

func GenerateRandom_Byte() byte {
start:
	n, err := rand.Int(rand.Reader, big.NewInt(255))
	if err != nil {
		goto start
	}
	if n.Uint64() == 0 {
		goto start
	}

	return byte(n.Uint64())
}

func GenerateRandom_ByteArray(count int) []byte {
	bytes := make([]byte, count)
	rand.Read(bytes)

	return bytes
}

func GenerateRandomUint() uint32 {
	bs := GenerateRandom_ByteArray(4)

	result := binary.LittleEndian.Uint32(bs)

	return result
}

func GetTimestamp() int64 {
	now := time.Now()
	return now.UnixNano()
}

func GenerateUniqueStr() string {
	uuidWithHyphen := uuid.New()
	uuid := strings.Replace(uuidWithHyphen.String(), "-", "", -1)

	return uuid
}

func LittleInt64ToBytes(val int64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(val))
	return b
}

func GetCurrentDir() (string, error) {
	// 找到该启动当前进程的可执行文件的路径名
	str, err := os.Executable()
	if err != nil {
		return "", err
	}
	str = filepath.Dir(str)

	return str, nil
}

func ExecProgram(name string, arg ...string) error {
	cmd := exec.Command(name, arg...)

	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

func IsFileExist(path string) bool {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return false
	}

	return true
}

func IsDir(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	return s.IsDir()
}

func IsFile(path string) bool {
	return !IsDir(path)
}

func TrimEx(s string) string {
	if len(s) == 0 {
		return s
	}
	re, err := regexp.Compile(`(^\s+|\s+$)`)
	if err != nil {
		return s
	}

	return re.ReplaceAllString(s, "")
}

func Splite_Space(s string, n int) ([]string, error) {
	if len(s) == 0 {
		return nil, errors.New("the strig is empty")
	}
	re, err := regexp.Compile(`(\s+)`)
	if err != nil {
		return nil, err
	}

	splits := re.Split(s, n)

	return splits, nil
}

// 类似 222-2222,222,33,44,44-265
func Splite_Port(s string) []uint16 {
	result := make([]uint16, 0)
	l1 := strings.Split(s, ",")
	for _, item := range l1 {
		p := strings.Split(item, "-")
		l := len(p)
		if l == 2 {
			begin_p, err := strconv.Atoi(p[0])
			if err != nil {
				return result
			}

			end_p, err := strconv.Atoi(p[1])
			if err != nil {
				return result
			}

			if begin_p > end_p {
				return result
			}

			for i := begin_p; i <= end_p; i++ {
				result = append(result, uint16(i))
			}
		} else if l == 1 {
			ps, err := strconv.Atoi(p[0])
			if err != nil {
				return result
			}
			result = append(result, uint16(ps))
		}
	}

	return result
}

func ToJsonEncodeStruct(s interface{}) string {
	if s == nil {
		return ""
	}

	byteBuf := bytes.NewBuffer([]byte{})
	encoder := json.NewEncoder(byteBuf)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(s)
	if err != nil {
		return ""
	}

	return byteBuf.String()
}

func IsCIDR(sz string) bool {
	return false
}

/*
IP地址格式：
192.168.1.1
192.168.1.1/24
192.168.1.1,192.168.1.3
192.168.1.1,192.168.3.1/24
*/
func GetIPsFromString(sz string) []net.IP {
	result := make([]net.IP, 0)

	// 检测分隔符
	sps := strings.Split(sz, ",")
	for _, item := range sps {
		item = TrimEx(item)
		// 检测普通IP
		singleip := net.ParseIP(item)
		if singleip != nil {
			result = append(result, singleip)
			continue
		}

		c, err := cidr.Parse(item)
		if err != nil {
			continue
		}

		c.Each(func(sip string) bool {
			ip := net.ParseIP(sip)
			result = append(result, ip)
			return true
		})
	}

	return result
}

// GZIPEn gzip加密
func GzipEncrypt(str string) []byte {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write([]byte(str)); err != nil {
		panic(err)
	}
	if err := gz.Flush(); err != nil {
		panic(err)
	}
	if err := gz.Close(); err != nil {
		panic(err)
	}
	return b.Bytes()
}

// GZIPDe gzip解密
func GzipDecrypt(in []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(in))
	if err != nil {
		var out []byte
		return out, err
	}
	defer reader.Close()
	return ioutil.ReadAll(reader)
}

func ZlibEn(data []byte) ([]byte, error) {
	var in bytes.Buffer
	w := zlib.NewWriter(&in)
	w.Write(data)
	w.Close()
	return in.Bytes(), nil
}

func ZlibDe(data []byte) ([]byte, error) {
	var out bytes.Buffer
	var in bytes.Buffer
	in.Write(data)

	r, err := zlib.NewReader(&in)
	if err != nil {
		return nil, err
	}

	io.Copy(&out, r)
	return out.Bytes(), nil
}

// 获取cpu核心个数
func GetCPUCoreCount() int {
	cores := runtime.NumCPU()
	return cores
}

func SetGOMAXPROCS(count int) {
	runtime.GOMAXPROCS(count)
}

func SafeRunner(entry interface{}, args ...interface{}) {
	defer func() {
		err := recover()
		if err != nil {
			buf := make([]byte, 1<<16)
			runtime.Stack(buf, true)
			buf = bytes.Trim(buf, "\x00")
			log.Error("run error:", err, string(buf))
		}
	}()

	// 将函数包装为反射值对象
	funcValue := reflect.ValueOf(entry)
	if funcValue.Kind() == reflect.Func {
		// 构造函数参数, 传入两个整型值
		paramList := make([]reflect.Value, 0)
		for _, arg := range args {
			paramList = append(paramList, reflect.ValueOf(arg))
		}
		funcValue.Call(paramList)
	}
}

// 超时执行函数
func WaitTimeProc(seconds float64, entry interface{}, args ...interface{}) ([]interface{}, error) {
	c := make(chan struct{})
	result := make([]interface{}, 0)
	go func() {
		defer close(c)
		// 将函数包装为反射值对象
		funcValue := reflect.ValueOf(entry)
		if funcValue.Kind() == reflect.Func {
			// 构造函数参数, 传入两个整型值
			paramList := make([]reflect.Value, 0)
			for _, arg := range args {
				paramList = append(paramList, reflect.ValueOf(arg))
			}
			vals := funcValue.Call(paramList)
			for _, val := range vals {
				result = append(result, val.Interface())
			}
		}
	}()
	select {
	case <-c:
		return result, nil // completed normally
	case <-time.After(time.Duration(seconds * float64(time.Second))):
		return nil, errors.New("time out") // timed out
	}
}

func Hex2Str(content []byte) string {
	var result string

	for _, item := range content {
		a := fmt.Sprintf("%0x", item)
		result = result + " " + a
	}

	return result
}

func WriteFile(file string, data []byte) (int, error) {
	f, err := os.Create(file)
	if err != nil {
		return -1, err
	}
	writed, err := f.Write(data)

	f.Close()
	return writed, err
}
