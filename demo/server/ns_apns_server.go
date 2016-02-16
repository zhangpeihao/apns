package main

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/zhangpeihao/apns"
	"github.com/zhangpeihao/log"
)

const (
	programName = "ns_apns_server"
	version     = "0.1"
)

var (
	TOKEN_SPLIT = []byte(",")
	TOKEN_SPACE = []byte(" ")
)

var (
	serverId    *string = flag.String("ServerId", "", "The server ID.")
	address     *string = flag.String("Address", ":7654", "The address to bind for HTTP requests.")
	timeout     *int    = flag.Int("Timeout", 1800, "The timeout value(in seconds) when send message to APNS server.")
	queueSize   *int    = flag.Int("QueueSize", 10000, "The main message queue size.")
	logPath     *string = flag.String("LogPath", ".", "The log path.")
	logLevel    *int    = flag.Int("LogLevel", 1, "Log level: [0:Off|1:Fatal|2:Warning|3:Trace|4:Debug]")
	maxCore     *int    = flag.Int("MaxCore", 1, "The max core number.")
	certPath    *string = flag.String("CertPath", ".", "The certificate files path(include key.pem & cert.pem).")
	apnsAddress *string = flag.String("ApnsAddress", "gateway.sandbox.push.apple.com:2195", "The APNS server address.")
	connections *int    = flag.Int("Connections", 20, "The number of connections with APNS server.")
	maxNumber   *int    = flag.Int("MaxNumber", 500, "The max number of messages push to APNS server.")
	sleep       *int    = flag.Int("Sleep", 0, "The sleep time(milliseconds) after send a message.")
)

var (
	LOG_COUNTER = []string{"queue", "conn", "IN", "conn_E", "reconn_E", "PHP_E"}
)

const (
	MAX_RETRY = 16
)

type Message struct {
	Tokens [][]byte
	Data   []byte
}

var (
	g_queue  chan *Message
	g_logger *log.Logger
	g_conns  chan *apns.Conn
	g_exit   bool
	g_cert   tls.Certificate
	g_count  int32
	g_sleep  time.Duration
)

// [PROTOCOL]
type AnchorOnlineReqFromClient struct {
	Id   int64  `json:"id"`
	Time int    `json:"time"`
	Sign string `json:"sign"`
}
type GetTokenListReqToPhp struct {
	Id   int64  `json:"id"`
	Time int    `json:"time"`
	Sign string `json:"sign"`
}
type GetTokenListRespFromPhp struct {
	Id      int64    `json:"id"`
	Tokens  []string `json:"tokens"`
	Message string   `json:"msg"`
}

func main() {
	var err error
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s version[%s]\r\nUsage: %s [OPTIONS]\r\n", programName, version, os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	var hostname string
	if hostname, err = os.Hostname(); err != nil {
		fmt.Fprintln(os.Stderr, "Get hostname err: ", err)
		os.Exit(-1)
	}
	if len(*serverId) == 0 {
		fmt.Fprintln(os.Stderr, "Set serverid as hostname")
		*serverId = hostname
	}

	g_logger = log.NewLogger(*logPath, *serverId+"_apns", append(LOG_COUNTER, apns.LOG_HEADERS...), 60, 3600*24, true)
	g_logger.SetMainLevel(*logLevel)
	g_sleep = time.Duration(*sleep) * time.Millisecond

	numcpu := runtime.NumCPU()
	currentcpu := runtime.GOMAXPROCS(0)
	g_logger.Printf("maxCore: %d\n", *maxCore)
	g_logger.Printf("CPU: %d/%d\n", currentcpu, numcpu)
	cpu := 0
	if *maxCore > 0 && *maxCore < numcpu-1 {
		cpu = *maxCore
	} else {
		cpu = numcpu - 1
	}
	if cpu > 1 && currentcpu != cpu {
		runtime.GOMAXPROCS(cpu)
		g_logger.Printf("CPU: %d/%d\n", cpu, numcpu)
	}
	apns.InitLog(g_logger)

	g_logger.Debugln("Before load keys")
	g_cert, err = tls.LoadX509KeyPair(*certPath+"/cert.pem", *certPath+"/key.pem")
	if err != nil {
		g_logger.Fatal("LoadX509KeyPair err:", err)
		os.Exit(-1)
	}

	g_queue = make(chan *Message, *queueSize)
	g_conns = make(chan *apns.Conn, *connections)
	for i := 0; i < *connections; i++ {
		go func() {
			g_conns <- reconn()
		}()
	}

	// Create http server
	g_logger.Debugln("Before start HTTP server")
	http.HandleFunc("/apns", apnsHandler)
	http.HandleFunc("/apns_check", apnsCheckHandler)
	go http.ListenAndServe(*address, nil)

	go sendToApns()

	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT)
MAIN_LOOP:
	for {
		select {
		case sig := <-ch:
			g_logger.Printf("Signal received: %v\n", sig)
			g_exit = true
			break MAIN_LOOP
		case <-time.After(time.Second):
			g_logger.Max("conn", int64(len(g_conns)))
			g_logger.Max("queue", int64(len(g_queue)))
			atomic.StoreInt32(&g_count, 0)
		}
	}
	time.Sleep(time.Second)
}

func apnsHandler(w http.ResponseWriter, req *http.Request) {
	g_logger.Debugln("apnsHandler()")
	g_logger.Add("IN", 1)
	msg := req.FormValue("msg")
	tokens_ := req.FormValue("tokens")
	g_logger.Debugln("<< ", tokens_)
	g_logger.Debugln("<< ", msg)

	tokensArray := bytes.Split([]byte(tokens_), TOKEN_SPLIT)

	var tokens [][]byte
	for _, t := range tokensArray {
		tokenBuf := make([]byte, 32)
		n, err := hex.Decode(tokenBuf, bytes.Replace(t, TOKEN_SPACE, nil, -1))
		if err != nil {
			g_logger.Add("PHP_E", 1)
			g_logger.Printf("apnsHandler() Decode err: %s\n", err.Error())
			io.WriteString(w, "Error")
			return
		}
		if n != 32 {
			g_logger.Add("PHP_E", 1)
			g_logger.Printf("apnsHandler() hex.Decode return len:%d\n", n)
			io.WriteString(w, "Error")
			return
		}
		tokens = append(tokens, tokenBuf)
	}
	//	g_logger.Debugf("tokens: %+v\n", tokens)
	msgData := &Message{
		Tokens: tokens,
		Data:   []byte(msg),
	}
	g_logger.Debugln("Before push")
	g_queue <- msgData
	g_logger.Debugln("After push")
	io.WriteString(w, "OK")
}

func sendTestData(token []byte, ch chan<- string) {
	testData := []byte(`{"aps":{}}`)
	tokenBuf := make([]byte, 32)
	n, err := hex.Decode(tokenBuf, bytes.Replace(token, TOKEN_SPACE, nil, -1))
	if err != nil {
		g_logger.Printf("sendTestData() Decode err: %s\n", err.Error())
		ch <- string(token) + ":BAD"
		return
	}
	if n != 32 {
		g_logger.Printf("sendTestData() hex.Decode return len:%d\n", n)
		ch <- string(token) + ":BAD"
		return
	}

	conn, err := apns.Dial(*apnsAddress,
		[]tls.Certificate{g_cert},
		time.Duration(*timeout)*time.Second)
	if err != nil {
		g_logger.Printf("sendTestData() Dial err: %s\n", err)
		ch <- string(token) + ":UNKNOWN"
		return
	}
	defer conn.Close()
	err = conn.SendMessage2(tokenBuf, testData)
	if err != nil {
		g_logger.Printf("sendTestData() SendMessage err: %s\n", err)
		ch <- string(token) + ":UNKNOWN"
		return
	}
	time.Sleep(time.Duration(1000) * time.Millisecond)
	if conn.Closed() {
		ch <- string(token) + ":BAD"
		return
	}
	ch <- string(token) + ":GOOD"
}

func apnsCheckHandler(w http.ResponseWriter, req *http.Request) {
	g_logger.Debugln("apnsCheckHandler()")
	g_logger.Add("IN", 1)
	tokens_ := req.FormValue("tokens")
	g_logger.Debugln("<< ", tokens_)

	tokensArray := bytes.Split([]byte(tokens_), TOKEN_SPLIT)
	var resp []string
	ch := make(chan string)
	i := 0
	for _, t := range tokensArray {
		go sendTestData(t, ch)
		i++
	}
	for i > 0 {
		resp = append(resp, <-ch)
		i--
	}
	io.WriteString(w, strings.Join(resp, "\n"))
}

func send(conn *apns.Conn, msg *Message) {
	g_logger.Debugln("Send to device begin")

	for _, deviceToken := range msg.Tokens {
		for !g_exit {
			err := conn.SendMessage2(deviceToken, msg.Data)
			if err != nil {
				// Reconnect
				g_logger.Debugln("Send to device err:", err)
				g_logger.Add("conn_E", 1)
				conn = reconn()
			} else {
				if g_sleep > 0 {
					time.Sleep(g_sleep)
				}
				break
			}
		}
	}
	g_logger.Debugln("Send to device end")
	g_conns <- conn
}

func sendToApns() {
	var msg *Message
	var conn *apns.Conn
	g_logger.Debugln("Send loop")
MAIN_LOOP:
	for !g_exit {
		select {
		case msg = <-g_queue:
			g_logger.Debugln("Get conn")
			conn := <-g_conns
			if conn == nil || g_exit {
				break MAIN_LOOP
			}
			if count := atomic.AddInt32(&g_count, 1); count > int32(*maxNumber) {
				time.Sleep(time.Second)
			}

			go send(conn, msg)
		case <-time.After(time.Second):
			// TODO: keepalive
		}
	}
	g_logger.Debugln("exit")
	for len(g_conns) > 0 {
		conn = <-g_conns
		conn.Close()
	}
	g_logger.Debugln("Send loop end")
}

func reconn() (conn *apns.Conn) {
	var err error
	for !g_exit {
		g_logger.Debug("To reconnect")
		conn, err = apns.Dial(*apnsAddress,
			[]tls.Certificate{g_cert},
			time.Duration(*timeout)*time.Second)
		if err == nil {
			g_logger.Debugln("Connect APNS server OK")
			return
		}
		g_logger.Add("reconn_E", 1)
		time.Sleep(time.Second)
	}
	return
}
