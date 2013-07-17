package apns

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/zhangpeihao/log"
	"strings"
	"testing"
	"time"
)

var (
	g_logger = log.NewLogger(".", "apns_test", LOG_HEADERS, 1, 24*3600, true)
)

var (
	DeviceTokens = []string{
		//		strings.Replace("69e8072c 4a82a3d7 32608416 dacc4353 c219c826 8df4feea 8c2e63b2 cf909098", " ", "", -1),
		strings.Replace("68877dd9 6c573c5e 1ffe1526 eace028b 8ec56798 f8e1f3a4 4454e2d7 a0247f55", " ", "", -1),
		// strings.Replace("f2a55b62 f228a529 5e2f528f 7efc6ecc 2c2b4df3 45fac8f2 58feb23a f78456ee", " ", "", -1),
	}
)

func TestApns(t *testing.T) {
	fmt.Println(``)
	fmt.Println(`//////////////////// TestApns \\\\\\\\\\\\\\\\\\\\`)
	g_logger.SetMainLevel(log.LOG_LEVEL_DEBUG)
	InitLog(g_logger)
	// Load certificate files
	cert, err := tls.LoadX509KeyPair("./prod/cert.pem", "./prod/key.pem")
	if err != nil {
		t.Fatal("LoadX509KeyPair err:", err)
	}
	conn, err := Dial("gateway.sandbox.push.apple.com:2195",
		[]tls.Certificate{cert},
		1000,
		time.Minute)
	if err != nil {
		t.Fatal("Dial err:", err)
	}
	defer conn.Close()

	message := []byte(`{"aps":{"alert":"Test"}}`)
	var deviceTokens [][]byte
	for _, token := range DeviceTokens {
		buf := new(bytes.Buffer)
		if _, err = buf.Write([]byte{0, 0, 32}); err != nil {
			t.Fatal("buf.Write 1 err:", err)
		}
		tokenBuf, err := hex.DecodeString(token)
		if err != nil {
			t.Fatal("hex.DecodeString err:", err)
		}
		if len(tokenBuf) != 32 {
			t.Fatalf("hex.DecodeString return len:%d\n", len(tokenBuf))
		}
		if _, err = buf.Write(tokenBuf); err != nil {
			t.Fatal("buf.Write 2 err:", err)
		}
		if err = binary.Write(buf, binary.BigEndian, uint16(len(message))); err != nil {
			t.Fatal("buf.Write 3 err:", err)
		}

		if _, err = buf.Write(message); err != nil {
			t.Fatal("buf.Write 4 err:", err)
		}

		if err = conn.Send(buf.Bytes()); err != nil {
			t.Fatal("conn.Send err:", err)
		}
		if err = conn.SendMessage(tokenBuf, message); err != nil {
			t.Fatal("conn.SendMessage err:", err)
		}
		deviceTokens = append(deviceTokens, tokenBuf)
	}
	if err = conn.SendMessageToDevices(deviceTokens, message); err != nil {
		t.Fatal("conn.SendMessageToDevices err:", err)
	}
	time.Sleep(3 * time.Second)
	fmt.Println(`\\\\\\\\\\\\\\\\\\\\ TestApns ////////////////////`)
	fmt.Println(``)
}
