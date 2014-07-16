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
		strings.Replace("dadb49f0 6874a2f6 4a9cf19d 0343e94b 7811915a 4f503463 775b69e7 0d479bbf", " ", "", -1),
		//		strings.Replace("f2a55b62 f228a529 5e2f528f 7efc6ecc 2c2b4df3 45fac8f2 58feb23a f78456ee", " ", "", -1),
	}
)

func TestApns(t *testing.T) {
	fmt.Println(``)
	fmt.Println(`//////////////////// TestApns \\\\\\\\\\\\\\\\\\\\`)
	g_logger.SetMainLevel(log.LOG_LEVEL_DEBUG)
	InitLog(g_logger)
	// Load certificate files
	cert, err := tls.LoadX509KeyPair("./nvshenol/cert.pem", "./nvshenol/key.pem")
	if err != nil {
		t.Fatal("LoadX509KeyPair err:", err)
	}
	//	apns_addr := "gateway.sandbox.push.apple.com:2195"
	apns_addr := "gateway.push.apple.com:2195"
	conn, err := Dial(apns_addr,
		[]tls.Certificate{cert},
		time.Minute)
	if err != nil {
		t.Fatal("Dial err:", err)
	}
	defer conn.Close()

	message1 := []byte(`{"aps":{"alert":"Test1"}}`)
	message2 := []byte(`{"aps":{"alert":"Test2"}}`)
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
		if err = binary.Write(buf, binary.BigEndian, uint16(len(message1))); err != nil {
			t.Fatal("buf.Write 3 err:", err)
		}

		if _, err = buf.Write(message1); err != nil {
			t.Fatal("buf.Write 4 err:", err)
		}

		if err = conn.Send(buf.Bytes()); err != nil {
			t.Fatal("conn.Send err:", err)
		}
		if err = conn.SendMessage(tokenBuf, message2); err != nil {
			t.Fatal("conn.SendMessage err:", err)
		}
	}
	time.Sleep(3 * time.Second)
	fmt.Println(`\\\\\\\\\\\\\\\\\\\\ TestApns ////////////////////`)
	fmt.Println(``)
}
