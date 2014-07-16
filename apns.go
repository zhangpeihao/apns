package apns

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"github.com/zhangpeihao/log"
	"net"
	"time"
)

const (
	MIN_QUEUE_SIZE = 8
)

var (
	LOG_HEADERS  = []string{"Out", "Out_E"}
	logger       *log.Logger
	READ_TIMEOUT = time.Second * 3600
)

var (
	ErrClosed  = errors.New("Closed")
	ErrBlocked = errors.New("Blocked")
)

func InitLog(l *log.Logger) {
	logger = l
	logger.Println("InitLog()")
}

type Conn struct {
	c           *tls.Conn
	sendTimeout time.Duration
	exit        bool
}

func Dial(serverAddress string, cert []tls.Certificate,
	sendTimeout time.Duration) (c *Conn, err error) {
	var conn net.Conn
	if conn, err = net.Dial("tcp", serverAddress); err != nil {
		return
	}
	tlsConn := tls.Client(conn, &tls.Config{
		Certificates: cert,
	})
	if err = tlsConn.Handshake(); err != nil {
		return
	}
	c = &Conn{
		c:           tlsConn,
		sendTimeout: sendTimeout,
	}

	go c.readLoop()
	return
}

func (c *Conn) Close() {
	c.exit = true
	c.c.Close()
}

func (c *Conn) readLoop() {
	var err error
	buf := make([]byte, 256)
	for !c.exit {
		// read response
		if _, err = c.c.Read(buf); err != nil {
			netErr, ok := err.(net.Error)
			if ok && netErr.Temporary() {
				time.Sleep(time.Second)
			} else {
				logger.Add("Out_E", int64(1))
				logger.Debugln("apns.Conn::readLoop() Read err:", err)
				break
			}
		}
	}
	c.Close()
}

func (c *Conn) Send(data []byte) (err error) {
	if c.exit {
		return ErrClosed
	}
	if err = c.c.SetWriteDeadline(time.Now().Add(c.sendTimeout)); err != nil {
		logger.Add("Out_E", int64(1))
		logger.Warningln("apns.Conn::Send() SetWriteDeadline err:", err)
		return
	}
	logger.Debugf("apns.Conn::Send() data: % 02X\n", data)
	if _, err = c.c.Write(data); err != nil {
		logger.Add("Out_E", int64(1))
		logger.Warningln("apns.Conn::Send() Write err:", err)
		return
	}

	logger.Add("Out", int64(1))
	return
}

func (c *Conn) SendMessage(deviceToken []byte, message []byte) (err error) {
	buf := new(bytes.Buffer)
	if _, err = buf.Write([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32}); err != nil {
		return
	}
	if _, err = buf.Write(deviceToken); err != nil {
		return
	}
	if err = binary.Write(buf, binary.BigEndian, uint16(len(message))); err != nil {
		return
	}
	if _, err = buf.Write(message); err != nil {
		return
	}
	return c.Send(buf.Bytes())
}
