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
	LOG_HEADERS  = []string{"Out", "Out_B", "Out_E"}
	logger       *log.Logger
	READ_TIMEOUT = time.Second * 3
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
	queue       chan []byte
	queueSize   int
	sendTimeout time.Duration
	exit        bool
}

func Dial(serverAddress string, cert []tls.Certificate, queueSize int,
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
		queueSize:   queueSize,
		queue:       make(chan []byte, queueSize+MIN_QUEUE_SIZE),
		sendTimeout: sendTimeout,
	}
	go c.sendLoop()
	go c.readLoop()
	return
}

func (c *Conn) Close() {
	c.exit = true
}

func (c *Conn) Send(data []byte) error {
	if c.exit {
		return ErrClosed
	}
	if len(c.queue) > c.queueSize {
		logger.Add("Out_B", int64(1))
		return ErrBlocked
	}
	c.queue <- data
	return nil
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

func (c *Conn) SendMessageToDevices(deviceTokens [][]byte, message []byte) (err error) {
	for _, deviceToken := range deviceTokens {
		buf := new(bytes.Buffer)
		if _, err = buf.Write([]byte{0, 0, 32}); err != nil {
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
		if err = c.Send(buf.Bytes()); err != nil {
			return
		}
	}
	return
}

func (c *Conn) sendLoop() {
	var err error
FOR_LOOP:
	for !c.exit {
		select {
		case data := <-c.queue:
			logger.Add("Out", int64(1))
			if err = c.c.SetWriteDeadline(time.Now().Add(c.sendTimeout)); err != nil {
				logger.Add("Out_E", int64(1))
				logger.Warningln("sendLoop() SetWriteDeadline err:", err)
				break FOR_LOOP
			}
			if _, err = c.c.Write(data); err != nil {
				logger.Add("Out_E", int64(1))
				logger.Warningln("sendLoop() Write err:", err)
				break FOR_LOOP
			}
		case <-time.After(time.Second):
			// Check close
			if c.exit {
				break FOR_LOOP
			}
		}
	}
	c.exit = true
}

func (c *Conn) readLoop() {
	var err error
	buf := make([]byte, 256)
FOR_LOOP:
	for !c.exit {
		// Read response
		if err = c.c.SetReadDeadline(time.Now().Add(READ_TIMEOUT)); err != nil {
			logger.Add("Out_E", int64(1))
			logger.Warningln("sendLoop() SetReadDeadline err:", err)
			break FOR_LOOP
		}
		if _, err = c.c.Read(buf); err == nil {
			logger.Debugf("Read: % x\n", buf)
		}
		// TODO: Check response
	}
}
