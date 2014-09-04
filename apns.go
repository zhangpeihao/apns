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
	ErrTimeout = errors.New("Timeout")
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
	if conn, err = net.DialTimeout("tcp", serverAddress, sendTimeout); err != nil {
		return
	}
	tlsConn := tls.Client(conn, &tls.Config{
		Certificates:       cert,
		InsecureSkipVerify: true,
	})
	if err = tlsConn.SetWriteDeadline(time.Now().Add(sendTimeout)); err != nil {
		return
	}
	handshakeChan := make(chan bool)
	go func(ch chan<- bool) {
		logger.Debugln("apnd.Dial() Handshake")
		if err = tlsConn.Handshake(); err != nil {
			logger.Debugln("apnd.Dial() Handshake failed")
			ch <- false
			return
		}
		logger.Debugln("apnd.Dial() Handshake success")
		ch <- true
	}(handshakeChan)
	select {
	case b := <-handshakeChan:
		if !b {
			return
		}
	case <-time.After(time.Second * time.Duration(5)):
		logger.Debugln("apnd.Dial() Handshake timeout")
		tlsConn.Close()
		err = ErrTimeout
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
	//	var err error
	if err := c.c.SetReadDeadline(time.Unix(9999999999, 0)); err != nil {
		logger.Add("Out_E", int64(1))
		logger.Warningln("apns.Conn::readLoop() SetReadDeadline err:", err)
		c.Close()
		return
	}
	buf := make([]byte, 6)
	for !c.exit {
		// read response
		if n, err := c.c.Read(buf); err != nil {
			netErr, ok := err.(net.Error)
			if ok && netErr.Temporary() {
				time.Sleep(time.Second)
			} else {
				logger.Add("Out_E", int64(1))
				logger.Debugln("apns.Conn::readLoop() Read err:", err)
				if n > 0 {
					logger.Debugf("APNS read %02X\n", buf)
				}
				break
			}
		} else {
			logger.Debugf("APNS read %02X\n", buf)
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
	logger.Debugf("sendLoop() data: % 02X\n", data)
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
	return c.Send(buf.Bytes())
}
