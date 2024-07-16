package torctrlgo

import (
	"bufio"
	"bytes"
	"log"
	"net"
	"strconv"
	"sync"
)

// Defines low-level protocol routines. Specific commands are defined in low.go

// LowController provides a low-level API for communication over TOR's ControlPort protocol.
//
// All exported functions are concurrency-safe. Since TOR processes commands sequentially,
type LowController struct {
	conn             net.Conn
	replyLock        sync.Mutex
	NotificationChan chan []ReplyLine
	replyChan        chan chan []ReplyLine
	lineChan         chan []byte
	lastProtocolInfo *ProtocolInfo
}

type ReplyLine struct {
	StatusCode uint16
	Separator  byte
	Line       []byte
}

func NewLowController() *LowController {
	return &LowController{
		replyLock:        sync.Mutex{},
		NotificationChan: make(chan []ReplyLine, 1024),
		replyChan:        make(chan chan []ReplyLine, 256),
		lineChan:         make(chan []byte, 256),
		lastProtocolInfo: nil,
	}
}

func (c *LowController) Open(addr string) (err error) {
	c.conn, err = net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	go c.workerReceiveLines()
	go c.workerAssemblePackets()
	return
}

func (c *LowController) sendPacket(data []byte) ([]ReplyLine, error) {
	c.replyLock.Lock()
	ch := make(chan []ReplyLine)
	c.replyChan <- ch
	_, err := c.conn.Write(data)
	c.replyLock.Unlock()
	if err != nil {
		return nil, err
	}
	rep := <-ch
	c.replyLock.Unlock()
	return rep, nil
}

func parseLine(data []byte) (ReplyLine, error) {
	statusCode, err := strconv.ParseInt(string(data[:3]), 10, 16)
	if err != nil {
		return ReplyLine{}, err
	}
	return ReplyLine{
		StatusCode: uint16(statusCode),
		Separator:  data[3],
		Line:       data[4:],
	}, nil
}

func (c *LowController) assemblePacket() ([]ReplyLine, error) {
	var lines []ReplyLine
	var data []byte
	var line ReplyLine
	var err error
	for {
		data = <-c.lineChan
		line, err = parseLine(data)
		if err != nil {
			return nil, err
		}
		switch line.Separator {
		case ' ':
			lines = append(lines, line)
			return lines, nil
		case '-':
			lines = append(lines, line)
		case '+':
			for {
				data = <-c.lineChan
				if bytes.Equal(data, []byte(".\r\n")) {
					break
				}
				if bytes.Equal(data[:2], []byte("..")) {
					data = data[1:]
				}
				line.Line = append(line.Line, data...)
			}
			lines = append(lines, line)
		}
	}
}

func (c *LowController) workerAssemblePackets() {
	for {
		reply, err := c.assemblePacket()
		if err != nil {
			log.Fatal(err)
		}
		if reply[0].StatusCode == 650 {
			select {
			case c.NotificationChan <- reply:
			default:
				<-c.NotificationChan
				c.NotificationChan <- reply
				print("Notification channel is full, discarding oldest...")
			}
		} else {
			select {
			case ch := <-c.replyChan:
				ch <- reply
			default:
				print("Unsolicited response, discarding...")
			}
		}
	}
}

func (c *LowController) workerReceiveLines() {
	reader := bufio.NewReader(c.conn)
	for {
		lb, err := reader.ReadBytes('\n')
		if err != nil {
			log.Fatal(err)
		}
		if !bytes.Equal(lb[len(lb)-2:], []byte("\r\n")) {
			log.Fatal("Line incorrectly terminated")
		}
		print(string(lb))
		c.lineChan <- lb
	}
}
