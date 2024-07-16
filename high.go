package torctrlgo

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
)

// Defines high-level API for communication via ControlPort

// Controller provides a high-level API for communication over TOR's ControlPort protocol.
//
// Certain functions may declare high concurrency-safety.
type Controller struct {
	TorVersion        string
	TorRCPath         string
	VersionStatus     string
	LowController     *LowController
	notifHandler      map[string]func([]ReplyLine)
	iNotifHandler     map[string]func([]ReplyLine) //TODO make registering multiple internal listeners possible
	availableConfigs  map[string][2]string
	availableInfos    map[string]string
	availableEvents   []string
	availableFeatures []string
	availableSignals  []string
}

func NewController() *Controller {
	return &Controller{
		LowController:     NewLowController(),
		notifHandler:      make(map[string]func([]ReplyLine)),
		iNotifHandler:     make(map[string]func([]ReplyLine)),
		availableConfigs:  make(map[string][2]string),
		availableInfos:    make(map[string]string),
		availableEvents:   make([]string, 0),
		availableFeatures: make([]string, 0),
		availableSignals:  make([]string, 0),
	}
}

func (c *Controller) Open(addr string) error {
	err := c.LowController.Open(addr)
	if err != nil {
		return err
	}
	go c.workerNotification()
	return nil
}

func (c *Controller) loadCompatData() error {
	info, err := c.LowController.GetInfo([]string{"version", "config-file", "status/version/current", "config/names", "info/names", "events/names", "features/names", "signal/names"})
	if err != nil {
		return err
	}
	c.TorVersion = info["version"]
	c.TorRCPath = info["config-file"]
	c.VersionStatus = info["status/version/current"]
	var segs []string
	for _, config := range strings.Split(info["config/names"], "\r\n") {
		segs = strings.Split(config, " ")
		c.availableConfigs[segs[0]] = [2]string{segs[1], strings.TrimSpace(config[len(segs[0])+1+len(segs[1]):])}
	}
	for _, info := range strings.Split(info["info/names"], "\r\n") {
		segs = strings.Split(info, " ")
		c.availableInfos[segs[0]] = strings.Trim(info[len(segs[0]):], " \t\r\n-_&")
	}
	c.availableEvents = strings.Split(info["events/names"], " ")
	c.availableFeatures = strings.Split(info["features/names"], " ")
	c.availableSignals = strings.Split(info["signal/names"], " ")
	return nil
}

// AuthMethod declares the way of authentication on the ControlPort connection.
type AuthMethod string

const (
	// AUTH_NULL No authentication is required.
	//
	// To prevent cross-protocol attacks, calling authenticate is still required, even when all methods are disabled.
	AUTH_NULL AuthMethod = "NULL"
	// AUTH_HASHEDPASSWORD A password needs to be presented.
	//
	// The password's hash is defined in the configuration.
	AUTH_HASHEDPASSWORD AuthMethod = "HASHEDPASSWORD"
	// AUTH_COOKIE A cookie-file's contents must be provided.
	//
	// The Controller needs to prove its privileges to read one of them.
	AUTH_COOKIE AuthMethod = "COOKIE"
	// AUTH_SAFECOOKIE A Challenge must be completed
	//
	// The Controller needs to prove its knowledge of a cookie-file, similar to AUTH_COOKIE.
	AUTH_SAFECOOKIE AuthMethod = "SAFECOOKIE"
)

// AuthData declares the data passed for authentication.
//
//   - Password may be declared for AUTH_HASHEDPASSWORD authentication.
//   - CookieData may be declared to pass a cookie-file's contents manually.
//     If CookieData is nil, AUTH_COOKIE and AUTH_SAFECOOKIE authentication will read
//     the first available cookie-file's contents automatically.
type AuthData struct {
	Password   string
	CookieData []byte
}

func (c *Controller) Authenticate(method AuthMethod, data AuthData) (bool, error) {
	succ, err := c.iAuthenticate(method, data)
	if err != nil || !succ {
		return succ, err
	}
	err = c.loadCompatData()
	return succ, err
}

func (c *Controller) iAuthenticate(method AuthMethod, data AuthData) (bool, error) {
	var rep []ReplyLine
	var err error
	if c.LowController.lastProtocolInfo == nil && (method == AUTH_COOKIE || method == AUTH_SAFECOOKIE) {
		_, err = c.LowController.GetProtocolInfo([]string{"1"})
		if err != nil {
			return false, err
		}
	}
	switch method {
	case AUTH_NULL:
		return c.LowController.AuthenticateNull()
	case AUTH_HASHEDPASSWORD:
		return c.LowController.AuthenticateString(data.Password)
	case AUTH_COOKIE, AUTH_SAFECOOKIE:
		if len(c.LowController.lastProtocolInfo.CookieFiles) == 0 {
			return false, errors.New("no cookie files found")
		}
		b := data.CookieData
		if b == nil {
			for _, path := range c.LowController.lastProtocolInfo.CookieFiles {
				f, err := os.Open(path)
				if err != nil {
					continue
				}
				b, err = io.ReadAll(f)
				if err != nil {
					continue
				}
			}
		}
		if b == nil {
			return false, errors.New("cookie files couldn't be accessed")
		} else if method == AUTH_COOKIE {
			return c.LowController.AuthenticateBytes(b)
		} else {
			clientNonce := make([]byte, 32)
			_, err = rand.Read(clientNonce)
			if err != nil {
				return false, err
			}
			serverHash, serverNonce, err := c.LowController.AuthChallenge("SAFECOOKIE", clientNonce)
			if err != nil {
				return false, err
			}
			mac := hmac.New(sha256.New, []byte("Tor safe cookie authentication server-to-controller hash"))
			mac.Write(b)
			mac.Write(clientNonce)
			mac.Write(serverNonce)
			expectedServerHash := mac.Sum(nil)
			testNonce := make([]byte, 32)
			_, err = rand.Read(testNonce)
			if err != nil {
				return false, err
			}
			mac = hmac.New(sha256.New, testNonce)
			mac.Write(serverHash)
			challengeHmac := mac.Sum(nil)
			mac.Reset()
			mac.Write(expectedServerHash)
			if !bytes.Equal(challengeHmac, mac.Sum(nil)) {
				return false, errors.New("tor provided wrong serverNonce")
			}
			mac = hmac.New(sha256.New, []byte("Tor safe cookie authentication controller-to-server hash"))
			mac.Write(b)
			mac.Write(clientNonce)
			mac.Write(serverNonce)
			return c.LowController.AuthenticateBytes(mac.Sum(nil))
		}
	}
	if rep[0].StatusCode != 250 {
		return false, errors.New("authentication failed")
	}
	return true, nil
}

type EventCode string

const (
	EVENT_CIRC               EventCode = "CIRC"
	EVENT_STREAM             EventCode = "STREAM"
	EVENT_ORCONN             EventCode = "ORCONN"
	EVENT_BW                 EventCode = "BW"
	EVENT_DEBUG              EventCode = "DEBUG"
	EVENT_INFO               EventCode = "INFO"
	EVENT_NOTICE             EventCode = "NOTICE"
	EVENT_WARN               EventCode = "WARN"
	EVENT_ERR                EventCode = "ERR"
	EVENT_NEWDESC            EventCode = "NEWDESC"
	EVENT_ADDRMAP            EventCode = "ADDRMAP"
	EVENT_AUTHDIR_NEWDESCS   EventCode = "AUTHDIR_NEWDESCS"
	EVENT_DESCCHANGED        EventCode = "DESCCHANGED"
	EVENT_STATUS_GENERAL     EventCode = "STATUS_GENERAL"
	EVENT_STATUS_CLIENT      EventCode = "STATUS_CLIENT"
	EVENT_STATUS_SERVER      EventCode = "STATUS_SERVER"
	EVENT_GUARD              EventCode = "GUARD"
	EVENT_NS                 EventCode = "NS"
	EVENT_STREAM_BW          EventCode = "STREAM_BW"
	EVENT_CLIENTS_SEEN       EventCode = "CLIENTS_SEEN"
	EVENT_NEWCONSENSUS       EventCode = "NEWCONSENSUS"
	EVENT_BUILDTIMEOUT_SET   EventCode = "BUILDTIMEOUT_SET"
	EVENT_SIGNAL             EventCode = "SIGNAL"
	EVENT_CONF_CHANGED       EventCode = "CONF_CHANGED"
	EVENT_CIRC_MINOR         EventCode = "CIRC_MINOR"
	EVENT_TRANSPORT_LAUNCHED EventCode = "TRANSPORT_LAUNCHED"
	EVENT_CONN_BW            EventCode = "CONN_BW"
	EVENT_CIRC_BW            EventCode = "CIRC_BW"
	EVENT_CELL_STATS         EventCode = "CELL_STATS"
	EVENT_TB_EMPTY           EventCode = "TB_EMPTY"
	EVENT_HS_DESC            EventCode = "HS_DESC"
	EVENT_HS_DESC_CONTENT    EventCode = "HS_DESC_CONTENT"
	EVENT_NETWORK_LIVENESS   EventCode = "NETWORK_LIVENESS"
	EVENT_PT_LOG             EventCode = "PT_LOG"
	EVENT_PT_STATUS          EventCode = "PT_STATUS"
)

func (c *Controller) updateEvents() (bool, error) {
	keys := make([]string, len(c.notifHandler)+len(c.iNotifHandler))
	i := 0
	for k := range c.notifHandler {
		keys[i] = k
		i++
	}
	for k := range c.iNotifHandler {
		keys[i] = k
		i++
	}
	slices.Sort(keys)
	return c.LowController.SetEvents(slices.Compact(keys))
}

func (c *Controller) RegisterEvent(code EventCode, callback func([]ReplyLine)) (bool, error) {
	c.notifHandler[string(code)] = callback
	return c.updateEvents()
}

func (c *Controller) iRegisterEvent(code EventCode, callback func([]ReplyLine)) (bool, error) {
	c.iNotifHandler[string(code)] = callback
	return c.updateEvents()
}

func (c *Controller) UnregisterEvent(code EventCode) (bool, error) {
	delete(c.notifHandler, string(code))
	return c.updateEvents()
}

func (c *Controller) iUnregisterEvent(code EventCode) (bool, error) {
	delete(c.iNotifHandler, string(code))
	return c.updateEvents()
}

func (c *Controller) HSAlive(addr string) (bool, error) {
	done := make(chan bool)
	succ, err := c.iRegisterEvent(EVENT_HS_DESC, func(lines []ReplyLine) {
		segs := strings.Split(string(lines[0].Line), " ")
		if segs[2] != addr {
			return
		}
		if segs[1] == "RECEIVED" {
			done <- true
		} else if segs[1] == "FAILED" {
			done <- false
		}
	})
	if err != nil || !succ {
		return false, err
	}
	err = c.LowController.HSFetch(addr, []string{})
	if err != nil {
		return false, err
	}
	ret := <-done
	succ, err = c.iUnregisterEvent(EVENT_HS_DESC)
	if err != nil || !succ {
		return false, err
	}
	return ret, nil
}

func (c *Controller) workerNotification() {
	for {
		notif := <-c.LowController.NotificationChan
		ev := string(notif[0].Line[:bytes.IndexByte(notif[0].Line, ' ')])
		if callback, ok := c.notifHandler[ev]; ok {
			callback(notif)
		}
		if callback, ok := c.iNotifHandler[ev]; ok {
			callback(notif)
		}
	}
}

func (c *Controller) NewIdentity() error {
	if !slices.Contains(c.availableSignals, string(SIGNAL_NEWNYM)) {
		return errors.New("NEWNYM not available")
	}
	return c.LowController.SendSignal(SIGNAL_NEWNYM)
}
