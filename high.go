package torctrlgo

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
)

// Defines high-level API for communication via ControlPort

// Controller provides a high-level API for communication over TOR's ControlPort protocol.
//
// Certain functions may declare high concurrency-safety.
type Controller struct {
	networkLiveness          string
	networkLivenessHandlerID int
	genericPropLock          sync.Mutex
	torVersion               string
	torRCPath                string
	VersionStatus            string
	LowController            *LowController
	notifLock                sync.Mutex
	notifHandler             map[string]func([]ReplyLine)
	iNotifLock               sync.Mutex
	iNotifHandler            map[string]map[int]func([]ReplyLine)
	iNotifCount              map[string]int
	availableLock            sync.Mutex
	availableConfigs         map[string][2]string
	availableInfos           map[string]string
	availableEvents          []string
	availableFeatures        []string
	availableSignals         []string
}

func (c *Controller) TorVersion() string {
	c.genericPropLock.Lock()
	defer c.genericPropLock.Unlock()
	return c.torVersion
}

func (c *Controller) TorRCPath() string {
	c.genericPropLock.Lock()
	defer c.genericPropLock.Unlock()
	return c.torRCPath
}

func (c *Controller) AvailableConfigs() map[string][2]string {
	c.availableLock.Lock()
	defer c.availableLock.Unlock()
	return c.availableConfigs
}

func (c *Controller) AvailableInfos() map[string]string {
	c.availableLock.Lock()
	defer c.availableLock.Unlock()
	return c.availableInfos
}

func (c *Controller) AvailableEvents() []string {
	c.availableLock.Lock()
	defer c.availableLock.Unlock()
	return c.availableEvents
}

func (c *Controller) AvailableFeatures() []string {
	c.availableLock.Lock()
	defer c.availableLock.Unlock()
	return c.availableFeatures
}

func (c *Controller) AvailableSignals() []string {
	c.availableLock.Lock()
	defer c.availableLock.Unlock()
	return c.availableSignals
}

func (c *Controller) Online() bool {
	return c.networkLiveness == "UP"
}

func NewController() *Controller {
	return &Controller{
		LowController:     NewLowController(),
		notifHandler:      make(map[string]func([]ReplyLine)),
		iNotifHandler:     make(map[string]map[int]func([]ReplyLine)),
		iNotifCount:       make(map[string]int),
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
	info, err := c.LowController.GetInfo([]string{"version", "config-file", "status/version/current", "config/names", "info/names", "events/names", "features/names", "signal/names", "network-liveness"})
	if err != nil {
		return err
	}
	c.genericPropLock.Lock()
	c.torVersion = info["version"]
	c.torRCPath = info["config-file"]
	c.VersionStatus = info["status/version/current"]
	c.genericPropLock.Unlock()
	var segs []string
	c.availableLock.Lock()
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
	c.networkLiveness = strings.ToUpper(info["network-liveness"])
	c.availableLock.Unlock()
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

// Authenticate the connection using the given AuthMethod and (if required) AuthData
//
// This function is fully thread-safe, although there shouldn't be any scenario, where that's applicable
func (c *Controller) Authenticate(method AuthMethod, data AuthData) error {
	err := c.iAuthenticate(method, data)
	if err != nil {
		return err
	}
	c.networkLivenessHandlerID, err = c.iRegisterEvent(EVENT_NETWORK_LIVENESS, c.notifNetworkLiveness)
	if err != nil {
		return err
	}
	return c.loadCompatData()
}

func (c *Controller) iAuthenticate(method AuthMethod, data AuthData) error {
	var rep []ReplyLine
	var err error
	c.LowController.lastProtoLock.Lock()
	lpi := c.LowController.lastProtocolInfo
	c.LowController.lastProtoLock.Unlock()
	if lpi == nil && (method == AUTH_COOKIE || method == AUTH_SAFECOOKIE) {
		_, err = c.LowController.GetProtocolInfo([]string{"1"})
		if err != nil {
			return err
		}
		c.LowController.lastProtoLock.Lock()
		lpi = c.LowController.lastProtocolInfo
		c.LowController.lastProtoLock.Unlock()
	}
	switch method {
	case AUTH_NULL:
		return c.LowController.AuthenticateNull()
	case AUTH_HASHEDPASSWORD:
		return c.LowController.AuthenticateString(data.Password)
	case AUTH_COOKIE, AUTH_SAFECOOKIE:
		if len(lpi.CookieFiles) == 0 {
			return errors.New("no cookie files found")
		}
		b := data.CookieData
		if b == nil {
			for _, path := range lpi.CookieFiles {
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
			return errors.New("cookie files couldn't be accessed")
		} else if method == AUTH_COOKIE {
			return c.LowController.AuthenticateBytes(b)
		} else {
			clientNonce := make([]byte, 32)
			_, err = rand.Read(clientNonce)
			if err != nil {
				return err
			}
			serverHash, serverNonce, err := c.LowController.AuthChallenge("SAFECOOKIE", clientNonce)
			if err != nil {
				return err
			}
			mac := hmac.New(sha256.New, []byte("Tor safe cookie authentication server-to-controller hash"))
			mac.Write(b)
			mac.Write(clientNonce)
			mac.Write(serverNonce)
			expectedServerHash := mac.Sum(nil)
			testNonce := make([]byte, 32)
			_, err = rand.Read(testNonce)
			if err != nil {
				return err
			}
			mac = hmac.New(sha256.New, testNonce)
			mac.Write(serverHash)
			challengeHmac := mac.Sum(nil)
			mac.Reset()
			mac.Write(expectedServerHash)
			if !bytes.Equal(challengeHmac, mac.Sum(nil)) {
				return errors.New("tor provided wrong serverNonce")
			}
			mac = hmac.New(sha256.New, []byte("Tor safe cookie authentication controller-to-server hash"))
			mac.Write(b)
			mac.Write(clientNonce)
			mac.Write(serverNonce)
			return c.LowController.AuthenticateBytes(mac.Sum(nil))
		}
	}
	return processErrorLine(rep[0])
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

func (c *Controller) updateEvents() error {
	c.iNotifLock.Lock()
	c.notifLock.Lock()
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
	defer func() {
		c.iNotifLock.Unlock()
		c.notifLock.Unlock()
	}()
	return c.LowController.SetEvents(slices.Compact(keys))
}

// RegisterEvent sets the callback function for the given event.
//
// This function is fully thread-safe.
func (c *Controller) RegisterEvent(code EventCode, callback func([]ReplyLine)) error {
	c.notifLock.Lock()
	c.notifHandler[string(code)] = callback
	c.notifLock.Unlock()
	return c.updateEvents()
}

func (c *Controller) iRegisterEvent(code EventCode, callback func([]ReplyLine)) (int, error) {
	c.iNotifLock.Lock()
	var id int
	if val, ok := c.iNotifCount[string(code)]; ok {
		id = val
		c.iNotifCount[string(code)]++
	} else {
		id = 0
		c.iNotifCount[string(code)] = 1
		c.iNotifHandler[string(code)] = make(map[int]func([]ReplyLine))
	}
	c.iNotifHandler[string(code)][id] = callback
	c.iNotifLock.Unlock()
	return id, c.updateEvents()
}

// UnregisterEvent removes the set callback function for the given event.
//
// This function is fully thread-safe.
func (c *Controller) UnregisterEvent(code EventCode) error {
	c.notifLock.Lock()
	delete(c.notifHandler, string(code))
	c.notifLock.Unlock()
	return c.updateEvents()
}

func (c *Controller) iUnregisterEvent(code EventCode, id int) error {
	c.iNotifLock.Lock()
	delete(c.iNotifHandler[string(code)], id)
	if len(c.iNotifHandler[string(code)]) == 0 {
		delete(c.iNotifHandler, string(code))
		delete(c.iNotifCount, string(code))
	}
	c.iNotifLock.Unlock()
	return c.updateEvents()
}

// HSDescAvailable checks for the availability of the given hidden service on the hash-ring.
// This usually means, that the hidden service is reachable.
//
// This function is fully thread-safe
func (c *Controller) HSDescAvailable(addr string) (bool, error) {
	done := make(chan bool)
	id, err := c.iRegisterEvent(EVENT_HS_DESC, func(lines []ReplyLine) {
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
	if err != nil {
		return false, err
	}
	err = c.LowController.HSFetch(addr, []string{})
	if err != nil {
		return false, err
	}
	ret := <-done
	err = c.iUnregisterEvent(EVENT_HS_DESC, id)
	if err != nil {
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
		c.iNotifLock.Lock()
		if m, ok := c.iNotifHandler[ev]; ok {
			for _, callback := range m {
				callback(notif)
			}
		}
		c.iNotifLock.Unlock()
	}
}

// NewIdentity switches to new circuits, so that new requests don't share any circuits with old ones.
//
// This function is fully thread-safe, although TOR might rate-limit its usage.
func (c *Controller) NewIdentity() error {
	c.availableLock.Lock()
	if !slices.Contains(c.availableSignals, string(SIGNAL_NEWNYM)) {
		c.availableLock.Unlock()
		return errors.New("NEWNYM not available")
	}
	c.availableLock.Unlock()
	return c.LowController.SendSignal(SIGNAL_NEWNYM)
}

func (c *Controller) notifNetworkLiveness(reply []ReplyLine) {
	c.networkLiveness = strings.Split(string(reply[0].Line), " ")[1]
}

type HiddenService struct {
	ctrl   *Controller
	Config *HSConfigReply
}

func (c *Controller) NewListener(virtPort uint16, keyBlob string, auths []HSAuthConfig) (net.Listener, *HiddenService, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		return nil, nil, err
	}
	hs, err := c.NewForwarder([]HSPortConfig{{VirtPort: virtPort, Target: listener.Addr().String()}}, keyBlob, auths)
	return listener, hs, err
}

func (c *Controller) NewForwarder(ports []HSPortConfig, keyBlob string, auths []HSAuthConfig) (*HiddenService, error) {
	if len(keyBlob) == 0 {
		keyBlob = GENERATE_ED25519_V3
	}
	config, err := c.LowController.AddOnion(KEYTYPE_NEW, keyBlob, nil, 0, ports, auths)
	return &HiddenService{
		ctrl:   c,
		Config: config,
	}, err
}
