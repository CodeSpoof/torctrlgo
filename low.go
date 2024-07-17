package torctrlgo

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"
)

// Defines commands directly supported by the protocol.
// Commands that accept multiple arg-formats may have multiple representing functions.

var (
	ErrOperationUnnecessary        = errors.New("operation was unnecessary")
	ErrResourceExhausted           = errors.New("resource exhausted")
	ErrProtocolSyntaxError         = errors.New("syntax error: protocol")
	ErrUnrecognizedCommand         = errors.New("unrecognized command")
	ErrUnimplementedCommand        = errors.New("unimplemented command")
	ErrSyntaxCommandArgument       = errors.New("syntax error in command argument")
	ErrUnrecognizedCommandArgument = errors.New("unrecognized command argument")
	ErrAuthenticationRequired      = errors.New("authentication required")
	ErrBadAuthentication           = errors.New("bad authentication")
	ErrUnspecified                 = errors.New("unspecified Tor error")
	ErrInternal                    = errors.New("internal error")
	ErrUnrecognizedEntity          = errors.New("unrecognized entity")
	ErrInvalidConfigurationValue   = errors.New("invalid configuration value")
	ErrInvalidDescriptor           = errors.New("invalid descriptor")
	ErrUnmanagedEntity             = errors.New("unmanaged entity")

	ErrUnknown = errors.New("unknown status code")
)

func processErrorLine(line ReplyLine) error {
	switch line.StatusCode {
	case 251:
		return wrapError(string(line.Line), ErrOperationUnnecessary)
	case 451:
		return wrapError(string(line.Line), ErrResourceExhausted)
	case 500:
		return wrapError(string(line.Line), ErrProtocolSyntaxError)
	case 510:
		return wrapError(string(line.Line), ErrUnrecognizedCommand)
	case 511:
		return wrapError(string(line.Line), ErrUnimplementedCommand)
	case 512:
		return wrapError(string(line.Line), ErrSyntaxCommandArgument)
	case 513:
		return wrapError(string(line.Line), ErrUnrecognizedCommandArgument)
	case 514:
		return wrapError(string(line.Line), ErrAuthenticationRequired)
	case 515:
		return wrapError(string(line.Line), ErrBadAuthentication)
	case 550:
		return wrapError(string(line.Line), ErrUnspecified)
	case 551:
		return wrapError(string(line.Line), ErrInternal)
	case 552:
		return wrapError(string(line.Line), ErrUnrecognizedEntity)
	case 553:
		return wrapError(string(line.Line), ErrInvalidConfigurationValue)
	case 554:
		return wrapError(string(line.Line), ErrInvalidDescriptor)
	case 555:
		return wrapError(string(line.Line), ErrUnmanagedEntity)
	default:
		if line.StatusCode != 250 && line.StatusCode != 252 {
			return wrapError(string(line.Line), ErrUnknown)
		}
	}
	return nil
}

type ProtocolInfo struct {
	PIVERSION   string
	TorVersion  string
	AuthMethods []string
	CookieFiles []string
	OtherLines  []string
}

func (c *LowController) iSetConf(cmd string, configs map[string]string) error {
	if len(configs) == 0 {
		return wrapError("configs can't be empty", ErrSyntaxCommandArgument)
	}
	l := make([]string, len(configs))
	for k, v := range configs {
		st := k
		if len(v) > 0 {
			st += "="
			if strings.Contains(v, "\"") {
				st += writeQString(v)
			} else {
				st += v
			}
		}
		l = append(l, st)
	}
	rep, err := c.sendPacket([]byte(string(cmd) + " " + strings.Join(l, " ") + "\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) SetConf(confs map[string]string) error {
	return c.iSetConf("SETCONF", confs)
}

func (c *LowController) ResetConf(confs map[string]string) error {
	return c.iSetConf("RESETCONF", confs)
}

func (c *LowController) GetConf(names []string) (configs map[string][]string, defaults map[string]int, err error) {
	rep, err := c.sendPacket([]byte("GETCONF " + strings.Join(names, " ") + "\r\n"))
	if err != nil {
		return
	}
	err = processErrorLine(rep[0])
	if err != nil {
		return
	}
	configs = make(map[string][]string)
	defaults = make(map[string]int)
	for _, line := range rep {
		match := patternConfigValue.FindStringSubmatch(string(line.Line))
		if match == nil && slices.Contains(names, string(line.Line)) {
			if _, ok := defaults[string(line.Line)]; ok {
				defaults[string(line.Line)]++
			} else {
				defaults[string(line.Line)] = 1
			}
		}
		if match[2][0] == '"' {
			match[2], _ = readQCString(match[2])
		}
		if val, ok := configs[match[1]]; ok {
			configs[match[1]] = append(val, strings.Trim(match[2], "\r\n "))
		} else {
			configs[match[1]] = []string{strings.Trim(match[2], "\r\n ")}
		}
	}
	return
}

func (c *LowController) SetEvents(codes []string, extended bool) error {
	st := "SETEVENTS "
	if extended {
		st += "EXTENDED "
	}
	rep, err := c.sendPacket([]byte(st + strings.Join(codes, " ") + "\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) AuthenticateNull() error {
	rep, err := c.sendPacket([]byte("AUTHENTICATE\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) AuthenticateBytes(data []byte) error {
	rep, err := c.sendPacket([]byte("AUTHENTICATE " + hex.EncodeToString(data) + "\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) AuthenticateString(data string) error {
	rep, err := c.sendPacket([]byte("AUTHENTICATE " + writeQString(data) + "\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) SaveConf(force bool) error {
	st := "SAVECONF"
	if force {
		st += " FORCE"
	}
	rep, err := c.sendPacket([]byte(st + "\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

type Signal string

const (
	SIGNAL_RELOAD        Signal = "RELOAD"
	SIGNAL_HUP           Signal = "HUP" // Same as SIGNAL_RELOAD
	SIGNAL_SHUTDOWN      Signal = "SHUTDOWN"
	SIGNAL_INT           Signal = "INT" // Same as SIGNAL_SHUTDOWN
	SIGNAL_DUMP          Signal = "DUMP"
	SIGNAL_USR1          Signal = "USR1" // Same as SIGNAL_DUMP
	SIGNAL_DEBUG         Signal = "DEBUG"
	SIGNAL_USR2          Signal = "USR2" // Same as SIGNAL_DEBUG
	SIGNAL_HALT          Signal = "HALT"
	SIGNAL_TERM          Signal = "TERM" // Same as SIGNAL_HALT
	SIGNAL_CLEARDNSCACHE Signal = "CLEARDNSCACHE"
	SIGNAL_NEWNYM        Signal = "NEWNYM"
	SIGNAL_HEARTBEAT     Signal = "HEARTBEAT"
	SIGNAL_DORMANT       Signal = "DORMANT"
	SIGNAL_ACTIVE        Signal = "ACTIVE"
)

func (c *LowController) SendSignal(signal Signal) error {
	rep, err := c.sendPacket([]byte("SIGNAL " + string(signal) + "\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) MapAddress(addrs map[string]string) (map[string]string, error) {
	if len(addrs) == 0 {
		return nil, wrapError("addresses can't be empty", ErrSyntaxCommandArgument)
	}
	st := "MAPADDRESS"
	for k, v := range addrs {
		st += " " + k + "=" + v
	}
	rep, err := c.sendPacket([]byte(st + "\r\n"))
	if err != nil {
		return nil, err
	}
	ret := make(map[string]string)
	for _, line := range rep {
		err = processErrorLine(line)
		if err != nil {
			if errors.Is(err, ErrSyntaxCommandArgument) {
				continue
			}
			return nil, err
		}
		if match := patternConfigValue.FindStringSubmatch(string(line.Line)); match != nil {
			ret[match[1]] = strings.Trim(match[2], "\r\n ")
		} else {
			return nil, wrapError("invalid reply line", ErrUnknown)
		}
	}
	return ret, nil
}

func (c *LowController) GetInfo(keywords []string) (map[string]string, error) {
	if len(keywords) == 0 {
		return nil, wrapError("keywords can't be empty", ErrSyntaxCommandArgument)
	}
	rep, err := c.sendPacket([]byte(strings.Join(append([]string{"GETINFO"}, keywords...), " ") + "\r\n"))
	if err != nil {
		return nil, err
	}
	err = processErrorLine(rep[len(rep)-1])
	if err != nil {
		return nil, err
	}
	ret := make(map[string]string)
	for _, line := range rep {
		match := patternConfigValue.FindSubmatch(line.Line)
		if match == nil {
			continue
		}
		if !slices.Contains(keywords, string(match[1])) {
			return nil, errors.New("keyword \"" + string(match[1]) + "\" not requested")
		}
		ret[string(match[1])] = strings.Trim(string(match[2]), "\r\n\t ")
	}
	if len(ret) < len(keywords) {
		return nil, errors.New("keywords left unanswered")
	}
	return ret, nil
}

func (c *LowController) ExtendCircuit(circuitID int, path []string, purpose string) (int, error) {
	st := "EXTENDCIRCUIT " + strconv.Itoa(circuitID)
	if circuitID != 0 && len(path) == 0 {
		return 0, wrapError("path can't be empty for extending existing circuits", ErrSyntaxCommandArgument)
	}
	if len(path) > 0 {
		st += " " + strings.Join(path, ",")
	}
	if len(purpose) > 0 {
		if purpose != "general" && purpose != "controller" {
			return 0, wrapError("purpose must be \"general\" or \"controller\"", ErrSyntaxCommandArgument)
		}
		st += " purpose=" + purpose
	}
	rep, err := c.sendPacket([]byte(st + "\r\n"))
	if err != nil {
		return 0, err
	}
	err = processErrorLine(rep[0])
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(string(rep[0].Line[bytes.IndexByte(rep[0].Line, ' ')+1:]))
}

func (c *LowController) SetCircuitPurpose(circuitID int, purpose string) error {
	if purpose != "general" && purpose != "controller" {
		return wrapError("purpose must be \"general\" or \"controller\"", ErrSyntaxCommandArgument)
	}
	rep, err := c.sendPacket([]byte("SETCIRCUITPURPOSE " + strconv.Itoa(circuitID) + " purpose=" + purpose + "\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) SetRouterPurpose(nicknameOrKey, purpose string) error {
	if purpose != "general" && purpose != "controller" && purpose != "bridge" {
		return wrapError("\""+purpose+"\" is not a valid router purpose", ErrUnrecognizedEntity)
	}
	rep, err := c.sendPacket([]byte("SETROUTERPURPOSE " + nicknameOrKey + " " + purpose + "\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) AttachStream(streamID string, circuitID, hopNum int) error {
	st := "ATTACHSTREAM " + streamID + strconv.Itoa(circuitID)
	if hopNum > 0 {
		if hopNum < 2 {
			return wrapError("hop can't be 1", ErrSyntaxCommandArgument)
		}
		st += " HOP=" + strconv.Itoa(hopNum)
	}
	rep, err := c.sendPacket([]byte(st + "\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) PostDescriptor(purpose string, cache string, descriptor string) error {
	st := "+POSTDESCRIPTOR"
	if len(purpose) > 0 {
		if purpose != "general" && purpose != "controller" && purpose != "bridge" {
			return wrapError("\""+purpose+"\" is not a valid router purpose", ErrUnrecognizedEntity)
		}
		st += " purpose=" + purpose
	}
	if len(cache) > 0 {
		if cache != "yes" && cache != "no" {
			return wrapError("\""+cache+"\" is not a valid option for cache", ErrUnrecognizedEntity)
		}
		st += " cache=" + cache
	}
	rep, err := c.sendPacket([]byte(st + "\r\n" + descriptor + "\r\n.\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) RedirectStream(streamID string, address string, port uint16) error {
	st := "REDIRECTSTREAM " + streamID + " " + address
	if port > 0 {
		st += " " + strconv.Itoa(int(port))
	}
	rep, err := c.sendPacket([]byte(st + "\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

type RelayEndReason byte

const (
	RELAY_END_REASON_MISC           RelayEndReason = 1
	RELAY_END_REASON_RESOLVEFAILED  RelayEndReason = 2
	RELAY_END_REASON_CONNECTREFUSED RelayEndReason = 3
	RELAY_END_REASON_EXITPOLICY     RelayEndReason = 4
	RELAY_END_REASON_DESTROY        RelayEndReason = 5
	RELAY_END_REASON_DONE           RelayEndReason = 6
	RELAY_END_REASON_TIMEOUT        RelayEndReason = 7
	RELAY_END_REASON_NOROUTE        RelayEndReason = 8
	RELAY_END_REASON_HIBERNATING    RelayEndReason = 9
	RELAY_END_REASON_INTERNAL       RelayEndReason = 10
	RELAY_END_REASON_RESOURCELIMIT  RelayEndReason = 11
	RELAY_END_REASON_CONNRESET      RelayEndReason = 12
	RELAY_END_REASON_TORPROTOCOL    RelayEndReason = 13
	RELAY_END_REASON_NOTDIRECTORY   RelayEndReason = 14
)

func (c *LowController) CloseStream(streamID string, reason RelayEndReason, flags []string) error {
	b := append([]byte("CLOSESTREAM "+streamID+" "), byte(reason))
	if len(flags) > 0 {
		b = append(b, []byte(" "+strings.Join(flags, " "))...)
	}
	rep, err := c.sendPacket(append(b, '\r', '\n'))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

const (
	FLAG_CIRCUITCLOSE_IFUNUSED = "IfUnused"
)

func (c *LowController) CloseCircuit(circuitID int, flags []string) error {
	st := "CLOSECIRCUIT " + strconv.Itoa(circuitID)
	if len(flags) > 0 {
		st += " " + strings.Join(flags, " ")
	}
	rep, err := c.sendPacket([]byte(st + "\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) Quit() error {
	err := c.sendPacketDiscardReply([]byte("QUIT\r\n"))
	return err
}

func (c *LowController) UseFeature(features []string) error {
	st := "USEFEATURE"
	if len(features) > 0 {
		st += " " + strings.Join(features, " ")
	}
	rep, err := c.sendPacket([]byte(st + "\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) Resolve(addrs []string, reverse bool) error {
	s := "RESOLVE"
	if reverse {
		s += " mode=reverse"
	}
	rep, err := c.sendPacket([]byte(s + " " + strings.Join(addrs, " ") + "\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) GetProtocolInfo(versions []string) (*ProtocolInfo, error) {
	ret := ProtocolInfo{}
	st := "PROTOCOLINFO"
	if len(versions) > 0 {
		st += " " + strings.Join(versions, " ")
	}
	rep, err := c.sendPacket([]byte(st + "\r\n"))
	if err != nil {
		return nil, err
	}
	err = processErrorLine(rep[len(rep)-1])
	if err != nil {
		return nil, err
	}
	var segs []string
	for _, lb := range rep {
		line := string(lb.Line)
		segs = strings.Split(strings.TrimSuffix(line, "\r\n"), " ")
		switch segs[0] {
		case "PROTOCOLINFO":
			ret.PIVERSION = segs[1]
		case "AUTH":
			for i := 4; i < len(line); i++ {
				if line[i] != ' ' {
					continue
				}
				if strings.HasPrefix(line[i+1:], "METHODS=") {
					ret.AuthMethods = append(ret.AuthMethods, strings.Split(line[i+9:i+9+strings.Index(line[i+9:], " ")], ",")...)
					i += strings.Index(line[i+1:], " ")
				} else if strings.HasPrefix(line[i+1:], "COOKIEFILE=") {
					str, j := readQCString(line[i+12:])
					ret.CookieFiles = append(ret.CookieFiles, str)
					i += 11 + j
				}
			}
		case "VERSION":
			if strings.HasPrefix(segs[1], "Tor=") {
				ret.TorVersion, _ = readQCString(line[len(segs[0])+5:])
			}
		default:
			ret.OtherLines = append(ret.OtherLines, line)
		}
	}
	c.lastProtoLock.Lock()
	c.lastProtocolInfo = &ret
	c.lastProtoLock.Unlock()
	return &ret, nil
}

func (c *LowController) LoadConf(config string) error {
	rep, err := c.sendPacket([]byte("+LOADCONF\r\n" + config + "\r\n.\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) TakeOwnership() error {
	rep, err := c.sendPacket([]byte("TAKEOWNERSHIP\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) AuthChallenge(chllngType string, clientNonce []byte) (serverHash []byte, serverNonce []byte, err error) {
	rep, err := c.sendPacket([]byte("AUTHCHALLENGE " + chllngType + " " + hex.EncodeToString(clientNonce) + "\r\n"))
	if err != nil {
		return
	}
	err = processErrorLine(rep[0])
	if err != nil {
		return
	}
	segs := strings.Split(string(rep[0].Line), " ")
	if segs[0] != "AUTHCHALLENGE" {
		err = errors.New("not an auth-challenge response")
		return
	}
	dict := parseStringDict(string(rep[0].Line)[len(segs[0])+1:])
	if _, ok := dict["SERVERHASH"]; !ok {
		err = errors.New("server-hash missing")
		return
	}
	serverHash, err = hex.DecodeString(dict["SERVERHASH"])
	if err != nil {
		return nil, nil, errors.New("server-hash malformed")
	}
	if _, ok := dict["SERVERNONCE"]; !ok {
		return nil, nil, errors.New("server-nonce missing")
	}
	serverNonce, err = hex.DecodeString(dict["SERVERNONCE"])
	if err != nil {
		return nil, nil, errors.New("server-nonce malformed")
	}
	return
}

func (c *LowController) DropGuards() error {
	rep, err := c.sendPacket([]byte("DROPGUARDS\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) HSFetch(addressOrDescriptor string, servers []string) error {
	cmd := "HSFETCH " + addressOrDescriptor
	if len(servers) > 0 {
		cmd += strings.Join(append([]string{""}, servers...), " SERVER=")
	}
	rep, err := c.sendPacket([]byte(cmd + "\r\n"))
	if err != nil {
		return err
	}
	err = processErrorLine(rep[0])
	if err != nil {
		return err
	}
	return nil
}

type KeyType string

const (
	// KEYTYPE_X25519 Only for use in OnionClientAuth
	KEYTYPE_X25519 KeyType = "x25519"
	// KEYTYPE_NEW pseudo-keytype, only for use in LowController.AddOnion
	KEYTYPE_NEW KeyType = "NEW"
	// KEYTYPE_RSA1024 Only for use in LowController.AddOnion
	KEYTYPE_RSA1024 KeyType = "RSA1024"
	// KEYTYPE_ED25519_V3 Only for use in LowController.AddOnion
	KEYTYPE_ED25519_V3 KeyType = "ED25519-V3"
)

const (
	GENERATE_BEST       = "BEST"
	GENERATE_RSA1024    = "RSA1024"
	GENERATE_ED25519_V3 = "ED25519-V3"
)

type HSPortConfig struct {
	VirtPort uint16
	Target   string
}

type HSAuthConfig struct {
	ClientName string
	AuthBlob   string
}

type HSConfigReply struct {
	ServiceID string
	keyType   KeyType
	keyBlob   string
	auths     []HSAuthConfig
}

func (c *LowController) AddOnion(keyType KeyType, keyBlob string, flags []string, maxStreams uint16, ports []HSPortConfig, auths []HSAuthConfig) (*HSConfigReply, error) {
	st := "ADD_ONION " + string(keyType) + ":" + keyBlob
	if len(flags) > 0 {
		st += " Flags=" + strings.Join(flags, " ")
	}
	if maxStreams > 0 {
		st += " MaxStreams=" + strconv.Itoa(int(maxStreams))
	}
	if len(ports) == 0 {
		return nil, wrapError("missing port configuration", ErrSyntaxCommandArgument)
	}
	for _, portConfig := range ports {
		st += " Port=" + strconv.Itoa(int(portConfig.VirtPort))
		if len(portConfig.Target) > 0 {
			st += "," + portConfig.Target
		}
	}
	for _, authConfig := range auths {
		if keyType == KEYTYPE_RSA1024 {
			st += " ClientAuth=" + authConfig.ClientName
			if len(authConfig.AuthBlob) > 0 {
				st += ":" + authConfig.AuthBlob
			}
		} else if keyType == KEYTYPE_ED25519_V3 {
			st += " ClientAuthV3=" + authConfig.AuthBlob
		}
	}
	rep, err := c.sendPacket([]byte(st + "\r\n"))
	if err != nil {
		return nil, err
	}
	if err = processErrorLine(rep[len(rep)-1]); err != nil {
		return nil, err
	}
	ret := HSConfigReply{}
	for _, line := range rep {
		if match := patternConfigValue.FindStringSubmatch(string(line.Line)); match != nil {
			i := strings.IndexByte(match[1], ':')
			switch match[1] {
			case "ServiceID":
				ret.ServiceID = strings.Trim(match[2], "\r\n ")
			case "PrivateKey":
				ret.keyType = KeyType(match[1][:i])
				ret.keyBlob = match[1][i+1:]
			case "ClientAuth":
				ret.auths = append(ret.auths, HSAuthConfig{
					ClientName: match[1][:i],
					AuthBlob:   match[1][i+1:],
				})
			}
		}
	}
	return &ret, nil
}

func (c *LowController) DelOnion(HSAddr string) error {
	rep, err := c.sendPacket([]byte("DEL_ONION " + HSAddr + "\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) HSPost(servers []string, HSAddr string, descriptor string) error {
	st := "+HSPOST" + strings.Join(append([]string{""}, servers...), " SERVER=")
	if len(HSAddr) > 0 {
		st += " HSADDRESS=" + HSAddr
	}
	rep, err := c.sendPacket([]byte(st + "\r\n" + descriptor + "\r\n.\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

type OnionClientAuth struct {
	HSAddr     string
	KType      KeyType
	KeyBlob    []byte
	ClientName string
	Flags      []string
}

func (c *LowController) OnionClientAuthAdd(auth OnionClientAuth) error {
	st := "ONION_CLIENT_AUTH_ADD " + auth.HSAddr + " " + string(auth.KType) + ":" + base64.StdEncoding.EncodeToString(auth.KeyBlob)
	if len(auth.ClientName) > 0 {
		st += " ClientName=" + auth.ClientName
	}
	if len(auth.Flags) > 0 {
		st += " Flags=" + strings.Join(auth.Flags, ",")
	}
	rep, err := c.sendPacket([]byte(st + "\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) OnionClientAuthRemove(HSAddr string) error {
	rep, err := c.sendPacket([]byte("ONION_CLIENT_AUTH_REMOVE " + HSAddr + "\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) OnionClientAuthView(HSAddr string) ([]OnionClientAuth, error) {
	st := "ONION_CLIENT_AUTH_VIEW"
	if len(HSAddr) > 0 {
		st += " " + HSAddr
	}
	rep, err := c.sendPacket([]byte(st + "\r\n"))
	if err != nil {
		return nil, err
	}
	err = processErrorLine(rep[0])
	if err != nil {
		return nil, err
	}
	var ret []OnionClientAuth
	for _, line := range rep {
		if i := bytes.IndexByte(line.Line, ' '); bytes.Equal(line.Line[:i], []byte("CLIENT")) {
			segs := strings.Split(string(line.Line[i+1:]), " ")
			keyX := strings.IndexByte(segs[1], ':')
			blob, err := base64.StdEncoding.DecodeString(segs[1][keyX+1:])
			if err != nil {
				return nil, err
			}
			ca := OnionClientAuth{
				HSAddr:  segs[0],
				KType:   KeyType(segs[1][:keyX]),
				KeyBlob: blob,
			}
			for i = 2; i < len(segs); i++ {
				j := strings.IndexByte(segs[i], '=')
				switch segs[i][:j] {
				case "ClientName":
					ca.ClientName = segs[i][j+1:]
				case "Flags":
					ca.Flags = strings.Split(segs[i][j+1:], ",")
				}
			}
			ret = append(ret, ca)
		}
	}
	return ret, nil
}

func (c *LowController) DropOwnership() error {
	rep, err := c.sendPacket([]byte("DROPOWNERSHIP\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) DropTimeouts() error {
	rep, err := c.sendPacket([]byte("DROPTIMEOUTS\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}
