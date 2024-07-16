package torctrlgo

import (
	"encoding/hex"
	"errors"
	"slices"
	"strings"
)

// Defines commands directly supported by the protocol.
// Commands that accept multiple arg-formats may have multiple representing functions.

type ErrOperationUnnecessary error
type ErrResourceExhausted error
type ErrProtocolSyntaxError error
type ErrUnrecognizedCommand error
type ErrUnimplementedCommand error
type ErrSyntaxCommandArgument error
type ErrUnrecognizedCommandArgument error
type ErrAuthenticationRequired error
type ErrBadAuthentication error
type ErrUnspecified error
type ErrInternal error
type ErrUnrecognizedEntity error
type ErrInvalidConfigurationValue error
type ErrInvalidDescriptor error
type ErrUnmanagedEntity error

type ErrUnknown error

func processErrorLine(line ReplyLine) error {
	switch line.StatusCode {
	case 251:
		return ErrOperationUnnecessary(errors.New(string(line.Line)))
	case 451:
		return ErrResourceExhausted(errors.New(string(line.Line)))
	case 500:
		return ErrProtocolSyntaxError(errors.New(string(line.Line)))
	case 510:
		return ErrUnrecognizedCommand(errors.New(string(line.Line)))
	case 511:
		return ErrUnimplementedCommand(errors.New(string(line.Line)))
	case 512:
		return ErrSyntaxCommandArgument(errors.New(string(line.Line)))
	case 513:
		return ErrUnrecognizedCommandArgument(errors.New(string(line.Line)))
	case 514:
		return ErrAuthenticationRequired(errors.New(string(line.Line)))
	case 515:
		return ErrBadAuthentication(errors.New(string(line.Line)))
	case 550:
		return ErrUnspecified(errors.New(string(line.Line)))
	case 551:
		return ErrInternal(errors.New(string(line.Line)))
	case 552:
		return ErrUnrecognizedEntity(errors.New(string(line.Line)))
	case 553:
		return ErrInvalidConfigurationValue(errors.New(string(line.Line)))
	case 554:
		return ErrInvalidDescriptor(errors.New(string(line.Line)))
	case 555:
		return ErrUnmanagedEntity(errors.New(string(line.Line)))
	default:
		if line.StatusCode != 250 {
			return ErrUnknown(errors.New(string(line.Line)))
		}
	}
	return nil
}

// Cmd represents a direct command on the ControlPort protocol
//
// Usage of Cmd outside the module itself will be mostly obsolete
// once all commands are implemented on the LowController API.
type Cmd string

const (
	CMD_SETCONF                  Cmd = "SETCONF"
	CMD_RESETCONF                Cmd = "RESETCONF"
	CMD_GETCONF                  Cmd = "GETCONF"
	CMD_SETEVENTS                Cmd = "SETEVENTS"
	CMD_AUTHENTICATE             Cmd = "AUTHENTICATE"
	CMD_SAVECONF                 Cmd = "SAVECONF"
	CMD_SIGNAL                   Cmd = "SIGNAL"
	CMD_MAPADDRESS               Cmd = "MAPADDRESS"
	CMD_GETINFO                  Cmd = "GETINFO"
	CMD_EXTENDCIRCUIT            Cmd = "EXTENDCIRCUIT"
	CMD_SETCIRCUITPURPOSE        Cmd = "SETCIRCUITPURPOSE"
	CMD_SETROUTERPURPOSE         Cmd = "SETROUTERPURPOSE"
	CMD_ATTACHSTREAM             Cmd = "ATTACHSTREAM"
	CMD_POSTDESCRIPTOR           Cmd = "POSTDESCRIPTOR"
	CMD_REDIRECTSTREAM           Cmd = "REDIRECTSTREAM"
	CMD_CLOSESTREAM              Cmd = "CLOSESTREAM"
	CMD_CLOSECIRCUIT             Cmd = "CLOSECIRCUIT"
	CMD_QUIT                     Cmd = "QUIT"
	CMD_USEFEATURE               Cmd = "USEFEATURE"
	CMD_RESOLVE                  Cmd = "RESOLVE"
	CMD_PROTOCOLINFO             Cmd = "PROTOCOLINFO"
	CMD_LOADCONF                 Cmd = "LOADCONF"
	CMD_TAKEOWNERSHIP            Cmd = "TAKEOWNERSHIP"
	CMD_AUTHCHALLENGE            Cmd = "AUTHCHALLENGE"
	CMD_DROPGUARDS               Cmd = "DROPGUARDS"
	CMD_HSFETCH                  Cmd = "HSFETCH"
	CMD_ADD_ONION                Cmd = "ADD_ONION"
	CMD_DEL_ONION                Cmd = "DEL_ONION"
	CMD_HSPOST                   Cmd = "HSPOST"
	CMD_ONION_CLIENT_AUTH_ADD    Cmd = "ONION_CLIENT_AUTH_ADD"
	CMD_ONION_CLIENT_AUTH_REMOVE Cmd = "ONION_CLIENT_AUTH_REMOVE"
	CMD_ONION_CLIENT_AUTH_VIEW   Cmd = "ONION_CLIENT_AUTH_VIEW"
	CMD_DROPOWNERSHIP            Cmd = "DROPOWNERSHIP"
	CMD_DROPTIMEOUTS             Cmd = "DROPTIMEOUTS"
)

type ProtocolInfo struct {
	PIVERSION   string
	TorVersion  string
	AuthMethods []string
	CookieFiles []string
}

func (c *LowController) iSetConf(cmd Cmd, confs map[string]string) error {
	if len(confs) == 0 {
		return errors.New("configs can't be empty")
	}
	l := make([]string, len(confs))
	for k, v := range confs {
		st := k
		if len(v) > 0 {
			st += "="
			if strings.ContainsAny(v, "\r\n\"\t") {
				st += writeQString(v)
			} else {
				st += v
			}
		}
		l = append(l, st)
	}
	rep, err := c.sendPacket([]byte(string(cmd) + " " + strings.Join(l, " ")))
	if err != nil {
		return err
	}
	if rep[0].StatusCode != 250 {
		return processErrorLine(rep[0])
	}
	return nil
}

func (c *LowController) SetConf(confs map[string]string) error {
	return c.iSetConf(CMD_SETCONF, confs)
}

func (c *LowController) ResetConf(confs map[string]string) error {
	return c.iSetConf(CMD_RESETCONF, confs)
}

func (c *LowController) GetConf(names []string) (map[string]string, error) {
	rep, err := c.sendPacket([]byte(string(CMD_GETCONF) + " " + strings.Join(names, " ") + "\r\n"))
	if err != nil {
		return nil, err
	}
	if rep[0].StatusCode != 250 {
		return nil, processErrorLine(rep[0])
	}
	ret := make(map[string]string)
	for _, line := range rep {
		match := patternConfigValue.FindStringSubmatch(string(line.Line))
		if match == nil {
			return nil, errors.New("invalid config value")
		}
		if match[2][0] == '"' {
			match[2], _ = readQString(match[2])
		}
		ret[match[1]] = strings.Trim(match[2], "\r\n ")
	}
	return ret, nil
}

func (c *LowController) SetEvents(codes []string) error {
	rep, err := c.sendPacket([]byte(string(CMD_SETEVENTS) + " " + strings.Join(codes, " ") + "\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) AuthenticateNull() error {
	rep, err := c.sendPacket([]byte(string(CMD_AUTHENTICATE) + "\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) AuthenticateBytes(data []byte) error {
	rep, err := c.sendPacket([]byte(string(CMD_AUTHENTICATE) + " " + hex.EncodeToString(data) + "\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) AuthenticateString(data string) error {
	rep, err := c.sendPacket([]byte(string(CMD_AUTHENTICATE) + " " + writeQString(data) + "\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) SaveConf(force bool) error {
	st := string(CMD_SAVECONF)
	if force {
		st += " FORCE"
	}
	rep, err := c.sendPacket([]byte(st + "\r\n"))
	if err != nil {
		return err
	}
	if rep[0].StatusCode != 250 {
		return processErrorLine(rep[0])
	}
	return nil
}

type Signal string

const (
	SIGNAL_RELOAD        Signal = "RELOAD"
	SIGNAL_SHUTDOWN      Signal = "SHUTDOWN"
	SIGNAL_DUMP          Signal = "DUMP"
	SIGNAL_DEBUG         Signal = "DEBUG"
	SIGNAL_HALT          Signal = "HALT"
	SIGNAL_CLEARDNSCACHE Signal = "CLEARDNSCACHE"
	SIGNAL_NEWNYM        Signal = "NEWNYM"
	SIGNAL_HEARTBEAT     Signal = "HEARTBEAT"
	SIGNAL_DORMANT       Signal = "DORMANT"
	SIGNAL_ACTIVE        Signal = "ACTIVE"
)

func (c *LowController) SendSignal(signal Signal) error {
	rep, err := c.sendPacket([]byte(string(CMD_SIGNAL) + " " + string(signal) + "\r\n"))
	if err != nil {
		return err
	}
	if rep[0].StatusCode != 250 {
		return processErrorLine(rep[0])
	}
	return nil
}

func (c *LowController) GetInfo(keywords []string) (map[string]string, error) {
	rep, err := c.sendPacket([]byte(strings.Join(append([]string{string(CMD_GETINFO)}, keywords...), " ") + "\r\n"))
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

func (c *LowController) Resolve(addr string, reverse bool) error {
	s := string(CMD_RESOLVE)
	if reverse {
		s += " mode=reverse"
	}
	rep, err := c.sendPacket([]byte(s + " " + addr + "\r\n"))
	if err != nil {
		return err
	}
	return processErrorLine(rep[0])
}

func (c *LowController) GetProtocolInfo(versions []string) (*ProtocolInfo, error) {
	ret := ProtocolInfo{
		AuthMethods: make([]string, 0),
		CookieFiles: make([]string, 0),
	}
	rep, err := c.sendPacket([]byte(string(CMD_PROTOCOLINFO) + " " + strings.Join(versions, " ") + "\r\n"))
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
			for i := 0; i < len(line); i++ {
				if line[i] != ' ' {
					continue
				}
				if strings.HasPrefix(line[i+1:], "METHODS=") {
					ret.AuthMethods = append(ret.AuthMethods, strings.Split(line[i+9:i+9+strings.Index(line[i+9:], " ")], ",")...)
					i += strings.Index(line[i+1:], " ")
				} else if strings.HasPrefix(line[i+1:], "COOKIEFILE=") {
					str, j := readQString(line[i+12:])
					ret.CookieFiles = append(ret.CookieFiles, str)
					i += 11 + j
				}
			}
		case "VERSION":
			if strings.HasPrefix(segs[1], "Tor=") {
				ret.TorVersion, _ = readQString(line[len(segs[0])+5:])
			}
		}
	}
	c.lastProtocolInfo = &ret
	return &ret, nil
}

func (c *LowController) AuthChallenge(chllngType string, clientNonce []byte) (serverHash []byte, serverNonce []byte, err error) {
	rep, err := c.sendPacket([]byte(string(CMD_AUTHCHALLENGE) + " " + chllngType + " " + hex.EncodeToString(clientNonce)))
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
	dict := parseQStringDict(string(rep[0].Line)[len(segs[0])+1:])
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

func (c *LowController) HSFetch(addressOrDescriptor string, servers []string) error {
	cmd := string(CMD_HSFETCH) + " " + addressOrDescriptor
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
