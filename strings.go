package torctrlgo

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

var patternQEscape = regexp.MustCompile(`\\([^ntr\d])`)
var patternCEscape = regexp.MustCompile(`\\(?:[ntr]|[1-7][0-7]{,2}|0)`)
var patternString = regexp.MustCompile(`^"((?:[^"\\]|\\.)*)"`)

var patternDict = regexp.MustCompile(`^([A-Za-z0-9_-]*)=`)

var patternConfigValue = regexp.MustCompile(`([^=]+)=(?:\r\n)?([\s\S]+)`)

func parseStringDict(s string) map[string]string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	ret := map[string]string{}
	var j int
	for i := 0; i < len(s); i++ {
		match := patternDict.FindStringSubmatch(s[i:])
		if match == nil {
			continue
		}
		i += len(match[0])
		key := match[1]
		if s[i] == '"' {
			ret[key], j = readQCString(s[i:])
			i += j
		} else {
			j = strings.Index(s[i:], " ")
			ret[key] = s[i : i+j]
			i += j
		}
	}
	return ret
}

func readQCString(st string) (string, int) {
	rawStr := patternString.FindStringSubmatch(st)[1]
	if matches := patternCEscape.FindAllStringSubmatch(rawStr, -1); matches != nil {
		// CString
		return patternCEscape.ReplaceAllStringFunc(rawStr, func(s string) string {
			switch s[1] {
			case 'n':
				return "\n"
			case 't':
				return "\t"
			case 'r':
				return "\r"
			default:
				for j := len(s); j > 1; j-- {
					i, err := strconv.ParseUint(s[1:j], 8, 8)
					if err != nil {
						if errors.Is(err, strconv.ErrRange) {
							continue
						}
						panic(err)
					}
					return string(byte(i))
				}
				return ""
			}
		}), len(rawStr) + 2

	}
	// QString
	return patternQEscape.ReplaceAllString(rawStr, "$1"), len(rawStr) + 2
}

func writeQString(s string) string {
	return "\"" + strings.ReplaceAll(s, "\"", "\\\"") + "\""
}
