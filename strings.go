package torctrlgo

import (
	"regexp"
	"strings"
)

var patternCEscape = regexp.MustCompile(`\\(?:3[0-7]{2}|[0-2]?[0-9]{2}|[ntr])`)
var patternCString = regexp.MustCompile(`"([^"]*)"`)
var patternQEscape = regexp.MustCompile(`\\(.)`)
var patternQString = regexp.MustCompile(`^"((?:[^"\\]|\\.)*)"`)

var patternQDict = regexp.MustCompile(`^([A-Za-z0-9_-]*)=`)

var patternConfigValue = regexp.MustCompile(`([^=]+)=(?:\r\n)?([\s\S]+)`)

func parseQStringDict(s string) map[string]string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	ret := map[string]string{}
	var j int
	for i := 0; i < len(s); i++ {
		match := patternQDict.FindStringSubmatch(s[i:])
		if match == nil {
			continue
		}
		i += len(match[0])
		key := match[1]
		if s[i] == '"' {
			ret[key], j = readQString(s[i:])
			i += j
		} else {
			j = strings.Index(s[i:], " ")
			ret[key] = s[i : i+j]
			i += j
		}
	}
	return ret
}

func readQString(s string) (string, int) {
	rawStr := patternQString.FindStringSubmatch(s)[1]
	return patternQEscape.ReplaceAllString(rawStr, "$1"), len(rawStr) + 2
}

func writeQString(s string) string {
	return "\"" + strings.ReplaceAll(s, "\"", "\\\"") + "\""
}
