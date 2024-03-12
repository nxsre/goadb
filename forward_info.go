package adb

import (
	"bufio"
	"bytes"
	"strings"
)

type ForwardInfo struct {
	Serial string `json:"serial"`
	Local  string `json:"local"`
	Remote string `json:"remote"`
}

func parseForwardInfo(list []byte) (forwardInfos []ForwardInfo) {
	scanner := bufio.NewScanner(bytes.NewReader(list))
	for scanner.Scan() {
		split := strings.Split(scanner.Text(), " ")
		if len(split) < 3 {
			continue
		}
		forwardInfos = append(forwardInfos, ForwardInfo{Serial: split[0], Local: split[1], Remote: split[2]})
	}
	return forwardInfos
}
