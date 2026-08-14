package main

import (
	"net"
	"sort"
	"strconv"
	"strings"
)

func parsePortProxyShow(output string) []SystemRule {
	var rules []SystemRule
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.ReplaceAll(output, "\r", ""), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 4 {
			continue
		}
		listenIP := net.ParseIP(fields[0])
		connectIP := net.ParseIP(fields[2])
		listenPort, err1 := strconv.Atoi(fields[1])
		connectPort, err2 := strconv.Atoi(fields[3])
		if listenIP == nil || listenIP.To4() == nil || connectIP == nil || connectIP.To4() == nil || err1 != nil || err2 != nil {
			continue
		}
		if validatePort(listenPort) != nil || validatePort(connectPort) != nil {
			continue
		}
		rule := SystemRule{
			ListenAddress: listenIP.To4().String(), ListenPort: listenPort,
			ConnectAddress: connectIP.To4().String(), ConnectPort: connectPort,
		}
		if !seen[rule.key()] {
			rules = append(rules, rule)
			seen[rule.key()] = true
		}
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].ListenAddress == rules[j].ListenAddress {
			return rules[i].ListenPort < rules[j].ListenPort
		}
		return rules[i].ListenAddress < rules[j].ListenAddress
	})
	return rules
}

func parseListeningPorts(output string) (map[int]bool, []string) {
	ports := map[int]bool{}
	var matched []string
	for _, raw := range strings.Split(strings.ReplaceAll(output, "\r", ""), "\n") {
		line := strings.TrimSpace(raw)
		fields := strings.Fields(line)
		if len(fields) < 4 || !strings.EqualFold(fields[0], "TCP") {
			continue
		}
		isListening := false
		for _, field := range fields[3:] {
			if strings.EqualFold(field, "LISTENING") {
				isListening = true
				break
			}
		}
		if !isListening {
			continue
		}
		local := fields[1]
		idx := strings.LastIndex(local, ":")
		if idx < 0 {
			continue
		}
		port, err := strconv.Atoi(local[idx+1:])
		if err != nil || validatePort(port) != nil {
			continue
		}
		ports[port] = true
		matched = append(matched, line)
	}
	return ports, matched
}
