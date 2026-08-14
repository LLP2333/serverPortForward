package app

import (
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
		// Windows renders a wildcard v4tov4 listener as "*" when the rule was
		// created with listenaddress=* (and may omit listenaddress from dump).
		// Normalize it to the canonical value used by the rest of the app so the
		// rule remains visible, editable, and deletable.
		listenAddress, err0 := normalizeIPv4(fields[0])
		connectAddress, err3 := normalizeIPv4(fields[2])
		listenPort, err1 := strconv.Atoi(fields[1])
		connectPort, err2 := strconv.Atoi(fields[3])
		if err0 != nil || err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		if validatePort(listenPort) != nil || validatePort(connectPort) != nil {
			continue
		}
		rule := SystemRule{
			ListenAddress: listenAddress, ListenPort: listenPort,
			ConnectAddress: connectAddress, ConnectPort: connectPort,
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
