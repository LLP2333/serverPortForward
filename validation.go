package main

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"
)

func normalizeIPv4(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "*" {
		value = "0.0.0.0"
	}
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil || strings.Contains(value, ":") {
		return "", fmt.Errorf("%q 不是有效的 IPv4 地址", value)
	}
	return ip.To4().String(), nil
}

func validatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("端口必须在 1 到 65535 之间")
	}
	return nil
}

func validateRuleInput(in RuleInput) (RuleInput, error) {
	listen, err := normalizeIPv4(in.ListenAddress)
	if err != nil {
		return RuleInput{}, appError("INVALID_LISTEN_ADDRESS", "监听地址无效", err.Error(), http.StatusBadRequest)
	}
	connect, err := normalizeIPv4(in.ConnectAddress)
	if err != nil {
		return RuleInput{}, appError("INVALID_CONNECT_ADDRESS", "目标地址无效", err.Error(), http.StatusBadRequest)
	}
	if err := validatePort(in.ListenPort); err != nil {
		return RuleInput{}, appError("INVALID_LISTEN_PORT", "监听端口无效", err.Error(), http.StatusBadRequest)
	}
	if err := validatePort(in.ConnectPort); err != nil {
		return RuleInput{}, appError("INVALID_CONNECT_PORT", "目标端口无效", err.Error(), http.StatusBadRequest)
	}
	description := strings.TrimSpace(in.Description)
	if utf8.RuneCountInString(description) > 80 {
		return RuleInput{}, appError("INVALID_DESCRIPTION", "备注过长", "备注最多 80 个字符", http.StatusBadRequest)
	}
	return RuleInput{
		Description: description, ListenAddress: listen, ListenPort: in.ListenPort,
		ConnectAddress: connect, ConnectPort: in.ConnectPort,
	}, nil
}

func ruleKey(address string, port int) string {
	return address + ":" + strconv.Itoa(port)
}

func sanitizeDetail(value string) string {
	value = strings.ToValidUTF8(value, "?")
	value = strings.ReplaceAll(value, "\x00", "")
	value = strings.TrimSpace(value)
	const max = 2000
	if len(value) > max {
		value = value[:max] + "…"
	}
	return value
}
