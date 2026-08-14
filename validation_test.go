package main

import "testing"

func TestValidateRuleInput(t *testing.T) {
	got, err := validateRuleInput(RuleInput{
		Description: "  公司 SSH  ", ListenAddress: "*", ListenPort: 71,
		ConnectAddress: "128.120.123.115", ConnectPort: 22,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ListenAddress != "0.0.0.0" || got.Description != "公司 SSH" {
		t.Fatalf("unexpected normalized input: %#v", got)
	}
}

func TestValidateRuleInputRejectsInjectionAndHostnames(t *testing.T) {
	values := []string{
		`128.120.123.115 & netsh interface portproxy reset`,
		`128.120.123.115" protocol=udp`,
		"company.example.com",
		"::1",
		"",
	}
	for _, value := range values {
		_, err := validateRuleInput(RuleInput{
			ListenAddress: "0.0.0.0", ListenPort: 71,
			ConnectAddress: value, ConnectPort: 22,
		})
		if err == nil {
			t.Errorf("expected %q to be rejected", value)
		}
	}
}

func TestValidatePorts(t *testing.T) {
	for _, port := range []int{-1, 0, 65536} {
		if validatePort(port) == nil {
			t.Errorf("expected port %d to be rejected", port)
		}
	}
	for _, port := range []int{1, 22, 65535} {
		if err := validatePort(port); err != nil {
			t.Errorf("expected port %d to be accepted: %v", port, err)
		}
	}
}
