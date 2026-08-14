package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type memoryConfigRepository struct {
	mu      sync.Mutex
	cfg     Config
	saveErr error
}

func newMemoryConfigRepository() *memoryConfigRepository {
	return &memoryConfigRepository{cfg: newConfig()}
}

func (r *memoryConfigRepository) Load() (Config, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	copy := r.cfg
	copy.ManagedRules = append([]ManagedRule(nil), r.cfg.ManagedRules...)
	return copy, nil
}

func (r *memoryConfigRepository) Save(cfg Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.saveErr != nil {
		return r.saveErr
	}
	r.cfg = cfg
	r.cfg.ManagedRules = append([]ManagedRule(nil), cfg.ManagedRules...)
	return nil
}

type fakeWindowsRunner struct {
	mu              sync.Mutex
	rules           map[string]SystemRule
	firewalls       map[string]bool
	calls           []string
	failFirewallAdd bool
	failDeleteKey   string
}

func newFakeWindowsRunner(rules ...SystemRule) *fakeWindowsRunner {
	f := &fakeWindowsRunner{rules: map[string]SystemRule{}, firewalls: map[string]bool{}}
	for _, rule := range rules {
		f.rules[rule.key()] = rule
	}
	return f
}

func (f *fakeWindowsRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if name == "netstat.exe" {
		var lines []string
		for _, rule := range f.rules {
			lines = append(lines, fmt.Sprintf("TCP 0.0.0.0:%d 0.0.0.0:0 LISTENING 1000", rule.ListenPort))
		}
		return strings.Join(lines, "\n"), nil
	}
	if name == "sc.exe" {
		if len(args) > 0 && args[0] == "query" {
			return "STATE : 4 RUNNING", nil
		}
		return "START_TYPE : 2 AUTO_START", nil
	}
	if name != "netsh.exe" {
		return "", fmt.Errorf("unexpected command: %s", call)
	}
	if len(args) >= 3 && args[0] == "interface" && args[1] == "portproxy" {
		switch args[2] {
		case "show":
			var lines []string
			for _, rule := range f.rules {
				lines = append(lines, fmt.Sprintf("%s %d %s %d", rule.ListenAddress, rule.ListenPort, rule.ConnectAddress, rule.ConnectPort))
			}
			return strings.Join(lines, "\n"), nil
		case "dump":
			return "pushd interface portproxy", nil
		case "add", "set":
			rule := ruleFromArgs(args)
			f.rules[rule.key()] = rule
			return "", nil
		case "delete":
			address := valueFor(args, "listenaddress")
			port, _ := strconv.Atoi(valueFor(args, "listenport"))
			key := ruleKey(address, port)
			if key == f.failDeleteKey {
				return "delete failed", errors.New("delete failed")
			}
			delete(f.rules, key)
			return "", nil
		}
	}
	if len(args) >= 4 && args[0] == "advfirewall" && args[1] == "firewall" {
		name := valueFor(args, "name")
		switch args[2] {
		case "add":
			if f.failFirewallAdd {
				return "firewall failed", errors.New("firewall failed")
			}
			f.firewalls[name] = true
			return "Ok.", nil
		case "delete":
			delete(f.firewalls, name)
			return "Deleted 1 rule(s).", nil
		case "show":
			if f.firewalls[name] {
				return "Rule Name: " + name, nil
			}
			return "No rules match", nil
		}
	}
	return "", fmt.Errorf("unexpected netsh command: %s", call)
}

func ruleFromArgs(args []string) SystemRule {
	listenPort, _ := strconv.Atoi(valueFor(args, "listenport"))
	connectPort, _ := strconv.Atoi(valueFor(args, "connectport"))
	return SystemRule{
		ListenAddress: valueFor(args, "listenaddress"), ListenPort: listenPort,
		ConnectAddress: valueFor(args, "connectaddress"), ConnectPort: connectPort,
	}
}

func valueFor(args []string, key string) string {
	prefix := key + "="
	for _, arg := range args {
		if strings.HasPrefix(arg, prefix) {
			return strings.TrimPrefix(arg, prefix)
		}
	}
	return ""
}

func TestCreateRuleRollsBackWhenFirewallFails(t *testing.T) {
	runner := newFakeWindowsRunner()
	runner.failFirewallAdd = true
	repo := newMemoryConfigRepository()
	manager := NewManager(runner, repo)
	err := manager.CreateRule(context.Background(), RuleInput{
		Description: "SSH", ListenAddress: "0.0.0.0", ListenPort: 71,
		ConnectAddress: "128.120.123.115", ConnectPort: 22,
	})
	if err == nil {
		t.Fatal("expected firewall failure")
	}
	if len(runner.rules) != 0 {
		t.Fatalf("portproxy was not rolled back: %#v", runner.rules)
	}
	if len(repo.cfg.ManagedRules) != 0 {
		t.Fatalf("config should remain unchanged: %#v", repo.cfg)
	}
}

func TestCreateRuleRollsBackWhenConfigSaveFails(t *testing.T) {
	runner := newFakeWindowsRunner()
	repo := newMemoryConfigRepository()
	repo.saveErr = errors.New("disk full")
	manager := NewManager(runner, repo)
	err := manager.CreateRule(context.Background(), RuleInput{
		ListenAddress: "0.0.0.0", ListenPort: 71,
		ConnectAddress: "10.0.0.8", ConnectPort: 22,
	})
	if err == nil {
		t.Fatal("expected config save failure")
	}
	if len(runner.rules) != 0 || len(runner.firewalls) != 0 {
		t.Fatalf("system state was not rolled back: rules=%#v firewalls=%#v", runner.rules, runner.firewalls)
	}
}

func TestDeleteExternalRuleDoesNotTouchFirewall(t *testing.T) {
	external := SystemRule{"0.0.0.0", 8080, "10.0.0.8", 80}
	runner := newFakeWindowsRunner(external)
	runner.firewalls["UnrelatedFirewall"] = true
	manager := NewManager(runner, newMemoryConfigRepository())
	if err := manager.DeleteRule(context.Background(), RuleKeyRequest{"0.0.0.0", 8080}); err != nil {
		t.Fatal(err)
	}
	if len(runner.rules) != 0 {
		t.Fatalf("external portproxy was not deleted: %#v", runner.rules)
	}
	if !runner.firewalls["UnrelatedFirewall"] {
		t.Fatal("external firewall rule was modified")
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "advfirewall firewall delete") {
			t.Fatalf("external deletion must not call firewall delete: %s", call)
		}
	}
}

func TestUpdateExternalRuleAdoptsIt(t *testing.T) {
	external := SystemRule{"0.0.0.0", 71, "10.0.0.8", 22}
	runner := newFakeWindowsRunner(external)
	repo := newMemoryConfigRepository()
	manager := NewManager(runner, repo)
	err := manager.UpdateRule(context.Background(), UpdateRuleRequest{
		OriginalListenAddress: "0.0.0.0", OriginalListenPort: 71, Adopt: true,
		Rule: RuleInput{Description: "公司 SSH", ListenAddress: "0.0.0.0", ListenPort: 71, ConnectAddress: "10.0.0.9", ConnectPort: 22},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(repo.cfg.ManagedRules) != 1 || repo.cfg.ManagedRules[0].Description != "公司 SSH" {
		t.Fatalf("external rule was not adopted: %#v", repo.cfg)
	}
	if len(runner.firewalls) != 1 {
		t.Fatalf("managed firewall was not created: %#v", runner.firewalls)
	}
	if got := runner.rules[ruleKey("0.0.0.0", 71)].ConnectAddress; got != "10.0.0.9" {
		t.Fatalf("target was not updated: %s", got)
	}
}

func TestMoveListenerRollsBackWhenOldDeleteFails(t *testing.T) {
	old := SystemRule{"0.0.0.0", 71, "10.0.0.8", 22}
	runner := newFakeWindowsRunner(old)
	runner.failDeleteKey = old.key()
	repo := newMemoryConfigRepository()
	manager := NewManager(runner, repo)
	err := manager.UpdateRule(context.Background(), UpdateRuleRequest{
		OriginalListenAddress: old.ListenAddress, OriginalListenPort: old.ListenPort, Adopt: true,
		Rule: RuleInput{ListenAddress: "0.0.0.0", ListenPort: 72, ConnectAddress: "10.0.0.8", ConnectPort: 22},
	})
	if err == nil {
		t.Fatal("expected old delete failure")
	}
	if _, ok := runner.rules[old.key()]; !ok {
		t.Fatal("old rule must remain")
	}
	if _, ok := runner.rules[ruleKey("0.0.0.0", 72)]; ok {
		t.Fatal("new rule must be rolled back")
	}
	if len(runner.firewalls) != 0 || len(repo.cfg.ManagedRules) != 0 {
		t.Fatalf("adoption state leaked: firewalls=%#v config=%#v", runner.firewalls, repo.cfg)
	}
}

func TestClearManagedRulesPreservesExternal(t *testing.T) {
	managedSystem := SystemRule{"0.0.0.0", 71, "10.0.0.8", 22}
	external := SystemRule{"0.0.0.0", 8080, "10.0.0.9", 80}
	runner := newFakeWindowsRunner(managedSystem, external)
	repo := newMemoryConfigRepository()
	repo.cfg.ManagedRules = []ManagedRule{{
		ID: "managed", ListenAddress: "0.0.0.0", ListenPort: 71,
		ConnectAddress: "10.0.0.8", ConnectPort: 22, FirewallName: "ServerPortForward-managed",
	}}
	runner.firewalls["ServerPortForward-managed"] = true
	manager := NewManager(runner, repo)
	if err := manager.ClearManagedRules(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := runner.rules[external.key()]; !ok {
		t.Fatal("external rule was deleted")
	}
	if _, ok := runner.rules[managedSystem.key()]; ok {
		t.Fatal("managed rule was not deleted")
	}
	if len(repo.cfg.ManagedRules) != 0 || len(runner.firewalls) != 0 {
		t.Fatalf("managed ownership was not cleared: config=%#v firewall=%#v", repo.cfg, runner.firewalls)
	}
}

func TestMergeRuleViewsShowsDriftAndExternal(t *testing.T) {
	cfg := newConfig()
	cfg.ManagedRules = []ManagedRule{{
		ID: "managed", ListenAddress: "0.0.0.0", ListenPort: 71,
		ConnectAddress: "10.0.0.8", ConnectPort: 22, FirewallName: "ServerPortForward-managed",
	}}
	system := []SystemRule{
		{"0.0.0.0", 71, "10.0.0.99", 22},
		{"0.0.0.0", 8080, "10.0.0.9", 80},
	}
	views := mergeRuleViews(cfg, system, map[int]bool{71: true}, map[string]bool{"ServerPortForward-managed": true})
	if len(views) != 2 || !views[0].Managed || !views[0].Drifted || views[1].Managed {
		t.Fatalf("unexpected merged views: %#v", views)
	}
}
