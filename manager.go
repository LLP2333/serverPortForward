package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Manager struct {
	runner CommandRunner
	config ConfigRepository
	mu     sync.Mutex

	lastError string
	dial      func(context.Context, string, string) (net.Conn, error)
}

func NewManager(runner CommandRunner, config ConfigRepository) *Manager {
	dialer := &net.Dialer{Timeout: 4 * time.Second}
	return &Manager{
		runner: runner,
		config: config,
		dial:   dialer.DialContext,
	}
}

func (m *Manager) State(ctx context.Context) (AppState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stateUnlocked(ctx)
}

func (m *Manager) stateUnlocked(ctx context.Context) (AppState, error) {
	cfg, err := m.config.Load()
	if err != nil {
		return AppState{}, m.remember(appError("CONFIG_READ_FAILED", "无法读取配置", err.Error(), http.StatusInternalServerError))
	}
	systemRules, err := m.listSystemRules(ctx)
	if err != nil {
		return AppState{}, m.remember(appError("PORTPROXY_LIST_FAILED", "无法读取 Windows 转发规则", err.Error(), http.StatusInternalServerError))
	}

	var warnings []string
	netstatOutput, netstatErr := m.runner.Run(ctx, "netstat.exe", "-ano", "-p", "tcp")
	listening := map[int]bool{}
	var listenerLines []string
	if netstatErr != nil {
		warnings = append(warnings, "无法读取 TCP 监听状态："+sanitizeDetail(netstatErr.Error()))
	} else {
		listening, listenerLines = parseListeningPorts(netstatOutput)
	}

	firewallState := make(map[string]bool, len(cfg.ManagedRules))
	for _, managed := range cfg.ManagedRules {
		ok, checkErr := m.firewallExists(ctx, managed.FirewallName)
		if checkErr != nil {
			warnings = append(warnings, fmt.Sprintf("无法检查 %s:%d 的防火墙规则", managed.ListenAddress, managed.ListenPort))
			continue
		}
		firewallState[managed.FirewallName] = ok
	}

	dump, dumpErr := m.runner.Run(ctx, "netsh.exe", "interface", "portproxy", "dump")
	if dumpErr != nil {
		dump = "读取 portproxy dump 失败：" + sanitizeDetail(dumpErr.Error())
	}
	ipHelper := m.ipHelperStatus(ctx)
	if !ipHelper.Running {
		if ipHelper.Disabled {
			warnings = append(warnings, "Windows IP Helper 服务已被禁用，portproxy 不会工作；请联系管理员或检查企业策略。")
		} else {
			warnings = append(warnings, "Windows IP Helper 服务未运行，请先在界面中确认启动。")
		}
	}
	warnings = append(warnings, "当前入站防火墙策略允许任意来源访问已管理端口，请确认符合公司安全规定。")

	state := AppState{
		DefaultTargetIPv4: cfg.DefaultTargetIPv4,
		LocalIPv4:         localIPv4Addresses(),
		Rules:             mergeRuleViews(cfg, systemRules, listening, firewallState),
		IPHelper:          ipHelper,
		Diagnostics: Diagnostics{
			PortProxyDump: dump,
			ListenerLines: listenerLines,
			LastError:     m.lastError,
		},
		Warnings:  warnings,
		UpdatedAt: time.Now(),
	}
	return state, nil
}

func (m *Manager) UpdateSettings(_ context.Context, req SettingsRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	value := strings.TrimSpace(req.DefaultTargetIPv4)
	if value != "" {
		normalized, err := normalizeIPv4(value)
		if err != nil {
			return m.remember(appError("INVALID_DEFAULT_TARGET", "默认目标地址无效", err.Error(), http.StatusBadRequest))
		}
		value = normalized
	}
	cfg, err := m.config.Load()
	if err != nil {
		return m.remember(appError("CONFIG_READ_FAILED", "无法读取配置", err.Error(), http.StatusInternalServerError))
	}
	cfg.DefaultTargetIPv4 = value
	if err := m.config.Save(cfg); err != nil {
		return m.remember(appError("CONFIG_WRITE_FAILED", "无法保存默认目标地址", err.Error(), http.StatusInternalServerError))
	}
	return nil
}

func (m *Manager) CreateRule(ctx context.Context, input RuleInput) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	in, err := validateRuleInput(input)
	if err != nil {
		return m.remember(err)
	}
	systemRules, err := m.listSystemRules(ctx)
	if err != nil {
		return m.remember(appError("PORTPROXY_LIST_FAILED", "无法检查端口冲突", err.Error(), http.StatusInternalServerError))
	}
	if findSystemRule(systemRules, in.ListenAddress, in.ListenPort) != nil {
		return m.remember(appError("RULE_CONFLICT", "监听地址和端口已存在转发规则", ruleKey(in.ListenAddress, in.ListenPort), http.StatusConflict))
	}
	cfg, err := m.config.Load()
	if err != nil {
		return m.remember(appError("CONFIG_READ_FAILED", "无法读取配置", err.Error(), http.StatusInternalServerError))
	}
	record, err := managedRuleFromInput(in)
	if err != nil {
		return m.remember(appError("ID_GENERATION_FAILED", "无法创建规则标识", err.Error(), http.StatusInternalServerError))
	}
	if err := m.addProxy(ctx, SystemRule{in.ListenAddress, in.ListenPort, in.ConnectAddress, in.ConnectPort}); err != nil {
		return m.remember(appError("PORTPROXY_ADD_FAILED", "创建 Windows 转发规则失败", err.Error(), http.StatusInternalServerError))
	}
	if err := m.addFirewall(ctx, record); err != nil {
		rollbackErr := m.deleteProxy(ctx, in.ListenAddress, in.ListenPort)
		return m.remember(appError("FIREWALL_ADD_FAILED", "创建防火墙规则失败，已尝试撤销端口转发", joinErrors(err, rollbackErr), http.StatusInternalServerError))
	}
	cfg.ManagedRules = append(cfg.ManagedRules, record)
	if err := m.config.Save(cfg); err != nil {
		fwErr := m.deleteFirewall(ctx, record.FirewallName)
		proxyErr := m.deleteProxy(ctx, record.ListenAddress, record.ListenPort)
		return m.remember(appError("CONFIG_WRITE_FAILED", "保存规则归属失败，已尝试回滚系统设置", joinErrors(err, fwErr, proxyErr), http.StatusInternalServerError))
	}
	return nil
}

func (m *Manager) UpdateRule(ctx context.Context, req UpdateRuleRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	originalAddress, err := normalizeIPv4(req.OriginalListenAddress)
	if err != nil || validatePort(req.OriginalListenPort) != nil {
		return m.remember(appError("INVALID_ORIGINAL_RULE", "原始监听地址或端口无效", joinErrors(err, validatePort(req.OriginalListenPort)), http.StatusBadRequest))
	}
	in, err := validateRuleInput(req.Rule)
	if err != nil {
		return m.remember(err)
	}
	systemRules, err := m.listSystemRules(ctx)
	if err != nil {
		return m.remember(appError("PORTPROXY_LIST_FAILED", "无法读取原始转发规则", err.Error(), http.StatusInternalServerError))
	}
	oldSystem := findSystemRule(systemRules, originalAddress, req.OriginalListenPort)
	if oldSystem == nil {
		return m.remember(appError("RULE_NOT_FOUND", "原始转发规则不存在，请刷新后重试", ruleKey(originalAddress, req.OriginalListenPort), http.StatusNotFound))
	}
	cfg, err := m.config.Load()
	if err != nil {
		return m.remember(appError("CONFIG_READ_FAILED", "无法读取配置", err.Error(), http.StatusInternalServerError))
	}
	managedIndex := findManagedRuleIndex(cfg.ManagedRules, originalAddress, req.OriginalListenPort)
	if managedIndex < 0 && !req.Adopt {
		return m.remember(appError("ADOPTION_REQUIRED", "外部规则必须确认接管后才能编辑", ruleKey(originalAddress, req.OriginalListenPort), http.StatusConflict))
	}

	if originalAddress == in.ListenAddress && req.OriginalListenPort == in.ListenPort {
		return m.updateSameListener(ctx, cfg, managedIndex, *oldSystem, in)
	}
	if findSystemRule(systemRules, in.ListenAddress, in.ListenPort) != nil {
		return m.remember(appError("RULE_CONFLICT", "新的监听地址和端口已存在转发规则", ruleKey(in.ListenAddress, in.ListenPort), http.StatusConflict))
	}
	return m.moveListener(ctx, cfg, managedIndex, *oldSystem, in)
}

func (m *Manager) updateSameListener(ctx context.Context, cfg Config, managedIndex int, old SystemRule, in RuleInput) error {
	newSystem := SystemRule{in.ListenAddress, in.ListenPort, in.ConnectAddress, in.ConnectPort}
	if err := m.setProxy(ctx, newSystem); err != nil {
		return m.remember(appError("PORTPROXY_UPDATE_FAILED", "更新 Windows 转发规则失败", err.Error(), http.StatusInternalServerError))
	}

	var record ManagedRule
	addedFirewall := false
	if managedIndex >= 0 {
		record = cfg.ManagedRules[managedIndex]
		record.Description = in.Description
		record.ConnectAddress = in.ConnectAddress
		record.ConnectPort = in.ConnectPort
		firewallOK, checkErr := m.firewallExists(ctx, record.FirewallName)
		if checkErr != nil {
			_ = m.setProxy(ctx, old)
			return m.remember(appError("FIREWALL_CHECK_FAILED", "检查防火墙规则失败，已尝试恢复原转发", checkErr.Error(), http.StatusInternalServerError))
		}
		if !firewallOK {
			if err := m.addFirewall(ctx, record); err != nil {
				_ = m.setProxy(ctx, old)
				return m.remember(appError("FIREWALL_ADD_FAILED", "修复防火墙规则失败，已尝试恢复原转发", err.Error(), http.StatusInternalServerError))
			}
			addedFirewall = true
		}
		cfg.ManagedRules[managedIndex] = record
	} else {
		var err error
		record, err = managedRuleFromInput(in)
		if err != nil {
			_ = m.setProxy(ctx, old)
			return m.remember(appError("ID_GENERATION_FAILED", "无法接管外部规则", err.Error(), http.StatusInternalServerError))
		}
		if err := m.addFirewall(ctx, record); err != nil {
			_ = m.setProxy(ctx, old)
			return m.remember(appError("FIREWALL_ADD_FAILED", "接管规则时创建防火墙失败，已尝试恢复原转发", err.Error(), http.StatusInternalServerError))
		}
		addedFirewall = true
		cfg.ManagedRules = append(cfg.ManagedRules, record)
	}
	if err := m.config.Save(cfg); err != nil {
		_ = m.setProxy(ctx, old)
		if addedFirewall {
			_ = m.deleteFirewall(ctx, record.FirewallName)
		}
		return m.remember(appError("CONFIG_WRITE_FAILED", "保存更新失败，已尝试恢复原规则", err.Error(), http.StatusInternalServerError))
	}
	return nil
}

func (m *Manager) moveListener(ctx context.Context, cfg Config, managedIndex int, old SystemRule, in RuleInput) error {
	newRecord, err := managedRuleFromInput(in)
	if err != nil {
		return m.remember(appError("ID_GENERATION_FAILED", "无法创建新规则标识", err.Error(), http.StatusInternalServerError))
	}
	newSystem := SystemRule{in.ListenAddress, in.ListenPort, in.ConnectAddress, in.ConnectPort}
	if err := m.addProxy(ctx, newSystem); err != nil {
		return m.remember(appError("PORTPROXY_ADD_FAILED", "创建新监听规则失败", err.Error(), http.StatusInternalServerError))
	}
	if err := m.addFirewall(ctx, newRecord); err != nil {
		_ = m.deleteProxy(ctx, newRecord.ListenAddress, newRecord.ListenPort)
		return m.remember(appError("FIREWALL_ADD_FAILED", "创建新监听的防火墙规则失败，已尝试回滚", err.Error(), http.StatusInternalServerError))
	}
	if err := m.deleteProxy(ctx, old.ListenAddress, old.ListenPort); err != nil {
		_ = m.deleteFirewall(ctx, newRecord.FirewallName)
		_ = m.deleteProxy(ctx, newRecord.ListenAddress, newRecord.ListenPort)
		return m.remember(appError("OLD_RULE_DELETE_FAILED", "新规则已创建，但无法删除旧规则；已尝试回滚新规则", err.Error(), http.StatusInternalServerError))
	}

	var oldManaged *ManagedRule
	if managedIndex >= 0 {
		copy := cfg.ManagedRules[managedIndex]
		oldManaged = &copy
		if err := m.deleteFirewall(ctx, copy.FirewallName); err != nil {
			_ = m.addProxy(ctx, old)
			_ = m.deleteFirewall(ctx, newRecord.FirewallName)
			_ = m.deleteProxy(ctx, newRecord.ListenAddress, newRecord.ListenPort)
			return m.remember(appError("OLD_FIREWALL_DELETE_FAILED", "无法删除旧防火墙规则，已尝试恢复原状态", err.Error(), http.StatusInternalServerError))
		}
		cfg.ManagedRules[managedIndex] = newRecord
	} else {
		cfg.ManagedRules = append(cfg.ManagedRules, newRecord)
	}
	if err := m.config.Save(cfg); err != nil {
		restoreErr := m.addProxy(ctx, old)
		if oldManaged != nil {
			restoreErr = errors.Join(restoreErr, m.addFirewall(ctx, *oldManaged))
		}
		cleanupErr := errors.Join(m.deleteFirewall(ctx, newRecord.FirewallName), m.deleteProxy(ctx, newRecord.ListenAddress, newRecord.ListenPort))
		return m.remember(appError("CONFIG_WRITE_FAILED", "保存新监听失败，已尝试恢复原状态", joinErrors(err, restoreErr, cleanupErr), http.StatusInternalServerError))
	}
	return nil
}

func (m *Manager) DeleteRule(ctx context.Context, req RuleKeyRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	address, err := normalizeIPv4(req.ListenAddress)
	if err != nil || validatePort(req.ListenPort) != nil {
		return m.remember(appError("INVALID_RULE_KEY", "监听地址或端口无效", joinErrors(err, validatePort(req.ListenPort)), http.StatusBadRequest))
	}
	return m.deleteRuleUnlocked(ctx, address, req.ListenPort)
}

func (m *Manager) deleteRuleUnlocked(ctx context.Context, address string, port int) error {
	cfg, err := m.config.Load()
	if err != nil {
		return m.remember(appError("CONFIG_READ_FAILED", "无法读取配置", err.Error(), http.StatusInternalServerError))
	}
	systemRules, err := m.listSystemRules(ctx)
	if err != nil {
		return m.remember(appError("PORTPROXY_LIST_FAILED", "无法读取转发规则", err.Error(), http.StatusInternalServerError))
	}
	system := findSystemRule(systemRules, address, port)
	managedIndex := findManagedRuleIndex(cfg.ManagedRules, address, port)
	if system == nil && managedIndex < 0 {
		return m.remember(appError("RULE_NOT_FOUND", "转发规则不存在", ruleKey(address, port), http.StatusNotFound))
	}
	if managedIndex < 0 {
		if err := m.deleteProxy(ctx, address, port); err != nil {
			return m.remember(appError("PORTPROXY_DELETE_FAILED", "删除外部转发规则失败", err.Error(), http.StatusInternalServerError))
		}
		return nil
	}

	record := cfg.ManagedRules[managedIndex]
	firewallExisted, checkErr := m.firewallExists(ctx, record.FirewallName)
	if checkErr != nil {
		return m.remember(appError("FIREWALL_CHECK_FAILED", "删除前无法确认防火墙状态", checkErr.Error(), http.StatusInternalServerError))
	}
	proxyDeleted := false
	if system != nil {
		if err := m.deleteProxy(ctx, address, port); err != nil {
			return m.remember(appError("PORTPROXY_DELETE_FAILED", "删除转发规则失败", err.Error(), http.StatusInternalServerError))
		}
		proxyDeleted = true
	}
	if firewallExisted {
		if err := m.deleteFirewall(ctx, record.FirewallName); err != nil {
			if proxyDeleted {
				_ = m.addProxy(ctx, *system)
			}
			return m.remember(appError("FIREWALL_DELETE_FAILED", "删除防火墙规则失败，已尝试恢复端口转发", err.Error(), http.StatusInternalServerError))
		}
	}
	cfg.ManagedRules = append(cfg.ManagedRules[:managedIndex], cfg.ManagedRules[managedIndex+1:]...)
	if err := m.config.Save(cfg); err != nil {
		var rollback []error
		if proxyDeleted {
			rollback = append(rollback, m.addProxy(ctx, *system))
		}
		if firewallExisted {
			rollback = append(rollback, m.addFirewall(ctx, record))
		}
		return m.remember(appError("CONFIG_WRITE_FAILED", "删除后保存配置失败，已尝试恢复系统规则", joinErrors(append([]error{err}, rollback...)...), http.StatusInternalServerError))
	}
	return nil
}

func (m *Manager) ClearManagedRules(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, err := m.config.Load()
	if err != nil {
		return m.remember(appError("CONFIG_READ_FAILED", "无法读取配置", err.Error(), http.StatusInternalServerError))
	}
	keys := make([]RuleKeyRequest, 0, len(cfg.ManagedRules))
	for _, rule := range cfg.ManagedRules {
		keys = append(keys, RuleKeyRequest{ListenAddress: rule.ListenAddress, ListenPort: rule.ListenPort})
	}
	var failures []string
	for _, key := range keys {
		if err := m.deleteRuleUnlocked(ctx, key.ListenAddress, key.ListenPort); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", ruleKey(key.ListenAddress, key.ListenPort), err))
		}
	}
	if len(failures) > 0 {
		return m.remember(appError("PARTIAL_CLEAR", "部分已管理规则未能清除", strings.Join(failures, "\n"), http.StatusInternalServerError))
	}
	return nil
}

func (m *Manager) StartIPHelper(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	status := m.ipHelperStatus(ctx)
	if status.Running {
		return nil
	}
	if status.Disabled {
		return m.remember(appError("IPHELPER_DISABLED", "IP Helper 服务已被禁用", "工具不会修改服务启动策略，请联系管理员或检查企业策略。", http.StatusConflict))
	}
	if _, err := m.runner.Run(ctx, "sc.exe", "start", "iphlpsvc"); err != nil {
		return m.remember(appError("IPHELPER_START_FAILED", "启动 IP Helper 服务失败", err.Error(), http.StatusInternalServerError))
	}
	return nil
}

func (m *Manager) TestRule(ctx context.Context, req RuleKeyRequest) (TestResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	address, err := normalizeIPv4(req.ListenAddress)
	if err != nil || validatePort(req.ListenPort) != nil {
		return TestResult{}, m.remember(appError("INVALID_RULE_KEY", "监听地址或端口无效", joinErrors(err, validatePort(req.ListenPort)), http.StatusBadRequest))
	}
	systemRules, err := m.listSystemRules(ctx)
	if err != nil {
		return TestResult{}, m.remember(appError("PORTPROXY_LIST_FAILED", "无法读取转发规则", err.Error(), http.StatusInternalServerError))
	}
	rule := findSystemRule(systemRules, address, req.ListenPort)
	if rule == nil {
		return TestResult{}, m.remember(appError("RULE_NOT_FOUND", "转发规则不存在", ruleKey(address, req.ListenPort), http.StatusNotFound))
	}
	result := TestResult{Reminder: "Windows 本机检测不能替代从 macOS 对 Windows 局域网地址发起的最终连接测试。"}
	targetAddress := net.JoinHostPort(rule.ConnectAddress, strconv.Itoa(rule.ConnectPort))
	if conn, dialErr := m.dial(ctx, "tcp4", targetAddress); dialErr != nil {
		result.TargetMessage = "Windows 无法连接 VPN 目标：" + sanitizeDetail(dialErr.Error())
	} else {
		result.TargetReachable = true
		result.TargetMessage = "Windows 可以建立到 VPN 目标的 TCP 连接"
		_ = conn.Close()
	}

	netstatOutput, netstatErr := m.runner.Run(ctx, "netstat.exe", "-ano", "-p", "tcp")
	if netstatErr != nil {
		result.ListenMessage = "无法读取监听状态：" + sanitizeDetail(netstatErr.Error())
	} else {
		listening, _ := parseListeningPorts(netstatOutput)
		result.Listening = listening[rule.ListenPort]
		if result.Listening {
			result.ListenMessage = "Windows 正在监听该本地端口"
		} else {
			result.ListenMessage = "未发现该端口处于 LISTENING 状态，请检查 IP Helper 服务"
		}
	}

	proxyHost := rule.ListenAddress
	if proxyHost == "0.0.0.0" {
		proxyHost = "127.0.0.1"
	}
	proxyAddress := net.JoinHostPort(proxyHost, strconv.Itoa(rule.ListenPort))
	if conn, dialErr := m.dial(ctx, "tcp4", proxyAddress); dialErr != nil {
		result.ProxyMessage = "通过本地映射端口连接失败：" + sanitizeDetail(dialErr.Error())
	} else {
		result.ProxyReachable = true
		result.ProxyMessage = "可以通过本地映射端口建立 TCP 连接"
		_ = conn.Close()
	}

	cfg, _ := m.config.Load()
	managedIndex := findManagedRuleIndex(cfg.ManagedRules, rule.ListenAddress, rule.ListenPort)
	if managedIndex >= 0 {
		ok, checkErr := m.firewallExists(ctx, cfg.ManagedRules[managedIndex].FirewallName)
		if checkErr != nil {
			result.FirewallMessage = "无法检查防火墙规则：" + sanitizeDetail(checkErr.Error())
		} else {
			result.FirewallOK = &ok
			if ok {
				result.FirewallMessage = "本工具创建的入站防火墙规则存在"
			} else {
				result.FirewallMessage = "本工具的入站防火墙规则缺失"
			}
		}
	} else {
		result.FirewallMessage = "外部规则未由本工具管理，未判断其原有防火墙策略"
	}
	return result, nil
}

func (m *Manager) listSystemRules(ctx context.Context) ([]SystemRule, error) {
	out, err := m.runner.Run(ctx, "netsh.exe", "interface", "portproxy", "show", "v4tov4")
	if err != nil {
		return nil, err
	}
	return parsePortProxyShow(out), nil
}

func (m *Manager) addProxy(ctx context.Context, rule SystemRule) error {
	_, err := m.runner.Run(ctx, "netsh.exe", "interface", "portproxy", "add", "v4tov4",
		"listenport="+strconv.Itoa(rule.ListenPort), "listenaddress="+rule.ListenAddress,
		"connectport="+strconv.Itoa(rule.ConnectPort), "connectaddress="+rule.ConnectAddress, "protocol=tcp")
	return err
}

func (m *Manager) setProxy(ctx context.Context, rule SystemRule) error {
	_, err := m.runner.Run(ctx, "netsh.exe", "interface", "portproxy", "set", "v4tov4",
		"listenport="+strconv.Itoa(rule.ListenPort), "listenaddress="+rule.ListenAddress,
		"connectport="+strconv.Itoa(rule.ConnectPort), "connectaddress="+rule.ConnectAddress, "protocol=tcp")
	return err
}

func (m *Manager) deleteProxy(ctx context.Context, address string, port int) error {
	_, err := m.runner.Run(ctx, "netsh.exe", "interface", "portproxy", "delete", "v4tov4",
		"listenport="+strconv.Itoa(port), "listenaddress="+address, "protocol=tcp")
	return err
}

func (m *Manager) addFirewall(ctx context.Context, rule ManagedRule) error {
	localIP := rule.ListenAddress
	if localIP == "0.0.0.0" {
		localIP = "any"
	}
	_, err := m.runner.Run(ctx, "netsh.exe", "advfirewall", "firewall", "add", "rule",
		"name="+rule.FirewallName, "dir=in", "action=allow", "enable=yes",
		"protocol=TCP", "localport="+strconv.Itoa(rule.ListenPort), "localip="+localIP,
		"remoteip=any", "profile=any")
	return err
}

func (m *Manager) deleteFirewall(ctx context.Context, name string) error {
	_, err := m.runner.Run(ctx, "netsh.exe", "advfirewall", "firewall", "delete", "rule", "name="+name)
	return err
}

func (m *Manager) firewallExists(ctx context.Context, name string) (bool, error) {
	out, err := m.runner.Run(ctx, "netsh.exe", "advfirewall", "firewall", "show", "rule", "name="+name)
	exists := strings.Contains(strings.ToLower(out), strings.ToLower(name))
	if exists || err == nil {
		return exists, nil
	}
	// netsh returns exit code 1 when no firewall rule matches. That is an
	// expected "not found" result, not a command failure. Avoid matching the
	// localized message text so this works on non-English Windows installs.
	var exitErr interface{ ExitCode() int }
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return false, nil
	}
	return false, err
}

var (
	runningPattern  = regexp.MustCompile(`(?im):\s*4\s+RUNNING\b`)
	disabledPattern = regexp.MustCompile(`(?im):\s*4\s+DISABLED\b`)
	autoPattern     = regexp.MustCompile(`(?im):\s*2\s+AUTO_START\b`)
	manualPattern   = regexp.MustCompile(`(?im):\s*3\s+DEMAND_START\b`)
)

func (m *Manager) ipHelperStatus(ctx context.Context) IPHelperStatus {
	query, queryErr := m.runner.Run(ctx, "sc.exe", "query", "iphlpsvc")
	config, configErr := m.runner.Run(ctx, "sc.exe", "qc", "iphlpsvc")
	status := IPHelperStatus{}
	if queryErr == nil {
		status.Running = runningPattern.MatchString(query) || strings.Contains(strings.ToUpper(query), "RUNNING")
	}
	switch {
	case disabledPattern.MatchString(config) || strings.Contains(strings.ToUpper(config), "DISABLED"):
		status.StartMode = "disabled"
		status.Disabled = true
	case autoPattern.MatchString(config) || strings.Contains(strings.ToUpper(config), "AUTO_START"):
		status.StartMode = "automatic"
	case manualPattern.MatchString(config) || strings.Contains(strings.ToUpper(config), "DEMAND_START"):
		status.StartMode = "manual"
	default:
		status.StartMode = "unknown"
	}
	if queryErr != nil || configErr != nil {
		status.Detail = sanitizeDetail(joinErrors(queryErr, configErr))
	}
	return status
}

func mergeRuleViews(cfg Config, system []SystemRule, listening map[int]bool, firewall map[string]bool) []RuleView {
	views := make([]RuleView, 0, len(system)+len(cfg.ManagedRules))
	usedSystem := map[string]bool{}
	for _, managed := range cfg.ManagedRules {
		view := RuleView{
			ID: managed.ID, Description: managed.Description,
			ListenAddress: managed.ListenAddress, ListenPort: managed.ListenPort,
			ConnectAddress: managed.ConnectAddress, ConnectPort: managed.ConnectPort,
			Managed: true, Listening: listening[managed.ListenPort],
		}
		if value, ok := firewall[managed.FirewallName]; ok {
			copy := value
			view.FirewallOK = &copy
		}
		if actual := findSystemRule(system, managed.ListenAddress, managed.ListenPort); actual != nil {
			view.Configured = true
			usedSystem[actual.key()] = true
			if actual.ConnectAddress != managed.ConnectAddress || actual.ConnectPort != managed.ConnectPort {
				view.Drifted = true
				view.ConnectAddress = actual.ConnectAddress
				view.ConnectPort = actual.ConnectPort
			}
		}
		views = append(views, view)
	}
	for _, actual := range system {
		if usedSystem[actual.key()] {
			continue
		}
		views = append(views, RuleView{
			ListenAddress: actual.ListenAddress, ListenPort: actual.ListenPort,
			ConnectAddress: actual.ConnectAddress, ConnectPort: actual.ConnectPort,
			Configured: true, Listening: listening[actual.ListenPort],
		})
	}
	sort.Slice(views, func(i, j int) bool {
		if views[i].ListenAddress == views[j].ListenAddress {
			return views[i].ListenPort < views[j].ListenPort
		}
		return views[i].ListenAddress < views[j].ListenAddress
	})
	return views
}

func managedRuleFromInput(in RuleInput) (ManagedRule, error) {
	id, err := newRuleID()
	if err != nil {
		return ManagedRule{}, err
	}
	return ManagedRule{
		ID: id, Description: in.Description,
		ListenAddress: in.ListenAddress, ListenPort: in.ListenPort,
		ConnectAddress: in.ConnectAddress, ConnectPort: in.ConnectPort,
		FirewallName: appName + "-" + id,
	}, nil
}

func newRuleID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func findSystemRule(rules []SystemRule, address string, port int) *SystemRule {
	key := ruleKey(address, port)
	for i := range rules {
		if rules[i].key() == key {
			return &rules[i]
		}
	}
	return nil
}

func findManagedRuleIndex(rules []ManagedRule, address string, port int) int {
	key := ruleKey(address, port)
	for i := range rules {
		if rules[i].key() == key {
			return i
		}
	}
	return -1
}

func localIPv4Addresses() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return []string{}
	}
	seen := map[string]bool{}
	var result []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil || ip.To4() == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			value := ip.To4().String()
			if !seen[value] {
				seen[value] = true
				result = append(result, value)
			}
		}
	}
	sort.Strings(result)
	return result
}

func joinErrors(values ...error) string {
	var parts []string
	for _, value := range values {
		if value != nil {
			parts = append(parts, sanitizeDetail(value.Error()))
		}
	}
	return strings.Join(parts, "; ")
}

func (m *Manager) remember(err error) error {
	if err != nil {
		m.lastError = sanitizeDetail(err.Error())
	}
	return err
}
