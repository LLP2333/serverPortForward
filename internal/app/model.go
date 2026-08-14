package app

import "time"

const (
	configVersion = 1
	appName       = "ServerPortForward"
)

type Config struct {
	Version           int           `json:"version"`
	DefaultTargetIPv4 string        `json:"defaultTargetIPv4"`
	ManagedRules      []ManagedRule `json:"managedRules"`
}

type ManagedRule struct {
	ID             string `json:"id"`
	Description    string `json:"description,omitempty"`
	ListenAddress  string `json:"listenAddress"`
	ListenPort     int    `json:"listenPort"`
	ConnectAddress string `json:"connectAddress"`
	ConnectPort    int    `json:"connectPort"`
	FirewallName   string `json:"firewallName"`
}

type SystemRule struct {
	ListenAddress  string `json:"listenAddress"`
	ListenPort     int    `json:"listenPort"`
	ConnectAddress string `json:"connectAddress"`
	ConnectPort    int    `json:"connectPort"`
}

type RuleView struct {
	ID             string `json:"id,omitempty"`
	Description    string `json:"description,omitempty"`
	ListenAddress  string `json:"listenAddress"`
	ListenPort     int    `json:"listenPort"`
	ConnectAddress string `json:"connectAddress"`
	ConnectPort    int    `json:"connectPort"`
	Managed        bool   `json:"managed"`
	Configured     bool   `json:"configured"`
	Drifted        bool   `json:"drifted"`
	Listening      bool   `json:"listening"`
	FirewallOK     *bool  `json:"firewallOK,omitempty"`
}

type RuleInput struct {
	Description    string `json:"description"`
	ListenAddress  string `json:"listenAddress"`
	ListenPort     int    `json:"listenPort"`
	ConnectAddress string `json:"connectAddress"`
	ConnectPort    int    `json:"connectPort"`
}

type UpdateRuleRequest struct {
	OriginalListenAddress string    `json:"originalListenAddress"`
	OriginalListenPort    int       `json:"originalListenPort"`
	Rule                  RuleInput `json:"rule"`
	Adopt                 bool      `json:"adopt"`
}

type RuleKeyRequest struct {
	ListenAddress string `json:"listenAddress"`
	ListenPort    int    `json:"listenPort"`
}

type SettingsRequest struct {
	DefaultTargetIPv4 string `json:"defaultTargetIPv4"`
}

type IPHelperStatus struct {
	Running   bool   `json:"running"`
	StartMode string `json:"startMode"`
	Disabled  bool   `json:"disabled"`
	Detail    string `json:"detail,omitempty"`
}

type Diagnostics struct {
	PortProxyDump string   `json:"portProxyDump"`
	ListenerLines []string `json:"listenerLines"`
	LastError     string   `json:"lastError,omitempty"`
}

type AppState struct {
	DefaultTargetIPv4 string         `json:"defaultTargetIPv4"`
	LocalIPv4         []string       `json:"localIPv4"`
	Rules             []RuleView     `json:"rules"`
	IPHelper          IPHelperStatus `json:"ipHelper"`
	Diagnostics       Diagnostics    `json:"diagnostics"`
	Warnings          []string       `json:"warnings"`
	UpdatedAt         time.Time      `json:"updatedAt"`
}

type TestResult struct {
	TargetReachable bool   `json:"targetReachable"`
	TargetMessage   string `json:"targetMessage"`
	Listening       bool   `json:"listening"`
	ListenMessage   string `json:"listenMessage"`
	ProxyReachable  bool   `json:"proxyReachable"`
	ProxyMessage    string `json:"proxyMessage"`
	FirewallOK      *bool  `json:"firewallOK,omitempty"`
	FirewallMessage string `json:"firewallMessage"`
	Reminder        string `json:"reminder"`
}

func newConfig() Config {
	return Config{Version: configVersion, ManagedRules: []ManagedRule{}}
}

func (r SystemRule) key() string {
	return ruleKey(r.ListenAddress, r.ListenPort)
}

func (r ManagedRule) key() string {
	return ruleKey(r.ListenAddress, r.ListenPort)
}
