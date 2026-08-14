package app

import (
	"reflect"
	"testing"
)

func TestParsePortProxyShowLocalizedHeadings(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{
			name: "English",
			output: `Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
0.0.0.0         71          128.120.123.115 22
172.16.0.4      8080        10.0.0.8        80
`,
		},
		{
			name: "Chinese",
			output: `侦听 ipv4:                 连接到 ipv4:

地址            端口        地址            端口
--------------- ----------  --------------- ----------
0.0.0.0         71          128.120.123.115 22
172.16.0.4      8080        10.0.0.8        80
`,
		},
	}
	want := []SystemRule{
		{ListenAddress: "0.0.0.0", ListenPort: 71, ConnectAddress: "128.120.123.115", ConnectPort: 22},
		{ListenAddress: "172.16.0.4", ListenPort: 8080, ConnectAddress: "10.0.0.8", ConnectPort: 80},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parsePortProxyShow(tt.output); !reflect.DeepEqual(got, want) {
				t.Fatalf("parsePortProxyShow() = %#v, want %#v", got, want)
			}
		})
	}
}

func TestParsePortProxyShowNormalizesWindowsWildcardListener(t *testing.T) {
	output := `Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
*               71          192.168.111.223 22
`
	want := []SystemRule{{
		ListenAddress: "0.0.0.0", ListenPort: 71,
		ConnectAddress: "192.168.111.223", ConnectPort: 22,
	}}
	if got := parsePortProxyShow(output); !reflect.DeepEqual(got, want) {
		t.Fatalf("parsePortProxyShow() = %#v, want %#v", got, want)
	}
}

func TestParsePortProxyShowRejectsInvalidRows(t *testing.T) {
	output := `0.0.0.0 0 10.0.0.1 22
0.0.0.0 71 example.com 22
0.0.0.0 71 10.0.0.1 70000
not-an-ip 71 10.0.0.1 22`
	if got := parsePortProxyShow(output); len(got) != 0 {
		t.Fatalf("expected invalid rows to be ignored, got %#v", got)
	}
}

func TestParseListeningPorts(t *testing.T) {
	output := `
  TCP    0.0.0.0:71           0.0.0.0:0              LISTENING       1000
  TCP    127.0.0.1:8080       127.0.0.1:51234        ESTABLISHED     1000
  TCP    [::]:443             [::]:0                 LISTENING       4
`
	ports, lines := parseListeningPorts(output)
	if !ports[71] || !ports[443] || ports[8080] {
		t.Fatalf("unexpected listening ports: %#v", ports)
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 listener lines, got %d", len(lines))
	}
}
