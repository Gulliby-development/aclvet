package acl

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseRulesValidRows(t *testing.T) {
	allAddresses := AddressRange{Min: 0, Max: Addr(^uint32(0))}
	tests := []struct {
		name string
		text string
		want []Rule
	}{
		{
			name: "TCP rule without ports covers the full destination-port range",
			text: "allow tcp 10.0.0.1 -> 10.0.0.2",
			want: []Rule{{
				Line: 1, Allow: true,
				Boxes: []Box{{Protocol: ProtocolTCP,
					Source:      AddressRange{Min: Addr(0x0a000001), Max: Addr(0x0a000001)},
					Destination: AddressRange{Min: Addr(0x0a000002), Max: Addr(0x0a000002)},
					Ports:       PortRange{Min: 0, Max: 65535}}},
			}},
		},
		{
			name: "UDP network and endpoint boundaries",
			text: "deny udp 0.0.0.0/0 -> 255.255.255.255/32 65534-65535",
			want: []Rule{{
				Line: 1, Allow: false,
				Boxes: []Box{{Protocol: ProtocolUDP,
					Source:      allAddresses,
					Destination: AddressRange{Min: Addr(^uint32(0)), Max: Addr(^uint32(0))},
					Ports:       PortRange{Min: 65534, Max: 65535}}},
			}},
		},
		{
			name: "explicit any port range",
			text: "allow tcp any -> any any",
			want: []Rule{{
				Line: 1, Allow: true,
				Boxes: []Box{{Protocol: ProtocolTCP, Source: allAddresses, Destination: allAddresses, Ports: PortRange{Min: 0, Max: 65535}}},
			}},
		},
		{
			name: "zero port",
			text: "deny tcp any -> any 0",
			want: []Rule{{
				Line: 1, Allow: false,
				Boxes: []Box{{Protocol: ProtocolTCP, Source: allAddresses, Destination: allAddresses, Ports: PortRange{Min: 0, Max: 0}}},
			}},
		},
		{
			name: "maximum port",
			text: "deny udp any -> any 65535",
			want: []Rule{{
				Line: 1, Allow: false,
				Boxes: []Box{{Protocol: ProtocolUDP, Source: allAddresses, Destination: allAddresses, Ports: PortRange{Min: 65535, Max: 65535}}},
			}},
		},
		{
			name: "ICMP uses its single port-zero representation",
			text: "allow icmp 192.0.2.0/24 -> 198.51.100.1",
			want: []Rule{{
				Line: 1, Allow: true,
				Boxes: []Box{{Protocol: ProtocolICMP,
					Source:      AddressRange{Min: Addr(0xc0000200), Max: Addr(0xc00002ff)},
					Destination: AddressRange{Min: Addr(0xc6336401), Max: Addr(0xc6336401)},
					Ports:       PortRange{Min: 0, Max: 0}}},
			}},
		},
		{
			name: "any expands in TCP UDP ICMP order",
			text: "deny any 10.0.0.0/8 -> 0.0.0.0/0",
			want: []Rule{{
				Line: 1, Allow: false,
				Boxes: []Box{
					{Protocol: ProtocolTCP, Source: AddressRange{Min: Addr(0x0a000000), Max: Addr(0x0affffff)}, Destination: allAddresses, Ports: PortRange{Min: 0, Max: 65535}},
					{Protocol: ProtocolUDP, Source: AddressRange{Min: Addr(0x0a000000), Max: Addr(0x0affffff)}, Destination: allAddresses, Ports: PortRange{Min: 0, Max: 65535}},
					{Protocol: ProtocolICMP, Source: AddressRange{Min: Addr(0x0a000000), Max: Addr(0x0affffff)}, Destination: allAddresses, Ports: PortRange{Min: 0, Max: 0}},
				},
			}},
		},
		{
			name: "blank lines comments tabs and physical line numbers",
			text: "  # heading\r\n\t\r\n  deny\tudp\tany  ->\tany\t22\r\n",
			want: []Rule{{
				Line: 3, Allow: false,
				Boxes: []Box{{Protocol: ProtocolUDP, Source: allAddresses, Destination: allAddresses, Ports: PortRange{Min: 22, Max: 22}}},
			}},
		},
		{
			name: "one leading BOM and CRLF",
			text: "\uFEFF# heading\r\nallow tcp 0.0.0.0/0 -> 0.0.0.0/0 443\r\n",
			want: []Rule{{
				Line: 2, Allow: true,
				Boxes: []Box{{Protocol: ProtocolTCP, Source: allAddresses, Destination: allAddresses, Ports: PortRange{Min: 443, Max: 443}}},
			}},
		},
		{
			name: "empty and comment-only input",
			text: "# only a comment\n \t\n",
			want: []Rule{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseRules("rules.acl", test.text)
			if err != nil {
				t.Fatalf("ParseRules() error = %v, want nil", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("ParseRules() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestParseRulesErrorsAndValidationOrder(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{name: "too few fields", text: "allow tcp", want: "rules.acl:1: expected \"ACTION PROTO SRC -> DST [PORTS]\""},
		{name: "wrong arrow", text: "allow tcp any => any", want: "rules.acl:1: expected \"ACTION PROTO SRC -> DST [PORTS]\""},
		{name: "too many fields", text: "allow tcp any -> any 1 extra", want: "rules.acl:1: expected \"ACTION PROTO SRC -> DST [PORTS]\""},
		{name: "action precedes protocol", text: "permit bad any -> any", want: "rules.acl:1: invalid action \"permit\" (expected allow or deny)"},
		{name: "invalid protocol", text: "allow sctp bad -> any", want: "rules.acl:1: invalid protocol \"sctp\" (expected tcp, udp, icmp or any)"},
		{name: "invalid source address", text: "allow tcp 256.0.0.1 -> bad", want: "rules.acl:1: invalid address \"256.0.0.1\""},
		{name: "invalid destination address", text: "allow tcp any -> 192.0.2.1/24", want: "rules.acl:1: invalid address \"192.0.2.1/24\" (host bits are set)"},
		{name: "host bits set at zero prefix", text: "allow tcp 0.0.0.1/0 -> any", want: "rules.acl:1: invalid address \"0.0.0.1/0\" (host bits are set)"},
		{name: "ports are rejected for ICMP before port validation", text: "allow icmp any -> any invalid", want: "rules.acl:1: ports need tcp or udp"},
		{name: "ports are rejected for any before port validation", text: "allow any any -> any invalid", want: "rules.acl:1: ports need tcp or udp"},
		{name: "invalid port range", text: "allow tcp any -> any 80-22", want: "rules.acl:1: invalid ports \"80-22\" (expected any, N or N-M with 0 <= N <= M <= 65535)"},
		{name: "no inline comments", text: "allow tcp any -> any #", want: "rules.acl:1: invalid ports \"#\" (expected any, N or N-M with 0 <= N <= M <= 65535)"},
		{name: "source is checked before destination", text: "allow tcp bad -> 300.1.1.1", want: "rules.acl:1: invalid address \"bad\""},
		{name: "display replaces each non-printable code point", text: "bad😀 tcp any -> any", want: "rules.acl:1: invalid action \"bad?\" (expected allow or deny)"},
		{name: "CR is removed only before LF", text: "allow tcp any -> any\r", want: "rules.acl:1: invalid address \"any?\""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got, err := ParseRules("rules.acl", test.text); err == nil || err.Error() != test.want {
				t.Fatalf("ParseRules() error = %v, want %q", err, test.want)
			} else if got != nil {
				t.Errorf("ParseRules() rules = %#v, want nil on error", got)
			}
		})
	}
}

func TestParseRulesLimitAndShapePrecedence(t *testing.T) {
	oneRule := "allow tcp any -> any\n"
	tests := []struct {
		name      string
		text      string
		wantCount int
		wantErr   string
	}{
		{name: "limit itself is allowed", text: strings.Repeat(oneRule, 150), wantCount: 150},
		{name: "151st rule is rejected", text: strings.Repeat(oneRule, 151), wantErr: "rules.acl:151: too many rules (limit 150)"},
		{name: "151st line shape is checked before the limit", text: strings.Repeat(oneRule, 150) + "malformed", wantErr: "rules.acl:151: expected \"ACTION PROTO SRC -> DST [PORTS]\""},
		{name: "151st valid shape hits limit before field validation", text: strings.Repeat(oneRule, 150) + "bad tcp any -> any", wantErr: "rules.acl:151: too many rules (limit 150)"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseRules("rules.acl", test.text)
			if test.wantErr != "" {
				if err == nil || err.Error() != test.wantErr {
					t.Fatalf("ParseRules() error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRules() error = %v, want nil", err)
			}
			if len(got) != test.wantCount {
				t.Errorf("ParseRules() returned %d rules, want %d", len(got), test.wantCount)
			}
		})
	}
}

func TestParseFlowsValidRows(t *testing.T) {
	tests := []struct {
		name string
		text string
		want []Flow
	}{
		{
			name: "TCP port and input spellings",
			text: "tcp 10.0.0.1 10.0.0.2 443",
			want: []Flow{{Protocol: ProtocolTCP, Source: Addr(0x0a000001), Destination: Addr(0x0a000002), Port: 443, SourceText: "10.0.0.1", DestinationText: "10.0.0.2", PortText: "443"}},
		},
		{
			name: "UDP port zero",
			text: "udp 0.0.0.0 255.255.255.255 0",
			want: []Flow{{Protocol: ProtocolUDP, Source: Addr(0), Destination: Addr(^uint32(0)), Port: 0, SourceText: "0.0.0.0", DestinationText: "255.255.255.255", PortText: "0"}},
		},
		{
			name: "maximum flow port",
			text: "tcp 255.255.255.255 0.0.0.0 65535",
			want: []Flow{{Protocol: ProtocolTCP, Source: Addr(^uint32(0)), Destination: Addr(0), Port: 65535, SourceText: "255.255.255.255", DestinationText: "0.0.0.0", PortText: "65535"}},
		},
		{
			name: "ICMP has port zero and no port spelling",
			text: "icmp 192.0.2.1 198.51.100.2",
			want: []Flow{{Protocol: ProtocolICMP, Source: Addr(0xc0000201), Destination: Addr(0xc6336402), SourceText: "192.0.2.1", DestinationText: "198.51.100.2"}},
		},
		{
			name: "comments tabs CRLF and physical line numbers",
			text: "# heading\r\n\t\r\n  udp\t10.0.0.1   10.0.0.2\t53\r\n",
			want: []Flow{{Protocol: ProtocolUDP, Source: Addr(0x0a000001), Destination: Addr(0x0a000002), Port: 53, SourceText: "10.0.0.1", DestinationText: "10.0.0.2", PortText: "53"}},
		},
		{
			name: "one leading BOM and CRLF",
			text: "\uFEFFtcp 10.0.0.1 10.0.0.2 80\r\n",
			want: []Flow{{Protocol: ProtocolTCP, Source: Addr(0x0a000001), Destination: Addr(0x0a000002), Port: 80, SourceText: "10.0.0.1", DestinationText: "10.0.0.2", PortText: "80"}},
		},
		{
			name: "empty and comment-only input",
			text: "# no flows\n \t\n",
			want: []Flow{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseFlows("flows.txt", test.text)
			if err != nil {
				t.Fatalf("ParseFlows() error = %v, want nil", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("ParseFlows() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestParseFlowsErrorsAndValidationOrder(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{name: "too few fields", text: "tcp 10.0.0.1", want: "flows.txt:1: expected \"PROTO SRC DST [PORT]\""},
		{name: "too many fields", text: "tcp 10.0.0.1 10.0.0.2 80 extra", want: "flows.txt:1: expected \"PROTO SRC DST [PORT]\""},
		{name: "invalid protocol precedes addresses", text: "any bad bad", want: "flows.txt:1: invalid protocol \"any\" (expected tcp, udp or icmp)"},
		{name: "invalid source address", text: "tcp 10.0.0.01 bad 80", want: "flows.txt:1: invalid address \"10.0.0.01\""},
		{name: "invalid destination address", text: "udp 10.0.0.1 192.0.2.0/24 53", want: "flows.txt:1: invalid address \"192.0.2.0/24\""},
		{name: "missing TCP port", text: "tcp 10.0.0.1 10.0.0.2", want: "flows.txt:1: missing port"},
		{name: "missing UDP port", text: "udp 10.0.0.1 10.0.0.2", want: "flows.txt:1: missing port"},
		{name: "ICMP forbids a port before checking its value", text: "icmp 10.0.0.1 10.0.0.2 invalid", want: "flows.txt:1: icmp has no port"},
		{name: "port above maximum", text: "tcp 10.0.0.1 10.0.0.2 65536", want: "flows.txt:1: invalid port \"65536\" (expected a whole number from 0 to 65535)"},
		{name: "leading zero port", text: "udp 10.0.0.1 10.0.0.2 080", want: "flows.txt:1: invalid port \"080\" (expected a whole number from 0 to 65535)"},
		{name: "non-decimal port", text: "tcp 10.0.0.1 10.0.0.2 8x", want: "flows.txt:1: invalid port \"8x\" (expected a whole number from 0 to 65535)"},
		{name: "display replaces each non-printable code point", text: "tcp 10.0.0.1 10.0.0.2 😀", want: "flows.txt:1: invalid port \"?\" (expected a whole number from 0 to 65535)"},
		{name: "line number counts skipped lines", text: "# heading\n\n tcp 10.0.0.1 10.0.0.2", want: "flows.txt:3: missing port"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got, err := ParseFlows("flows.txt", test.text); err == nil || err.Error() != test.want {
				t.Fatalf("ParseFlows() error = %v, want %q", err, test.want)
			} else if got != nil {
				t.Errorf("ParseFlows() flows = %#v, want nil on error", got)
			}
		})
	}
}
