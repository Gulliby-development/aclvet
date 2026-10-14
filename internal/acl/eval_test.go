package acl

import "testing"

func TestEvaluateVerdicts(t *testing.T) {
	tests := []struct {
		name  string
		rules string
		flow  string
		want  Verdict
	}{
		{
			name:  "first matching rule wins over a later opposite action",
			rules: "# policy\nallow tcp 10.0.0.0/8 -> any 80\ndeny tcp any -> any 80\n",
			flow:  "tcp 10.1.2.3 203.0.113.4 80",
			want:  Verdict{Allow: true, Line: 2},
		},
		{
			name:  "a matching deny keeps its physical line",
			rules: "# policy\n\ndeny udp any -> 192.0.2.0/24 53\n",
			flow:  "udp 198.51.100.1 192.0.2.255 53",
			want:  Verdict{Line: 3},
		},
		{
			name: "empty policy uses default deny",
			flow: "tcp 10.0.0.1 10.0.0.2 0",
			want: Verdict{Default: true},
		},
		{
			name:  "nonmatching policy uses default deny",
			rules: "allow tcp 10.0.0.0/24 -> any 80\n",
			flow:  "tcp 10.0.1.1 10.0.0.2 80",
			want:  Verdict{Default: true},
		},
		{
			name:  "lower source and upper destination and port boundaries are included",
			rules: "allow tcp 10.0.0.0/24 -> 192.0.2.0/24 80-81\n",
			flow:  "tcp 10.0.0.0 192.0.2.255 80",
			want:  Verdict{Allow: true, Line: 1},
		},
		{
			name:  "upper source and lower destination and port boundaries are included",
			rules: "allow tcp 10.0.0.0/24 -> 192.0.2.0/24 80-81\n",
			flow:  "tcp 10.0.0.255 192.0.2.0 81",
			want:  Verdict{Allow: true, Line: 1},
		},
		{
			name:  "source just below the range does not match",
			rules: "allow tcp 10.0.0.0/24 -> any 80\n",
			flow:  "tcp 9.255.255.255 192.0.2.1 80",
			want:  Verdict{Default: true},
		},
		{
			name:  "source just above the range does not match",
			rules: "allow tcp 10.0.0.0/24 -> any 80\n",
			flow:  "tcp 10.0.1.0 192.0.2.1 80",
			want:  Verdict{Default: true},
		},
		{
			name:  "destination just below the range does not match",
			rules: "allow tcp any -> 192.0.2.0/24 80\n",
			flow:  "tcp 10.0.0.1 192.0.1.255 80",
			want:  Verdict{Default: true},
		},
		{
			name:  "destination just above the range does not match",
			rules: "allow tcp any -> 192.0.2.0/24 80\n",
			flow:  "tcp 10.0.0.1 192.0.3.0 80",
			want:  Verdict{Default: true},
		},
		{
			name:  "port just below the range does not match",
			rules: "allow tcp any -> any 80-81\n",
			flow:  "tcp 10.0.0.1 192.0.2.1 79",
			want:  Verdict{Default: true},
		},
		{
			name:  "port just above the range does not match",
			rules: "allow tcp any -> any 80-81\n",
			flow:  "tcp 10.0.0.1 192.0.2.1 82",
			want:  Verdict{Default: true},
		},
		{
			name:  "TCP rule does not match UDP flow",
			rules: "allow tcp any -> any any\n",
			flow:  "udp 10.0.0.1 192.0.2.1 80",
			want:  Verdict{Default: true},
		},
		{
			name:  "UDP rule does not match TCP flow",
			rules: "allow udp any -> any any\n",
			flow:  "tcp 10.0.0.1 192.0.2.1 80",
			want:  Verdict{Default: true},
		},
		{
			name:  "TCP and UDP rules do not match ICMP flow",
			rules: "allow tcp any -> any any\ndeny udp any -> any any\n",
			flow:  "icmp 10.0.0.1 192.0.2.1",
			want:  Verdict{Default: true},
		},
		{
			name:  "any rule matches TCP",
			rules: "deny any any -> any\n",
			flow:  "tcp 10.0.0.1 192.0.2.1 65535",
			want:  Verdict{Line: 1},
		},
		{
			name:  "any rule matches UDP",
			rules: "allow any any -> any\n",
			flow:  "udp 10.0.0.1 192.0.2.1 0",
			want:  Verdict{Allow: true, Line: 1},
		},
		{
			name:  "any rule matches ICMP",
			rules: "allow any any -> any\n",
			flow:  "icmp 10.0.0.1 192.0.2.1",
			want:  Verdict{Allow: true, Line: 1},
		},
		{
			name:  "a preceding rule that misses does not block a later match",
			rules: "deny udp any -> any any\nallow tcp any -> any 0\n",
			flow:  "tcp 255.255.255.255 0.0.0.0 0",
			want:  Verdict{Allow: true, Line: 2},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var rules []Rule
			if test.rules != "" {
				var err error
				rules, err = ParseRules("rules.acl", test.rules)
				if err != nil {
					t.Fatalf("ParseRules() error = %v, want nil", err)
				}
			}

			flows, err := ParseFlows("flows.txt", test.flow)
			if err != nil {
				t.Fatalf("ParseFlows() error = %v, want nil", err)
			}
			if len(flows) != 1 {
				t.Fatalf("ParseFlows() returned %d flows, want 1", len(flows))
			}

			if got := Evaluate(rules, flows[0]); got != test.want {
				t.Errorf("Evaluate() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestEvaluateICMPIgnoresPort(t *testing.T) {
	rules, err := ParseRules("rules.acl", "allow icmp 192.0.2.0/24 -> 198.51.100.0/24\n")
	if err != nil {
		t.Fatalf("ParseRules() error = %v, want nil", err)
	}

	flow := Flow{
		Protocol:    ProtocolICMP,
		Source:      Addr(0xc0000200),
		Destination: Addr(0xc63364ff),
		Port:        65535,
	}
	if got, want := Evaluate(rules, flow), (Verdict{Allow: true, Line: 1}); got != want {
		t.Errorf("Evaluate() with an ICMP port = %#v, want %#v", got, want)
	}
}
