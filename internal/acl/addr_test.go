package acl

import "testing"

func TestParseIPv4Address(t *testing.T) {
	tests := []struct {
		name  string
		text  string
		want  Addr
		valid bool
	}{
		{name: "zero address", text: "0.0.0.0", want: Addr(0), valid: true},
		{name: "maximum address", text: "255.255.255.255", want: Addr(^uint32(0)), valid: true},
		{name: "mixed octets", text: "10.0.0.1", want: Addr(0x0a000001), valid: true},
		{name: "leading nonzero octets", text: "1.2.3.4", want: Addr(0x01020304), valid: true},
		{name: "maximum final octet", text: "0.0.0.255", want: Addr(255), valid: true},
		{name: "maximum first octet", text: "255.0.0.0", want: Addr(0xff000000), valid: true},
		{name: "empty", text: ""},
		{name: "missing first octet", text: ".1.2.3"},
		{name: "missing middle octet", text: "1..2.3"},
		{name: "missing final octet", text: "1.2.3."},
		{name: "too few octets", text: "1.2.3"},
		{name: "too many octets", text: "1.2.3.4.5"},
		{name: "leading zero", text: "01.2.3.4"},
		{name: "multiple leading zeroes", text: "1.02.3.4"},
		{name: "octet above maximum", text: "1.2.3.256"},
		{name: "four digit octet", text: "1000.2.3.4"},
		{name: "negative octet", text: "1.-2.3.4"},
		{name: "positive sign", text: "+1.2.3.4"},
		{name: "leading whitespace", text: " 1.2.3.4"},
		{name: "trailing whitespace", text: "1.2.3.4 "},
		{name: "non-decimal octet", text: "1.a.3.4"},
		{name: "unicode digit", text: "1.٢.3.4"},
		{name: "trailing dot", text: "1.2.3.4."},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, valid := parseIPv4Address(test.text)
			if valid != test.valid {
				t.Fatalf("parseIPv4Address(%q) valid = %t, want %t", test.text, valid, test.valid)
			}
			if valid && got != test.want {
				t.Errorf("parseIPv4Address(%q) = %s (%#x), want %s (%#x)", test.text, got, uint32(got), test.want, uint32(test.want))
			}
		})
	}
}

func TestAddrString(t *testing.T) {
	tests := []struct {
		name string
		addr Addr
		want string
	}{
		{name: "zero", addr: Addr(0), want: "0.0.0.0"},
		{name: "maximum", addr: Addr(^uint32(0)), want: "255.255.255.255"},
		{name: "mixed octets", addr: Addr(0x0a010203), want: "10.1.2.3"},
		{name: "octet boundaries", addr: Addr(0x00ff0100), want: "0.255.1.0"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.addr.String(); got != test.want {
				t.Errorf("Addr(%#x).String() = %q, want %q", uint32(test.addr), got, test.want)
			}
		})
	}
}

func TestParseIPv4Network(t *testing.T) {
	tests := []struct {
		name        string
		text        string
		want        AddressRange
		valid       bool
		hostBitsSet bool
	}{
		{name: "zero prefix", text: "0.0.0.0/0", want: AddressRange{Min: Addr(0), Max: Addr(^uint32(0))}, valid: true},
		{name: "host bits set at zero prefix", text: "10.0.0.0/0", hostBitsSet: true},
		{name: "maximum prefix", text: "255.255.255.255/32", want: AddressRange{Min: Addr(^uint32(0)), Max: Addr(^uint32(0))}, valid: true},
		{name: "single address prefix", text: "10.1.2.3/32", want: AddressRange{Min: Addr(0x0a010203), Max: Addr(0x0a010203)}, valid: true},
		{name: "eight bit prefix", text: "10.0.0.0/8", want: AddressRange{Min: Addr(0x0a000000), Max: Addr(0x0affffff)}, valid: true},
		{name: "one bit prefix", text: "128.0.0.0/1", want: AddressRange{Min: Addr(0x80000000), Max: Addr(^uint32(0))}, valid: true},
		{name: "twenty four bit prefix", text: "192.0.2.0/24", want: AddressRange{Min: Addr(0xc0000200), Max: Addr(0xc00002ff)}, valid: true},
		{name: "host bits set", text: "192.0.2.1/24", hostBitsSet: true},
		{name: "empty", text: ""},
		{name: "missing prefix", text: "192.0.2.0"},
		{name: "missing address", text: "/24"},
		{name: "empty prefix", text: "192.0.2.0/"},
		{name: "second slash", text: "192.0.2.0/24/1"},
		{name: "leading zero prefix", text: "192.0.2.0/024"},
		{name: "prefix above maximum", text: "192.0.2.0/33"},
		{name: "negative prefix", text: "192.0.2.0/-1"},
		{name: "signed prefix", text: "192.0.2.0/+24"},
		{name: "non-decimal prefix", text: "192.0.2.0/2a"},
		{name: "invalid address in network", text: "192.0.02.0/24"},
		{name: "host bits set at zero prefix", text: "0.0.0.1/0", hostBitsSet: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, valid, hostBitsSet := parseIPv4Network(test.text)
			if valid != test.valid {
				t.Fatalf("parseIPv4Network(%q) valid = %t, want %t", test.text, valid, test.valid)
			}
			if hostBitsSet != test.hostBitsSet {
				t.Fatalf("parseIPv4Network(%q) hostBitsSet = %t, want %t", test.text, hostBitsSet, test.hostBitsSet)
			}
			if valid && got != test.want {
				t.Errorf("parseIPv4Network(%q) = %#v, want %#v", test.text, got, test.want)
			}
		})
	}
}

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		name  string
		text  string
		want  PortRange
		valid bool
	}{
		{name: "any", text: "any", want: PortRange{Min: 0, Max: 65535}, valid: true},
		{name: "zero", text: "0", want: PortRange{Min: 0, Max: 0}, valid: true},
		{name: "maximum", text: "65535", want: PortRange{Min: 65535, Max: 65535}, valid: true},
		{name: "single port range", text: "1-1", want: PortRange{Min: 1, Max: 1}, valid: true},
		{name: "full range", text: "0-65535", want: PortRange{Min: 0, Max: 65535}, valid: true},
		{name: "range at maximum", text: "65534-65535", want: PortRange{Min: 65534, Max: 65535}, valid: true},
		{name: "ordinary range", text: "22-80", want: PortRange{Min: 22, Max: 80}, valid: true},
		{name: "empty", text: ""},
		{name: "leading zero", text: "01"},
		{name: "multiple leading zeroes", text: "00"},
		{name: "above maximum", text: "65536"},
		{name: "negative", text: "-1"},
		{name: "signed", text: "+1"},
		{name: "decimal point", text: "1.0"},
		{name: "leading range endpoint zero", text: "01-2"},
		{name: "trailing range endpoint zero", text: "1-02"},
		{name: "reversed range", text: "80-22"},
		{name: "range endpoint above maximum", text: "1-65536"},
		{name: "empty first range endpoint", text: "-2"},
		{name: "empty second range endpoint", text: "1-"},
		{name: "two range separators", text: "1-2-3"},
		{name: "spaces", text: "1 - 2"},
		{name: "case-sensitive any", text: "Any"},
		{name: "non-decimal endpoint", text: "1-a"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, valid := parsePortRange(test.text)
			if valid != test.valid {
				t.Fatalf("parsePortRange(%q) valid = %t, want %t", test.text, valid, test.valid)
			}
			if valid && got != test.want {
				t.Errorf("parsePortRange(%q) = %#v, want %#v", test.text, got, test.want)
			}
		})
	}
}

func TestDisplayValue(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{name: "empty", text: "", want: ""},
		{name: "printable ASCII", text: "!AZaz~", want: "!AZaz~"},
		{name: "quotes are unchanged", text: `a"b`, want: `a"b`},
		{name: "backslashes are unchanged", text: `a\b`, want: `a\b`},
		{name: "space becomes one question mark", text: "a b", want: "a?b"},
		{name: "tab and newline each become one question mark", text: "a\t\nb", want: "a??b"},
		{name: "unicode code points each become one question mark", text: "é猫", want: "??"},
		{name: "supplementary code point becomes one question mark", text: "a😀b", want: "a?b"},
		{name: "delete and nonbreaking space become question marks", text: "a\x7f\u00a0b", want: "a??b"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := displayValue(test.text); got != test.want {
				t.Errorf("displayValue(%q) = %q, want %q", test.text, got, test.want)
			}
		})
	}
}
