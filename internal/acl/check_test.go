package acl

import (
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestCheckFindingCases(t *testing.T) {
	tests := []struct {
		name string
		text string
		want []Finding
	}{
		{
			name: "one earlier rule covers the whole later rule",
			text: "deny tcp any -> any\nallow tcp 10.0.0.0/8 -> any 443\n",
			want: []Finding{{Line: 2, Code: "AV001", Message: "shadowed by line 1"}},
		},
		{
			name: "several partial rules cover the whole later rule",
			text: "deny tcp 10.0.0.0/25 -> any 443\ndeny tcp 10.0.0.128/25 -> any 443\nallow tcp 10.0.0.0/24 -> any 443\n",
			want: []Finding{{Line: 3, Code: "AV001", Message: "shadowed by lines 1, 2"}},
		},
		{
			name: "the first single covering rule is named",
			text: "deny tcp 10.0.0.0/25 -> any 443\ndeny tcp 10.0.0.0/24 -> any 443\nallow tcp 10.0.0.0/24 -> any 443\n",
			want: []Finding{
				{Line: 1, Code: "AV002", Message: "redundant: removing it changes no verdict"},
				{Line: 3, Code: "AV001", Message: "shadowed by line 2"},
			},
		},
		{
			name: "AV001 takes precedence over redundancy",
			text: "allow tcp any -> any 80\nallow tcp any -> any 80\nallow tcp any -> any 80\n",
			want: []Finding{
				{Line: 1, Code: "AV002", Message: "redundant: removing it changes no verdict"},
				{Line: 2, Code: "AV001", Message: "shadowed by line 1"},
				{Line: 3, Code: "AV001", Message: "shadowed by line 1"},
			},
		},
		{
			name: "an any rule can replace an earlier protocol-specific rule",
			text: "allow udp any -> any\nallow any any -> any\n",
			want: []Finding{{Line: 1, Code: "AV002", Message: "redundant: removing it changes no verdict"}},
		},
		{
			name: "later same-action rules can make separate rules redundant",
			text: "allow tcp 10.0.0.0/8 -> any 80\nallow tcp 10.0.0.0/8 -> any 81\nallow tcp 10.0.0.0/8 -> any 80-81\n",
			want: []Finding{
				{Line: 1, Code: "AV002", Message: "redundant: removing it changes no verdict"},
				{Line: 2, Code: "AV002", Message: "redundant: removing it changes no verdict"},
				{Line: 3, Code: "AV001", Message: "shadowed by lines 1, 2"},
			},
		},
		{
			name: "default deny does not make a deny rule redundant",
			text: "deny any any -> any\n",
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rules, err := ParseRules("rules.acl", test.text)
			if err != nil {
				t.Fatalf("ParseRules() error = %v, want nil", err)
			}
			if got := Check(rules); !equalFindings(got, test.want) {
				t.Errorf("Check() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestComputeRegionsPartitionAndVolumes(t *testing.T) {
	text := "allow tcp 10.0.0.0/9 -> 192.0.2.0/24 80-81\n" +
		"deny tcp 10.128.0.0/9 -> 192.0.2.0/24 81\n" +
		"allow tcp 10.0.0.0/8 -> 192.0.2.0/24 81\n" +
		"deny icmp any -> any\n"
	rules, err := ParseRules("rules.acl", text)
	if err != nil {
		t.Fatalf("ParseRules() error = %v, want nil", err)
	}

	regions := ComputeRegions(rules)
	if len(regions.Decided) != len(rules) {
		t.Fatalf("ComputeRegions() has %d decided entries, want %d", len(regions.Decided), len(rules))
	}
	if got := volumeOfBoxes(regions.Decided[0]); got.String() != "4294967296" {
		t.Errorf("first rule decided volume = %s, want 4294967296", got)
	}
	if got := volumeOfBoxes(regions.Decided[1]); got.String() != "2147483648" {
		t.Errorf("second rule decided volume = %s, want 2147483648", got)
	}
	if len(regions.Decided[2]) != 0 {
		t.Errorf("third rule decided %d boxes, want none", len(regions.Decided[2]))
	}
	if got := volumeOfBoxes(regions.Decided[3]); got.String() != "18446744073709551616" {
		t.Errorf("ICMP rule decided volume = %s, want 18446744073709551616", got)
	}

	allRegions := make([]Box, 0)
	for _, decided := range regions.Decided {
		allRegions = append(allRegions, decided...)
	}
	allRegions = append(allRegions, regions.Unmatched...)
	for first := range allRegions {
		for second := first + 1; second < len(allRegions); second++ {
			if _, overlaps := allRegions[first].Intersection(allRegions[second]); overlaps {
				t.Errorf("computed regions overlap: box %d and box %d", first, second)
			}
		}
	}

	wantTotal := totalFlowVolume()
	gotTotal := volumeOfBoxes(allRegions)
	if gotTotal.Cmp(wantTotal) != 0 {
		t.Errorf("decided plus unmatched volume = %s, want %s", gotTotal, wantTotal)
	}
	if got, want := volumeOfBoxes(regions.Unmatched).String(), "2417851639229251906961408"; got != want {
		t.Errorf("unmatched volume = %s, want %s", got, want)
	}
}

func TestComputeRegionsWithoutRulesLeavesAllTrafficUnmatched(t *testing.T) {
	regions := ComputeRegions(nil)
	if len(regions.Decided) != 0 {
		t.Errorf("ComputeRegions(nil) decided entries = %d, want 0", len(regions.Decided))
	}
	if len(regions.Unmatched) != 3 {
		t.Fatalf("ComputeRegions(nil) unmatched boxes = %d, want one per protocol", len(regions.Unmatched))
	}
	if got, want := volumeOfBoxes(regions.Unmatched), totalFlowVolume(); got.Cmp(want) != 0 {
		t.Errorf("unmatched volume = %s, want %s", got, want)
	}
}

func TestCheckOverlapping150RuleWorkloadCompletesWithinFiveSeconds(t *testing.T) {
	rules := overlappingRuleWorkload(t)
	protocolCounts := map[Protocol]int{}
	portRanges := map[Protocol]map[PortRange]struct{}{}
	for index, rule := range rules {
		if len(rule.Boxes) != 1 {
			t.Fatalf("fixture rule %d has %d boxes, want one protocol-specific box", index+1, len(rule.Boxes))
		}
		box := rule.Boxes[0]
		protocolCounts[box.Protocol]++
		if portRanges[box.Protocol] == nil {
			portRanges[box.Protocol] = make(map[PortRange]struct{})
		}
		portRanges[box.Protocol][box.Ports] = struct{}{}
	}

	if protocolCounts[ProtocolTCP] != 75 || protocolCounts[ProtocolUDP] != 75 {
		t.Fatalf("fixture protocol counts = %#v, want 75 TCP and 75 UDP rules", protocolCounts)
	}
	for _, protocol := range []Protocol{ProtocolTCP, ProtocolUDP} {
		if len(portRanges[protocol]) < 2 {
			t.Errorf("fixture has %d distinct %s port ranges, want multiple intersecting ranges", len(portRanges[protocol]), protocol)
		}
	}

	for first := range rules {
		for second := first + 1; second < len(rules); second++ {
			firstBox := rules[first].Boxes[0]
			secondBox := rules[second].Boxes[0]
			_, overlaps := firstBox.Intersection(secondBox)
			if firstBox.Protocol == secondBox.Protocol && !overlaps {
				t.Fatalf("same-protocol fixture rules %d and %d do not overlap", first+1, second+1)
			}
			if firstBox.Protocol != secondBox.Protocol && overlaps {
				t.Fatalf("different-protocol fixture rules %d and %d unexpectedly overlap", first+1, second+1)
			}
		}
	}

	started := time.Now()
	_ = Check(rules)
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Errorf("Check() on 150 overlapping TCP/UDP rules took %s, want no more than 5s", elapsed)
	}
}

func overlappingRuleWorkload(t *testing.T) []Rule {
	t.Helper()
	text := strings.Join(overlappingRuleWorkloadLines, "\n") + "\n"
	rules, err := ParseRules("overlapping-performance.rules", text)
	if err != nil {
		t.Fatalf("ParseRules(overlapping-performance.rules) error = %v, want nil", err)
	}
	if len(rules) != 150 {
		t.Fatalf("static overlapping fixture has %d rules, want 150", len(rules))
	}
	return rules
}

var overlappingRuleWorkloadLines = []string{
	// TCP overlap block 01.
	"allow tcp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"deny tcp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"allow tcp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"deny tcp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"allow tcp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// TCP overlap block 02.
	"allow tcp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"deny tcp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"allow tcp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"deny tcp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"allow tcp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// TCP overlap block 03.
	"allow tcp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"deny tcp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"allow tcp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"deny tcp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"allow tcp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// TCP overlap block 04.
	"allow tcp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"deny tcp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"allow tcp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"deny tcp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"allow tcp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// TCP overlap block 05.
	"allow tcp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"deny tcp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"allow tcp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"deny tcp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"allow tcp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// TCP overlap block 06.
	"allow tcp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"deny tcp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"allow tcp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"deny tcp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"allow tcp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// TCP overlap block 07.
	"allow tcp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"deny tcp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"allow tcp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"deny tcp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"allow tcp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// TCP overlap block 08.
	"allow tcp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"deny tcp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"allow tcp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"deny tcp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"allow tcp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// TCP overlap block 09.
	"allow tcp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"deny tcp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"allow tcp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"deny tcp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"allow tcp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// TCP overlap block 10.
	"allow tcp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"deny tcp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"allow tcp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"deny tcp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"allow tcp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// TCP overlap block 11.
	"allow tcp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"deny tcp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"allow tcp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"deny tcp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"allow tcp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// TCP overlap block 12.
	"allow tcp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"deny tcp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"allow tcp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"deny tcp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"allow tcp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// TCP overlap block 13.
	"allow tcp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"deny tcp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"allow tcp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"deny tcp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"allow tcp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// TCP overlap block 14.
	"allow tcp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"deny tcp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"allow tcp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"deny tcp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"allow tcp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// TCP overlap block 15.
	"allow tcp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"deny tcp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"allow tcp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"deny tcp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"allow tcp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// UDP overlap block 01.
	"deny udp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"allow udp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"deny udp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"allow udp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"deny udp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// UDP overlap block 02.
	"deny udp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"allow udp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"deny udp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"allow udp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"deny udp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// UDP overlap block 03.
	"deny udp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"allow udp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"deny udp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"allow udp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"deny udp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// UDP overlap block 04.
	"deny udp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"allow udp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"deny udp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"allow udp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"deny udp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// UDP overlap block 05.
	"deny udp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"allow udp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"deny udp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"allow udp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"deny udp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// UDP overlap block 06.
	"deny udp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"allow udp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"deny udp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"allow udp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"deny udp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// UDP overlap block 07.
	"deny udp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"allow udp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"deny udp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"allow udp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"deny udp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// UDP overlap block 08.
	"deny udp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"allow udp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"deny udp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"allow udp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"deny udp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// UDP overlap block 09.
	"deny udp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"allow udp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"deny udp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"allow udp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"deny udp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// UDP overlap block 10.
	"deny udp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"allow udp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"deny udp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"allow udp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"deny udp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// UDP overlap block 11.
	"deny udp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"allow udp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"deny udp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"allow udp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"deny udp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// UDP overlap block 12.
	"deny udp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"allow udp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"deny udp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"allow udp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"deny udp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// UDP overlap block 13.
	"deny udp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"allow udp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"deny udp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"allow udp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"deny udp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// UDP overlap block 14.
	"deny udp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"allow udp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"deny udp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"allow udp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"deny udp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
	// UDP overlap block 15.
	"deny udp 10.0.0.0/8 -> 192.0.2.0/24 0-10000",
	"allow udp 10.0.0.0/9 -> 192.0.2.0/25 1000-11000",
	"deny udp 10.0.0.0/10 -> 192.0.2.0/26 2000-12000",
	"allow udp 10.0.0.0/11 -> 192.0.2.0/27 3000-13000",
	"deny udp 10.0.0.0/12 -> 192.0.2.0/28 4000-14000",
}

func equalFindings(first, second []Finding) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func volumeOfBoxes(boxes []Box) *big.Int {
	total := new(big.Int)
	for _, box := range boxes {
		total.Add(total, box.Volume())
	}
	return total
}

func totalFlowVolume() *big.Int {
	total := new(big.Int).Lsh(big.NewInt(1), 81)
	total.Add(total, new(big.Int).Lsh(big.NewInt(1), 64))
	return total
}
