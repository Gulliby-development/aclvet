package acl

import (
	"math/big"
	"testing"
	"time"
)

func TestDiffCountsAndDefaultDecisions(t *testing.T) {
	tests := []struct {
		name string
		old  string
		new  string
		want []DiffChange
	}{
		{
			name: "all-protocol count is exact above 64 bits",
			old:  "allow any any -> any\n",
			new:  "deny any any -> any\n",
			want: []DiffChange{{
				Old:   Verdict{Allow: true, Line: 1},
				New:   Verdict{Allow: false, Line: 1},
				Flows: mustBigInt(t, "2417870085973332058963968"),
			}},
		},
		{
			name: "new default is a changed decider",
			old:  "allow any any -> any\n",
			new:  "allow tcp any -> any\n",
			want: []DiffChange{{
				Old:   Verdict{Allow: true, Line: 1},
				New:   Verdict{Default: true},
				Flows: mustBigInt(t, "1208944266358702884257792"),
			}},
		},
		{
			name: "old default is a changed decider for one flow",
			old:  "",
			new:  "allow tcp 10.0.0.1 -> 10.0.0.2 7\n",
			want: []DiffChange{{
				Old:   Verdict{Default: true},
				New:   Verdict{Allow: true, Line: 1},
				Flows: big.NewInt(1),
			}},
		},
		{
			name: "identical lists have no changes",
			old:  "allow tcp any -> any 80\ndeny udp any -> any 53\n",
			new:  "allow tcp any -> any 80\ndeny udp any -> any 53\n",
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			oldRules, err := ParseRules("old.rules", test.old)
			if err != nil {
				t.Fatalf("ParseRules(old) error = %v, want nil", err)
			}
			newRules, err := ParseRules("new.rules", test.new)
			if err != nil {
				t.Fatalf("ParseRules(new) error = %v, want nil", err)
			}

			assertDiffChanges(t, Diff(oldRules, newRules), test.want)
		})
	}
}

func TestDiffOrdersDeciderPairsByOldThenNewLine(t *testing.T) {
	oldRules, err := ParseRules("old.rules", ""+
		"allow tcp any -> any 80\n"+
		"allow tcp any -> any 81\n"+
		"allow udp 192.0.2.1 -> 198.51.100.2 53\n")
	if err != nil {
		t.Fatalf("ParseRules(old) error = %v, want nil", err)
	}
	newRules, err := ParseRules("new.rules", ""+
		"deny tcp any -> any 81\n"+
		"deny tcp any -> any 80\n"+
		"deny udp 192.0.2.1 -> 198.51.100.2 53\n"+
		"allow tcp any -> any 82\n")
	if err != nil {
		t.Fatalf("ParseRules(new) error = %v, want nil", err)
	}

	want := []DiffChange{
		{
			Old:   Verdict{Allow: true, Line: 1},
			New:   Verdict{Allow: false, Line: 2},
			Flows: mustBigInt(t, "18446744073709551616"),
		},
		{
			Old:   Verdict{Allow: true, Line: 2},
			New:   Verdict{Allow: false, Line: 1},
			Flows: mustBigInt(t, "18446744073709551616"),
		},
		{
			Old:   Verdict{Allow: true, Line: 3},
			New:   Verdict{Allow: false, Line: 3},
			Flows: big.NewInt(1),
		},
		{
			Old:   Verdict{Default: true},
			New:   Verdict{Allow: true, Line: 4},
			Flows: mustBigInt(t, "18446744073709551616"),
		},
	}
	got := Diff(oldRules, newRules)
	assertDiffChanges(t, got, want)

	total := new(big.Int)
	for _, change := range got {
		total.Add(total, change.Flows)
	}
	if got, want := total.String(), "55340232221128654849"; got != want {
		t.Errorf("total changed flows = %s, want %s", got, want)
	}
}

func TestDiffOverlapping150RuleWorkloadCompletesWithinFiveSeconds(t *testing.T) {
	const oldRulesText = `allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65534-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65534-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65533-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65533-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65532-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65532-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65531-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65531-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65530-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65530-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65529-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65529-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65528-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65528-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65527-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65527-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65526-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65526-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65525-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65525-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65524-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65524-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65523-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65523-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65522-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65522-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65521-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65521-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65520-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65520-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65519-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65519-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65518-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65518-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65517-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65517-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65516-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65516-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65515-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65515-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65514-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65514-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65513-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65513-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65512-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65512-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65511-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65511-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65510-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65510-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65509-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65509-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65508-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65508-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65507-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65507-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65506-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65506-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65505-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65505-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65504-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65504-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65503-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65503-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65502-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65502-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65501-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65501-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65500-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65500-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65499-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65499-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65498-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65498-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65497-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65497-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65496-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65496-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65495-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65495-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65494-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65494-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65493-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65493-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65492-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65492-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65491-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65491-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65490-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65490-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65489-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65489-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65488-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65488-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65487-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65487-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65486-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65486-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65485-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65485-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65484-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65484-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65483-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65483-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65482-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65482-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65481-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65481-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65480-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65480-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65479-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65479-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65478-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65478-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65477-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65477-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65476-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65476-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65475-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65475-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65474-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65474-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65473-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65473-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65472-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65472-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65471-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65471-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65470-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65470-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65469-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65469-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65468-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65468-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65467-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65467-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65466-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65466-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65465-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65465-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65464-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65464-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65463-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65463-65535
allow tcp 10.0.0.0/9 -> 192.0.2.0/25 65462-65535
allow udp 10.0.0.0/9 -> 192.0.2.0/25 65462-65535
allow tcp 10.0.0.0/8 -> 192.0.2.0/24 65461-65535
allow udp 10.0.0.0/8 -> 192.0.2.0/24 65461-65535`
	const newRulesText = `deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65534-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65534-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65533-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65533-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65532-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65532-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65531-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65531-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65530-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65530-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65529-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65529-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65528-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65528-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65527-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65527-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65526-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65526-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65525-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65525-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65524-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65524-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65523-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65523-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65522-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65522-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65521-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65521-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65520-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65520-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65519-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65519-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65518-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65518-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65517-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65517-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65516-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65516-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65515-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65515-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65514-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65514-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65513-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65513-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65512-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65512-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65511-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65511-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65510-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65510-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65509-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65509-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65508-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65508-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65507-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65507-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65506-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65506-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65505-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65505-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65504-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65504-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65503-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65503-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65502-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65502-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65501-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65501-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65500-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65500-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65499-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65499-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65498-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65498-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65497-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65497-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65496-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65496-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65495-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65495-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65494-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65494-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65493-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65493-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65492-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65492-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65491-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65491-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65490-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65490-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65489-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65489-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65488-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65488-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65487-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65487-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65486-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65486-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65485-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65485-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65484-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65484-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65483-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65483-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65482-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65482-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65481-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65481-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65480-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65480-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65479-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65479-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65478-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65478-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65477-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65477-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65476-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65476-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65475-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65475-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65474-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65474-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65473-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65473-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65472-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65472-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65471-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65471-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65470-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65470-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65469-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65469-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65468-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65468-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65467-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65467-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65466-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65466-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65465-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65465-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65464-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65464-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65463-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65463-65535
deny tcp 10.0.0.0/9 -> 192.0.2.0/25 65462-65535
deny udp 10.0.0.0/9 -> 192.0.2.0/25 65462-65535
deny tcp 10.0.0.0/8 -> 192.0.2.0/24 65461-65535
deny udp 10.0.0.0/8 -> 192.0.2.0/24 65461-65535`

	oldRules, err := ParseRules("old.rules", oldRulesText)
	if err != nil {
		t.Fatalf("ParseRules(old fixture) error = %v, want nil", err)
	}
	newRules, err := ParseRules("new.rules", newRulesText)
	if err != nil {
		t.Fatalf("ParseRules(new fixture) error = %v, want nil", err)
	}
	if len(oldRules) != 150 || len(newRules) != 150 {
		t.Fatalf("fixture sizes = %d old and %d new rules, want 150 each", len(oldRules), len(newRules))
	}
	for index := range oldRules {
		wantProtocol := ProtocolTCP
		if index%2 == 1 {
			wantProtocol = ProtocolUDP
		}
		if len(oldRules[index].Boxes) != 1 || oldRules[index].Boxes[0].Protocol != wantProtocol {
			t.Errorf("old fixture rule %d does not cover %s as expected", index+1, wantProtocol)
		}
		if len(newRules[index].Boxes) != 1 || newRules[index].Boxes[0].Protocol != wantProtocol {
			t.Errorf("new fixture rule %d does not cover %s as expected", index+1, wantProtocol)
		}
	}

	started := time.Now()
	changes := Diff(oldRules, newRules)
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Errorf("Diff() on two 150-rule overlapping lists took %s, want no more than 5s", elapsed)
	}
	if len(changes) != 150 {
		t.Fatalf("Diff() returned %d changes, want 150", len(changes))
	}
	for index, change := range changes {
		wantLine := index + 1
		if change.Old.Line != wantLine || change.New.Line != wantLine {
			t.Errorf("Diff() change %d deciders are old line %d and new line %d, want line %d on both sides", index, change.Old.Line, change.New.Line, wantLine)
		}
		if change.Old.Allow != true || change.New.Allow != false {
			t.Errorf("Diff() change %d actions are old allow=%t and new allow=%t, want allow and deny", index, change.Old.Allow, change.New.Allow)
		}
		ruleWithinProtocol := index / 2
		wantFlows := "1073741824"
		switch {
		case ruleWithinProtocol == 0:
			wantFlows = "4294967296"
		case ruleWithinProtocol%2 == 0:
			wantFlows = "7516192768"
		}
		if change.Flows == nil || change.Flows.String() != wantFlows {
			t.Errorf("Diff() change %d flow count = %v, want %s", index, change.Flows, wantFlows)
		}
	}
}

func assertDiffChanges(t *testing.T, got, want []DiffChange) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("Diff() returned %d changes, want %d: %#v", len(got), len(want), got)
	}
	for index := range want {
		if got[index].Old != want[index].Old {
			t.Errorf("Diff() change %d old verdict = %#v, want %#v", index, got[index].Old, want[index].Old)
		}
		if got[index].New != want[index].New {
			t.Errorf("Diff() change %d new verdict = %#v, want %#v", index, got[index].New, want[index].New)
		}
		if got[index].Flows == nil || got[index].Flows.Cmp(want[index].Flows) != 0 {
			t.Errorf("Diff() change %d flow count = %v, want %s", index, got[index].Flows, want[index].Flows)
		}
	}
}

func mustBigInt(t *testing.T, decimal string) *big.Int {
	t.Helper()
	value, ok := new(big.Int).SetString(decimal, 10)
	if !ok {
		t.Fatalf("SetString(%q) failed", decimal)
	}
	return value
}
