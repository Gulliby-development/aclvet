package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const referenceEdgeRules = `# edge firewall
allow tcp 10.0.0.0/8 -> 10.1.0.0/16 443
deny  tcp any -> 10.1.0.0/16 22
allow tcp 10.2.0.0/16 -> 10.1.0.0/16 22
deny  tcp 10.0.0.0/9 -> any 1-1023
deny  tcp 10.128.0.0/9 -> any 1-1023
allow tcp 10.0.0.0/8 -> any 80
allow icmp 10.0.0.0/8 -> any
deny  udp any -> any 53
deny  any any -> any
`

const referenceFlows = `tcp 10.0.0.5 10.1.2.3 443
tcp 10.2.0.9 10.1.0.7 22
udp 10.9.9.9 10.1.0.53 53
icmp 10.0.0.1 10.1.0.1
tcp 192.168.1.1 10.1.0.1 22
`

const referenceNewRules = `# edge firewall, revised
allow tcp 10.0.0.0/8 -> 10.1.0.0/16 443
allow tcp 10.0.0.0/8 -> 10.1.0.0/16 8443
deny  tcp any -> 10.1.0.0/16 22
allow tcp 10.2.0.0/16 -> 10.1.0.0/16 22
allow icmp 10.0.0.0/16 -> any
deny  any any -> any
`

const expectedUsage = `usage: aclvet check FILE
       aclvet eval RULES FLOWS
       aclvet diff OLD NEW
`

func TestRunReferenceExamples(t *testing.T) {
	dir := t.TempDir()
	edgePath := writeCLIFile(t, dir, "edge.rules", []byte(referenceEdgeRules))
	flowsPath := writeCLIFile(t, dir, "flows.txt", []byte(referenceFlows))
	newPath := writeCLIFile(t, dir, "new.rules", []byte(referenceNewRules))

	t.Run("check output and findings", func(t *testing.T) {
		code, stdout, stderr := runCLIForTest([]string{"check", edgePath}, nil)
		want := `edge.rules:4: AV001 shadowed by line 3
edge.rules:7: AV001 shadowed by lines 5, 6
edge.rules:9: AV002 redundant: removing it changes no verdict
`
		want = strings.ReplaceAll(want, "edge.rules", filepath.ToSlash(edgePath))
		assertCLIResult(t, code, stdout, stderr, 1, want, "")
	})

	t.Run("eval output and denied-flow exit", func(t *testing.T) {
		code, stdout, stderr := runCLIForTest([]string{"eval", edgePath, flowsPath}, nil)
		want := `tcp 10.0.0.5 -> 10.1.2.3 443: allow (line 2)
tcp 10.2.0.9 -> 10.1.0.7 22: deny (line 3)
udp 10.9.9.9 -> 10.1.0.53 53: deny (line 9)
icmp 10.0.0.1 -> 10.1.0.1: allow (line 8)
tcp 192.168.1.1 -> 10.1.0.1 22: deny (line 3)
`
		assertCLIResult(t, code, stdout, stderr, 1, want, "")
	})

	t.Run("diff exact counts and ordering", func(t *testing.T) {
		code, stdout, stderr := runCLIForTest([]string{"diff", edgePath, newPath}, nil)
		want := `allow -> deny (old line 8, new line 7): 71776119061217280 flows
deny -> allow (old line 10, new line 3): 1099511627776 flows
71777218572845056 flows change verdict
`
		assertCLIResult(t, code, stdout, stderr, 1, want, "")
	})
}

func TestRunDiffExactChangedVerdictOutputs(t *testing.T) {
	tests := []struct {
		name       string
		oldRules   string
		newRules   string
		wantStdout string
	}{
		{
			name:     "one changed flow uses singular forms",
			oldRules: "deny any any -> any\n",
			newRules: "allow tcp 10.0.0.1 -> 10.0.0.2 7\n",
			wantStdout: "deny -> allow (old line 1, new line 1): 1 flow\n" +
				"1 flow changes verdict\n",
		},
		{
			name:     "all protocols have the exact large count",
			oldRules: "allow any any -> any\n",
			newRules: "deny any any -> any\n",
			wantStdout: "allow -> deny (old line 1, new line 1): " +
				"2417870085973332058963968 flows\n" +
				"2417870085973332058963968 flows change verdict\n",
		},
		{
			name:     "new default is a changed decider",
			oldRules: "allow any any -> any\n",
			newRules: "allow tcp any -> any\n",
			wantStdout: "allow -> deny (old line 1, new default): " +
				"1208944266358702884257792 flows\n" +
				"1208944266358702884257792 flows change verdict\n",
		},
		{
			name:     "old default is a changed decider",
			oldRules: "deny tcp 192.0.2.1 -> 198.51.100.1 7\n",
			newRules: "allow tcp 10.0.0.1 -> 10.0.0.2 7\n",
			wantStdout: "deny -> allow (old default, new line 1): 1 flow\n" +
				"1 flow changes verdict\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			oldPath := writeCLIFile(t, dir, "old.rules", []byte(test.oldRules))
			newPath := writeCLIFile(t, dir, "new.rules", []byte(test.newRules))

			code, stdout, stderr := runCLIForTest([]string{"diff", oldPath, newPath}, nil)
			assertCLIResult(t, code, stdout, stderr, 1, test.wantStdout, "")
		})
	}
}

func TestRunSuccessfulCheckAndUnchangedDiff(t *testing.T) {
	dir := t.TempDir()
	oneRulePath := writeCLIFile(t, dir, "one.rules", []byte("deny any any -> any\n"))
	oldPath := writeCLIFile(t, dir, "old.rules", []byte("allow tcp any -> any 443\n"))
	newPath := writeCLIFile(t, dir, "new.rules", []byte("allow tcp any -> any 443\n"))

	t.Run("single rule uses singular form", func(t *testing.T) {
		code, stdout, stderr := runCLIForTest([]string{"check", oneRulePath}, nil)
		assertCLIResult(t, code, stdout, stderr, 0, filepath.ToSlash(oneRulePath)+": ok, 1 rule\n", "")
	})

	t.Run("identical verdict partitions report no changes", func(t *testing.T) {
		code, stdout, stderr := runCLIForTest([]string{"diff", oldPath, newPath}, nil)
		assertCLIResult(t, code, stdout, stderr, 0, "no verdict changes\n", "")
	})
}

func TestRunHelpAndUsageErrors(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "help alone", args: []string{"--help"}, wantCode: 0, wantStdout: expectedUsage},
		{name: "missing command", wantCode: 2, wantStderr: "aclvet: missing command (check, eval or diff)\n"},
		{name: "unknown command", args: []string{"remove"}, wantCode: 2, wantStderr: "aclvet: unknown command \"remove\"\n"},
		{name: "unknown option", args: []string{"check", "--help"}, wantCode: 2, wantStderr: "aclvet: unknown option \"--help\"\n"},
		{name: "missing argument", args: []string{"eval", "rules.txt"}, wantCode: 2, wantStderr: "aclvet: missing argument\n"},
		{name: "too many arguments", args: []string{"check", "rules.txt", "extra.txt"}, wantCode: 2, wantStderr: "aclvet: too many arguments\n"},
		{name: "stdin given twice", args: []string{"diff", "-", "-"}, wantCode: 2, wantStderr: "aclvet: standard input given twice\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runCLIForTest(tt.args, nil)
			assertCLIResult(t, code, stdout, stderr, tt.wantCode, tt.wantStdout, tt.wantStderr)
		})
	}
}

func TestRunInputErrors(t *testing.T) {
	tests := []struct {
		name         string
		command      string
		writeRules   bool
		rules        []byte
		writeFlows   bool
		flows        []byte
		errorFile    string
		errorLine    int
		errorMessage string
	}{
		{
			name:         "missing rule file",
			command:      "check",
			errorFile:    "rules",
			errorMessage: "cannot read the file",
		},
		{
			name:         "invalid UTF-8 rule file",
			command:      "check",
			writeRules:   true,
			rules:        []byte{0xff, '\n'},
			errorFile:    "rules",
			errorMessage: "input is not valid UTF-8",
		},
		{
			name:         "malformed rule line",
			command:      "check",
			writeRules:   true,
			rules:        []byte("allow tcp any any 80\n"),
			errorFile:    "rules",
			errorLine:    1,
			errorMessage: "expected \"ACTION PROTO SRC -> DST [PORTS]\"",
		},
		{
			name:         "host bits are rejected",
			command:      "check",
			writeRules:   true,
			rules:        []byte("allow tcp 10.0.0.1/8 -> any\n"),
			errorFile:    "rules",
			errorLine:    1,
			errorMessage: "invalid address \"10.0.0.1/8\" (host bits are set)",
		},
		{
			name:         "ports require tcp or udp",
			command:      "check",
			writeRules:   true,
			rules:        []byte("allow icmp any -> any 1\n"),
			errorFile:    "rules",
			errorLine:    1,
			errorMessage: "ports need tcp or udp",
		},
		{
			name:         "invalid port range",
			command:      "check",
			writeRules:   true,
			rules:        []byte("allow tcp any -> any 080\n"),
			errorFile:    "rules",
			errorLine:    1,
			errorMessage: "invalid ports \"080\" (expected any, N or N-M with 0 <= N <= M <= 65535)",
		},
		{
			name:         "empty rule file",
			command:      "check",
			writeRules:   true,
			rules:        []byte("# only a comment\n"),
			errorFile:    "rules",
			errorMessage: "no rules",
		},
		{
			name:         "invalid flow file",
			command:      "eval",
			writeRules:   true,
			rules:        []byte("allow tcp any -> any 80\n"),
			writeFlows:   true,
			flows:        []byte("tcp 10.0.0.1 10.0.0.2\n"),
			errorFile:    "flows",
			errorLine:    1,
			errorMessage: "missing port",
		},
		{
			name:         "empty flow file",
			command:      "eval",
			writeRules:   true,
			rules:        []byte("allow tcp any -> any 80\n"),
			writeFlows:   true,
			flows:        []byte("# only a comment\n"),
			errorFile:    "flows",
			errorMessage: "no flows",
		},
		{
			name:         "first file is parsed before second is read",
			command:      "eval",
			writeRules:   true,
			rules:        []byte("allow tcp any any 80\n"),
			errorFile:    "rules",
			errorLine:    1,
			errorMessage: "expected \"ACTION PROTO SRC -> DST [PORTS]\"",
		},
		{
			name:         "second file read error follows valid rules",
			command:      "eval",
			writeRules:   true,
			rules:        []byte("allow tcp any -> any 80\n"),
			errorFile:    "flows",
			errorMessage: "cannot read the file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			rulesPath := filepath.Join(dir, "rules.txt")
			flowsPath := filepath.Join(dir, "flows.txt")
			if tt.writeRules {
				writeCLIFile(t, dir, "rules.txt", tt.rules)
			}
			if tt.writeFlows {
				writeCLIFile(t, dir, "flows.txt", tt.flows)
			}

			args := []string{"check", rulesPath}
			if tt.command == "eval" {
				args = []string{"eval", rulesPath, flowsPath}
			}
			errorPath := rulesPath
			if tt.errorFile == "flows" {
				errorPath = flowsPath
			}
			location := filepath.ToSlash(errorPath)
			if tt.errorLine > 0 {
				location += ":" + strconv.Itoa(tt.errorLine)
			}
			wantStderr := "aclvet: " + location + ": " + tt.errorMessage + "\n"
			code, stdout, stderr := runCLIForTest(args, nil)
			assertCLIResult(t, code, stdout, stderr, 2, "", wantStderr)
		})
	}
}

func TestRunPathNormalizationAndStdin(t *testing.T) {
	t.Run("backslashes in a missing path are printed as slashes", func(t *testing.T) {
		code, stdout, stderr := runCLIForTest([]string{"check", "missing\\rules.txt"}, nil)
		assertCLIResult(t, code, stdout, stderr, 2, "", "aclvet: missing/rules.txt: cannot read the file\n")
	})

	t.Run("check reads standard input under its display name", func(t *testing.T) {
		code, stdout, stderr := runCLIForTest([]string{"check", "-"}, []byte("deny any any -> any\n"))
		assertCLIResult(t, code, stdout, stderr, 0, "<stdin>: ok, 1 rule\n", "")
	})

	t.Run("eval can read flows from standard input", func(t *testing.T) {
		dir := t.TempDir()
		rulesPath := writeCLIFile(t, dir, "rules.txt", []byte("allow tcp any -> any 80\n"))
		flow := []byte("tcp 1.2.3.4 5.6.7.8 80\n")
		code, stdout, stderr := runCLIForTest([]string{"eval", rulesPath, "-"}, flow)
		want := "tcp 1.2.3.4 -> 5.6.7.8 80: allow (line 1)\n"
		assertCLIResult(t, code, stdout, stderr, 0, want, "")
	})

	t.Run("eval can read rules from standard input", func(t *testing.T) {
		dir := t.TempDir()
		flowsPath := writeCLIFile(t, dir, "flows.txt", []byte("icmp 1.2.3.4 5.6.7.8\n"))
		code, stdout, stderr := runCLIForTest([]string{"eval", "-", flowsPath}, []byte("allow icmp any -> any\n"))
		assertCLIResult(t, code, stdout, stderr, 0, "icmp 1.2.3.4 -> 5.6.7.8: allow (line 1)\n", "")
	})
}

func TestRunBOMCRLFAndLFOutput(t *testing.T) {
	dir := t.TempDir()
	rulesPath := writeCLIFile(t, dir, "rules.txt", []byte("\ufeffallow tcp any -> any 80\r\n"))
	code, stdout, stderr := runCLIForTest([]string{"check", rulesPath}, nil)
	assertCLIResult(t, code, stdout, stderr, 0, filepath.ToSlash(rulesPath)+": ok, 1 rule\n", "")
	if strings.Contains(stdout, "\r") || strings.Contains(stderr, "\r") {
		t.Fatalf("Run output contains CR: stdout %q, stderr %q", stdout, stderr)
	}
}

func runCLIForTest(args []string, stdin []byte) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := Run(args, bytes.NewReader(stdin), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func writeCLIFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func assertCLIResult(t *testing.T, code int, stdout, stderr string, wantCode int, wantStdout, wantStderr string) {
	t.Helper()
	if code != wantCode {
		t.Errorf("Run exit code = %d, want %d", code, wantCode)
	}
	if stdout != wantStdout {
		t.Errorf("Run stdout = %q, want %q", stdout, wantStdout)
	}
	if stderr != wantStderr {
		t.Errorf("Run stderr = %q, want %q", stderr, wantStderr)
	}
	if strings.Contains(stdout, "\r") || strings.Contains(stderr, "\r") {
		t.Errorf("Run output contains CR: stdout %q, stderr %q", stdout, stderr)
	}
}
