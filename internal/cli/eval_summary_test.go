package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRunEvalSummaryAfterTheVerdicts(t *testing.T) {
	dir := t.TempDir()
	edgePath := writeCLIFile(t, dir, "edge.rules", []byte(referenceEdgeRules))
	flowsPath := writeCLIFile(t, dir, "flows.txt", []byte(referenceFlows))

	code, stdout, stderr := runCLIForTest([]string{"eval", "--summary", edgePath, flowsPath}, nil)
	want := `tcp 10.0.0.5 -> 10.1.2.3 443: allow (line 2)
tcp 10.2.0.9 -> 10.1.0.7 22: deny (line 3)
udp 10.9.9.9 -> 10.1.0.53 53: deny (line 9)
icmp 10.0.0.1 -> 10.1.0.1: allow (line 8)
tcp 192.168.1.1 -> 10.1.0.1 22: deny (line 3)
5 flows: 2 allowed, 3 denied
`
	assertCLIResult(t, code, stdout, stderr, 1, want, "")
}

func TestRunEvalSummaryCountsEveryFlowWithDenied(t *testing.T) {
	dir := t.TempDir()
	edgePath := writeCLIFile(t, dir, "edge.rules", []byte(referenceEdgeRules))
	flowsPath := writeCLIFile(t, dir, "flows.txt", []byte(referenceFlows))

	code, stdout, stderr := runCLIForTest([]string{"eval", "--denied", "--summary", edgePath, flowsPath}, nil)
	want := `tcp 10.2.0.9 -> 10.1.0.7 22: deny (line 3)
udp 10.9.9.9 -> 10.1.0.53 53: deny (line 9)
tcp 192.168.1.1 -> 10.1.0.1 22: deny (line 3)
5 flows: 2 allowed, 3 denied
`
	assertCLIResult(t, code, stdout, stderr, 1, want, "")
}

func TestRunEvalSummaryOfAllAllowedFlowsPrintsOnlyTheSummary(t *testing.T) {
	dir := t.TempDir()
	rules := writeCLIFile(t, dir, "open.rules", []byte("allow any any -> any\n"))
	flows := writeCLIFile(t, dir, "two.txt", []byte("tcp 10.0.0.1 10.0.0.2 80\nicmp 10.0.0.1 10.0.0.2\n"))

	code, stdout, stderr := runCLIForTest([]string{"eval", "--denied", "--summary", rules, flows}, nil)
	assertCLIResult(t, code, stdout, stderr, 0, "2 flows: 2 allowed, 0 denied\n", "")
}

func TestRunEvalSummaryUsesTheSingularForOneFlow(t *testing.T) {
	dir := t.TempDir()
	rules := writeCLIFile(t, dir, "open.rules", []byte("allow any any -> any\n"))
	flows := writeCLIFile(t, dir, "one.txt", []byte("udp 10.0.0.1 10.0.0.2 53\n"))

	code, stdout, stderr := runCLIForTest([]string{"eval", rules, flows, "--summary"}, nil)
	assertCLIResult(t, code, stdout, stderr, 0, "udp 10.0.0.1 -> 10.0.0.2 53: allow (line 1)\n1 flow: 1 allowed, 0 denied\n", "")

	denied := writeCLIFile(t, dir, "closed.rules", []byte("deny any any -> any\n"))
	code, stdout, stderr = runCLIForTest([]string{"eval", "--summary", denied, flows}, nil)
	assertCLIResult(t, code, stdout, stderr, 1, "udp 10.0.0.1 -> 10.0.0.2 53: deny (line 1)\n1 flow: 0 allowed, 1 denied\n", "")
}

func TestRunEvalSummaryCountsDefaultDenials(t *testing.T) {
	dir := t.TempDir()
	rules := writeCLIFile(t, dir, "one.rules", []byte("allow tcp 10.0.0.0/8 -> any 80\n"))
	flows := writeCLIFile(t, dir, "flows.txt", []byte("tcp 10.0.0.1 10.0.0.2 80\ntcp 192.168.0.1 10.0.0.2 80\n"))

	code, stdout, stderr := runCLIForTest([]string{"eval", "--summary", rules, flows}, nil)
	want := "tcp 10.0.0.1 -> 10.0.0.2 80: allow (line 1)\n" +
		"tcp 192.168.0.1 -> 10.0.0.2 80: deny (default)\n" +
		"2 flows: 1 allowed, 1 denied\n"
	assertCLIResult(t, code, stdout, stderr, 1, want, "")
}

func TestRunEvalSummaryRepeatedOptionCountsOnce(t *testing.T) {
	dir := t.TempDir()
	rules := writeCLIFile(t, dir, "open.rules", []byte("allow any any -> any\n"))
	flows := writeCLIFile(t, dir, "one.txt", []byte("udp 10.0.0.1 10.0.0.2 53\n"))

	code, stdout, stderr := runCLIForTest([]string{"eval", "--summary", rules, "--summary", flows, "--summary"}, nil)
	assertCLIResult(t, code, stdout, stderr, 0, "udp 10.0.0.1 -> 10.0.0.2 53: allow (line 1)\n1 flow: 1 allowed, 0 denied\n", "")
}

func TestRunEvalSummaryReadsStandardInput(t *testing.T) {
	dir := t.TempDir()
	rules := writeCLIFile(t, dir, "open.rules", []byte("allow any any -> any\n"))

	code, stdout, stderr := runCLIForTest([]string{"eval", "--summary", rules, "-"}, []byte("tcp 10.0.0.1 10.0.0.2 80\n"))
	assertCLIResult(t, code, stdout, stderr, 0, "tcp 10.0.0.1 -> 10.0.0.2 80: allow (line 1)\n1 flow: 1 allowed, 0 denied\n", "")
}

func TestRunEvalWithoutSummaryIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	rules := writeCLIFile(t, dir, "open.rules", []byte("allow any any -> any\n"))
	flows := writeCLIFile(t, dir, "one.txt", []byte("udp 10.0.0.1 10.0.0.2 53\n"))

	code, stdout, stderr := runCLIForTest([]string{"eval", rules, flows}, nil)
	assertCLIResult(t, code, stdout, stderr, 0, "udp 10.0.0.1 -> 10.0.0.2 53: allow (line 1)\n", "")
	if strings.Contains(stdout, "flow:") {
		t.Errorf("eval without --summary printed a summary: %q", stdout)
	}
}

func TestRunEvalSummaryErrorsPrintNoSummary(t *testing.T) {
	dir := t.TempDir()
	rules := writeCLIFile(t, dir, "open.rules", []byte("allow any any -> any\n"))
	bad := writeCLIFile(t, dir, "bad.txt", []byte("tcp 10.0.0.1 10.0.0.2\n"))

	code, stdout, stderr := runCLIForTest([]string{"eval", "--summary", rules, bad}, nil)
	assertCLIResult(t, code, stdout, stderr, 2, "", "aclvet: "+filepath.ToSlash(bad)+":1: missing port\n")
}

func TestRunSummaryIsStillRefusedByDiff(t *testing.T) {
	code, stdout, stderr := runCLIForTest([]string{"diff", "--summary", "old.rules", "new.rules"}, nil)
	assertCLIResult(t, code, stdout, stderr, 2, "", "aclvet: unknown option \"--summary\"\n")
}
