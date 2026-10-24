package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCheckSummaryAfterTheFindings(t *testing.T) {
	dir := t.TempDir()
	edgePath := writeCLIFile(t, dir, "edge.rules", []byte(referenceEdgeRules))

	code, stdout, stderr := runCLIForTest([]string{"check", "--summary", edgePath}, nil)
	want := `edge.rules:4: AV001 shadowed by line 3
edge.rules:7: AV001 shadowed by lines 5, 6
edge.rules:9: AV002 redundant: removing it changes no verdict
3 findings in 9 rules: 2 shadowed, 1 redundant
`
	want = strings.ReplaceAll(want, "edge.rules", filepath.ToSlash(edgePath))
	assertCLIResult(t, code, stdout, stderr, 1, want, "")
}

func TestRunCheckSummaryWithOneShadowedFinding(t *testing.T) {
	dir := t.TempDir()
	path := writeCLIFile(t, dir, "one.rules", []byte("allow tcp any -> any 80\ndeny tcp any -> any 80\n"))
	want := filepath.ToSlash(path) + ":2: AV001 shadowed by line 1\n" +
		"1 finding in 2 rules: 1 shadowed, 0 redundant\n"

	code, stdout, stderr := runCLIForTest([]string{"check", "--summary", path}, nil)
	assertCLIResult(t, code, stdout, stderr, 1, want, "")
}

func TestRunCheckSummaryWithOneRedundantFinding(t *testing.T) {
	dir := t.TempDir()
	path := writeCLIFile(t, dir, "two.rules", []byte("allow tcp 10.0.0.0/8 -> any 80\nallow tcp any -> any 80\n"))
	want := filepath.ToSlash(path) + ":1: AV002 redundant: removing it changes no verdict\n" +
		"1 finding in 2 rules: 0 shadowed, 1 redundant\n"

	code, stdout, stderr := runCLIForTest([]string{"check", path, "--summary"}, nil)
	assertCLIResult(t, code, stdout, stderr, 1, want, "")
}

func TestRunCheckSummaryRepeatedOptionCountsOnce(t *testing.T) {
	dir := t.TempDir()
	path := writeCLIFile(t, dir, "one.rules", []byte("allow tcp any -> any 80\ndeny tcp any -> any 80\n"))
	want := filepath.ToSlash(path) + ":2: AV001 shadowed by line 1\n" +
		"1 finding in 2 rules: 1 shadowed, 0 redundant\n"

	code, stdout, stderr := runCLIForTest([]string{"check", "--summary", path, "--summary"}, nil)
	assertCLIResult(t, code, stdout, stderr, 1, want, "")
}

func TestRunCheckSummaryIsNotPrintedForACleanFile(t *testing.T) {
	dir := t.TempDir()
	path := writeCLIFile(t, dir, "clean.rules", []byte("allow tcp any -> any 80\ndeny udp any -> any 53\n"))

	code, stdout, stderr := runCLIForTest([]string{"check", "--summary", path}, nil)
	assertCLIResult(t, code, stdout, stderr, 0, filepath.ToSlash(path)+": ok, 2 rules\n", "")
}

func TestRunCheckSummaryReadsStandardInput(t *testing.T) {
	code, stdout, stderr := runCLIForTest(
		[]string{"check", "--summary", "-"},
		[]byte("allow any any -> any\ndeny tcp any -> any 22\n"),
	)
	assertCLIResult(t, code, stdout, stderr, 1,
		"<stdin>:2: AV001 shadowed by line 1\n1 finding in 2 rules: 1 shadowed, 0 redundant\n", "")
}

func TestRunCheckWithoutSummaryIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := writeCLIFile(t, dir, "one.rules", []byte("allow tcp any -> any 80\ndeny tcp any -> any 80\n"))

	code, stdout, stderr := runCLIForTest([]string{"check", path}, nil)
	assertCLIResult(t, code, stdout, stderr, 1, filepath.ToSlash(path)+":2: AV001 shadowed by line 1\n", "")
}

func TestRunSummaryIsAnOptionOfCheckOnly(t *testing.T) {
	code, stdout, stderr := runCLIForTest([]string{"eval", "--summary", "rules.txt", "flows.txt"}, nil)
	assertCLIResult(t, code, stdout, stderr, 2, "", "aclvet: unknown option \"--summary\"\n")

	code, stdout, stderr = runCLIForTest([]string{"diff", "--summary", "old.txt", "new.txt"}, nil)
	assertCLIResult(t, code, stdout, stderr, 2, "", "aclvet: unknown option \"--summary\"\n")

	code, stdout, stderr = runCLIForTest([]string{"check", "--summary=1", "rules.txt"}, nil)
	assertCLIResult(t, code, stdout, stderr, 2, "", "aclvet: unknown option \"--summary=1\"\n")

	code, stdout, stderr = runCLIForTest([]string{"check", "--denied", "rules.txt"}, nil)
	assertCLIResult(t, code, stdout, stderr, 2, "", "aclvet: unknown option \"--denied\"\n")
}

func TestRunCheckSummaryStillNeedsOneFile(t *testing.T) {
	code, stdout, stderr := runCLIForTest([]string{"check", "--summary"}, nil)
	assertCLIResult(t, code, stdout, stderr, 2, "", "aclvet: missing argument\n")

	code, stdout, stderr = runCLIForTest([]string{"check", "--summary", "a.rules", "b.rules"}, nil)
	assertCLIResult(t, code, stdout, stderr, 2, "", "aclvet: too many arguments\n")
}
