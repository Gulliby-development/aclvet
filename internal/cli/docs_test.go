package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestREADMEExamplesMatchReference(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	document := string(readme)

	assertREADMECodeBlock(t, document, expectedUsage)
	assertREADMECodeBlock(t, document, referenceEdgeRules)
	assertREADMECodeBlock(t, document, referenceFlows)
	assertREADMECodeBlock(t, document, referenceNewRules)

	for _, heading := range []string{
		"## Install",
		"## Usage",
		"## Rule file",
		"## Findings",
		"## Exit codes",
		"## Development",
	} {
		if !strings.Contains(document, heading) {
			t.Errorf("README is missing heading %q", heading)
		}
	}

	dir := t.TempDir()
	edgePath := writeCLIFile(t, dir, "edge.rules", []byte(referenceEdgeRules))
	flowsPath := writeCLIFile(t, dir, "flows.txt", []byte(referenceFlows))
	newPath := writeCLIFile(t, dir, "new.rules", []byte(referenceNewRules))

	checkCode, checkOutput, checkError := runCLIForTest([]string{"check", edgePath}, nil)
	if checkCode != 1 || checkError != "" {
		t.Fatalf("check example returned code %d and stderr %q", checkCode, checkError)
	}
	checkOutput = strings.ReplaceAll(checkOutput, filepath.ToSlash(edgePath), "edge.rules")
	assertREADMECodeBlock(t, document, checkOutput)

	evalCode, evalOutput, evalError := runCLIForTest([]string{"eval", edgePath, flowsPath}, nil)
	if evalCode != 1 || evalError != "" {
		t.Fatalf("eval example returned code %d and stderr %q", evalCode, evalError)
	}
	assertREADMECodeBlock(t, document, evalOutput)

	diffCode, diffOutput, diffError := runCLIForTest([]string{"diff", edgePath, newPath}, nil)
	if diffCode != 1 || diffError != "" {
		t.Fatalf("diff example returned code %d and stderr %q", diffCode, diffError)
	}
	assertREADMECodeBlock(t, document, diffOutput)
}

func assertREADMECodeBlock(t *testing.T, document, body string) {
	t.Helper()
	block := "```\n" + body + "```"
	if !strings.Contains(document, block) {
		t.Errorf("README is missing exact code block:\n%s", body)
	}
}
