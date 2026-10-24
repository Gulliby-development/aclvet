package cli

import (
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/Gulliby-development/aclvet/internal/acl"
)

const usage = "usage: aclvet check [--summary] FILE\n       aclvet eval [--denied] RULES FLOWS\n       aclvet diff OLD NEW\n"

// Run executes the requested aclvet command using the supplied streams.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	parsed, help, err := parseArgs(args)
	if help {
		_, _ = io.WriteString(stdout, usage)
		return 0
	}
	if err != nil {
		writeError(stderr, err.Error())
		return 2
	}

	switch parsed.command {
	case "check":
		rules, err := readRules(parsed.files[0], stdin)
		if err != nil {
			writeError(stderr, err.Error())
			return 2
		}
		findings := acl.Check(rules)
		var output strings.Builder
		if len(findings) == 0 {
			word := "rules"
			if len(rules) == 1 {
				word = "rule"
			}
			fmt.Fprintf(&output, "%s: ok, %d %s\n", displayPath(parsed.files[0]), len(rules), word)
			_, _ = io.WriteString(stdout, output.String())
			return 0
		}
		for _, finding := range findings {
			fmt.Fprintf(&output, "%s:%d: %s %s\n",
				displayPath(parsed.files[0]), finding.Line, finding.Code, finding.Message)
		}
		if parsed.summary {
			output.WriteString(summaryLine(findings, len(rules)))
		}
		_, _ = io.WriteString(stdout, output.String())
		return 1

	case "eval":
		rules, err := readRules(parsed.files[0], stdin)
		if err != nil {
			writeError(stderr, err.Error())
			return 2
		}
		flows, err := readFlows(parsed.files[1], stdin)
		if err != nil {
			writeError(stderr, err.Error())
			return 2
		}
		var output strings.Builder
		allAllowed := true
		for _, flow := range flows {
			verdict := acl.Evaluate(rules, flow)
			action := "deny"
			if verdict.Allow {
				action = "allow"
			} else {
				allAllowed = false
			}
			if parsed.deniedOnly && verdict.Allow {
				continue
			}
			if verdict.Default {
				fmt.Fprintf(&output, "%s %s -> %s", flow.Protocol, flow.SourceText, flow.DestinationText)
				if flow.Protocol != acl.ProtocolICMP {
					fmt.Fprintf(&output, " %s", flow.PortText)
				}
				fmt.Fprintf(&output, ": %s (default)\n", action)
				continue
			}
			fmt.Fprintf(&output, "%s %s -> %s", flow.Protocol, flow.SourceText, flow.DestinationText)
			if flow.Protocol != acl.ProtocolICMP {
				fmt.Fprintf(&output, " %s", flow.PortText)
			}
			fmt.Fprintf(&output, ": %s (line %d)\n", action, verdict.Line)
		}
		_, _ = io.WriteString(stdout, output.String())
		if allAllowed {
			return 0
		}
		return 1

	case "diff":
		oldRules, err := readRules(parsed.files[0], stdin)
		if err != nil {
			writeError(stderr, err.Error())
			return 2
		}
		newRules, err := readRules(parsed.files[1], stdin)
		if err != nil {
			writeError(stderr, err.Error())
			return 2
		}
		changes := acl.Diff(oldRules, newRules)
		if len(changes) == 0 {
			_, _ = io.WriteString(stdout, "no verdict changes\n")
			return 0
		}
		var output strings.Builder
		total := new(big.Int)
		for _, change := range changes {
			oldAction := verdictAction(change.Old)
			newAction := verdictAction(change.New)
			fmt.Fprintf(&output, "%s -> %s (old %s, new %s): %s flow%s\n",
				oldAction, newAction, decisionLabel(change.Old), decisionLabel(change.New),
				change.Flows.String(), plural(change.Flows))
			total.Add(total, change.Flows)
		}
		changeVerb := "change"
		if plural(total) == "" {
			changeVerb = "changes"
		}
		fmt.Fprintf(&output, "%s flow%s %s verdict\n", total.String(), plural(total), changeVerb)
		_, _ = io.WriteString(stdout, output.String())
		return 1
	}

	return 2
}

func readRules(name string, stdin io.Reader) ([]acl.Rule, error) {
	data, err := readInput(name, stdin)
	display := displayPath(name)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot read the file", display)
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%s: input is not valid UTF-8", display)
	}
	rules, err := acl.ParseRules(display, string(data))
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("%s: no rules", display)
	}
	return rules, nil
}

func readFlows(name string, stdin io.Reader) ([]acl.Flow, error) {
	data, err := readInput(name, stdin)
	display := displayPath(name)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot read the file", display)
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%s: input is not valid UTF-8", display)
	}
	flows, err := acl.ParseFlows(display, string(data))
	if err != nil {
		return nil, err
	}
	if len(flows) == 0 {
		return nil, fmt.Errorf("%s: no flows", display)
	}
	return flows, nil
}

func readInput(name string, stdin io.Reader) ([]byte, error) {
	if name == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(name)
}

func displayPath(path string) string {
	if path == "-" {
		return "<stdin>"
	}
	return strings.ReplaceAll(path, "\\", "/")
}

func writeError(stderr io.Writer, message string) {
	_, _ = fmt.Fprintf(stderr, "aclvet: %s\n", message)
}

func verdictAction(verdict acl.Verdict) string {
	if verdict.Allow {
		return "allow"
	}
	return "deny"
}

func decisionLabel(verdict acl.Verdict) string {
	if verdict.Default {
		return "default"
	}
	return fmt.Sprintf("line %d", verdict.Line)
}

func summaryLine(findings []acl.Finding, ruleCount int) string {
	shadowed, redundant := 0, 0
	for _, finding := range findings {
		if finding.Code == "AV001" {
			shadowed++
		} else {
			redundant++
		}
	}
	return fmt.Sprintf("%d %s in %d %s: %d shadowed, %d redundant\n",
		len(findings), countWord("finding", len(findings)),
		ruleCount, countWord("rule", ruleCount), shadowed, redundant)
}

func countWord(word string, count int) string {
	if count == 1 {
		return word
	}
	return word + "s"
}

func plural(count *big.Int) string {
	if count.Cmp(big.NewInt(1)) == 0 {
		return ""
	}
	return "s"
}
