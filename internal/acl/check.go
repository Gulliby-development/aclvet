package acl

import (
	"sort"
	"strconv"
	"strings"
)

// Finding is one check diagnostic attached to a rule's physical input line.
type Finding struct {
	Line    int
	Code    string
	Message string
}

// Check reports shadowed and redundant rules in file order.
func Check(rules []Rule) []Finding {
	regions := ComputeRegions(rules)
	findings := make([]Finding, 0)

	for index, rule := range rules {
		if len(regions.Decided[index]) == 0 {
			coveringLine := 0
			var partialLines []string
			for previous := 0; previous < index; previous++ {
				if ruleCoversBoxes(rules[previous], rule.Boxes) {
					coveringLine = rules[previous].Line
					break
				}
				if rulesIntersect(rules[previous], rule.Boxes) {
					partialLines = append(partialLines, strconv.Itoa(rules[previous].Line))
				}
			}

			message := ""
			if coveringLine != 0 {
				message = "shadowed by line " + strconv.Itoa(coveringLine)
			} else if len(partialLines) > 0 {
				message = "shadowed by lines " + strings.Join(partialLines, ", ")
			}
			if message != "" {
				findings = append(findings, Finding{Line: rule.Line, Code: "AV001", Message: message})
			}
			continue
		}

		if redundantAfterRule(regions.Decided[index], rules, index) {
			findings = append(findings, Finding{
				Line:    rule.Line,
				Code:    "AV002",
				Message: "redundant: removing it changes no verdict",
			})
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].Line < findings[j].Line
	})
	return findings
}

func ruleCoversBoxes(rule Rule, targets []Box) bool {
	for _, target := range targets {
		remaining := []Box{target}
		for _, cover := range rule.Boxes {
			remaining = subtractFromBoxes(remaining, cover)
			if len(remaining) == 0 {
				break
			}
		}
		if len(remaining) != 0 {
			return false
		}
	}
	return true
}

func rulesIntersect(rule Rule, targets []Box) bool {
	for _, own := range targets {
		for _, candidate := range rule.Boxes {
			if _, ok := own.Intersection(candidate); ok {
				return true
			}
		}
	}
	return false
}

func redundantAfterRule(decided []Box, rules []Rule, index int) bool {
	if len(decided) == 0 {
		return false
	}

	for _, decidedBox := range decided {
		remaining := []Box{decidedBox}
		for later := index + 1; later < len(rules) && len(remaining) > 0; later++ {
			nextRemaining := make([]Box, 0, len(remaining))
			for _, piece := range remaining {
				pieces := []Box{piece}
				for _, laterBox := range rules[later].Boxes {
					if _, overlaps := piece.Intersection(laterBox); overlaps &&
						rules[later].Allow != rules[index].Allow {
						return false
					}
					pieces = subtractFromBoxes(pieces, laterBox)
				}
				nextRemaining = append(nextRemaining, pieces...)
			}
			remaining = nextRemaining
		}
		// Unmatched traffic is default-denied, which does not make a rule redundant.
		if len(remaining) != 0 {
			return false
		}
	}
	return true
}

func subtractFromBoxes(boxes []Box, cutter Box) []Box {
	pieces := make([]Box, 0, len(boxes))
	for _, box := range boxes {
		pieces = append(pieces, box.Subtract(cutter)...)
	}
	return pieces
}
