package acl

import (
	"math/big"
	"sort"
)

// DiffChange describes a pair of old and new decisions whose actions differ.
type DiffChange struct {
	Old   Verdict
	New   Verdict
	Flows *big.Int
}

// Diff returns the exact flow count for each old/new deciding-rule pair whose
// actions differ. It intersects first-match regions rather than enumerating flows.
func Diff(oldRules, newRules []Rule) []DiffChange {
	oldRegions := decisionRegions(oldRules)
	newRegions := decisionRegions(newRules)
	changes := make([]DiffChange, 0)

	for _, oldDecision := range oldRegions {
		for _, newDecision := range newRegions {
			if oldDecision.verdict.Allow == newDecision.verdict.Allow {
				continue
			}
			count := new(big.Int)
			for _, oldBox := range oldDecision.boxes {
				for _, newBox := range newDecision.boxes {
					if overlap, ok := oldBox.Intersection(newBox); ok {
						count.Add(count, overlap.Volume())
					}
				}
			}
			if count.Sign() > 0 {
				changes = append(changes, DiffChange{
					Old:   oldDecision.verdict,
					New:   newDecision.verdict,
					Flows: count,
				})
			}
		}
	}

	sort.SliceStable(changes, func(i, j int) bool {
		if lessVerdict(changes[i].Old, changes[j].Old) {
			return true
		}
		if lessVerdict(changes[j].Old, changes[i].Old) {
			return false
		}
		return lessVerdict(changes[i].New, changes[j].New)
	})
	return changes
}

type decisionRegion struct {
	verdict Verdict
	boxes   []Box
}

func decisionRegions(rules []Rule) []decisionRegion {
	regions := ComputeRegions(rules)
	decisions := make([]decisionRegion, 0, len(rules)+1)
	for index, rule := range rules {
		decisions = append(decisions, decisionRegion{
			verdict: Verdict{Allow: rule.Allow, Line: rule.Line},
			boxes:   regions.Decided[index],
		})
	}
	decisions = append(decisions, decisionRegion{
		verdict: Verdict{Default: true},
		boxes:   regions.Unmatched,
	})
	return decisions
}

func lessVerdict(first, second Verdict) bool {
	if first.Default != second.Default {
		return !first.Default
	}
	if first.Default {
		return false
	}
	return first.Line < second.Line
}
