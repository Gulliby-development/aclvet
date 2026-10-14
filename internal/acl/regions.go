package acl

// Regions partitions flow space according to first-match rule order. Decided
// has one entry per input rule; Unmatched contains traffic not covered by any
// rule.
type Regions struct {
	Decided   [][]Box
	Unmatched []Box
}

// ComputeRegions computes the exact regions decided by each rule and the
// remaining unmatched regions. The computation subtracts boxes, not flows.
func ComputeRegions(rules []Rule) Regions {
	unmatched := []Box{
		{Protocol: ProtocolTCP, Source: fullAddressRange(), Destination: fullAddressRange(), Ports: PortRange{Min: 0, Max: 65535}},
		{Protocol: ProtocolUDP, Source: fullAddressRange(), Destination: fullAddressRange(), Ports: PortRange{Min: 0, Max: 65535}},
		{Protocol: ProtocolICMP, Source: fullAddressRange(), Destination: fullAddressRange(), Ports: PortRange{Min: 0, Max: 0}},
	}
	decided := make([][]Box, len(rules))

	for ruleIndex, rule := range rules {
		decidedForRule := make([]Box, 0)
		for _, available := range unmatched {
			for _, ruleBox := range rule.Boxes {
				if intersection, ok := available.Intersection(ruleBox); ok {
					decidedForRule = append(decidedForRule, intersection)
				}
			}
		}
		decided[ruleIndex] = decidedForRule

		nextUnmatched := make([]Box, 0, len(unmatched))
		for _, available := range unmatched {
			pieces := []Box{available}
			for _, ruleBox := range rule.Boxes {
				nextPieces := make([]Box, 0, len(pieces))
				for _, piece := range pieces {
					nextPieces = append(nextPieces, piece.Subtract(ruleBox)...)
				}
				pieces = nextPieces
				if len(pieces) == 0 {
					break
				}
			}
			nextUnmatched = append(nextUnmatched, pieces...)
		}
		unmatched = nextUnmatched
	}

	return Regions{Decided: decided, Unmatched: unmatched}
}

func fullAddressRange() AddressRange {
	return AddressRange{Min: 0, Max: ^Addr(0)}
}
