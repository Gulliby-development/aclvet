package acl

// Verdict records the action and deciding rule for one flow. A default verdict
// has Default set and no deciding rule line.
type Verdict struct {
	Allow   bool
	Line    int
	Default bool
}

// Evaluate returns the first matching rule's verdict, or the default deny
// verdict when no rule matches.
func Evaluate(rules []Rule, flow Flow) Verdict {
	for _, rule := range rules {
		for _, box := range rule.Boxes {
			if box.Protocol != flow.Protocol ||
				flow.Source < box.Source.Min || flow.Source > box.Source.Max ||
				flow.Destination < box.Destination.Min || flow.Destination > box.Destination.Max {
				continue
			}
			if flow.Protocol != ProtocolICMP &&
				(flow.Port < box.Ports.Min || flow.Port > box.Ports.Max) {
				continue
			}
			return Verdict{Allow: rule.Allow, Line: rule.Line}
		}
	}
	return Verdict{Default: true}
}
