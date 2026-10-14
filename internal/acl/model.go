// Package acl defines the data model used by the ACL parser and analyzer.
package acl

// Protocol identifies an IP traffic protocol supported by aclvet.
type Protocol string

const (
	ProtocolTCP  Protocol = "tcp"
	ProtocolUDP  Protocol = "udp"
	ProtocolICMP Protocol = "icmp"
	ProtocolAny  Protocol = "any"
)

// Rule is one ordered ACL entry. Boxes contains one protocol-specific box for
// each protocol matched by the rule.
type Rule struct {
	Line  int
	Allow bool
	Boxes []Box
}

// Flow is one concrete packet flow. SourceText and DestinationText retain the
// address spellings from the input so command output can reproduce the flow as
// written. PortText is empty for ICMP flows.
type Flow struct {
	Protocol        Protocol
	Source          Addr
	Destination     Addr
	Port            uint16
	SourceText      string
	DestinationText string
	PortText        string
}
