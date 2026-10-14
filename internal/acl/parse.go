package acl

import (
	"fmt"
	"strings"
)

// ParseRules parses ordered ACL rules from text. display is the path spelling
// used in diagnostics; it is not interpreted as a filesystem path.
func ParseRules(display, text string) ([]Rule, error) {
	lines := inputLines(text)
	rules := make([]Rule, 0)
	for index, line := range lines {
		line = trimSpaceTab(line)
		if line == "" || line[0] == '#' {
			continue
		}

		tokens := splitSpaceTab(line)
		if len(tokens) != 5 && len(tokens) != 6 || tokens[3] != "->" {
			return nil, parseLineError(display, index+1, `expected "ACTION PROTO SRC -> DST [PORTS]"`)
		}
		if len(rules) == 150 {
			return nil, parseLineError(display, index+1, "too many rules (limit 150)")
		}

		action := tokens[0]
		if action != "allow" && action != "deny" {
			return nil, parseLineError(display, index+1, `invalid action "`+displayValue(action)+`" (expected allow or deny)`)
		}

		protocol, ok := parseRuleProtocol(tokens[1])
		if !ok {
			return nil, parseLineError(display, index+1, `invalid protocol "`+displayValue(tokens[1])+`" (expected tcp, udp, icmp or any)`)
		}

		source, err := parseRuleAddress(tokens[2])
		if err != nil {
			return nil, parseLineError(display, index+1, err.Error())
		}
		destination, err := parseRuleAddress(tokens[4])
		if err != nil {
			return nil, parseLineError(display, index+1, err.Error())
		}

		hasPorts := len(tokens) == 6
		if hasPorts && (protocol == ProtocolICMP || protocol == ProtocolAny) {
			return nil, parseLineError(display, index+1, "ports need tcp or udp")
		}

		var ports PortRange
		if hasPorts {
			var valid bool
			ports, valid = parsePortRange(tokens[5])
			if !valid {
				return nil, parseLineError(display, index+1, `invalid ports "`+displayValue(tokens[5])+`" (expected any, N or N-M with 0 <= N <= M <= 65535)`)
			}
		} else {
			ports = PortRange{Min: 0, Max: 65535}
		}

		rule := Rule{Line: index + 1, Allow: action == "allow"}
		for _, coveredProtocol := range expandedProtocols(protocol) {
			protocolPorts := ports
			if coveredProtocol == ProtocolICMP {
				protocolPorts = PortRange{Min: 0, Max: 0}
			}
			rule.Boxes = append(rule.Boxes, Box{
				Protocol:    coveredProtocol,
				Source:      source,
				Destination: destination,
				Ports:       protocolPorts,
			})
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// ParseFlows parses concrete flows from text. Flow address and port spellings
// are retained for output by the CLI.
func ParseFlows(display, text string) ([]Flow, error) {
	lines := inputLines(text)
	flows := make([]Flow, 0)
	for index, line := range lines {
		line = trimSpaceTab(line)
		if line == "" || line[0] == '#' {
			continue
		}

		tokens := splitSpaceTab(line)
		if len(tokens) != 3 && len(tokens) != 4 {
			return nil, parseLineError(display, index+1, `expected "PROTO SRC DST [PORT]"`)
		}

		protocol, ok := parseFlowProtocol(tokens[0])
		if !ok {
			return nil, parseLineError(display, index+1, `invalid protocol "`+displayValue(tokens[0])+`" (expected tcp, udp or icmp)`)
		}
		source, ok := parseIPv4Address(tokens[1])
		if !ok {
			return nil, parseLineError(display, index+1, `invalid address "`+displayValue(tokens[1])+`"`)
		}
		destination, ok := parseIPv4Address(tokens[2])
		if !ok {
			return nil, parseLineError(display, index+1, `invalid address "`+displayValue(tokens[2])+`"`)
		}

		flow := Flow{
			Protocol:        protocol,
			Source:          source,
			Destination:     destination,
			SourceText:      tokens[1],
			DestinationText: tokens[2],
		}
		hasPort := len(tokens) == 4
		if protocol == ProtocolICMP {
			if hasPort {
				return nil, parseLineError(display, index+1, "icmp has no port")
			}
		} else {
			if !hasPort {
				return nil, parseLineError(display, index+1, "missing port")
			}
			port, valid := parseDecimal(tokens[3], 65535)
			if !valid {
				return nil, parseLineError(display, index+1, `invalid port "`+displayValue(tokens[3])+`" (expected a whole number from 0 to 65535)`)
			}
			flow.Port = uint16(port)
			flow.PortText = tokens[3]
		}
		flows = append(flows, flow)
	}
	return flows, nil
}

func inputLines(text string) []string {
	text = strings.TrimPrefix(text, "\uFEFF")
	lines := strings.Split(text, "\n")
	for index := 0; index+1 < len(lines); index++ {
		if strings.HasSuffix(lines[index], "\r") {
			lines[index] = lines[index][:len(lines[index])-1]
		}
	}
	return lines
}

func trimSpaceTab(value string) string {
	start := 0
	for start < len(value) && (value[start] == ' ' || value[start] == '\t') {
		start++
	}
	end := len(value)
	for end > start && (value[end-1] == ' ' || value[end-1] == '\t') {
		end--
	}
	return value[start:end]
}

func splitSpaceTab(value string) []string {
	var tokens []string
	for index := 0; index < len(value); {
		for index < len(value) && (value[index] == ' ' || value[index] == '\t') {
			index++
		}
		if index == len(value) {
			break
		}
		start := index
		for index < len(value) && value[index] != ' ' && value[index] != '\t' {
			index++
		}
		tokens = append(tokens, value[start:index])
	}
	return tokens
}

func parseLineError(display string, line int, message string) error {
	return fmt.Errorf("%s:%d: %s", display, line, message)
}

func parseRuleAddress(value string) (AddressRange, error) {
	if value == "any" {
		return AddressRange{Min: 0, Max: ^Addr(0)}, nil
	}
	if address, ok := parseIPv4Address(value); ok {
		return AddressRange{Min: address, Max: address}, nil
	}
	if network, valid, hostBitsSet := parseIPv4Network(value); valid {
		return network, nil
	} else if hostBitsSet {
		return AddressRange{}, fmt.Errorf(`invalid address "%s" (host bits are set)`, displayValue(value))
	}
	return AddressRange{}, fmt.Errorf(`invalid address "%s"`, displayValue(value))
}

func parseRuleProtocol(value string) (Protocol, bool) {
	protocol := Protocol(value)
	switch protocol {
	case ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolAny:
		return protocol, true
	default:
		return "", false
	}
}

func parseFlowProtocol(value string) (Protocol, bool) {
	protocol := Protocol(value)
	switch protocol {
	case ProtocolTCP, ProtocolUDP, ProtocolICMP:
		return protocol, true
	default:
		return "", false
	}
}

func expandedProtocols(protocol Protocol) []Protocol {
	switch protocol {
	case ProtocolTCP:
		return []Protocol{ProtocolTCP}
	case ProtocolUDP:
		return []Protocol{ProtocolUDP}
	case ProtocolICMP:
		return []Protocol{ProtocolICMP}
	default:
		return []Protocol{ProtocolTCP, ProtocolUDP, ProtocolICMP}
	}
}
