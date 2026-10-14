package acl

import "strconv"

// Addr is an IPv4 address represented as an unsigned 32-bit integer in
// network byte order.
type Addr uint32

// AddressRange is an inclusive range of IPv4 addresses.
type AddressRange struct {
	Min Addr
	Max Addr
}

// PortRange is an inclusive range of transport-layer destination ports.
type PortRange struct {
	Min uint16
	Max uint16
}

// String formats an IPv4 address in dotted-decimal notation.
func (addr Addr) String() string {
	value := uint32(addr)
	return strconv.FormatUint(uint64(value>>24), 10) + "." +
		strconv.FormatUint(uint64((value>>16)&0xff), 10) + "." +
		strconv.FormatUint(uint64((value>>8)&0xff), 10) + "." +
		strconv.FormatUint(uint64(value&0xff), 10)
}

// parseIPv4Address parses the strict dotted-decimal address form used by the
// rule and flow grammars. Leading zeroes are rejected except for the value 0.
func parseIPv4Address(value string) (Addr, bool) {
	var result uint32
	start := 0
	for octetIndex := 0; octetIndex < 4; octetIndex++ {
		end := len(value)
		if octetIndex < 3 {
			relative := -1
			for i := start; i < len(value); i++ {
				if value[i] == '.' {
					relative = i
					break
				}
			}
			if relative < 0 {
				return 0, false
			}
			end = relative
		} else {
			for i := start; i < len(value); i++ {
				if value[i] == '.' {
					return 0, false
				}
			}
		}

		part := value[start:end]
		if len(part) == 0 || len(part) > 3 || (len(part) > 1 && part[0] == '0') {
			return 0, false
		}
		octet, ok := parseDecimal(part, 255)
		if !ok {
			return 0, false
		}
		result = (result << 8) | octet
		start = end + 1
	}
	if start != len(value)+1 {
		return 0, false
	}
	return Addr(result), true
}

// parseIPv4Network parses a strict address/prefix network. Its boolean results
// are (valid, hostBitsSet); hostBitsSet is true only for a syntactically valid
// address and prefix whose address is not the network address.
func parseIPv4Network(value string) (AddressRange, bool, bool) {
	slash := -1
	for i := 0; i < len(value); i++ {
		if value[i] == '/' {
			if slash >= 0 {
				return AddressRange{}, false, false
			}
			slash = i
		}
	}
	if slash <= 0 || slash == len(value)-1 {
		return AddressRange{}, false, false
	}
	address, ok := parseIPv4Address(value[:slash])
	if !ok {
		return AddressRange{}, false, false
	}
	prefix, ok := parseDecimal(value[slash+1:], 32)
	if !ok {
		return AddressRange{}, false, false
	}

	var mask uint32
	if prefix != 0 {
		mask = ^uint32(0) << (32 - prefix)
	}
	start := uint32(address)
	network := start & mask
	if network != start {
		return AddressRange{}, false, true
	}
	return AddressRange{
		Min: Addr(network),
		Max: Addr(network | ^mask),
	}, true, false
}

// parsePortRange parses a destination-port range, including the any spelling
// used by rules. A single number produces a one-port range.
func parsePortRange(value string) (PortRange, bool) {
	if value == "any" {
		return PortRange{Min: 0, Max: 65535}, true
	}

	dash := -1
	for i := 0; i < len(value); i++ {
		if value[i] == '-' {
			if dash >= 0 {
				return PortRange{}, false
			}
			dash = i
		}
	}

	if dash < 0 {
		port, ok := parseDecimal(value, 65535)
		if !ok {
			return PortRange{}, false
		}
		return PortRange{Min: uint16(port), Max: uint16(port)}, true
	}
	if dash == 0 || dash == len(value)-1 {
		return PortRange{}, false
	}
	first, ok := parseDecimal(value[:dash], 65535)
	if !ok {
		return PortRange{}, false
	}
	last, ok := parseDecimal(value[dash+1:], 65535)
	if !ok || first > last {
		return PortRange{}, false
	}
	return PortRange{Min: uint16(first), Max: uint16(last)}, true
}

// parseDecimal parses canonical ASCII decimal digits no greater than max.
func parseDecimal(value string, max uint32) (uint32, bool) {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return 0, false
	}
	var result uint32
	for i := 0; i < len(value); i++ {
		digit := value[i]
		if digit < '0' || digit > '9' {
			return 0, false
		}
		value := uint32(digit - '0')
		if result > (max-value)/10 {
			return 0, false
		}
		result = result*10 + value
	}
	return result, true
}

// displayValue replaces every rune outside printable ASCII with one question
// mark for use in quoted parser diagnostics. Printable ASCII is not escaped.
func displayValue(value string) string {
	var result []rune
	for _, r := range value {
		if r < '!' || r > '~' {
			result = append(result, '?')
		} else {
			result = append(result, r)
		}
	}
	return string(result)
}
