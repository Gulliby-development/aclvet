package acl

import "math/big"

// Box is a protocol-specific rectangular region of flow space. Its address
// and port ranges are inclusive.
type Box struct {
	Protocol    Protocol
	Source      AddressRange
	Destination AddressRange
	Ports       PortRange
}

// Intersection returns the overlap between two boxes. Boxes for distinct
// protocols never intersect.
func (box Box) Intersection(other Box) (Box, bool) {
	if box.Protocol != other.Protocol {
		return Box{}, false
	}

	source, ok := intersectAddresses(box.Source, other.Source)
	if !ok {
		return Box{}, false
	}
	destination, ok := intersectAddresses(box.Destination, other.Destination)
	if !ok {
		return Box{}, false
	}
	ports, ok := intersectPorts(box.Ports, other.Ports)
	if !ok {
		return Box{}, false
	}
	return Box{
		Protocol:    box.Protocol,
		Source:      source,
		Destination: destination,
		Ports:       ports,
	}, true
}

// Contains reports whether box includes every flow represented by other.
func (box Box) Contains(other Box) bool {
	return box.Protocol == other.Protocol &&
		box.Source.Min <= other.Source.Min && box.Source.Max >= other.Source.Max &&
		box.Destination.Min <= other.Destination.Min && box.Destination.Max >= other.Destination.Max &&
		box.Ports.Min <= other.Ports.Min && box.Ports.Max >= other.Ports.Max
}

// Subtract returns disjoint boxes representing box minus other.
func (box Box) Subtract(other Box) []Box {
	intersection, ok := box.Intersection(other)
	if !ok {
		return []Box{box}
	}

	remaining := box
	pieces := make([]Box, 0, 6)

	if remaining.Source.Min < intersection.Source.Min {
		piece := remaining
		piece.Source.Max = intersection.Source.Min - 1
		pieces = append(pieces, piece)
		remaining.Source.Min = intersection.Source.Min
	}
	if remaining.Source.Max > intersection.Source.Max {
		piece := remaining
		piece.Source.Min = intersection.Source.Max + 1
		pieces = append(pieces, piece)
		remaining.Source.Max = intersection.Source.Max
	}

	if remaining.Destination.Min < intersection.Destination.Min {
		piece := remaining
		piece.Destination.Max = intersection.Destination.Min - 1
		pieces = append(pieces, piece)
		remaining.Destination.Min = intersection.Destination.Min
	}
	if remaining.Destination.Max > intersection.Destination.Max {
		piece := remaining
		piece.Destination.Min = intersection.Destination.Max + 1
		pieces = append(pieces, piece)
		remaining.Destination.Max = intersection.Destination.Max
	}

	if remaining.Ports.Min < intersection.Ports.Min {
		piece := remaining
		piece.Ports.Max = intersection.Ports.Min - 1
		pieces = append(pieces, piece)
		remaining.Ports.Min = intersection.Ports.Min
	}
	if remaining.Ports.Max > intersection.Ports.Max {
		piece := remaining
		piece.Ports.Min = intersection.Ports.Max + 1
		pieces = append(pieces, piece)
		remaining.Ports.Max = intersection.Ports.Max
	}
	return pieces
}

// Volume returns the exact number of flows represented by box.
func (box Box) Volume() *big.Int {
	sourceSize := uint64(uint32(box.Source.Max)-uint32(box.Source.Min)) + 1
	destinationSize := uint64(uint32(box.Destination.Max)-uint32(box.Destination.Min)) + 1
	portSize := uint64(box.Ports.Max-box.Ports.Min) + 1

	volume := new(big.Int).SetUint64(sourceSize)
	volume.Mul(volume, new(big.Int).SetUint64(destinationSize))
	volume.Mul(volume, new(big.Int).SetUint64(portSize))
	return volume
}

// Matches reports whether the concrete flow lies in box.
func (box Box) Matches(flow Flow) bool {
	return box.Protocol == flow.Protocol &&
		box.Source.Min <= flow.Source && flow.Source <= box.Source.Max &&
		box.Destination.Min <= flow.Destination && flow.Destination <= box.Destination.Max &&
		box.Ports.Min <= flow.Port && flow.Port <= box.Ports.Max
}

func intersectAddresses(first, second AddressRange) (AddressRange, bool) {
	minimum := first.Min
	if second.Min > minimum {
		minimum = second.Min
	}
	maximum := first.Max
	if second.Max < maximum {
		maximum = second.Max
	}
	if minimum > maximum {
		return AddressRange{}, false
	}
	return AddressRange{Min: minimum, Max: maximum}, true
}

func intersectPorts(first, second PortRange) (PortRange, bool) {
	minimum := first.Min
	if second.Min > minimum {
		minimum = second.Min
	}
	maximum := first.Max
	if second.Max < maximum {
		maximum = second.Max
	}
	if minimum > maximum {
		return PortRange{}, false
	}
	return PortRange{Min: minimum, Max: maximum}, true
}
