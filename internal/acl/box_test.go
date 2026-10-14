package acl

import (
	"math/big"
	"testing"
)

func boxForTest(protocol Protocol, sourceMin, sourceMax, destinationMin, destinationMax uint32, portMin, portMax uint16) Box {
	return Box{
		Protocol:    protocol,
		Source:      AddressRange{Min: Addr(sourceMin), Max: Addr(sourceMax)},
		Destination: AddressRange{Min: Addr(destinationMin), Max: Addr(destinationMax)},
		Ports:       PortRange{Min: portMin, Max: portMax},
	}
}

func TestBoxIntersection(t *testing.T) {
	tests := []struct {
		name  string
		first Box
		other Box
		want  Box
		ok    bool
	}{
		{
			name:  "overlap in every dimension",
			first: boxForTest(ProtocolTCP, 10, 20, 100, 110, 80, 90),
			other: boxForTest(ProtocolTCP, 15, 25, 105, 115, 85, 95),
			want:  boxForTest(ProtocolTCP, 15, 20, 105, 110, 85, 90),
			ok:    true,
		},
		{
			name:  "inclusive contact at maximum endpoints",
			first: boxForTest(ProtocolUDP, 10, 20, 100, 110, 80, 81),
			other: boxForTest(ProtocolUDP, 20, 30, 110, 120, 81, 82),
			want:  boxForTest(ProtocolUDP, 20, 20, 110, 110, 81, 81),
			ok:    true,
		},
		{
			name:  "disjoint source ranges",
			first: boxForTest(ProtocolTCP, 0, 10, 100, 110, 80, 90),
			other: boxForTest(ProtocolTCP, 11, 20, 100, 110, 80, 90),
		},
		{
			name:  "disjoint destination ranges",
			first: boxForTest(ProtocolTCP, 0, 10, 100, 110, 80, 90),
			other: boxForTest(ProtocolTCP, 0, 10, 111, 120, 80, 90),
		},
		{
			name:  "disjoint port ranges",
			first: boxForTest(ProtocolTCP, 0, 10, 100, 110, 80, 90),
			other: boxForTest(ProtocolTCP, 0, 10, 100, 110, 91, 100),
		},
		{
			name:  "different protocols do not intersect",
			first: boxForTest(ProtocolTCP, 0, 10, 100, 110, 80, 90),
			other: boxForTest(ProtocolUDP, 0, 10, 100, 110, 80, 90),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := test.first.Intersection(test.other)
			if ok != test.ok {
				t.Fatalf("Intersection() ok = %t, want %t", ok, test.ok)
			}
			if ok && got != test.want {
				t.Errorf("Intersection() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestBoxContains(t *testing.T) {
	outer := boxForTest(ProtocolTCP, 10, 20, 30, 40, 5, 9)
	tests := []struct {
		name  string
		outer Box
		other Box
		want  bool
	}{
		{
			name:  "same box is contained including both endpoints",
			outer: outer,
			other: outer,
			want:  true,
		},
		{
			name:  "strictly inside",
			outer: outer,
			other: boxForTest(ProtocolTCP, 11, 19, 31, 39, 6, 8),
			want:  true,
		},
		{
			name:  "all inclusive endpoints",
			outer: outer,
			other: boxForTest(ProtocolTCP, 10, 10, 40, 40, 9, 9),
			want:  true,
		},
		{
			name:  "source starts before outer minimum",
			outer: outer,
			other: boxForTest(ProtocolTCP, 9, 10, 30, 30, 5, 5),
		},
		{
			name:  "source ends after outer maximum",
			outer: outer,
			other: boxForTest(ProtocolTCP, 20, 21, 30, 30, 5, 5),
		},
		{
			name:  "destination starts before outer minimum",
			outer: outer,
			other: boxForTest(ProtocolTCP, 10, 10, 29, 30, 5, 5),
		},
		{
			name:  "destination ends after outer maximum",
			outer: outer,
			other: boxForTest(ProtocolTCP, 10, 10, 40, 41, 5, 5),
		},
		{
			name:  "ports start before outer minimum",
			outer: outer,
			other: boxForTest(ProtocolTCP, 10, 10, 30, 30, 4, 5),
		},
		{
			name:  "ports end after outer maximum",
			outer: outer,
			other: boxForTest(ProtocolTCP, 10, 10, 30, 30, 9, 10),
		},
		{
			name:  "protocols must match",
			outer: outer,
			other: boxForTest(ProtocolUDP, 10, 20, 30, 40, 5, 9),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.outer.Contains(test.other); got != test.want {
				t.Errorf("Contains() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestBoxSubtract(t *testing.T) {
	original := boxForTest(ProtocolTCP, 0, 10, 20, 30, 100, 110)
	centered := boxForTest(ProtocolTCP, 3, 7, 23, 27, 103, 107)
	tests := []struct {
		name     string
		original Box
		removed  Box
		want     []Box
	}{
		{
			name:     "disjoint adjacent boxes leave original unchanged",
			original: original,
			removed:  boxForTest(ProtocolTCP, 11, 20, 20, 30, 100, 110),
			want:     []Box{original},
		},
		{
			name:     "different protocol leaves original unchanged",
			original: original,
			removed:  boxForTest(ProtocolUDP, 0, 10, 20, 30, 100, 110),
			want:     []Box{original},
		},
		{
			name:     "complete overlap leaves no boxes",
			original: original,
			removed:  original,
			want:     []Box{},
		},
		{
			name:     "interior overlap splits all six sides",
			original: original,
			removed:  centered,
			want: []Box{
				boxForTest(ProtocolTCP, 0, 2, 20, 30, 100, 110),
				boxForTest(ProtocolTCP, 8, 10, 20, 30, 100, 110),
				boxForTest(ProtocolTCP, 3, 7, 20, 22, 100, 110),
				boxForTest(ProtocolTCP, 3, 7, 28, 30, 100, 110),
				boxForTest(ProtocolTCP, 3, 7, 23, 27, 100, 102),
				boxForTest(ProtocolTCP, 3, 7, 23, 27, 108, 110),
			},
		},
		{
			name:     "removing the zero source endpoint does not underflow",
			original: boxForTest(ProtocolUDP, 0, 2, 20, 22, 0, 2),
			removed:  boxForTest(ProtocolUDP, 0, 0, 20, 22, 0, 2),
			want:     []Box{boxForTest(ProtocolUDP, 1, 2, 20, 22, 0, 2)},
		},
		{
			name:     "removing maximum endpoints does not overflow",
			original: boxForTest(ProtocolTCP, 0xfffffffe, 0xffffffff, 255, 255, 65534, 65535),
			removed:  boxForTest(ProtocolTCP, 0xffffffff, 0xffffffff, 255, 255, 65535, 65535),
			want: []Box{
				boxForTest(ProtocolTCP, 0xfffffffe, 0xfffffffe, 255, 255, 65534, 65535),
				boxForTest(ProtocolTCP, 0xffffffff, 0xffffffff, 255, 255, 65534, 65534),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.original.Subtract(test.removed)
			assertBoxSetEqual(t, got, test.want)

			total := new(big.Int)
			for i, piece := range got {
				if overlap, ok := piece.Intersection(test.removed); ok {
					t.Errorf("piece %d still intersects removed box: %#v", i, overlap)
				}
				for j := 0; j < i; j++ {
					if overlap, ok := piece.Intersection(got[j]); ok {
						t.Errorf("pieces %d and %d overlap: %#v", j, i, overlap)
					}
				}
				total.Add(total, piece.Volume())
			}

			wantVolume := test.original.Volume()
			if overlap, ok := test.original.Intersection(test.removed); ok {
				wantVolume.Sub(wantVolume, overlap.Volume())
			}
			if total.Cmp(wantVolume) != 0 {
				t.Errorf("subtracted volume = %s, want %s", total, wantVolume)
			}
		})
	}
}

func TestBoxVolume(t *testing.T) {
	tests := []struct {
		name string
		box  Box
		want string
	}{
		{
			name: "single flow at zero address and port",
			box:  boxForTest(ProtocolTCP, 0, 0, 0, 0, 0, 0),
			want: "1",
		},
		{
			name: "single flow at maximum address and port",
			box:  boxForTest(ProtocolTCP, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 65535, 65535),
			want: "1",
		},
		{
			name: "inclusive mixed ranges",
			box:  boxForTest(ProtocolUDP, 0, 2, 5, 9, 0, 1),
			want: "30",
		},
		{
			name: "full icmp address space is exactly 2^64",
			box:  boxForTest(ProtocolICMP, 0, 0xffffffff, 0, 0xffffffff, 0, 0),
			want: "18446744073709551616",
		},
		{
			name: "full tcp space exceeds 64 bits",
			box:  boxForTest(ProtocolTCP, 0, 0xffffffff, 0, 0xffffffff, 0, 65535),
			want: "1208925819614629174706176",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.box.Volume()
			want, ok := new(big.Int).SetString(test.want, 10)
			if !ok {
				t.Fatalf("invalid expected volume %q", test.want)
			}
			if got.Cmp(want) != 0 {
				t.Errorf("Volume() = %s, want %s", got, want)
			}
		})
	}
}

func assertBoxSetEqual(t *testing.T, got, want []Box) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d boxes, want %d: got %#v, want %#v", len(got), len(want), got, want)
	}
	matched := make([]bool, len(want))
	for _, gotBox := range got {
		found := false
		for index, wantBox := range want {
			if !matched[index] && gotBox == wantBox {
				matched[index] = true
				found = true
				break
			}
		}
		if !found {
			t.Errorf("unexpected box %#v; wanted %#v", gotBox, want)
		}
	}
}
