// Package coverage tracks which edges of a target have been reached.
// Maps are not safe for concurrent use; the coordinator guards them.
package coverage

import "slices"

// Edge identifies one instrumented edge (afl-showmap ID, or a demo block ID).
type Edge uint32

// Normalize returns the edges sorted, with duplicates removed.
func Normalize(edges []Edge) []Edge {
	out := slices.Clone(edges)
	slices.Sort(out)
	return slices.Compact(out)
}

type Map struct {
	seen map[Edge]struct{}
}

func NewMap() *Map { return &Map{seen: make(map[Edge]struct{})} }

// Novel returns the edges not yet in the map, without adding them.
func (m *Map) Novel(edges []Edge) []Edge {
	var out []Edge
	for _, e := range Normalize(edges) {
		if _, ok := m.seen[e]; !ok {
			out = append(out, e)
		}
	}
	return out
}

// Add merges edges and returns how many were new.
func (m *Map) Add(edges []Edge) int {
	n := 0
	for _, e := range edges {
		if _, ok := m.seen[e]; !ok {
			m.seen[e] = struct{}{}
			n++
		}
	}
	return n
}

func (m *Map) Len() int { return len(m.seen) }
