package manifest

import (
	"strings"
	"testing"
	"time"
)

func TestSeed_Count(t *testing.T) {
	const want = 10
	if got := len(Seed()); got != want {
		t.Fatalf("manifest seed count: got %d want %d", got, want)
	}
}

func TestSeed_KeysAreUnique(t *testing.T) {
	seen := map[string]int{}
	for _, e := range Seed() {
		seen[e.Key]++
	}
	for k, n := range seen {
		if n != 1 {
			t.Errorf("duplicate key %q: %d occurrences", k, n)
		}
	}
}

func TestSeed_AllEntriesHaveSchemaVersion(t *testing.T) {
	for _, e := range Seed() {
		if e.SchemaVersion != SchemaVersion {
			t.Errorf("entry %s: SchemaVersion=%d want %d", e.Key, e.SchemaVersion, SchemaVersion)
		}
	}
}

func TestSeed_AllEntriesHaveSource(t *testing.T) {
	for _, e := range Seed() {
		if e.Source == "" {
			t.Errorf("entry %s: empty Source", e.Key)
		}
	}
}

func TestSeed_AllEntriesHaveJurisdiction(t *testing.T) {
	valid := map[Jurisdiction]bool{
		JurisdictionUS:  true,
		JurisdictionUK:  true,
		JurisdictionEU:  true,
		JurisdictionICH: true,
	}
	for _, e := range Seed() {
		if !valid[e.Jurisdiction] {
			t.Errorf("entry %s: invalid Jurisdiction %q", e.Key, e.Jurisdiction)
		}
	}
}

func TestSeed_JurisdictionCoverage(t *testing.T) {
	counts := map[Jurisdiction]int{}
	for _, e := range Seed() {
		counts[e.Jurisdiction]++
	}
	// At inception: 6 US + 1 UK + 2 EU + 1 ICH = 10.
	cases := map[Jurisdiction]int{
		JurisdictionUS:  6,
		JurisdictionUK:  1,
		JurisdictionEU:  2,
		JurisdictionICH: 1,
	}
	for j, want := range cases {
		if got := counts[j]; got != want {
			t.Errorf("jurisdiction %s count: got %d want %d", j, got, want)
		}
	}
}

func TestIsStale_UnknownFreshAt(t *testing.T) {
	e := Entry{Key: "x", FreshAt: FreshAtUnknown}
	if !e.IsStale(time.Now(), 24*time.Hour) {
		t.Fatalf("FreshAtUnknown must always be stale")
	}
}

func TestIsStale_FreshWithinMaxAge(t *testing.T) {
	now := time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)
	e := Entry{Key: "x", FreshAt: now.Add(-1 * time.Hour)}
	if e.IsStale(now, 24*time.Hour) {
		t.Fatalf("entry 1h old must not be stale at maxAge=24h")
	}
}

func TestIsStale_OverMaxAge(t *testing.T) {
	now := time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)
	e := Entry{Key: "x", FreshAt: now.Add(-48 * time.Hour)}
	if !e.IsStale(now, 24*time.Hour) {
		t.Fatalf("entry 48h old must be stale at maxAge=24h")
	}
}

func TestStaleEntries_FiltersAndSorts(t *testing.T) {
	now := time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)
	m := Manifest{
		{Key: "z.fresh", FreshAt: now},
		{Key: "a.stale", FreshAt: FreshAtUnknown},
		{Key: "m.stale", FreshAt: now.Add(-365 * 24 * time.Hour)},
	}
	got := m.StaleEntries(now, 30*24*time.Hour)
	if len(got) != 2 {
		t.Fatalf("expected 2 stale entries, got %d", len(got))
	}
	if got[0].Key != "a.stale" || got[1].Key != "m.stale" {
		t.Fatalf("StaleEntries not sorted: %v", got)
	}
}

func TestFilterByJurisdiction(t *testing.T) {
	cases := []struct {
		j    Jurisdiction
		want int
	}{
		{JurisdictionUS, 6},
		{JurisdictionUK, 1},
		{JurisdictionEU, 2},
		{JurisdictionICH, 1},
	}
	seed := Seed()
	for _, tc := range cases {
		got := seed.FilterByJurisdiction(tc.j)
		if len(got) != tc.want {
			t.Errorf("FilterByJurisdiction(%s) count: got %d want %d", tc.j, len(got), tc.want)
		}
	}
}

func TestAllSources_NoDuplicates(t *testing.T) {
	seen := map[string]int{}
	for _, s := range AllSources() {
		seen[s]++
	}
	for s, n := range seen {
		if n != 1 {
			t.Errorf("duplicate source %q: %d occurrences", s, n)
		}
	}
}

// TestSeed_KeysFollowCanonicalNamespace pins the namespace shape:
// each key is dot-separated, lowercase, starts with one of the known
// prefixes.
func TestSeed_KeysFollowCanonicalNamespace(t *testing.T) {
	validPrefixes := []string{"regulation.", "r85."}
	for _, e := range Seed() {
		matched := false
		for _, p := range validPrefixes {
			if strings.HasPrefix(e.Key, p) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("entry key %q does not start with any of %v", e.Key, validPrefixes)
		}
		if strings.ToLower(e.Key) != e.Key {
			t.Errorf("entry key %q must be lowercase", e.Key)
		}
	}
}

func TestSortedKeys_IsSorted(t *testing.T) {
	keys := Seed().SortedKeys()
	for i := 1; i < len(keys); i++ {
		if keys[i-1] >= keys[i] {
			t.Errorf("keys not sorted: %q >= %q", keys[i-1], keys[i])
		}
	}
}
