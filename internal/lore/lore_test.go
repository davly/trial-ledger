package lore

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// TestKAT1_DigestPin is the R151 cohort firewall. If this fails, the
// cohort byte-identical invariant is broken and a regulator-facing
// cold-verify will not reproduce.
func TestKAT1_DigestPin(t *testing.T) {
	got := Compute()
	if got != Digest {
		t.Fatalf("KAT-1 digest drift: got %q want %q", got, Digest)
	}
}

func TestKAT1_DigestIsLowercaseHex(t *testing.T) {
	if Digest != strings.ToLower(Digest) {
		t.Fatalf("KAT-1 digest must be lowercase hex: %q", Digest)
	}
	if _, err := hex.DecodeString(Digest); err != nil {
		t.Fatalf("KAT-1 digest must hex-decode cleanly: %v", err)
	}
}

func TestKAT1_DigestLen(t *testing.T) {
	if len(Digest) != 2*sha256.Size {
		t.Fatalf("KAT-1 digest hex length: got %d want %d", len(Digest), 2*sha256.Size)
	}
}

func TestKAT1_InputShape(t *testing.T) {
	in := CanonicalInput()
	if len(in) != InputLen {
		t.Fatalf("canonical input length: got %d want %d", len(in), InputLen)
	}
	if in[0] != VersionTag {
		t.Fatalf("canonical input[0]: got 0x%02x want 0x%02x", in[0], VersionTag)
	}
	for i := 1; i < len(in); i++ {
		if in[i] != 0x00 {
			t.Fatalf("canonical input[%d]: got 0x%02x want 0x00", i, in[i])
		}
	}
}

func TestKAT1_CanonicalKeyIsEmpty(t *testing.T) {
	if got := CanonicalKey(); len(got) != 0 {
		t.Fatalf("canonical key must be empty: got %d bytes", len(got))
	}
}

func TestComputeFor_KAT1Parity(t *testing.T) {
	got := ComputeFor(CanonicalInput(), CanonicalKey())
	if got != Digest {
		t.Fatalf("ComputeFor parity: got %q want %q", got, Digest)
	}
}

// TestComputeFor_DifferentInputDifferentDigest is a sanity check —
// HMAC must not collapse different inputs to the same output.
func TestComputeFor_DifferentInputDifferentDigest(t *testing.T) {
	a := ComputeFor([]byte("trial-ledger"), []byte("k"))
	b := ComputeFor([]byte("trial-ledger-rust"), []byte("k"))
	if a == b {
		t.Fatalf("distinct inputs must produce distinct digests")
	}
}
