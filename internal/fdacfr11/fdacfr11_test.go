package fdacfr11

import (
	"strings"
	"testing"
	"time"
)

var testTime = time.Date(2026, 5, 27, 14, 30, 0, 0, time.UTC)

func validRecord() ElectronicRecord {
	return ElectronicRecord{
		RecordType:  "ecrf.subject_visit",
		RecordID:    "trial-001-subj-007-visit-3",
		RecordHash:  strings.Repeat("a", 64),
		CreatedAt:   testTime,
		CreatorID:   "investigator-alice",
		TrialID:     "NCT06000001",
		SubjectID:   "S-007",
		ContentType: "application/json",
	}
}

func validSignature() ElectronicSignature {
	return ElectronicSignature{
		SignerID:         "investigator-alice",
		SignedAt:         testTime,
		Meaning:          MeaningApproval,
		RecordHash:       strings.Repeat("a", 64),
		Method:           MethodMFA_WebAuthn,
		CertificationRef: "FDA-cert-letter-2026-001",
	}
}

func TestAllSignatureMeanings_Count(t *testing.T) {
	const want = 5
	if got := len(AllSignatureMeanings()); got != want {
		t.Fatalf("meaning count: got %d want %d", got, want)
	}
}

func TestAllSignatureMeanings_PinnedSet(t *testing.T) {
	want := map[SignatureMeaning]bool{
		MeaningReview:         true,
		MeaningApproval:       true,
		MeaningResponsibility: true,
		MeaningAuthorship:     true,
		MeaningVerification:   true,
	}
	got := AllSignatureMeanings()
	gotSet := map[SignatureMeaning]bool{}
	for _, m := range got {
		gotSet[m] = true
	}
	for m := range want {
		if !gotSet[m] {
			t.Errorf("meaning %q missing from AllSignatureMeanings", m)
		}
	}
}

func TestAllAuthenticationMethods_Count(t *testing.T) {
	const want = 4
	if got := len(AllAuthenticationMethods()); got != want {
		t.Fatalf("method count: got %d want %d", got, want)
	}
}

func TestElectronicRecord_ValidatePasses(t *testing.T) {
	if err := validRecord().Validate(); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
}

func TestElectronicRecord_ValidateRejectsEmptyFields(t *testing.T) {
	cases := map[string]func(*ElectronicRecord){
		"RecordType":  func(r *ElectronicRecord) { r.RecordType = "" },
		"RecordID":    func(r *ElectronicRecord) { r.RecordID = "" },
		"RecordHash":  func(r *ElectronicRecord) { r.RecordHash = "" },
		"CreatorID":   func(r *ElectronicRecord) { r.CreatorID = "" },
		"TrialID":     func(r *ElectronicRecord) { r.TrialID = "" },
		"ContentType": func(r *ElectronicRecord) { r.ContentType = "" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			r := validRecord()
			mut(&r)
			if err := r.Validate(); err == nil {
				t.Errorf("missing %s: expected error", name)
			}
		})
	}
}

func TestElectronicRecord_ValidateRejectsZeroTime(t *testing.T) {
	r := validRecord()
	r.CreatedAt = time.Time{}
	if err := r.Validate(); err == nil {
		t.Fatalf("zero CreatedAt must be rejected per §11.10(e) time-stamp invariant")
	}
}

func TestElectronicRecord_CanonicalBytesNormalisesToUTC(t *testing.T) {
	r := validRecord()
	loc, _ := time.LoadLocation("America/New_York")
	r.CreatedAt = testTime.In(loc) // wall-clock identical, location not UTC

	bUTC, err := r.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}

	// Re-marshal the original UTC version; expect byte-equal output.
	rUTC := validRecord()
	bWant, _ := rUTC.CanonicalBytes()
	if string(bUTC) != string(bWant) {
		t.Fatalf("CanonicalBytes not timezone-normalised:\n got %s\nwant %s", string(bUTC), string(bWant))
	}
}

func TestHashRecordBody_Determinism(t *testing.T) {
	a := HashRecordBody([]byte("trial-record-body"))
	b := HashRecordBody([]byte("trial-record-body"))
	if a != b {
		t.Fatalf("HashRecordBody must be deterministic")
	}
	if len(a) != 64 {
		t.Fatalf("HashRecordBody hex length: got %d want 64", len(a))
	}
}

func TestHashRecordBody_DifferentInputDifferentHash(t *testing.T) {
	a := HashRecordBody([]byte("a"))
	b := HashRecordBody([]byte("b"))
	if a == b {
		t.Fatalf("distinct bodies must produce distinct hashes")
	}
}

func TestElectronicSignature_ValidatePasses(t *testing.T) {
	if err := validSignature().Validate(); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestElectronicSignature_ValidateRejectsEmptyFields(t *testing.T) {
	cases := map[string]func(*ElectronicSignature){
		"SignerID":   func(s *ElectronicSignature) { s.SignerID = "" },
		"RecordHash": func(s *ElectronicSignature) { s.RecordHash = "" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			s := validSignature()
			mut(&s)
			if err := s.Validate(); err == nil {
				t.Errorf("missing %s: expected error", name)
			}
		})
	}
}

func TestElectronicSignature_ValidateRejectsZeroTime(t *testing.T) {
	s := validSignature()
	s.SignedAt = time.Time{}
	if err := s.Validate(); err == nil {
		t.Fatalf("zero SignedAt must be rejected per §11.50(a)(2)")
	}
}

func TestElectronicSignature_ValidateRejectsInvalidMeaning(t *testing.T) {
	s := validSignature()
	s.Meaning = SignatureMeaning("not-a-real-meaning")
	if err := s.Validate(); err == nil {
		t.Fatalf("invalid meaning must be rejected per §11.50(a)(3)")
	}
}

func TestElectronicSignature_ValidateRejectsInvalidMethod(t *testing.T) {
	s := validSignature()
	s.Method = AuthenticationMethod("smoke-signals")
	if err := s.Validate(); err == nil {
		t.Fatalf("invalid auth method must be rejected per §11.200(a)")
	}
}

// TestElectronicSignature_LinksTo_RoundTrip is the §11.70
// signature/record-linking pin.
func TestElectronicSignature_LinksTo_RoundTrip(t *testing.T) {
	r := validRecord()
	rb, _ := r.CanonicalBytes()
	wantHash := HashRecordBody(rb)

	s := validSignature()
	s.RecordHash = wantHash

	ok, err := s.LinksTo(r)
	if err != nil {
		t.Fatalf("LinksTo err: %v", err)
	}
	if !ok {
		t.Fatalf("LinksTo must return true when RecordHash matches §11.70 linking")
	}
}

func TestElectronicSignature_LinksTo_TamperDetected(t *testing.T) {
	r := validRecord()
	s := validSignature()
	s.RecordHash = strings.Repeat("0", 64)

	ok, err := s.LinksTo(r)
	if err != nil {
		t.Fatalf("LinksTo err: %v", err)
	}
	if ok {
		t.Fatalf("LinksTo must return false when RecordHash does not match")
	}
}

func TestSortedMeanings_IsSorted(t *testing.T) {
	got := SortedMeanings()
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Errorf("SortedMeanings not sorted: %v", got)
		}
	}
}
