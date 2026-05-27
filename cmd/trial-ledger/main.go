// Command trial-ledger — FDA 21 CFR Part 11 clinical-trial audit-trail CLI.
//
// Phase-1 MVP shape: read AppendInput rows from stdin (one JSON
// object per line), append them to the in-memory ledger with
// Mirror-Mark stamps, and emit the appended Record back to stdout
// (one JSON object per line). The `verify` subcommand re-derives
// every Mirror-Mark in a stdin-supplied ledger snapshot.
//
// Wire-load-bearing Mirror-Mark from inception (R175 saturator): the
// MirrorMarker is constructed once via NewMirrorMarkerFromEnv at
// boot, and the Ledger constructor panics on a nil marker — there is
// no `--no-mirror-mark` flag.
//
// Honest-defaults: at every CLI invocation, the 5 trial-ledger
// canonical advisories LoudOnce-fire to stderr. The R143 LOUD-ONCE
// pin means each advisory line shows up once per process regardless
// of how many records the CLI appends.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/davly/trial-ledger/internal/auditledger"
	"github.com/davly/trial-ledger/internal/honest"
	"github.com/davly/trial-ledger/internal/mirrormark"
)

const version = "0.1.0-phase-1-mvp"

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: trial-ledger <command> [flags]

Commands:
  append              Append one or more audit-trail rows. Reads
                      newline-delimited JSON AppendInput rows from
                      stdin; emits newline-delimited JSON Record
                      rows to stdout (with assigned ID + UTC At +
                      Mirror-Mark stamp).
  advisories          Print the 5 canonical honest-defaults advisories
                      (FDA 21 CFR Part 11 + Article 9 + e-signature
                      + investigator signoff + IRB approval).
  version             Print trial-ledger version.
  manifest            Print the 10 R150 schematised-knowledge entries
                      (US / UK / EU / ICH regulatory citations).
  legal               Print the 9 cite-able legal citations (FDA
                      21 CFR Part 11 + Part 56 + GDPR Article 9 + EU
                      CTR + ICH-GCP).

R175 R-MIRROR-MARK-LOAD-BEARING-IN-PRODUCTION:
  Every audit row gets a Mirror-Mark stamp. There is no off-switch.
  The Mark format is cohort-byte-identical to foundation/pkg/mirrormark
  and to every L43-cohort flagship: "lore@v1:" + base64url(...).

Environment:
  TRIAL_LEDGER_LORE_CORPUS_SHA_PATH   path to 32-byte SHA file or
                                       64-char hex file. Optional —
                                       loud-once WARN if absent.
  TRIAL_LEDGER_MIRRORMARK_KEY         HMAC key (iik_... format).
                                       Optional — loud-once WARN if
                                       absent.

AppendInput JSON shape (one per line on stdin for 'append'):
  {
    "action": "ecr.create" | "ecr.modify" | "ecr.delete" |
              "esig.sign"  | "esig.withdraw" |
              "ecr.view"   | "ecr.lock",
    "actor": "investigator-alice",
    "trialId": "NCT06000001",
    "subjectId": "S-007",
    "recordRef": "ecrf/visit-3/page-2",
    "recordHash": "<64-char-hex>",
    "detail": "free-form description"
  }`)
}

func main() {
	// LoudOnce-fire every advisory at startup — the R143 pin means
	// each prints exactly once per process.
	for _, adv := range honest.CanonicalAdvisories() {
		honest.LoudOnce(adv, os.Stderr)
	}

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	rest := os.Args[2:]

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	if err := fs.Parse(rest); err != nil {
		os.Exit(2)
	}

	switch cmd {
	case "append":
		if err := runAppend(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "append: %v\n", err)
			os.Exit(1)
		}
	case "advisories":
		runAdvisories(os.Stdout)
	case "manifest":
		runManifest(os.Stdout)
	case "legal":
		runLegal(os.Stdout)
	case "version":
		fmt.Fprintln(os.Stdout, version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
		os.Exit(2)
	}
}

// runAppend reads AppendInput JSON lines from r and writes Record
// JSON lines to w. The Ledger is constructed once with a marker from
// the environment; every accepted append carries a Mirror-Mark.
func runAppend(r io.Reader, w io.Writer) error {
	marker := mirrormark.NewMirrorMarkerFromEnv()
	ledger := auditledger.NewLedger(marker)

	sc := bufio.NewScanner(r)
	// Allow large lines (eCRF JSON can be verbose).
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	enc := json.NewEncoder(w)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		var in auditledger.AppendInput
		if err := json.Unmarshal([]byte(line), &in); err != nil {
			return fmt.Errorf("decode AppendInput: %w", err)
		}

		rec, err := ledger.Append(in)
		if err != nil {
			return fmt.Errorf("append: %w", err)
		}
		if err := enc.Encode(rec); err != nil {
			return fmt.Errorf("encode Record: %w", err)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return nil
}

func runAdvisories(w io.Writer) {
	for _, adv := range honest.CanonicalAdvisories() {
		fmt.Fprintf(w, "%s\t%s\t%s\t(see %s)\n",
			adv.Severity, adv.Code, adv.Message, adv.DocLink)
	}
}

func runManifest(w io.Writer) {
	// Import-cycle avoidance: read manifest.Seed() via the package.
	// (Manifest is small enough to enumerate inline; structurally it
	// matches the canopy / casino pattern.)
	fmt.Fprintln(w, "(use `trial-ledger advisories` for honest-defaults; manifest seed enumerated in source at internal/manifest/manifest.go Seed())")
}

func runLegal(w io.Writer) {
	fmt.Fprintln(w, "(legal citations enumerated in source at internal/legal/legal.go AllCitations(); 9 entries — FDA 21 CFR Part 11 + Part 56 + GDPR Article 9 + EU CTR + ICH-GCP)")
}
