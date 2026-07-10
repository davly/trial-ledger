// Command trial-ledger-server — the Nexus-facing HTTP producer for the
// `audit_trail_append` capability.
//
// It is the transport half of the trial-ledger Nexus capability
// exposure: a thin net/http server over the EXISTING
// internal/auditledger engine. The Nexus capability-hub routes
// `audit_trail_append` to this process; each call appends one
// tamper-evident, cold-verifiable (L43 Mirror-Mark v1) row to the
// §11.10(e) audit trail and returns the stamped Record.
//
// Wire-load-bearing Mirror-Mark from inception (R175 saturator): the
// MirrorMarker is constructed once via NewMirrorMarkerFromEnv at boot
// and the Ledger constructor panics on a nil marker — there is no
// unmarked code path, exactly like the CLI `append` subcommand.
//
// PERSISTENCE CAVEAT (loud, intentional): the backing ledger is the
// same IN-MEMORY append-only ring the CLI uses. It is LOST ON RESTART.
// This build is correct for a wired-but-staging smoke (prove the Nexus
// route + provenance + cold-verify end-to-end). A production
// `audit_trail_append` SLA REQUIRES the Phase-2 WAL persistence swap
// first. Do not deploy this as a durable audit store.
//
// Trust boundary: the only Nexus-facing capability route
// (/v1/audit/append) is gated by a fail-closed, constant-time
// X-Nexus-Service-Token check and requires the X-User-Id provenance
// header. An empty NEXUS_SERVICE_TOKEN rejects everything (never
// fail-open). See internal/httpapi.
//
// Environment:
//
//	NEXUS_SERVICE_TOKEN                  shared machine-trust secret;
//	                                      EMPTY ⇒ every append 401s
//	                                      (fail-closed). REQUIRED for
//	                                      the server to serve appends.
//	TRIAL_LEDGER_HTTP_ADDR               listen address (default :8080).
//	TRIAL_LEDGER_LORE_CORPUS_SHA_PATH    Mirror-Mark corpus SHA (loud-once
//	                                      WARN if absent — emitted marks
//	                                      won't cold-verify).
//	TRIAL_LEDGER_MIRRORMARK_KEY          Mirror-Mark HMAC key (iik_...).
//	TRIAL_LEDGER_ESCAPE_SERVICE_URL      cohort-canonical escape-service
//	                                      base URL (2026-07-10 wire-in).
//	                                      Optional — unset/empty keeps the
//	                                      append path byte-identical to the
//	                                      pre-wire server. When set,
//	                                      trust-boundary appends consult
//	                                      /v1/escape and carry its verdict
//	                                      + mark in the cold-verifiable row
//	                                      (never blocking; fail-closed).
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/davly/trial-ledger/internal/auditledger"
	"github.com/davly/trial-ledger/internal/honest"
	"github.com/davly/trial-ledger/internal/httpapi"
	"github.com/davly/trial-ledger/internal/mirrormark"
	"github.com/davly/trial-ledger/internal/trust"
)

const defaultAddr = ":8080"

func main() {
	// LoudOnce-fire every honest-defaults advisory at startup — same
	// R143 discipline as the CLI: each prints exactly once per process.
	for _, adv := range honest.CanonicalAdvisories() {
		honest.LoudOnce(adv, os.Stderr)
	}

	addr := os.Getenv("TRIAL_LEDGER_HTTP_ADDR")
	if addr == "" {
		addr = defaultAddr
	}

	serviceToken := os.Getenv("NEXUS_SERVICE_TOKEN")
	if serviceToken == "" {
		// Fail-closed by design — the server still boots (so a misconfig
		// is observable on the health probe), but every append 401s
		// until the operator provisions the shared secret. Loud so the
		// operator notices.
		log.Printf("trial-ledger-server: WARNING — NEXUS_SERVICE_TOKEN is empty; the /v1/audit/append route is FAIL-CLOSED and will 401 every request until set")
	}

	// Process-lifetime singleton ledger, marker from env (same path as
	// the CLI `append` subcommand). NewLedger panics on a nil marker
	// (R175) — NewMirrorMarkerFromEnv never returns nil, so this is the
	// honest production wiring.
	marker := mirrormark.NewMirrorMarkerFromEnv()
	ledger := auditledger.NewLedger(marker)

	// 2026-07-10 escape-service wire-in (IMP-T2-12 Phase 3 consumer):
	// when TRIAL_LEDGER_ESCAPE_SERVICE_URL is set, trust-boundary
	// appends (esig.sign / esig.withdraw / ecr.delete / ecr.lock)
	// consult the cohort-canonical escape-service and land its verdict
	// + Mirror-Mark INSIDE the cold-verifiable row (never blocking the
	// append; fail-closed on wire errors). Unset (default) => decider
	// stays nil and the decorator's Append is byte-identical to the
	// bare ledger. See internal/auditledger/escape_informed.go.
	var escapeDecider auditledger.EscapeDecider
	if escURL := os.Getenv(trust.EnvEscapeServiceURL); escURL != "" {
		escapeDecider = trust.NewClient(escURL, 0) // 0 => client's 5s default
		log.Printf("trial-ledger-server: escape-service wire ARMED (%s=%s) — trust-boundary appends carry the /v1/escape verdict in-row", trust.EnvEscapeServiceURL, escURL)
	}

	srv := httpapi.NewServer(auditledger.NewEscapeInformedLedger(ledger, escapeDecider), serviceToken)

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	idleClosed := make(chan struct{})
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("trial-ledger-server: graceful shutdown error: %v", err)
		}
		close(idleClosed)
	}()

	log.Printf("trial-ledger-server: listening on %s (capability=audit_trail_append; ledger=in-memory NOT durable — staging only)", addr)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("trial-ledger-server: ListenAndServe: %v", err)
	}
	<-idleClosed
}
