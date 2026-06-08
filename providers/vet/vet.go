// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package vet is the FIRST registered (ASP, appraiser) pair, and it is first on
// purpose. vet is the non-Nitro shape — no hardware, no native nonce binding —
// so building it before nitro makes it structurally impossible for the kernel
// to become Nitro-shaped. Freshness rides entirely on the kernel's outer AM
// signature, which is exactly the layer this consumer proves.
//
// vet qualifies the software: it verifies a supply-chain provenance bundle
// (Sigstore signature, SLSA level, SBOM/CVE posture) for an artifact target and
// emits Cedar workload attributes. Both the bundle source and the signature
// verifier are injected, so the founding vertical slice tests with no network.
package vet

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/provabl/evidence/asp"
	"github.com/provabl/evidence/ev"
	"github.com/provabl/evidence/term"
)

// ID is the ASPID that keys this pair in the registry.
const ID term.ASPID = "vet"

// Bundle is the provenance the source returns for an artifact. In production the
// DSSE envelope is verified against Sigstore Fulcio/Rekor; here it is opaque
// bytes the appraiser hands to the injected verifier.
type Bundle struct {
	SubjectDigest string `json:"subject_digest"`
	SLSALevel     int    `json:"slsa_level"`
	CriticalCVEs  int    `json:"critical_cves"`
	RekorLogIndex int64  `json:"rekor_log_index"`
	DSSEEnvelope  []byte `json:"dsse_envelope"`
}

// Source fetches the provenance bundle for an artifact target.
type Source interface {
	Fetch(ctx context.Context, target term.Target) (Bundle, error)
}

// Verifier checks a DSSE envelope against the Sigstore roots. Injected so the
// slice test can supply a deterministic stub; production wires cosign/rekor.
type Verifier interface {
	Verify(ctx context.Context, env []byte) (ok bool, err error)
}

// Provider assembles the pair from an injected source and verifier.
func Provider(src Source, ver Verifier) asp.Provider {
	return asp.Provider{
		ID:        ID,
		Measurer:  measurer{src: src},
		Appraiser: appraiser{ver: ver},
	}
}

// --- measurer: gather, do not judge -----------------------------------------

type measurer struct{ src Source }

func (m measurer) Measure(ctx context.Context, in asp.MeasureIn) (ev.Measurement, error) {
	b, err := m.src.Fetch(ctx, in.Target)
	if err != nil {
		// A missing bundle is a recorded fact, not a kernel fault: the artifact
		// simply has no provenance to inspect. Surface it as CollectFailed so it
		// can never be mistaken for a pass.
		return ev.Measurement{
			Status: ev.CollectFailed,
			Detail: fmt.Sprintf("no provenance for %s: %v", in.Target, err),
		}, nil
	}
	// Note: vet does not bind in.Nonce — it has no native channel for it. The
	// kernel's outer SIG over Seq(Nonce, Meas) is what makes this measurement
	// fresh. That asymmetry from Nitro is the whole reason vet is built first.
	payload, err := json.Marshal(b)
	if err != nil {
		return ev.Measurement{}, fmt.Errorf("vet: marshal bundle: %w", err)
	}
	return ev.Measurement{Payload: payload, Status: ev.Collected}, nil
}

// --- appraiser: decode the opaque payload, judge, emit claims ----------------

type appraiser struct{ ver Verifier }

func (a appraiser) Appraise(ctx context.Context, in asp.AppraiseIn) (asp.Verdict, error) {
	var b Bundle
	if err := json.Unmarshal(in.Meas.Payload, &b); err != nil {
		return asp.Verdict{}, fmt.Errorf("vet: decode payload: %w", err)
	}

	claims := []asp.Claim{
		{Key: "workload.slsa_level", Value: strconv.Itoa(b.SLSALevel), Type: "long"},
		{Key: "workload.cves_critical", Value: strconv.Itoa(b.CriticalCVEs), Type: "long"},
		{Key: "workload.subject_digest", Value: b.SubjectDigest, Type: "string"},
	}

	okSig, err := a.ver.Verify(ctx, b.DSSEEnvelope)
	if err != nil {
		return asp.Verdict{}, fmt.Errorf("vet: verify signature: %w", err)
	}
	if !okSig {
		return asp.Verdict{Pass: false, Claims: append(claims,
			asp.Claim{Key: "workload.signature_valid", Value: "false", Type: "bool"}),
			Reason: "sigstore signature did not verify"}, nil
	}
	claims = append(claims, asp.Claim{Key: "workload.signature_valid", Value: "true", Type: "bool"})

	minLevel := 1
	if s, ok := in.Params["min_slsa_level"]; ok {
		if n, err := strconv.Atoi(s); err == nil {
			minLevel = n
		}
	}
	if b.SLSALevel < minLevel {
		return asp.Verdict{Pass: false, Claims: claims,
			Reason: fmt.Sprintf("SLSA level %d below required %d", b.SLSALevel, minLevel)}, nil
	}
	if b.CriticalCVEs > 0 {
		return asp.Verdict{Pass: false, Claims: claims,
			Reason: fmt.Sprintf("%d critical CVEs present", b.CriticalCVEs)}, nil
	}
	return asp.Verdict{Pass: true, Claims: claims, Reason: "supply-chain provenance verified"}, nil
}
