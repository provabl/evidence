// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Package nitro is the SECOND registered (ASP, appraiser) pair, and it is the
// Nitro shape: runtime/enclave attestation with NATIVE nonce binding and a real
// hardware trust root. vet was built first on purpose (no hardware, freshness
// rides the kernel's outer SIG), so by the time nitro arrives the kernel cannot
// have become Nitro-shaped. nitro proves the abstraction generalized — and it is
// where the kernel's "native nonce binding is an appraisal check, not a kernel
// branch" rule earns its keep.
//
// An AWS Nitro Enclave's NSM device issues a COSE_Sign1 (CBOR) attestation
// document: module_id, a PCR map (PCR0=image, PCR1=kernel, PCR2=app, PCR8=signing
// cert; SHA384), a nonce echoed from the requester, and a cabundle cert chain to
// the AWS Nitro Attestation PKI root. Decoding COSE/CBOR and verifying the X.509
// chain require libraries the evidence kernel deliberately does not depend on, so
// both the document Source and the signature Verifier are INJECTED. The provider
// owns the universal appraisal logic (nonce binding, PCR policy, claim emission)
// and works on a parsed NSMDoc; the COSE/CBOR/X.509 specifics live behind the
// injected interfaces, keeping this repo stdlib-only. The same shape lets the
// tests run with a fabricated doc and no hardware.
package nitro

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/provabl/evidence/asp"
	"github.com/provabl/evidence/ev"
	"github.com/provabl/evidence/term"
	"github.com/provabl/evidence/trust"
)

// ID keys this pair in the registry.
const ID term.ASPID = "nitro"

// RootName is the named trust root the appraiser resolves from the trust store to
// verify the NSM document's signature chain.
const RootName = "aws-nitro"

// NSMDoc is the PARSED Nitro attestation document. The injected Source produces
// it (decoding the COSE_Sign1/CBOR); the appraiser works on this shape and hands
// Raw to the injected Verifier for signature + cert-chain verification.
type NSMDoc struct {
	ModuleID  string            `json:"module_id"`
	Nonce     []byte            `json:"nonce"`     // echoed from the requester's challenge
	PCRs      map[string]string `json:"pcrs"`      // PCR index ("0","1","2","8") -> hex SHA384
	Timestamp int64             `json:"timestamp"` // ms since epoch, from the doc
	Raw       []byte            `json:"raw"`       // original COSE_Sign1 bytes, for the Verifier
}

// Source obtains the NSM attestation document for a target, embedding the given
// nonce as the document's challenge. In production this calls the enclave's NSM
// device (the Nitro SDK's get-attestation-document, which takes a caller nonce);
// in tests it is a stub. The nonce parameter is the deliberate difference from
// vet's Source: a nitro measurement is nonce-parameterized — the document binds
// the challenge natively, which is the whole point of building nitro second.
type Source interface {
	Fetch(ctx context.Context, target term.Target, nonce []byte) (NSMDoc, error)
}

// Verifier checks that raw (the COSE_Sign1 document) carries a valid signature
// whose certificate chain anchors to root (the aws-nitro PKI root). Injected so
// the evidence repo needs no COSE/CBOR/X.509 dependency; production wires the AWS
// Nitro verification, tests supply a deterministic stub.
type Verifier interface {
	Verify(ctx context.Context, raw []byte, root trust.Root) (ok bool, err error)
}

// Provider assembles the pair from an injected document source and verifier.
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
	// The Source embeds in.Nonce as the document's challenge. The measurer does
	// NOT itself verify the binding — gathering only; the appraiser confirms the
	// returned document actually carries this nonce.
	doc, err := m.src.Fetch(ctx, in.Target, in.Nonce)
	if err != nil {
		// Not running in an enclave / no NSM device is a recorded fact, not a
		// kernel fault, and must never read as a pass.
		return ev.Measurement{
			Status: ev.CollectFailed,
			Detail: fmt.Sprintf("nitro: no attestation document for %s: %v", in.Target, err),
		}, nil
	}
	payload, err := json.Marshal(doc)
	if err != nil {
		return ev.Measurement{}, fmt.Errorf("nitro: marshal document: %w", err)
	}
	return ev.Measurement{Payload: payload, Status: ev.Collected}, nil
}

// --- appraiser: decode, verify, judge, emit platform.* claims ----------------

type appraiser struct{ ver Verifier }

func (a appraiser) Appraise(ctx context.Context, in asp.AppraiseIn) (asp.Verdict, error) {
	var doc NSMDoc
	if err := json.Unmarshal(in.Meas.Payload, &doc); err != nil {
		return asp.Verdict{}, fmt.Errorf("nitro: decode document: %w", err)
	}

	claims := []asp.Claim{
		{Key: "platform.module_id", Value: doc.ModuleID, Type: "string"},
	}
	for _, idx := range sortedPCRIndexes(doc.PCRs) {
		claims = append(claims, asp.Claim{Key: "platform.pcr" + idx, Value: doc.PCRs[idx], Type: "string"})
	}

	// (1) Native nonce binding — the platform-native freshness vet cannot do. The
	// document must carry the exact challenge the kernel issued for this run.
	if !bytes.Equal(doc.Nonce, in.Nonce) {
		return fail(claims, "nonce_verified", "nitro: attestation nonce does not match the issued challenge"), nil
	}
	claims = append(claims, asp.Claim{Key: "platform.nonce_verified", Value: "true", Type: "bool"})

	// (2) Signature + cert chain to the aws-nitro root.
	root, ok := in.Trust.Root(RootName)
	if !ok {
		return asp.Verdict{}, fmt.Errorf("nitro: trust root %q not available", RootName)
	}
	okSig, err := a.ver.Verify(ctx, doc.Raw, root)
	if err != nil {
		return asp.Verdict{}, fmt.Errorf("nitro: verify signature: %w", err)
	}
	if !okSig {
		return fail(claims, "signature_valid", "nitro: attestation signature did not verify against "+RootName), nil
	}
	claims = append(claims, asp.Claim{Key: "platform.signature_valid", Value: "true", Type: "bool"})

	// (3) PCR policy — every expected_pcr<N> param must match the measured PCR.
	for key, want := range in.Params {
		idx, ok := strings.CutPrefix(key, "expected_pcr")
		if !ok {
			continue
		}
		got, present := doc.PCRs[idx]
		if !present || got != want {
			return fail(claims, "nitro_attested",
				fmt.Sprintf("nitro: PCR%s = %q, expected %q", idx, got, want)), nil
		}
	}

	claims = append(claims, asp.Claim{Key: "platform.nitro_attested", Value: "true", Type: "bool"})
	return asp.Verdict{Pass: true, Claims: claims, Reason: "nitro: enclave attestation verified"}, nil
}

// fail returns a failing verdict, recording the specific failed check as a false
// claim and surfacing platform.nitro_attested=false so a policy can gate on the
// single overall boolean.
func fail(claims []asp.Claim, failedCheck, reason string) asp.Verdict {
	claims = append(claims,
		asp.Claim{Key: "platform." + failedCheck, Value: "false", Type: "bool"},
		asp.Claim{Key: "platform.nitro_attested", Value: "false", Type: "bool"},
	)
	return asp.Verdict{Pass: false, Claims: claims, Reason: reason}
}

// sortedPCRIndexes returns the PCR indexes in deterministic order for stable
// claim output.
func sortedPCRIndexes(pcrs map[string]string) []string {
	idxs := make([]string, 0, len(pcrs))
	for k := range pcrs {
		idxs = append(idxs, k)
	}
	sort.Strings(idxs)
	return idxs
}
