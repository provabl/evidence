// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Package nitrotpm is a registered (ASP, appraiser) pair that attests the BOOT
// CHAIN of a regular EC2 instance via a TPM 2.0 quote. It is the sibling of the
// nitro Enclaves provider and the same Nitro shape: runtime/platform attestation
// with NATIVE nonce binding and a real hardware trust root.
//
//   - nitro (enclave): an NSM COSE/CBOR document whose PCRs measure the enclave
//     image. Answers "is this workload running in a known-good isolated enclave?"
//   - nitrotpm (this): a TPM 2.0 Quote over the platform PCRs (UEFI -> bootloader
//     -> kernel) on an ordinary instance. Answers "did this instance boot a
//     known-good OS?" — weaker for workload identity, but it applies to the many
//     workloads that are NOT in an enclave.
//
// They are complements, not substitutes, and they share the kernel contract
// exactly — nitrotpm adds zero ASP-specific branches to the kernel and proves the
// abstraction generalizes to a second platform-attestation source.
//
// A TPM 2.0 Quote is a signed structure (TPMS_ATTEST) over a selected set of PCRs,
// carrying qualifyingData (the requester's nonce, bound natively) and signed by an
// Attestation Key whose certificate chains to a platform root (here, the AWS
// NitroTPM PKI root). Parsing the TPM wire structures and verifying the AK
// signature + cert chain require libraries the evidence kernel deliberately does
// not depend on, so — exactly as for the enclave provider's COSE/CBOR/X.509 — both
// the quote Source and the signature Verifier are INJECTED. This provider owns the
// universal appraisal logic (nonce binding, PCR policy, claim emission) and works
// on a parsed TPMQuote; the TPM/x509 specifics live behind the injected interfaces,
// keeping this repo stdlib-only and letting tests run with a fabricated quote and
// no hardware.
//
// The real Source (reading /dev/tpmrm0 and issuing TPM2_Quote) and Verifier
// (go-tpm + x509) are the producer half, deliberately deferred: this provider is
// producer-agnostic, just as the nitro provider landed before its NSM producer.
package nitrotpm

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
const ID term.ASPID = "nitrotpm"

// RootName is the named trust root the appraiser resolves from the trust store to
// verify the TPM quote's attestation-key certificate chain.
const RootName = "aws-tpm"

// TPMQuote is the PARSED TPM 2.0 quote. The injected Source produces it (reading
// the TPM and decoding the TPMS_ATTEST/PCR structures); the appraiser works on this
// shape and hands Raw to the injected Verifier for signature + cert-chain checks.
type TPMQuote struct {
	// Nonce is the quote's qualifyingData — the challenge the requester embedded so
	// the quote binds this run natively (the platform-native freshness vet cannot do).
	Nonce []byte `json:"nonce"`
	// PCRs maps PCR index ("0".."23") to its hex digest. The boot-chain PCRs of
	// interest are typically 0 (UEFI firmware), 1 (UEFI config), 4 (bootloader),
	// 7 (secure boot policy), 8/9 (kernel/initrd via the OS).
	PCRs map[string]string `json:"pcrs"`
	// FirmwareVersion and ClockInfo are optional diagnostic fields carried in the
	// TPMS_ATTEST; they are not appraised, only surfaced for the record.
	FirmwareVersion string `json:"firmware_version,omitempty"`
	// Raw is the original signed quote blob (TPMS_ATTEST + signature, and whatever
	// the producer needs for cert-chain verification), passed to the Verifier.
	Raw []byte `json:"raw"`
}

// Source obtains a TPM 2.0 quote for a target, embedding the given nonce as the
// quote's qualifyingData. In production this opens /dev/tpmrm0 and issues a
// TPM2_Quote over the selected PCRs; in tests it is a stub. The nonce parameter is
// what makes a nitrotpm measurement fresh — the quote binds the challenge natively.
type Source interface {
	Fetch(ctx context.Context, target term.Target, nonce []byte) (TPMQuote, error)
}

// Verifier checks that raw (the signed TPM quote) carries a valid signature whose
// attestation-key certificate chain anchors to root (the aws-tpm PKI root).
// Injected so the evidence repo needs no TPM/x509 dependency; production wires the
// go-tpm + x509 verification, tests supply a deterministic stub.
type Verifier interface {
	Verify(ctx context.Context, raw []byte, root trust.Root) (ok bool, err error)
}

// Provider assembles the pair from an injected quote source and verifier.
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
	// The Source embeds in.Nonce as the quote's qualifyingData. The measurer does
	// NOT verify the binding — gathering only; the appraiser confirms the returned
	// quote actually carries this nonce.
	q, err := m.src.Fetch(ctx, in.Target, in.Nonce)
	if err != nil {
		// No TPM device / not a TPM-equipped instance is a recorded fact, not a
		// kernel fault, and must never read as a pass.
		return ev.Measurement{
			Status: ev.CollectFailed,
			Detail: fmt.Sprintf("nitrotpm: no TPM quote for %s: %v", in.Target, err),
		}, nil
	}
	payload, err := json.Marshal(q)
	if err != nil {
		return ev.Measurement{}, fmt.Errorf("nitrotpm: marshal quote: %w", err)
	}
	return ev.Measurement{Payload: payload, Status: ev.Collected}, nil
}

// --- appraiser: decode, verify, judge, emit platform.tpm_* claims ------------

type appraiser struct{ ver Verifier }

func (a appraiser) Appraise(ctx context.Context, in asp.AppraiseIn) (asp.Verdict, error) {
	var q TPMQuote
	if err := json.Unmarshal(in.Meas.Payload, &q); err != nil {
		return asp.Verdict{}, fmt.Errorf("nitrotpm: decode quote: %w", err)
	}

	claims := make([]asp.Claim, 0, len(q.PCRs)+4)
	for _, idx := range sortedPCRIndexes(q.PCRs) {
		claims = append(claims, asp.Claim{Key: "platform.tpm_pcr" + idx, Value: q.PCRs[idx], Type: "string"})
	}

	// (1) Native nonce binding — the quote must carry the exact qualifyingData the
	// kernel issued for this run.
	if !bytes.Equal(q.Nonce, in.Nonce) {
		return fail(claims, "tpm_nonce_verified", "nitrotpm: quote qualifyingData does not match the issued challenge"), nil
	}
	claims = append(claims, asp.Claim{Key: "platform.tpm_nonce_verified", Value: "true", Type: "bool"})

	// (2) Signature + AK cert chain to the aws-tpm root.
	root, ok := in.Trust.Root(RootName)
	if !ok {
		return asp.Verdict{}, fmt.Errorf("nitrotpm: trust root %q not available", RootName)
	}
	okSig, err := a.ver.Verify(ctx, q.Raw, root)
	if err != nil {
		return asp.Verdict{}, fmt.Errorf("nitrotpm: verify signature: %w", err)
	}
	if !okSig {
		return fail(claims, "tpm_signature_valid", "nitrotpm: quote signature did not verify against "+RootName), nil
	}
	claims = append(claims, asp.Claim{Key: "platform.tpm_signature_valid", Value: "true", Type: "bool"})

	// (3) PCR policy — every expected_pcr<N> param must match the measured PCR.
	for key, want := range in.Params {
		idx, ok := strings.CutPrefix(key, "expected_pcr")
		if !ok {
			continue
		}
		got, present := q.PCRs[idx]
		if !present || got != want {
			return fail(claims, "tpm_attested",
				fmt.Sprintf("nitrotpm: PCR%s = %q, expected %q", idx, got, want)), nil
		}
	}

	claims = append(claims, asp.Claim{Key: "platform.tpm_attested", Value: "true", Type: "bool"})
	return asp.Verdict{Pass: true, Claims: claims, Reason: "nitrotpm: boot-chain attestation verified"}, nil
}

// fail returns a failing verdict, recording the specific failed check as a false
// claim and surfacing platform.tpm_attested=false so a policy can gate on the
// single overall boolean.
func fail(claims []asp.Claim, failedCheck, reason string) asp.Verdict {
	claims = append(claims,
		asp.Claim{Key: "platform." + failedCheck, Value: "false", Type: "bool"},
		asp.Claim{Key: "platform.tpm_attested", Value: "false", Type: "bool"},
	)
	return asp.Verdict{Pass: false, Claims: claims, Reason: reason}
}

// sortedPCRIndexes returns the PCR indexes in deterministic order for stable claim
// output.
func sortedPCRIndexes(pcrs map[string]string) []string {
	idxs := make([]string, 0, len(pcrs))
	for k := range pcrs {
		idxs = append(idxs, k)
	}
	sort.Strings(idxs)
	return idxs
}
