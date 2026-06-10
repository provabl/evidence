// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package nitrotpm_test

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/provabl/evidence/asp"
	"github.com/provabl/evidence/cvm"
	"github.com/provabl/evidence/lower"
	"github.com/provabl/evidence/providers/nitrotpm"
	"github.com/provabl/evidence/term"
	"github.com/provabl/evidence/trust"
)

// amSigner is the ephemeral attestation-manager key (the SIG built-in).
type amSigner struct {
	priv  ed25519.PrivateKey
	keyID string
}

func (s amSigner) Sign(msg []byte) ([]byte, string, error) {
	return ed25519.Sign(s.priv, msg), s.keyID, nil
}

// memTrust verifies the AM key by ID and serves named roots (the aws-tpm root).
type memTrust struct {
	keys  map[string]ed25519.PublicKey
	roots map[string]trust.Root
}

func (t memTrust) Verify(keyID string, msg, sig []byte) (bool, error) {
	pub, ok := t.keys[keyID]
	if !ok {
		return false, nil
	}
	return ed25519.Verify(pub, msg, sig), nil
}
func (t memTrust) Root(name string) (trust.Root, bool) { r, ok := t.roots[name]; return r, ok }

// stubSource returns a fabricated TPM quote. echoNonce controls how it sets the
// quote's qualifyingData relative to the challenge it receives.
type stubSource struct {
	quote     nitrotpm.TPMQuote
	echoNonce bool // true: echo the run's challenge (real TPM2_Quote behavior); false: use quote.Nonce as-is
	fetchErr  error
}

func (s stubSource) Fetch(_ context.Context, _ term.Target, nonce []byte) (nitrotpm.TPMQuote, error) {
	if s.fetchErr != nil {
		return nitrotpm.TPMQuote{}, s.fetchErr
	}
	q := s.quote
	if s.echoNonce {
		q.Nonce = nonce
	}
	return q, nil
}

// stubVerifier returns a fixed verdict for the signature/cert-chain check.
type stubVerifier struct {
	ok      bool
	callErr error
}

func (v stubVerifier) Verify(context.Context, []byte, trust.Root) (bool, error) {
	return v.ok, v.callErr
}

// appraise builds a CVM with the nitrotpm provider, an ephemeral AM, and a trust
// store that (unless told otherwise) serves the aws-tpm root. withRoot=false omits
// it to exercise the missing-root path.
func appraise(t *testing.T, src nitrotpm.Source, ver nitrotpm.Verifier, withRoot bool, params term.Params) (asp.Verdict, error) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	roots := map[string]trust.Root{}
	if withRoot {
		roots[nitrotpm.RootName] = trust.Root{Name: nitrotpm.RootName, Material: []byte("fake-aws-tpm-root")}
	}
	ts := memTrust{keys: map[string]ed25519.PublicKey{"provabl-am-v1": pub}, roots: roots}

	reg := asp.NewRegistry()
	if err := reg.Register(nitrotpm.Provider(src, ver)); err != nil {
		t.Fatal(err)
	}
	c := cvm.New(reg, amSigner{priv, "provabl-am-v1"}, ts, nil)

	protocol := term.Seq(
		term.Nonce(),
		term.Seq(term.Meas(term.Self, nitrotpm.ID, "tpm://self", params), term.Sig()),
	)
	bundle, ch, err := c.Run(context.Background(), protocol)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return c.Appraise(context.Background(), bundle, ch)
}

func goodQuote() nitrotpm.TPMQuote {
	return nitrotpm.TPMQuote{
		PCRs:            map[string]string{"0": "aa", "1": "bb", "4": "cc", "7": "dd"},
		FirmwareVersion: "2.0",
		Raw:             []byte("tpms-attest-and-sig-bytes"),
	}
}

func TestNitroTPM_PassBindsNonce(t *testing.T) {
	v, err := appraise(t, stubSource{quote: goodQuote(), echoNonce: true}, stubVerifier{ok: true}, true, term.Params{})
	if err != nil {
		t.Fatalf("appraise: %v", err)
	}
	if !v.Pass {
		t.Fatalf("expected pass, reason: %s", v.Reason)
	}
	attrs := lower.ToAttributes(v)
	if attrs["platform.tpm_attested"].Value != "true" {
		t.Errorf("platform.tpm_attested = %q, want true", attrs["platform.tpm_attested"].Value)
	}
	if attrs["platform.tpm_nonce_verified"].Value != "true" {
		t.Errorf("platform.tpm_nonce_verified = %q, want true", attrs["platform.tpm_nonce_verified"].Value)
	}
	if attrs["platform.tpm_signature_valid"].Value != "true" {
		t.Errorf("platform.tpm_signature_valid = %q, want true", attrs["platform.tpm_signature_valid"].Value)
	}
	if attrs["platform.tpm_pcr0"].Value != "aa" {
		t.Errorf("platform.tpm_pcr0 = %q, want aa", attrs["platform.tpm_pcr0"].Value)
	}
	if attrs["attested"].Value != "true" {
		t.Errorf("attested = %q, want true", attrs["attested"].Value)
	}
	// Namespace isolation: nitrotpm must NOT emit the enclave provider's keys.
	if _, ok := attrs["platform.nitro_attested"]; ok {
		t.Error("nitrotpm leaked the enclave provider's platform.nitro_attested key")
	}
}

// The native-binding proof: a quote whose qualifyingData does NOT match the run's
// challenge must fail before signature/PCR checks matter.
func TestNitroTPM_NonceMismatchFails(t *testing.T) {
	q := goodQuote()
	q.Nonce = []byte("a-stale-or-forged-nonce-value...") // not the run's challenge; echoNonce=false
	v, err := appraise(t, stubSource{quote: q, echoNonce: false}, stubVerifier{ok: true}, true, term.Params{})
	if err != nil {
		t.Fatalf("appraise: %v", err)
	}
	if v.Pass {
		t.Fatal("expected fail on nonce mismatch (native binding)")
	}
	if lower.ToAttributes(v)["platform.tpm_nonce_verified"].Value != "false" {
		t.Error("expected platform.tpm_nonce_verified=false")
	}
}

func TestNitroTPM_BadSignatureFails(t *testing.T) {
	v, err := appraise(t, stubSource{quote: goodQuote(), echoNonce: true}, stubVerifier{ok: false}, true, term.Params{})
	if err != nil {
		t.Fatalf("appraise: %v", err)
	}
	if v.Pass {
		t.Fatal("expected fail on bad signature")
	}
	if lower.ToAttributes(v)["platform.tpm_signature_valid"].Value != "false" {
		t.Error("expected platform.tpm_signature_valid=false")
	}
}

func TestNitroTPM_PCRPolicyMismatchFails(t *testing.T) {
	// Expected PCR0 differs from the measured "aa".
	v, err := appraise(t, stubSource{quote: goodQuote(), echoNonce: true}, stubVerifier{ok: true}, true,
		term.Params{"expected_pcr0": "deadbeef"})
	if err != nil {
		t.Fatalf("appraise: %v", err)
	}
	if v.Pass {
		t.Fatal("expected fail on PCR0 mismatch")
	}
	if lower.ToAttributes(v)["platform.tpm_attested"].Value != "false" {
		t.Error("expected platform.tpm_attested=false on PCR mismatch")
	}
}

func TestNitroTPM_PCRPolicyMatchPasses(t *testing.T) {
	v, err := appraise(t, stubSource{quote: goodQuote(), echoNonce: true}, stubVerifier{ok: true}, true,
		term.Params{"expected_pcr0": "aa", "expected_pcr7": "dd"})
	if err != nil {
		t.Fatalf("appraise: %v", err)
	}
	if !v.Pass {
		t.Fatalf("expected pass when expected PCRs match, reason: %s", v.Reason)
	}
}

func TestNitroTPM_MissingRootErrors(t *testing.T) {
	_, err := appraise(t, stubSource{quote: goodQuote(), echoNonce: true}, stubVerifier{ok: true}, false, term.Params{})
	if err == nil {
		t.Fatal("expected an error when the aws-tpm root is unavailable")
	}
}

// No TPM device / not a TPM-equipped instance: the measurer reports CollectFailed;
// appraisal fails and emits no platform.* claims, only the kernel's
// nitrotpm.collected marker.
func TestNitroTPM_CollectFailedWhenNoDevice(t *testing.T) {
	v, err := appraise(t, stubSource{fetchErr: context.DeadlineExceeded}, stubVerifier{ok: true}, true, term.Params{})
	if err != nil {
		t.Fatalf("appraise: %v", err)
	}
	if v.Pass {
		t.Fatal("expected fail when no TPM quote could be collected")
	}
	attrs := lower.ToAttributes(v)
	if _, ok := attrs["platform.tpm_attested"]; ok {
		t.Error("expected no platform.* claims on a CollectFailed measurement")
	}
	if attrs["nitrotpm.collected"].Value != "false" {
		t.Errorf("expected nitrotpm.collected=false, got %q", attrs["nitrotpm.collected"].Value)
	}
}
