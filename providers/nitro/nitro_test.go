// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package nitro_test

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/provabl/evidence/asp"
	"github.com/provabl/evidence/cvm"
	"github.com/provabl/evidence/lower"
	"github.com/provabl/evidence/providers/nitro"
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

// memTrust verifies the AM key by ID and serves named roots (the aws-nitro root).
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

// stubSource returns a fabricated NSM document. nonceMode controls how it sets
// the document's nonce relative to the challenge it receives.
type stubSource struct {
	doc       nitro.NSMDoc
	echoNonce bool // true: echo the run's challenge (the real NSM behavior); false: use doc.Nonce as-is
	fetchErr  error
}

func (s stubSource) Fetch(_ context.Context, _ term.Target, nonce []byte) (nitro.NSMDoc, error) {
	if s.fetchErr != nil {
		return nitro.NSMDoc{}, s.fetchErr
	}
	d := s.doc
	if s.echoNonce {
		d.Nonce = nonce
	}
	return d, nil
}

// stubVerifier returns a fixed verdict for the signature/cert-chain check.
type stubVerifier struct {
	ok      bool
	callErr error
}

func (v stubVerifier) Verify(context.Context, []byte, trust.Root) (bool, error) {
	return v.ok, v.callErr
}

// harness builds a CVM with the nitro provider, an ephemeral AM, and a trust
// store that (unless told otherwise) serves the aws-nitro root. withRoot=false
// omits it to exercise the missing-root path.
func appraise(t *testing.T, src nitro.Source, ver nitro.Verifier, withRoot bool, params term.Params) (asp.Verdict, error) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	roots := map[string]trust.Root{}
	if withRoot {
		roots[nitro.RootName] = trust.Root{Name: nitro.RootName, Material: []byte("fake-aws-nitro-root")}
	}
	ts := memTrust{keys: map[string]ed25519.PublicKey{"provabl-am-v1": pub}, roots: roots}

	reg := asp.NewRegistry()
	if err := reg.Register(nitro.Provider(src, ver)); err != nil {
		t.Fatal(err)
	}
	c := cvm.New(reg, amSigner{priv, "provabl-am-v1"}, ts, nil)

	protocol := term.Seq(
		term.Nonce(),
		term.Seq(term.Meas(term.Self, nitro.ID, "nitro://self", params), term.Sig()),
	)
	bundle, ch, err := c.Run(context.Background(), protocol)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return c.Appraise(context.Background(), bundle, ch)
}

func goodDoc() nitro.NSMDoc {
	return nitro.NSMDoc{
		ModuleID: "i-0abc.enclave",
		PCRs:     map[string]string{"0": "aa", "1": "bb", "2": "cc", "8": "dd"},
		Raw:      []byte("cose-sign1-bytes"),
	}
}

func TestNitro_PassBindsNonce(t *testing.T) {
	v, err := appraise(t, stubSource{doc: goodDoc(), echoNonce: true}, stubVerifier{ok: true}, true, term.Params{})
	if err != nil {
		t.Fatalf("appraise: %v", err)
	}
	if !v.Pass {
		t.Fatalf("expected pass, reason: %s", v.Reason)
	}
	attrs := lower.ToAttributes(v)
	if attrs["platform.nitro_attested"].Value != "true" {
		t.Errorf("platform.nitro_attested = %q, want true", attrs["platform.nitro_attested"].Value)
	}
	if attrs["platform.nonce_verified"].Value != "true" {
		t.Errorf("platform.nonce_verified = %q, want true", attrs["platform.nonce_verified"].Value)
	}
	if attrs["platform.module_id"].Value != "i-0abc.enclave" {
		t.Errorf("platform.module_id = %q", attrs["platform.module_id"].Value)
	}
	if attrs["platform.pcr0"].Value != "aa" {
		t.Errorf("platform.pcr0 = %q, want aa", attrs["platform.pcr0"].Value)
	}
	if attrs["attested"].Value != "true" {
		t.Errorf("attested = %q, want true", attrs["attested"].Value)
	}
}

// The native-binding proof: a document whose nonce does NOT match the run's
// challenge must fail before signature/PCR checks matter.
func TestNitro_NonceMismatchFails(t *testing.T) {
	doc := goodDoc()
	doc.Nonce = []byte("a-stale-or-forged-nonce-value...") // not the run's challenge; echoNonce=false
	v, err := appraise(t, stubSource{doc: doc, echoNonce: false}, stubVerifier{ok: true}, true, term.Params{})
	if err != nil {
		t.Fatalf("appraise: %v", err)
	}
	if v.Pass {
		t.Fatal("expected fail on nonce mismatch (native binding)")
	}
	if lower.ToAttributes(v)["platform.nonce_verified"].Value != "false" {
		t.Error("expected platform.nonce_verified=false")
	}
}

func TestNitro_BadSignatureFails(t *testing.T) {
	v, err := appraise(t, stubSource{doc: goodDoc(), echoNonce: true}, stubVerifier{ok: false}, true, term.Params{})
	if err != nil {
		t.Fatalf("appraise: %v", err)
	}
	if v.Pass {
		t.Fatal("expected fail on bad signature")
	}
	if lower.ToAttributes(v)["platform.signature_valid"].Value != "false" {
		t.Error("expected platform.signature_valid=false")
	}
}

func TestNitro_PCRPolicyMismatchFails(t *testing.T) {
	// Expected PCR0 differs from the measured "aa".
	v, err := appraise(t, stubSource{doc: goodDoc(), echoNonce: true}, stubVerifier{ok: true}, true,
		term.Params{"expected_pcr0": "deadbeef"})
	if err != nil {
		t.Fatalf("appraise: %v", err)
	}
	if v.Pass {
		t.Fatal("expected fail on PCR0 mismatch")
	}
}

func TestNitro_PCRPolicyMatchPasses(t *testing.T) {
	v, err := appraise(t, stubSource{doc: goodDoc(), echoNonce: true}, stubVerifier{ok: true}, true,
		term.Params{"expected_pcr0": "aa", "expected_pcr8": "dd"})
	if err != nil {
		t.Fatalf("appraise: %v", err)
	}
	if !v.Pass {
		t.Fatalf("expected pass when expected PCRs match, reason: %s", v.Reason)
	}
}

func TestNitro_MissingRootErrors(t *testing.T) {
	_, err := appraise(t, stubSource{doc: goodDoc(), echoNonce: true}, stubVerifier{ok: true}, false, term.Params{})
	if err == nil {
		t.Fatal("expected an error when the aws-nitro root is unavailable")
	}
}

// No NSM device / not in an enclave: the measurer reports CollectFailed; appraisal
// fails and emits no platform.* claims, only the kernel's nitro.collected marker.
func TestNitro_CollectFailedWhenNoDevice(t *testing.T) {
	v, err := appraise(t, stubSource{fetchErr: context.DeadlineExceeded}, stubVerifier{ok: true}, true, term.Params{})
	if err != nil {
		t.Fatalf("appraise: %v", err)
	}
	if v.Pass {
		t.Fatal("expected fail when no attestation document could be collected")
	}
	attrs := lower.ToAttributes(v)
	if _, ok := attrs["platform.module_id"]; ok {
		t.Error("expected no platform.* claims on a CollectFailed measurement")
	}
	if attrs["nitro.collected"].Value != "false" {
		t.Errorf("expected nitro.collected=false, got %q", attrs["nitro.collected"].Value)
	}
}
