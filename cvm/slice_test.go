// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package cvm_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/provabl/evidence/asp"
	"github.com/provabl/evidence/cvm"
	"github.com/provabl/evidence/ev"
	"github.com/provabl/evidence/lower"
	"github.com/provabl/evidence/providers/vet"
	"github.com/provabl/evidence/term"
	"github.com/provabl/evidence/trust"
)

// --- deterministic, no-network test doubles ---------------------------------

// amSigner is the provabl Attestation Manager key (the SIG built-in).
type amSigner struct {
	priv  ed25519.PrivateKey
	keyID string
}

func (s amSigner) Sign(msg []byte) ([]byte, string, error) {
	return ed25519.Sign(s.priv, msg), s.keyID, nil
}

// memTrust verifies the AM key by ID and serves named roots.
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

// staticSource returns a fixed provenance bundle for any target.
type staticSource struct{ b vet.Bundle }

func (s staticSource) Fetch(_ context.Context, _ term.Target) (vet.Bundle, error) { return s.b, nil }

// okVerifier / badVerifier stand in for Sigstore verification.
type okVerifier struct{}

func (okVerifier) Verify(context.Context, []byte) (bool, error) { return true, nil }

// --- harness ----------------------------------------------------------------

func newCVM(t *testing.T, src vet.Source, ver vet.Verifier) *cvm.CVM {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer := amSigner{priv: priv, keyID: "provabl-am-v1"}
	ts := memTrust{
		keys:  map[string]ed25519.PublicKey{"provabl-am-v1": pub},
		roots: map[string]trust.Root{"sigstore-rekor": {Name: "sigstore-rekor"}},
	}
	reg := asp.NewRegistry()
	if err := reg.Register(vet.Provider(src, ver)); err != nil {
		t.Fatal(err)
	}
	return cvm.New(reg, signer, ts, nil)
}

// canonical v1 protocol: Signed(Seq(Nonce, Meas(vet)))
func vetTerm(target term.Target, minSLSA string) *term.Term {
	return term.Seq(
		term.Nonce(),
		term.Seq(
			term.Meas(term.Self, vet.ID, target, term.Params{"min_slsa_level": minSLSA}),
			term.Sig(),
		),
	)
}

// --- the founding vertical slice --------------------------------------------

func TestVerticalSlice_PassEmitsCedarAttribute(t *testing.T) {
	c := newCVM(t, staticSource{vet.Bundle{
		SubjectDigest: "sha256:abc", SLSALevel: 2, CriticalCVEs: 0, RekorLogIndex: 42,
	}}, okVerifier{})

	bundle, ch, err := c.Run(context.Background(), vetTerm("artifact://pipeline:v1.2", "2"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	// The bundle is exactly Signed(Seq(Nonce, Meas)) — depth-3 on the first run.
	if bundle.Kind != ev.Signed {
		t.Fatalf("top node = %v, want Signed", bundle.Kind)
	}
	inner := bundle.Children[0]
	if inner.Kind != ev.Seq || len(inner.Children) != 2 {
		t.Fatalf("inner = %v with %d children, want Seq of 2", inner.Kind, len(inner.Children))
	}
	if inner.Children[0].Kind != ev.Nonce || inner.Children[1].Kind != ev.Meas {
		t.Fatalf("inner children = %v,%v want Nonce,Meas", inner.Children[0].Kind, inner.Children[1].Kind)
	}
	if inner.Children[1].Place != term.Self {
		t.Fatalf("meas place = %q, want self (kernel-stamped)", inner.Children[1].Place)
	}

	v, err := c.Appraise(context.Background(), bundle, ch)
	if err != nil {
		t.Fatalf("appraise: %v", err)
	}
	if !v.Pass {
		t.Fatalf("verdict not pass: %s", v.Reason)
	}

	attrs := lower.ToAttributes(v)
	if a := attrs["attested"]; a.Value != "true" || a.Type != "bool" {
		t.Fatalf("attested attr = %+v, want true/bool", a)
	}
	if a := attrs["workload.slsa_level"]; a.Value != "2" || a.Type != "long" {
		t.Fatalf("slsa_level attr = %+v, want 2/long", a)
	}
	if a := attrs["workload.signature_valid"]; a.Value != "true" {
		t.Fatalf("signature_valid attr = %+v, want true", a)
	}
}

func TestVerticalSlice_BelowMinSLSAFails(t *testing.T) {
	c := newCVM(t, staticSource{vet.Bundle{SubjectDigest: "sha256:abc", SLSALevel: 1}}, okVerifier{})
	bundle, ch, err := c.Run(context.Background(), vetTerm("artifact://x", "2"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.Appraise(context.Background(), bundle, ch)
	if err != nil {
		t.Fatal(err)
	}
	if v.Pass {
		t.Fatal("expected fail for SLSA 1 < required 2")
	}
	if lower.ToAttributes(v)["attested"].Value != "false" {
		t.Fatal("attested should be false on a failing verdict")
	}
}

// Freshness: a replayed bundle whose nonce does not match the live challenge
// must fail at the spine before any appraiser runs.
func TestFreshness_NonceMismatchFails(t *testing.T) {
	c := newCVM(t, staticSource{vet.Bundle{SLSALevel: 2}}, okVerifier{})
	bundle, _, err := c.Run(context.Background(), vetTerm("artifact://x", "2"))
	if err != nil {
		t.Fatal(err)
	}
	stale := cvm.Challenge{Nonce: sha256Sum("a-different-challenge")}
	v, err := c.Appraise(context.Background(), bundle, stale)
	if err != nil {
		t.Fatal(err)
	}
	if v.Pass {
		t.Fatal("expected freshness failure on nonce mismatch")
	}
}

// The registry refuses a half-pair: register pairs, never halves.
func TestRegistry_RefusesHalfPair(t *testing.T) {
	reg := asp.NewRegistry()
	err := reg.Register(asp.Provider{ID: "vet", Measurer: vet.Provider(staticSource{}, okVerifier{}).Measurer})
	if err == nil {
		t.Fatal("expected registry to refuse a provider missing its appraiser")
	}
}

func sha256Sum(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }
