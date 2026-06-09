// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Command slice is a runnable end-to-end demonstration of the kernel with both
// registered providers: it runs the canonical Signed(Seq(Nonce, Meas)) term for
// vet (supply-chain provenance, freshness on the kernel's outer SIG) and for
// nitro (enclave attestation, native nonce binding), appraises each, and prints
// the resulting Cedar-shaped attributes. It uses no network and no real trust
// roots; it exists so `go run ./cmd/slice` shows the loop working for both shapes.
package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sort"

	"github.com/provabl/evidence/asp"
	"github.com/provabl/evidence/cvm"
	"github.com/provabl/evidence/ev"
	"github.com/provabl/evidence/lower"
	"github.com/provabl/evidence/providers/nitro"
	"github.com/provabl/evidence/providers/vet"
	"github.com/provabl/evidence/term"
	"github.com/provabl/evidence/trust"
)

type signer struct {
	priv  ed25519.PrivateKey
	keyID string
}

func (s signer) Sign(msg []byte) ([]byte, string, error) {
	return ed25519.Sign(s.priv, msg), s.keyID, nil
}

type store struct{ pub ed25519.PublicKey }

func (s store) Verify(_ string, msg, sig []byte) (bool, error) {
	return ed25519.Verify(s.pub, msg, sig), nil
}

// Root serves the aws-nitro root the nitro appraiser resolves. Material is a
// placeholder here; production supplies the real AWS Nitro PKI root.
func (s store) Root(name string) (trust.Root, bool) {
	if name == nitro.RootName {
		return trust.Root{Name: nitro.RootName, Material: []byte("demo-aws-nitro-root")}, true
	}
	return trust.Root{}, false
}

// --- vet stub source/verifier ---

type src struct{}

func (src) Fetch(context.Context, term.Target) (vet.Bundle, error) {
	return vet.Bundle{SubjectDigest: "sha256:1f3a…", SLSALevel: 2, CriticalCVEs: 0, RekorLogIndex: 90210}, nil
}

type ver struct{}

func (ver) Verify(context.Context, []byte) (bool, error) { return true, nil }

// --- nitro stub source/verifier ---

// nitroSrc echoes the run's challenge as the document nonce (the real NSM device
// embeds the caller-supplied nonce) and returns fabricated PCRs.
type nitroSrc struct{}

func (nitroSrc) Fetch(_ context.Context, _ term.Target, nonce []byte) (nitro.NSMDoc, error) {
	return nitro.NSMDoc{
		ModuleID: "i-0abc123.enclave",
		Nonce:    nonce,
		PCRs:     map[string]string{"0": "7fb5c5…", "1": "235c9e…", "2": "0f0ac3…", "8": "70da58…"},
		Raw:      []byte("demo-cose-sign1"),
	}, nil
}

type nitroVer struct{}

func (nitroVer) Verify(context.Context, []byte, trust.Root) (bool, error) { return true, nil }

func main() {
	pub, priv, _ := ed25519.GenerateKey(nil)
	reg := asp.NewRegistry()
	if err := reg.Register(vet.Provider(src{}, ver{})); err != nil {
		panic(err)
	}
	if err := reg.Register(nitro.Provider(nitroSrc{}, nitroVer{})); err != nil {
		panic(err)
	}
	c := cvm.New(reg, signer{priv, "provabl-am-v1"}, store{pub}, nil)

	// vet: supply-chain provenance; freshness rides the kernel's outer SIG.
	runDemo(c, "vet — supply-chain provenance", term.Seq(
		term.Nonce(),
		term.Seq(
			term.Meas(term.Self, vet.ID, "artifact://pipeline:v1.2", term.Params{"min_slsa_level": "2"}),
			term.Sig(),
		),
	))

	// nitro: enclave attestation; the document binds the run's nonce natively.
	runDemo(c, "nitro — enclave attestation (native nonce binding)", term.Seq(
		term.Nonce(),
		term.Seq(
			term.Meas(term.Self, nitro.ID, "nitro://self", term.Params{"expected_pcr0": "7fb5c5…"}),
			term.Sig(),
		),
	))
}

// runDemo runs one protocol through the CVM, appraises it, and prints the bundle,
// verdict, and lowered Cedar attributes.
func runDemo(c *cvm.CVM, title string, protocol *term.Term) {
	fmt.Printf("\n=== %s ===\nevidence bundle:\n", title)
	bundle, ch, err := c.Run(context.Background(), protocol)
	if err != nil {
		panic(err)
	}
	printEv(bundle, 1)

	v, err := c.Appraise(context.Background(), bundle, ch)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\nverdict: pass=%v  (%s)\n", v.Pass, v.Reason)

	fmt.Println("\nlowered Cedar attributes:")
	attrs := lower.ToAttributes(v)
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  %-26s = %-10s (%s)\n", k, attrs[k].Value, attrs[k].Type)
	}
}

func printEv(e ev.Evidence, depth int) {
	pad := ""
	for i := 0; i < depth; i++ {
		pad += "  "
	}
	switch e.Kind {
	case ev.Signed:
		fmt.Printf("%sSigned[by=%s]\n", pad, e.SigKeyID)
	case ev.Seq:
		fmt.Printf("%sSeq\n", pad)
	case ev.Nonce:
		fmt.Printf("%sNonce(%d bytes)\n", pad, len(e.NonceVal))
	case ev.Meas:
		fmt.Printf("%sMeas[asp=%s place=%s status=%s]\n", pad, e.Meas.ASP, e.Place, e.Meas.Status)
	case ev.Hashed:
		fmt.Printf("%sHashed\n", pad)
	case ev.Empty:
		fmt.Printf("%sEmpty\n", pad)
	}
	for _, c := range e.Children {
		printEv(c, depth+1)
	}
}
