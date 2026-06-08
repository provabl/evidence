// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package cvm is the interpreter. It does EXACTLY five things and no more:
//
//  1. route an ASPID to its registered measurer/appraiser pair
//  2. thread evidence through a term (Append-accumulate; Seq left then right)
//  3. stamp the resolved place onto each Meas node
//  4. apply the nonce / SIG / HSH built-ins (the freshness spine)
//  5. dispatch each Meas node to its paired appraiser and combine verdicts
//
// All domain meaning lives in the (ASP, appraiser) pairs. The falsifiable test:
// the day `if id == "nitro"` (or any other ASP-specific branch) appears in this
// package, the abstraction has failed — fix the interface, not the kernel.
package cvm

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/provabl/evidence/asp"
	"github.com/provabl/evidence/ev"
	"github.com/provabl/evidence/term"
	"github.com/provabl/evidence/trust"
)

// PlaceResolver turns a term place into the place a measurement actually runs
// at. v1 resolves only Self; remoteness is transport the CVM holds, never
// something a measurer knows about.
type PlaceResolver interface {
	Resolve(p term.Place) (term.Place, error)
}

// SelfResolver accepts Self (and the empty zero value) and refuses anything
// else, so a v1 term that names a remote place fails loudly rather than lying.
type SelfResolver struct{}

func (SelfResolver) Resolve(p term.Place) (term.Place, error) {
	if p == "" || p == term.Self {
		return term.Self, nil
	}
	return "", fmt.Errorf("cvm: place %q not resolvable in v1 (only %q)", p, term.Self)
}

// Challenge carries the nonce issued for one run so an appraiser can confirm
// freshness against it.
type Challenge struct {
	Nonce []byte
}

// CVM interprets terms and appraises the evidence they produce.
type CVM struct {
	reg    *asp.Registry
	signer trust.Signer
	trust  trust.Store
	places PlaceResolver
	hash   func([]byte) []byte
}

// New builds a CVM. places may be nil to default to SelfResolver.
func New(reg *asp.Registry, signer trust.Signer, ts trust.Store, places PlaceResolver) *CVM {
	if places == nil {
		places = SelfResolver{}
	}
	return &CVM{
		reg:    reg,
		signer: signer,
		trust:  ts,
		places: places,
		hash:   func(b []byte) []byte { s := sha256.Sum256(b); return s[:] },
	}
}

// Run issues a fresh challenge and interprets t, returning the evidence bundle.
// Appraisal is a separate step (see Appraise) so evidence can be stored,
// forwarded, and judged later or elsewhere.
func (c *CVM) Run(ctx context.Context, t *term.Term) (ev.Evidence, Challenge, error) {
	n := make([]byte, 32)
	if _, err := rand.Read(n); err != nil {
		return ev.Evidence{}, Challenge{}, fmt.Errorf("cvm: nonce: %w", err)
	}
	ch := Challenge{Nonce: n}
	out, err := c.eval(ctx, t, ev.Evidence{Kind: ev.Empty}, ch)
	return out, ch, err
}

// eval threads the accumulator e through term t: eval(t, e) -> e'.
func (c *CVM) eval(ctx context.Context, t *term.Term, e ev.Evidence, ch Challenge) (ev.Evidence, error) {
	switch t.Kind {
	case term.KEmpty:
		return ev.Evidence{Kind: ev.Empty}, nil

	case term.KNonce:
		return ev.Append(e, ev.Evidence{Kind: ev.Nonce, NonceVal: ch.Nonce}), nil

	case term.KMeas:
		pl, err := c.places.Resolve(t.Place) // (3) stamp place
		if err != nil {
			return ev.Evidence{}, err
		}
		prov, ok := c.reg.Get(t.ASP) // (1) route
		if !ok {
			return ev.Evidence{}, fmt.Errorf("cvm: no provider for ASP %q", t.ASP)
		}
		m, err := prov.Measurer.Measure(ctx, asp.MeasureIn{
			Target:   t.Target,
			Params:   t.Params,
			Nonce:    ch.Nonce,
			Incoming: e, // layered measurement input; v1 measurers ignore it
		})
		if err != nil {
			// A measurer error is distinct from a CollectFailed measurement: the
			// former is a kernel/transport fault, the latter is a recorded fact.
			return ev.Evidence{}, fmt.Errorf("cvm: measure %q: %w", t.ASP, err)
		}
		m.ASP = t.ASP       // the kernel owns the ID binding, not the measurer
		m.Params = t.Params // recorded so the bundle is self-contained for appraisal
		return ev.Append(e, ev.Evidence{Kind: ev.Meas, Place: pl, Meas: &m}), nil

	case term.KSig: // (4) freshness spine: sign everything accumulated so far
		msg := ev.Canonical(e)
		sig, keyID, err := c.signer.Sign(msg)
		if err != nil {
			return ev.Evidence{}, fmt.Errorf("cvm: sign: %w", err)
		}
		return ev.Evidence{Kind: ev.Signed, Sig: sig, SigKeyID: keyID, Children: []ev.Evidence{e}}, nil

	case term.KHash: // (4)
		h := c.hash(ev.Canonical(e))
		return ev.Evidence{Kind: ev.Hashed, Hash: h, Children: []ev.Evidence{e}}, nil

	case term.KSeq: // (2) thread left then right
		left, err := c.eval(ctx, t.Left, e, ch)
		if err != nil {
			return ev.Evidence{}, err
		}
		return c.eval(ctx, t.Right, left, ch)

	case term.KPar:
		// Typed but inert in v1: refuse cleanly rather than silently ignore.
		return ev.Evidence{}, fmt.Errorf("cvm: Par not supported in v1")

	default:
		return ev.Evidence{}, fmt.Errorf("cvm: unknown term kind %d", t.Kind)
	}
}

// Appraise walks a bundle and renders a combined verdict. It (a) checks the
// freshness spine — the bundle's nonce must equal the issued challenge, and any
// Signed node must verify under its recorded key — then (b) dispatches each Meas
// node to its paired appraiser and unions the claims. Overall Pass requires the
// freshness checks to hold and every measurement to be Collected and to pass.
func (c *CVM) Appraise(ctx context.Context, e ev.Evidence, ch Challenge) (asp.Verdict, error) {
	// (a) freshness + signature spine.
	if err := c.verifySpine(e, ch); err != nil {
		return asp.Verdict{Pass: false, Reason: err.Error()}, nil
	}

	// (b) per-measurement appraisal.
	pass := true
	var claims []asp.Claim
	var reasons []string
	var walkErr error

	ev.WalkMeas(e, func(m *ev.Measurement, _ term.Place) {
		if walkErr != nil {
			return
		}
		switch m.Status {
		case ev.CollectFailed:
			pass = false
			claims = append(claims, asp.Claim{Key: string(m.ASP) + ".collected", Value: "false", Type: "bool"})
			reasons = append(reasons, fmt.Sprintf("%s: could not measure (%s)", m.ASP, m.Detail))
			return
		case ev.NotApplicable:
			claims = append(claims, asp.Claim{Key: string(m.ASP) + ".applicable", Value: "false", Type: "bool"})
			return
		}
		prov, ok := c.reg.Get(m.ASP)
		if !ok {
			walkErr = fmt.Errorf("cvm: appraise: no provider for ASP %q", m.ASP)
			return
		}
		v, err := prov.Appraiser.Appraise(ctx, asp.AppraiseIn{
			Meas: *m, Params: m.Params, Nonce: ch.Nonce, Trust: c.trust,
		})
		if err != nil {
			walkErr = fmt.Errorf("cvm: appraise %q: %w", m.ASP, err)
			return
		}
		claims = append(claims, v.Claims...)
		if !v.Pass {
			pass = false
			if v.Reason != "" {
				reasons = append(reasons, fmt.Sprintf("%s: %s", m.ASP, v.Reason))
			}
		}
	})
	if walkErr != nil {
		return asp.Verdict{}, walkErr
	}

	reason := "all measurements collected and passed"
	if !pass {
		reason = joinReasons(reasons)
	}
	return asp.Verdict{Pass: pass, Claims: claims, Reason: reason}, nil
}

func (c *CVM) verifySpine(e ev.Evidence, ch Challenge) error {
	n, ok := ev.FindNonce(e)
	if !ok {
		return fmt.Errorf("freshness: bundle carries no nonce")
	}
	if !bytesEqual(n, ch.Nonce) {
		return fmt.Errorf("freshness: bundle nonce does not match the issued challenge")
	}
	return c.verifySigs(e)
}

func (c *CVM) verifySigs(e ev.Evidence) error {
	if e.Kind == ev.Signed {
		if len(e.Children) != 1 {
			return fmt.Errorf("signature: malformed Signed node")
		}
		msg := ev.Canonical(e.Children[0])
		ok, err := c.trust.Verify(e.SigKeyID, msg, e.Sig)
		if err != nil {
			return fmt.Errorf("signature: verify %q: %w", e.SigKeyID, err)
		}
		if !ok {
			return fmt.Errorf("signature: invalid signature by %q", e.SigKeyID)
		}
	}
	for _, ch := range e.Children {
		if err := c.verifySigs(ch); err != nil {
			return err
		}
	}
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func joinReasons(rs []string) string {
	switch len(rs) {
	case 0:
		return "appraisal failed"
	case 1:
		return rs[0]
	default:
		out := rs[0]
		for _, r := range rs[1:] {
			out += "; " + r
		}
		return out
	}
}
