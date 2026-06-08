// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package asp defines the one interface that determines whether v1 is "on the
// way to v2" or a teardown: the unit of extension is an (ASP, appraiser) PAIR,
// keyed by ASPID, with a typed Measurement flowing between them.
//
// A measurer that produces evidence nobody can judge is useless; an appraiser
// without its measurer judges nothing. So the registry holds pairs and refuses
// halves. Get this contract right and the deep version (re-pointing attest,
// qualify and vet onto the kernel) is a dependency fact, not a rewrite.
package asp

import (
	"context"
	"fmt"

	"github.com/provabl/evidence/ev"
	"github.com/provabl/evidence/term"
	"github.com/provabl/evidence/trust"
)

// MeasureIn is everything a measurer receives. It always runs locally — the CVM
// resolves @place before calling, so a measurer's world is "measure here, now."
type MeasureIn struct {
	Target term.Target
	Params term.Params
	Nonce  []byte // the challenge; an ASP MAY bind it natively (Nitro). If
	// it cannot (vet), freshness rides the kernel's outer SIG.
	Incoming ev.Evidence // accumulator, for layered "measure-the-measurer". v1 ASPs ignore it.
}

// Measurer gathers raw evidence. It returns an ev.Measurement: UNSIGNED and not
// itself freshness-bound. The kernel owns SIG/HSH and the freshness spine, so no
// ASP signs its own output (that would scatter trust roots and prevent signing a
// sequence of measurements under one key).
type Measurer interface {
	Measure(ctx context.Context, in MeasureIn) (ev.Measurement, error)
}

// Claim is one attribute an appraiser asserts. Type guides Cedar lowering.
type Claim struct {
	Key   string
	Value string
	Type  string // "bool" | "string" | "long" | "set"
}

// Verdict is the appraisal result for a measurement (or, when combined by the
// CVM, for a whole bundle).
type Verdict struct {
	Pass   bool
	Claims []Claim
	Reason string
}

// AppraiseIn is everything an appraiser receives.
type AppraiseIn struct {
	Meas   ev.Measurement
	Params term.Params
	Nonce  []byte      // the issued challenge, for native-binding checks
	Trust  trust.Store // named roots + signature verification
}

// Appraiser judges one measurement, decoding the opaque payload its paired
// measurer produced and emitting attribute-shaped claims.
type Appraiser interface {
	Appraise(ctx context.Context, in AppraiseIn) (Verdict, error)
}

// Provider is the unit of extension: a measurer and its appraiser under one ID.
type Provider struct {
	ID        term.ASPID
	Measurer  Measurer
	Appraiser Appraiser
}

// Registry maps ASPID to Provider. It refuses to register a half-pair.
type Registry struct {
	m map[term.ASPID]Provider
}

func NewRegistry() *Registry { return &Registry{m: map[term.ASPID]Provider{}} }

// Register adds a provider, rejecting duplicates and either-half-missing pairs.
func (r *Registry) Register(p Provider) error {
	if p.ID == "" {
		return fmt.Errorf("asp: provider has empty ID")
	}
	if p.Measurer == nil || p.Appraiser == nil {
		return fmt.Errorf("asp: provider %q must register both a measurer and an appraiser", p.ID)
	}
	if _, dup := r.m[p.ID]; dup {
		return fmt.Errorf("asp: provider %q already registered", p.ID)
	}
	r.m[p.ID] = p
	return nil
}

// Get returns the provider for id.
func (r *Registry) Get(id term.ASPID) (Provider, bool) {
	p, ok := r.m[id]
	return p, ok
}
