// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Package term defines the protocol language: the AST a CVM interprets to
// gather evidence. It is a Copland-style term algebra. The kernel interprets
// these terms; it never special-cases any particular ASP, target, or place.
//
// A v1 protocol is built from Nonce, Meas, Sig, Hash and Seq only. Par and the
// Place value are carried in the types but inert in v1 (see ARCHITECTURE.md,
// "carry structure, skip content").
package term

// Place identifies where a Meas term executes. In v1 only Self is resolvable;
// the field is carried on every Meas so multi-site execution does not force a
// term-type rework later.
type Place string

const Self Place = "self"

// Target is an opaque, scheme-tagged reference to what an ASP measures, e.g.
// "artifact://pipeline:v1.2", "nitro://self", "principal://user-sub". The
// kernel routes on the scheme only and never parses past it.
type Target string

// ASPID keys BOTH a measurer and its paired appraiser in the registry. It is
// the only thing the kernel knows about an ASP: how to route to it.
type ASPID string

// Params are opaque key/values handed to a measurer and its appraiser (golden
// references, minimum levels, target config). The kernel never interprets them.
type Params map[string]string

// Kind enumerates the term operators.
type Kind uint8

const (
	KEmpty Kind = iota // {}      no evidence
	KNonce             // NONCE   inject the run's fresh challenge nonce
	KMeas              // measure run ASP at Place against Target
	KSig               // SIG     kernel signs the accumulated evidence (AM key)
	KHash              // HSH     kernel hashes the accumulated evidence
	KSeq               // ->      linear sequencing: thread evidence L then R
	KPar               // +<+     parallel branch — TYPED but refused by the v1 CVM
)

// Term is an AST node. Construct with the helpers below rather than by hand.
type Term struct {
	Kind   Kind
	Place  Place  // KMeas: where to run (v1 must resolve to Self)
	ASP    ASPID  // KMeas
	Target Target // KMeas
	Params Params // KMeas
	Left   *Term  // KSeq / KPar
	Right  *Term  // KSeq / KPar
}

// Empty is the term producing no evidence.
func Empty() *Term { return &Term{Kind: KEmpty} }

// Nonce injects this run's challenge nonce into the evidence accumulator.
func Nonce() *Term { return &Term{Kind: KNonce} }

// Meas runs the ASP identified by id at place p against target t with params.
func Meas(p Place, id ASPID, t Target, params Params) *Term {
	return &Term{Kind: KMeas, Place: p, ASP: id, Target: t, Params: params}
}

// Sig signs everything accumulated so far under the kernel's AM key.
func Sig() *Term { return &Term{Kind: KSig} }

// Hash hashes everything accumulated so far.
func Hash() *Term { return &Term{Kind: KHash} }

// Seq threads the accumulator through l, then through r.
func Seq(l, r *Term) *Term { return &Term{Kind: KSeq, Left: l, Right: r} }

// Par is the parallel branch. Carried for forward compatibility; the v1 CVM
// refuses to interpret it rather than silently ignoring it.
func Par(l, r *Term) *Term { return &Term{Kind: KPar, Left: l, Right: r} }
