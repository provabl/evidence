// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Package ev defines the evidence a CVM produces: an inductive tree, not a
// blob. The very first real evidence value, Signed(Seq(Nonce, Meas)), is
// already depth-3 — the tree is load-bearing on day one, not speculative.
package ev

import (
	"bytes"
	"encoding/binary"
	"sort"

	"github.com/provabl/evidence/term"
)

// Kind tags an evidence node.
type Kind uint8

const (
	Empty Kind = iota
	Nonce
	Meas
	Signed
	Hashed
	Seq
	Par
)

// CollectStatus is orthogonal to any appraisal verdict. It records whether the
// measurement could be taken at all — the distinction between measured-and-bad
// and could-not-measure. Nitro never needs this (it returns a doc or errors);
// attest scanning many controls absolutely does (throttled != fail != pass).
type CollectStatus uint8

const (
	Collected     CollectStatus = iota // evidence was gathered
	CollectFailed                      // the measurer could not gather it
	NotApplicable                      // there was nothing to measure
)

func (s CollectStatus) String() string {
	switch s {
	case Collected:
		return "collected"
	case CollectFailed:
		return "collect_failed"
	case NotApplicable:
		return "not_applicable"
	default:
		return "unknown"
	}
}

// Measurement is what a Measurer returns. Payload is opaque to the kernel and
// is decoded ONLY by the paired appraiser. ASP and Params are stamped by the
// kernel (not the measurer) so a stored bundle is self-contained: a separate
// appraiser service can judge it later from the bundle alone.
//
// v1 simplification: recording Params in evidence trusts the term that produced
// it. In a layered/remote setting an appraiser should prefer its own policy over
// params carried in possibly-untrusted evidence; that is a phase-two concern.
type Measurement struct {
	ASP     term.ASPID
	Params  term.Params
	Payload []byte
	Status  CollectStatus
	Detail  string
}

// Evidence is a node in the evidence tree.
type Evidence struct {
	Kind     Kind
	Place    term.Place   // CVM-stamped on Meas nodes; never ASP-supplied
	NonceVal []byte       // Kind == Nonce
	Meas     *Measurement // Kind == Meas
	Sig      []byte       // Kind == Signed
	SigKeyID string       // Kind == Signed: appraiser resolves the key via TrustStore
	Hash     []byte       // Kind == Hashed
	Children []Evidence   // Seq / Par / Signed / Hashed
}

// Append accumulates x onto the threaded evidence e, flattening into a single
// Seq so a linear protocol produces a flat sequence rather than a right-leaning
// comb. Empty is the identity.
func Append(e, x Evidence) Evidence {
	switch e.Kind {
	case Empty:
		return x
	case Seq:
		e.Children = append(e.Children, x)
		return e
	default:
		return Evidence{Kind: Seq, Children: []Evidence{e, x}}
	}
}

// FindNonce returns the first nonce value found in a depth-first walk, used by
// the appraiser to check freshness against the issued challenge.
func FindNonce(e Evidence) ([]byte, bool) {
	if e.Kind == Nonce {
		return e.NonceVal, true
	}
	for _, c := range e.Children {
		if n, ok := FindNonce(c); ok {
			return n, true
		}
	}
	return nil, false
}

// WalkMeas visits every Meas node in document order.
func WalkMeas(e Evidence, fn func(*Measurement, term.Place)) {
	if e.Kind == Meas && e.Meas != nil {
		fn(e.Meas, e.Place)
	}
	for _, c := range e.Children {
		WalkMeas(c, fn)
	}
}

// Canonical produces a deterministic byte encoding of an evidence tree, used as
// the message for the SIG and HSH built-ins. Stdlib-only and stable: a fixed
// tag per kind, length-prefixed bytes, children in slice order. Production may
// swap this for canonical CBOR; the contract is only that it is deterministic.
func Canonical(e Evidence) []byte {
	var b bytes.Buffer
	canon(&b, e)
	return b.Bytes()
}

func canon(b *bytes.Buffer, e Evidence) {
	b.WriteByte(byte(e.Kind))
	writeBytes(b, []byte(e.Place))
	writeBytes(b, e.NonceVal)
	if e.Meas != nil {
		b.WriteByte(1)
		writeBytes(b, []byte(e.Meas.ASP))
		writeBytes(b, e.Meas.Payload)
		b.WriteByte(byte(e.Meas.Status))
		keys := make([]string, 0, len(e.Meas.Params))
		for k := range e.Meas.Params {
			keys = append(keys, k)
		}
		sort.Strings(keys) // sorted for deterministic encoding of the map
		var pn [4]byte
		binary.BigEndian.PutUint32(pn[:], uint32(len(keys)))
		b.Write(pn[:])
		for _, k := range keys {
			writeBytes(b, []byte(k))
			writeBytes(b, []byte(e.Meas.Params[k]))
		}
	} else {
		b.WriteByte(0)
	}
	writeBytes(b, e.Sig)
	writeBytes(b, []byte(e.SigKeyID))
	writeBytes(b, e.Hash)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(e.Children)))
	b.Write(n[:])
	for _, c := range e.Children {
		canon(b, c)
	}
}

func writeBytes(b *bytes.Buffer, p []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(p)))
	b.Write(n[:])
	b.Write(p)
}
