# Changelog

All notable changes to evidence will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-08

### Added

- **The evidence kernel** — the Copland attestation model (terms, typed evidence,
  appraisal, freshness) in Go, sitting one layer below Cedar. Appraisal produces a
  verdict; Cedar acts on it; the two never merge.
- **`term`** — Copland-style protocol AST (`Nonce`, `Meas`, `Sig`, `Hash`, `Seq`;
  `Par` and `Place` carried but inert in v1).
- **`ev`** — inductive typed evidence tree with deterministic `Canonical` encoding,
  and `CollectStatus` (`Collected` / `CollectFailed` / `NotApplicable`) kept orthogonal
  to the appraisal verdict.
- **`trust`** — AM `Signer` plus a multi-root verification `Store` (designed for the
  four genuinely different roots the suite brings: AWS Nitro, Sigstore Fulcio/Rekor,
  the provabl AM key, the training authority).
- **`asp`** — the `(Measurer, Appraiser)` pair contract and a `Registry` that refuses
  half-pairs. The unit of extension is a pair keyed by `ASPID`, never a lone ASP.
- **`cvm`** — the interpreter that does exactly five things (route, thread, stamp place,
  apply the nonce/SIG/HSH freshness spine, dispatch appraisal). Zero ASP-specific
  branches — the falsifiable test for the whole design.
- **`lower`** — the single path turning appraisal claims into Cedar-shaped attributes
  (`ToAttributes`), surfacing overall pass as `attested`.
- **`providers/vet`** — the first registered `(ASP, appraiser)` pair (the non-Nitro
  shape), verifying supply-chain provenance and emitting `workload.*` Cedar attributes.
- **`cmd/slice`** — a runnable end-to-end demonstration of the founding vertical slice.
- Conformance tests in `cvm/slice_test.go` covering pass, sub-policy fail, freshness
  (nonce mismatch), and registry half-pair rejection.

[Unreleased]: https://github.com/provabl/evidence/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/provabl/evidence/releases/tag/v0.1.0
