# Changelog

All notable changes to evidence will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Added a `Security Scan` workflow** (`.github/workflows/security.yml`): govulncheck + Trivy filesystem (dependency) + Trivy IaC scans on every push/PR and weekly, blocking on HIGH/CRITICAL. Trivy pinned to `v0.36.0`. Brings this repo in line with the rest of the suite — every Provabl tool now self-scans, fitting a security/compliance suite. The standalone govulncheck job moved out of `ci.yaml` into this workflow (no longer duplicated).

## [0.3.0] - 2026-06-10

### Added

- **`providers/nitrotpm`** (evidence#6): a third registered `(ASP, appraiser)` pair — boot-chain
  attestation of a regular EC2 instance via a TPM 2.0 quote, sibling to the `nitro` enclave
  provider. Same kernel contract (injected `Source`/`Verifier`, native nonce binding on the quote's
  qualifyingData, PCR policy), distinct `platform.tpm_*` claim namespace (no collision with the
  enclave provider's `platform.nitro_*`). Hardware-free stub tests; the kernel stays stdlib-only
  (no new go.mod deps). The real TPM-quote `Source` (`/dev/tpmrm0` + `TPM2_Quote`) and signature
  `Verifier` (go-tpm/x509) are the producer half, deferred and producer-agnostic. `cmd/slice` now
  demonstrates all three providers.

### Changed

- Copyright holder normalized to Playground Logic LLC.

## [0.2.0] - 2026-06-09

### Added

- **`providers/nitro`** — the second registered `(ASP, appraiser)` pair: runtime/enclave
  attestation via AWS Nitro. It is the Nitro shape — the appraiser performs **native nonce
  binding** (the NSM document must carry the run's issued challenge), verifies the COSE_Sign1
  signature against the `aws-nitro` trust root, enforces a PCR policy from `expected_pcr<N>`
  params, and emits `platform.*` claims (`nitro_attested`, `module_id`, `nonce_verified`,
  `signature_valid`, `pcr0/1/2/8`). COSE/CBOR decode and X.509 chain verification are behind
  injected `Source`/`Verifier` interfaces, so the kernel module stays stdlib-only. No NSM device
  / not in an enclave surfaces as `CollectFailed`.
- **`cmd/slice`** now demonstrates both providers end to end (vet riding the kernel's outer SIG,
  nitro binding the nonce natively).

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

[Unreleased]: https://github.com/provabl/evidence/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/provabl/evidence/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/provabl/evidence/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/provabl/evidence/releases/tag/v0.1.0
