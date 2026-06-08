# CLAUDE.md — build guide for `provabl/evidence`

This repo is the **evidence kernel** for the provabl suite: the Copland
attestation model in Go, sitting one layer below Cedar. Read `ARCHITECTURE.md`
first — it is the contract. This file is the operational guide for extending it.

## Conventions

- Module: `github.com/provabl/evidence`. Go 1.22+. Apache-2.0; keep the
  copyright header on every `.go` file.
- Go-first, matching the rest of provabl. Stdlib-only in the kernel where it is
  reasonable; the founding commit has **no external dependencies**.
- Repo lives at `~/src/evidence` (the `~/src/<repo>` convention). Providers may
  live here under `providers/<id>` during the founding push; in production a
  provider may move into its tool's repo — the import direction is identical
  either way (provider imports kernel).

## Hard invariants — do not violate

These are the difference between an evolution and a teardown. A change that
breaks one of these is wrong even if it compiles and passes tests.

1. **No ASP-specific branch in the kernel.** `term`, `ev`, `trust`, `asp`,
   `cvm`, `lower` must never contain `if id == "nitro"` or any equivalent. All
   domain meaning lives in `(ASP, appraiser)` pairs. This is the falsifiable
   test for the whole design.
2. **Dependency direction is one-way.** Tools depend on the kernel; the kernel
   never imports a tool. Providers import the kernel.
3. **Register pairs, never halves.** Extension is always a full `asp.Provider`.
   The registry already refuses a missing half; do not add a way around it.
4. **The kernel owns `SIG`/`HSH` and the nonce.** Measurers return *unsigned*
   `ev.Measurement`. Never sign inside a measurer; never make freshness a
   per-ASP responsibility. Native nonce binding (Nitro) is an *appraisal* check,
   not a kernel branch.
5. **Targets are opaque.** Route on the scheme; never parse a target's internals
   in the kernel.
6. **`CollectStatus` never collapses into the verdict.** A measurement that
   could not be taken is `CollectFailed`, surfaced as its own claim, and must
   never read as a pass.
7. **Carry structure, skip content.** Keep `Place`, `MeasureIn.Incoming`, and
   `Par` in the types. Do not delete them to simplify v1, and do not implement
   them until their consumer exists.

## Layout

```
term/      protocol AST                 ev/        evidence tree + Canonical
trust/     Signer + multi-root Store    asp/       pair contract + Registry
cvm/       interpreter + Appraise       lower/     claims -> Cedar attributes
providers/vet/   first registered pair
cmd/slice/       runnable end-to-end demo
```

## Commands

```bash
go vet ./...           # must be clean
go test ./...          # must be green
go run ./cmd/slice     # prints bundle, verdict, lowered attributes
```

## Adding a provider (the repeatable shape)

Each tool becomes a provider with the same five moves. Use `providers/vet` as
the template.

1. Pick an `ASPID` and a target scheme (`vet` → `artifact://`).
2. **Measurer**: gather raw evidence, marshal it into an opaque `Payload`, set
   `Status`. Gather only — never judge, never sign. Missing input that is a fact
   about the world (no provenance, no training record) is `CollectFailed` or
   `NotApplicable`, not an error.
3. **Appraiser**: decode the payload, verify signatures via `in.Trust`, judge
   against `in.Params`, emit attribute-shaped `Claim`s with correct `Type`.
4. Provide a `Provider(...)` constructor that injects external dependencies
   (sources, verifiers) so the provider tests with no network.
5. Add a deterministic test that runs the canonical
   `Signed(Seq(Nonce, Meas))` term through the CVM and asserts pass, fail, and
   freshness cases. Before freezing anything, sketch one *other* tool against
   your interface change on paper — two imagined consumers keep it honest; one
   does not.

## Build order

Founding push, in order: **kernel → `vet` → `nitro` → `qualify` → `attest`**.
`vet` first is not arbitrary — it is the non-Nitro shape, so building it before
`nitro` makes a Nitro-shaped kernel impossible. `attest` is last because its
many-control scan is the strain test for typed evidence and `CollectStatus`.

Do not start `nitro` until `vet` emits a real lowered Cedar attribute end to
end. "All the way now" means the full *consumer set* on the minimal *operator
set* — never the full operator set before anything real runs.

## Phase two (roadmap — not the founding commit)

When re-pointing the existing tools onto the kernel, migrate **`vet` → `qualify`
→ `attest`** (smallest leap to largest). `attest` stays the Cedar PDP and
*consumes* the kernel; it never absorbs it. Only then consider implementing the
deferred machinery (multi-place transport for the lab marketplace, layered
measure-the-measurer, `Par`) — each driven by a concrete consumer, never ahead
of one.
