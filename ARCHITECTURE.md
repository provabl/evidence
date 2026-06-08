# provabl/evidence — architecture

The evidence kernel beneath the provabl suite. It is the Copland attestation
*model* (terms, typed evidence, appraisal, freshness), reimplemented in Go and
pinned by conformance tests rather than re-proved. provabl makes no
formal-verification claim, so the kernel takes Copland's model and leaves
Copland's Coq proof where it belongs — in the work that sells "formally
verified" to others. Here the *model* is the asset.

It sits one layer below Cedar. Appraisal produces a verdict; Cedar acts on it;
the two never merge. That is the same line as the Copland→Cedar mapping, held
inside provabl: the kernel is the evidence layer, `attest` stays the PDP.

## The one rule

The kernel does **exactly five things**:

1. **route** an `ASPID` to its registered measurer/appraiser pair
2. **thread** evidence through a term (accumulate; `Seq` is left-then-right)
3. **stamp** the resolved place onto each `Meas` node
4. **apply** the nonce / `SIG` / `HSH` built-ins — the freshness spine
5. **dispatch** each `Meas` node to its paired appraiser and combine verdicts

All domain meaning lives in the `(ASP, appraiser)` pairs. The falsifiable test:
**the day `if id == "nitro"` — or any ASP-specific branch — appears in the
kernel, the abstraction has failed.** Fix the interface, not the kernel.

## The load-bearing decision

The unit of extension is **not an ASP — it's an `(ASP, appraiser)` pair, keyed
by `ASPID`, with a typed `Measurement` flowing between them.** A measurer whose
evidence nobody can judge is useless; an appraiser without its measurer judges
nothing. The registry holds pairs and refuses halves (`asp.Registry.Register`).

Get this right and the deep version — re-pointing `attest`, `qualify`, `vet`
onto the kernel — is a dependency fact, not a rewrite. Get it subtly wrong (by
designing it against Nitro as the only example) and you bake in Nitro's shape
and discover it the day you try to migrate. The mitigation is structural: the
first consumer built is **`vet`, not `nitro`** (see Build order).

## Packages and dependency direction

```
term   protocol AST (places, targets, ASPID, operators)         — no kernel deps
ev     typed evidence tree + canonical encoding for SIG/HSH      — imports term
trust  AM Signer + multi-root verification Store                 — no kernel deps
asp    the (Measurer, Appraiser) pair contract + Registry        — imports ev, term, trust
cvm    the interpreter (the five things) + Appraise              — imports asp, ev, term, trust
lower  verdict claims -> Cedar-shaped attributes                 — imports asp
providers/<id>  one registered pair each                         — import asp, ev, term, trust
```

Dependency direction is one-way and non-negotiable: **tools depend on the
kernel; the kernel never depends on a tool.** `attest`/`qualify`/`vet` will
import `provabl/evidence`; they must never import "the runtime-attestation
tool." That direction is the difference between an evolution and a teardown.

## The pair contract (`asp`)

```go
type Measurer  interface { Measure(ctx, MeasureIn)  (ev.Measurement, error) }
type Appraiser interface { Appraise(ctx, AppraiseIn) (Verdict, error) }
type Provider  struct { ID term.ASPID; Measurer Measurer; Appraiser Appraiser }
```

Four properties are deliberate, and three of them are things Nitro alone would
never force you to write:

- **The measurer returns UNSIGNED measurement evidence; the kernel owns
  `SIG`/`HSH`.** If each ASP signed its own output you would get scattered trust
  roots and could not sign a *sequence* of measurements under one key. Freshness
  has two layers that must not be conflated: the kernel's outer `Signed` over
  `Seq(Nonce, …)` binds every bundle (the spine), and platform-native binding
  (Nitro stuffs the nonce inside its own COSE doc) is an *additional appraisal
  requirement* for that one ASP — never a kernel branch.
- **`Target` is opaque and scheme-tagged.** `nitro://self`,
  `artifact://pipeline:v1.2`, `principal://user-sub`. The kernel routes on the
  scheme and never parses past it. The instant the kernel understands a target's
  internals it is Nitro-shaped.
- **`CollectStatus` is orthogonal to the verdict.** `Collected` /
  `CollectFailed` / `NotApplicable` distinguishes *measured-and-bad* from
  *could-not-measure*. Nitro returns a doc or errors and never needs this;
  `attest` scanning many controls absolutely does ("throttled" must not collapse
  into pass or fail). Designing against Nitro alone omits this field and
  rediscovers it as a migration the day `attest` is touched.
- **Place leaves the measurer entirely.** The CVM resolves `@p`, invokes the
  always-local measurer, and *stamps* the resolved place into the evidence node.
  A measurer's world is "measure here, now"; remoteness is transport the kernel
  holds.

## Evidence is a tree, not a blob (`ev`)

The first real evidence value is `Signed(Seq(Nonce, Meas))` — depth-3 on the
first run, so the inductive tree is load-bearing on day one, not speculative.
`Measurement.Payload` is opaque to the kernel and decoded **only** by the paired
appraiser. The kernel stamps `ASP` and `Params` onto each measurement so a
stored bundle is self-contained: a separate appraiser service can judge it later
from the bundle alone.

`Canonical` gives a deterministic byte encoding (stdlib-only, sorted map keys)
used as the message for `SIG`/`HSH`. Production may swap it for canonical CBOR;
the only contract is determinism.

## Freshness model

`SIG` over `Seq(Nonce, Meas)` is the spine and it is in the kernel from day one,
because freshness is the structural payoff and the single most painful thing to
retrofit. Ship real challenge/response now and freshness comes free when the
other tools fold in; bolt it on later and it is a migration across three tools.
This is the piece that fixes Cedar's "trusts stale attributes" gap and makes the
conditionally-computable-data design's "continuous proof-of-presence" real
rather than aspirational.

## Cedar lowering (`lower`)

`ToAttributes` is the **one path** all providers' claims flow through — which
incidentally unifies the attribute writing `qualify` and `vet` each do their own
way today. It produces a typed attribute map and surfaces overall pass as
`attested` so a policy can gate on a single boolean. The kernel *produces*
attributes; `attest` *injects* them into Cedar entities/context and decides.

## Deferred but typed — carry structure, skip content

Inert in v1, but present in the types so they never force a rework:

- **Place** — every `Meas` carries a place; v1 resolves only `Self` and refuses
  anything else loudly. Multi-site (the marketplace shape, or multi-enclave
  provabl) needs no term-type change.
- **Layered measurement** — `MeasureIn.Incoming` threads the accumulator into
  the measurer (the reason Copland ASPs take incoming evidence: measure the
  measurer). v1 measurers ignore it.
- **Par / branching** — `term.KPar` and `ev.Par` exist; the CVM has the case and
  *refuses* it cleanly rather than lacking it.

## Build order (the founding push)

1. **kernel** — `term`, `ev`, `trust`, `asp`, `cvm`, `lower`. Its own module,
   depended on, never containing a tool.
2. **`vet` first** — the non-Nitro shape (no hardware, no native nonce binding),
   so the kernel *cannot* become Nitro-shaped, and it forces `trust` to be real
   (Fulcio/Rekor) before AWS's root ever touches it. Sigstore is callable today.
3. **`nitro` second** — proves the kernel generalized; delivers the
   runtime-attestation capability that started this.
4. **`qualify`** — trivial; makes `NotApplicable` earn its keep (no training
   record ≠ failed training).
5. **`attest` capstone** — one ASP per control family under a `Seq`, each
   `Measurement` carrying its own `CollectStatus`; the partial-scan problem
   dissolves into per-node `CollectFailed`. It is the strain test that justifies
   the typed tree, and it stays *consuming* the kernel, never containing it.

The four consumers bring four genuinely different trust roots (AWS Nitro,
Sigstore Fulcio/Rekor, the provabl AM key, the training authority), which keeps
`trust` honest the same way `vet`-first keeps evidence honest.

## Definition of done — founding commit

- `go test ./...` green; `go vet ./...` clean.
- `go run ./cmd/slice` prints `Signed(Seq(Nonce, Meas))`, a passing verdict, and
  lowered Cedar attributes including `attested = true`.
- The kernel contains **zero** ASP-specific branches.
- `vet` emits a real lowered Cedar attribute before any second provider exists.

If `vet` is not emitting an attribute before `nitro` begins, the build has
slipped into the failure mode (a beautiful general kernel nothing real ran
through). Stop and finish the slice.
