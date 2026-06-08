# provabl/evidence

**The Copland-model evidence kernel beneath Cedar for the Provabl suite.**

Part of the [Provabl](https://provabl.dev) suite:
- **[ground](https://ground.provabl.dev)** — deploy correct AWS foundations
- **[attest](https://attest.provabl.dev)** — compile, enforce, and prove compliance
- **[qualify](https://qualify.provabl.dev)** — train and qualify researchers
- **[vet](https://vet.provabl.dev)** — verify the software supply chain
- **evidence** — the attestation layer the others gather and appraise evidence through ← you are here

> Ground your infrastructure, attest your controls, qualify your people, vet your software.

---

The evidence kernel for the [provabl](https://provabl.dev) suite. The Copland
attestation model — terms, typed evidence, appraisal, freshness — in Go,
sitting one layer below Cedar.

Appraisal produces a verdict; Cedar acts on it. The kernel is the evidence
layer; `attest` stays the policy decision point. Each provabl capability
(`vet`, `nitro`, `qualify`, `attest`) becomes one `(ASP, appraiser)` pair
registered against the kernel.

```bash
go test ./...          # green
go run ./cmd/slice     # kernel + vet, end to end
```

```
$ go run ./cmd/slice
evidence bundle:
  Signed[by=provabl-am-v1]
    Seq
      Nonce(32 bytes)
      Meas[asp=vet place=self status=collected]

verdict: pass=true  (all measurements collected and passed)

lowered Cedar attributes:
  attested                   = true     (bool)
  workload.cves_critical     = 0        (long)
  workload.signature_valid   = true     (bool)
  workload.slsa_level        = 2        (long)
  workload.subject_digest    = sha256:1f3a… (string)
```

See `ARCHITECTURE.md` for the contract and `CLAUDE.md` for the build guide.

The one rule: the kernel does exactly five things — route, thread, stamp place,
apply the nonce/SIG/HSH built-ins, dispatch appraisal. All domain meaning lives
in the pairs. The day an ASP-specific branch appears in the kernel, the
abstraction has failed.

Apache-2.0 · © 2026 Scott Friedman
