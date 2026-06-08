// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package trust holds the kernel's signing key (the provabl Attestation
// Manager key, used by the SIG built-in) and a multi-root verification store
// that appraisers consult. Designing this against more than one root from day
// one is deliberate: four consumers bring four genuinely different roots (AWS
// Nitro, Sigstore Fulcio/Rekor, the provabl AM key, the training authority),
// so single-root assumptions cannot be baked in.
package trust

// Signer signs evidence for the SIG built-in. The keyID it returns is recorded
// on the Signed node so an appraiser can resolve the verifying key by name.
type Signer interface {
	Sign(msg []byte) (sig []byte, keyID string, err error)
}

// Root is opaque trust-anchor material an appraiser interprets for its own
// domain (a CA bundle, a public key, a Rekor instance URL, etc).
type Root struct {
	Name     string
	Material []byte
}

// Store resolves named roots and verifies signatures by key ID. The kernel uses
// Verify to check Signed nodes; appraisers use Root to get the anchors they need.
type Store interface {
	// Verify reports whether sig is a valid signature over msg by keyID.
	Verify(keyID string, msg, sig []byte) (bool, error)
	// Root returns named root material, e.g. "aws-nitro", "sigstore-rekor".
	Root(name string) (Root, bool)
}
