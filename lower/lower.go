// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package lower is the ONE path that turns appraisal claims into Cedar-shaped
// attributes. Every provider's claims flow through here, which is what unifies
// the attribute-writing that qualify and vet currently each do their own way.
//
// The kernel produces attributes; it does not inject them. attest stays the
// Cedar PDP / authorization layer and owns injection into entities/context.
// That preserves, inside provabl, the same line as the Copland -> Cedar
// mapping: appraisal produces the verdict, Cedar acts on it, they never merge.
package lower

import "github.com/provabl/evidence/asp"

// Attr is a typed attribute value destined for a Cedar entity or context.
type Attr struct {
	Value string
	Type  string // "bool" | "string" | "long" | "set"
}

// ToAttributes flattens a verdict's claims into a typed attribute map. Later
// claims for the same key win, so a combined bundle's most specific assertion
// is the one that lowers. The verdict's overall pass is surfaced as
// "attested" so a Cedar policy can gate on a single boolean if it wants to.
func ToAttributes(v asp.Verdict) map[string]Attr {
	out := make(map[string]Attr, len(v.Claims)+1)
	for _, c := range v.Claims {
		t := c.Type
		if t == "" {
			t = "string"
		}
		out[c.Key] = Attr{Value: c.Value, Type: t}
	}
	out["attested"] = Attr{Value: boolStr(v.Pass), Type: "bool"}
	return out
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
