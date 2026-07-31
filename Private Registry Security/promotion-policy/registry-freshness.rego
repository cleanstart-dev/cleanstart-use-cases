package registry.freshness

import rego.v1

# registry-freshness.rego
#
# Given metadata about one image (the same shape that
# ../staleness-audit/audit.sh writes per image), decide whether it's fit to be
# promoted from your internal registry into the next environment.
#
# This does not evaluate CVEs directly — it evaluates the two properties a
# private registry actually controls on its own: how recently the image was
# rebuilt, and whether it's signed. Pair it with a CVE check (see
# ../cve-comparison) for the rest of the picture.
#
# Input shape (one image):
#   {
#     "image":    "myregistry.internal/team/api:2.3.1",
#     "age_days": 214,
#     "signed":   false
#   }
#
# Thresholds come from an external data document (see thresholds.json),
# not from a hardcoded value in this file — so the same policy can be
# stricter for a production gate than for a dev gate.
#   {
#     "max_age_days":      180,
#     "require_signature": true
#   }

deny contains msg if {
    input.age_days != null
    input.age_days > data.thresholds.max_age_days
    msg := sprintf(
        "image %s is %d days old (max allowed: %d) — rebuild or re-pull before promoting",
        [input.image, input.age_days, data.thresholds.max_age_days],
    )
}

deny contains msg if {
    input.age_days == null
    msg := sprintf(
        "image %s has no build timestamp available — cannot verify freshness, blocking by default",
        [input.image],
    )
}

deny contains msg if {
    data.thresholds.require_signature
    not input.signed
    msg := sprintf(
        "image %s has no verified signature — promotion blocked",
        [input.image],
    )
}

allow if {
    count(deny) == 0
}
