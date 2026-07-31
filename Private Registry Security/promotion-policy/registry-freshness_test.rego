package registry.freshness

import rego.v1

# registry-freshness_test.rego
#
# Run with:  opa test . -v --ignore examples
#      (or:  opa test promotion-policy/ -v --ignore examples  from the repo root)

test_denies_stale_image if {
    deny["image demo:old is 1150 days old (max allowed: 180) — rebuild or re-pull before promoting"]
        with input as {"image": "demo:old", "age_days": 1150, "signed": true}
        with data.thresholds as {"max_age_days": 180, "require_signature": true}
}

test_denies_unsigned_image if {
    deny["image demo:fresh has no verified signature — promotion blocked"]
        with input as {"image": "demo:fresh", "age_days": 2, "signed": false}
        with data.thresholds as {"max_age_days": 180, "require_signature": true}
}

test_denies_unknown_age_by_default if {
    deny["image demo:unknown has no build timestamp available — cannot verify freshness, blocking by default"]
        with input as {"image": "demo:unknown", "age_days": null, "signed": true}
        with data.thresholds as {"max_age_days": 180, "require_signature": true}
}

test_allows_fresh_signed_image if {
    allow
        with input as {"image": "cleanstart/postgres:latest", "age_days": 2, "signed": true}
        with data.thresholds as {"max_age_days": 180, "require_signature": true}
}

test_allows_old_image_when_signature_not_required_and_threshold_relaxed if {
    allow
        with input as {"image": "demo:old-but-within-relaxed-threshold", "age_days": 1150, "signed": true}
        with data.thresholds as {"max_age_days": 9999, "require_signature": false}
}

test_denies_when_both_stale_and_unsigned if {
    count(deny) == 2
        with input as {"image": "demo:worst-case", "age_days": 900, "signed": false}
        with data.thresholds as {"max_age_days": 180, "require_signature": true}
}
