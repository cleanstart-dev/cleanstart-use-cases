# ============================================================================
# policies/docker_policy.rego
# CIS Docker Benchmark rules as machine-checkable policy.
# Classic Rego syntax — compatible with every version of Conftest/OPA.
# ============================================================================

package main

# ---------- CIS 4.7 — never use the :latest tag ----------
deny[msg] {
    input[i].Cmd == "from"
    val := input[i].Value
    contains(val[0], ":latest")
    msg := sprintf(
        "CIS 4.7 violation: image '%s' uses the :latest tag. Pin to a specific tag or @sha256 digest.",
        [val[0]],
    )
}

deny[msg] {
    input[i].Cmd == "from"
    val := input[i].Value
    not contains(val[0], ":")
    not contains(val[0], "@sha256:")
    msg := sprintf(
        "CIS 4.7 violation: image '%s' has no tag at all (implicit :latest).",
        [val[0]],
    )
}

# ---------- CIS 4.1 — must declare a non-root USER ----------
deny[msg] {
    not has_user_directive
    msg := "CIS 4.1 violation: no USER directive — container would run as root."
}

has_user_directive {
    input[i].Cmd == "user"
    input[i].Value[0] != "root"
    input[i].Value[0] != "0"
}

deny[msg] {
    input[i].Cmd == "user"
    user_val := input[i].Value[0]
    user_val == "root"
    msg := "CIS 4.1 violation: USER is set to 'root'."
}

# ---------- CIS 4.6 — image must declare a HEALTHCHECK ----------
warn[msg] {
    not has_healthcheck
    msg := "CIS 4.6 violation: no HEALTHCHECK declared — orchestrators can't tell if the container is actually healthy."
}

has_healthcheck {
    input[i].Cmd == "healthcheck"
}

# ---------- CIS 5.8 — don't expose privileged ports (<1024) ----------
deny[msg] {
    input[i].Cmd == "expose"
    port := input[i].Value[_]
    port_num := to_number(port)
    port_num < 1024
    msg := sprintf(
        "CIS 5.8 violation: privileged port %v exposed. Use a port >= 1024 and map it on the host.",
        [port],
    )
}

# ---------- CIS 4.9 — prefer COPY over ADD ----------
warn[msg] {
    input[i].Cmd == "add"
    msg := "CIS 4.9 advisory: ADD used. Prefer COPY unless you specifically need URL fetch or auto-extract."
}

# ---------- CIS 4.10 — never bake secrets into images ----------
deny[msg] {
    input[i].Cmd == "env"
    kv := input[i].Value[_]
    secret_keywords := ["PASSWORD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY"]
    keyword := secret_keywords[_]
    contains(upper(kv), keyword)
    msg := sprintf("CIS 4.10 violation: possible secret in ENV — '%s'.", [kv])
}