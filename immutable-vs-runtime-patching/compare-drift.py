#!/usr/bin/env python3
"""
Reads the output of company-a-runtime-patch.sh and company-b-immutable-rebuild.sh
and prints a short comparison: how much the runtime-patched container's
package state changed, versus whether the immutable image's digest is
reproducible across a re-pull.

Usage: python3 compare-drift.py
"""
import pathlib

OUT = pathlib.Path("results")


def count_lines(path):
    p = OUT / path
    if not p.exists():
        return None
    return len([l for l in p.read_text().splitlines() if l.strip()])


def read(path):
    p = OUT / path
    return p.read_text().strip() if p.exists() else None


def main():
    print("=" * 60)
    print("Company A — runtime patching (public image)")
    print("=" * 60)
    before = count_lines("company-a-before.txt")
    after = count_lines("company-a-after.txt")
    if before is not None and after is not None:
        print(f"  packages before patch: {before}")
        print(f"  packages after patch:  {after}")
        print(f"  delta:                 {after - before:+d} package entries changed")
    else:
        print("  run company-a-runtime-patch.sh first")
    print("  reproducible artifact for this patched state: NONE")
    print("  (the patch lives only inside this one container's filesystem)")

    print()
    print("=" * 60)
    print("Company B — immutable rebuild (CleanStart image)")
    print("=" * 60)
    shell = read("company-b-shell-attempt.txt")
    before_d = read("company-b-digest-before.txt")
    after_d = read("company-b-digest-after.txt")
    if shell:
        print(f"  shell access: {shell}")
    if before_d and after_d:
        same = before_d.split()[-1] == after_d.split()[-1]
        print(f"  digest before: {before_d}")
        print(f"  digest after re-pull: {after_d}")
        print(f"  reproducible across hosts: {'YES — identical digest' if same else 'digest changed (new release published)'}")
    else:
        print("  run company-b-immutable-rebuild.sh first")

    print()
    print("The comparison that matters isn't CVE count — it's whether the")
    print("patched state is an artifact you can verify and redeploy, or a")
    print("side effect that lives only in one running container.")


if __name__ == "__main__":
    main()
