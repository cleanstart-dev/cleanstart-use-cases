#!/usr/bin/env bash
# Technique 1: kubectl debug — attach ephemeral debug container
# Requires: kubectl, a running pod with a hardened image
set -euo pipefail

POD="${1:-hardened-app}"
TARGET="${2:-app}"

echo "=== Attempt 1: Try to exec a shell (will fail on hardened image) ==="
echo "$ kubectl exec -it $POD -c $TARGET -- sh"
kubectl exec -it "$POD" -c "$TARGET" -- sh 2>&1 || true

echo ""
echo "=== Solution: kubectl debug with shared process namespace ==="
echo "$ kubectl debug -it $POD --image=busybox --target=$TARGET"
echo ""
echo "Inside the debug container, try:"
echo "  ps -ef                      # see the hardened app's processes"
echo "  ls /proc/1/root/app/        # browse the hardened container's filesystem"
echo "  netstat -tulpn              # check ports the app is listening on"
echo ""
kubectl debug -it "$POD" --image=busybox --target="$TARGET"
