#!/usr/bin/env bash
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$DIR/../../.." && pwd)"
POL="clusters/talos-cluster/apps/kyverno/policies/protect-dr-validate-boundary.yaml"
IMG="ghcr.io/kyverno/kyverno-cli:v1.18.2"
runner="$(command -v podman || command -v docker)"
[ -z "$runner" ] && { echo "need podman or docker"; exit 2; }
chmod -R a+rX "$REPO/$DIR" 2>/dev/null || true
apply() { "$runner" run --rm --user 0 -v "$REPO:/repo:Z" -w /repo "$IMG" apply "/repo/$POL" --resource "/repo/$1" 2>&1; }
bad=0
for f in "$DIR"/fixtures/pass/*.yaml; do
  rel="${f#$REPO/}"; fn=$(apply "$rel" | grep -oE 'fail: [0-9]+' | grep -oE '[0-9]+' | head -1)
  [ "${fn:-1}" != "0" ] && { echo "FALSE-POSITIVE (should pass): $(basename "$f")"; bad=$((bad+1)); }
done
for f in "$DIR"/fixtures/fail/*.yaml; do
  rel="${f#$REPO/}"; fn=$(apply "$rel" | grep -oE 'fail: [0-9]+' | grep -oE '[0-9]+' | head -1)
  [ "${fn:-0}" = "0" ] && { echo "MISSED (should fail): $(basename "$f")"; bad=$((bad+1)); }
done
[ "$bad" = 0 ] && echo "OK: all fixtures correct (approved pass, attacks fail)" || echo "FAILURES: $bad"
exit $bad
