#!/usr/bin/env bash
# Everything CI checks, run here first — and a receipt the push hooks read.
#
# Runs the repo's gates from scripts/verify.steps.sh in order, stopping at the first failure. When
# everything passes it writes `<git-dir>/verified` holding a digest of exactly what was verified (HEAD plus
# every uncommitted change), and `.githooks/pre-push` plus the Claude `push-guard` hook refuse a push whose
# tree does not match. Edit one file after a green run and the receipt is stale; run this again.
#
#   scripts/verify.sh            # from anywhere inside the worktree being shipped
#
# Org standard: cvhome-saas/orchestrator templates/repo (the `repo-standard` skill).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

digest() {
  { git rev-parse HEAD; git status --porcelain=v1 --untracked-files=all; git diff HEAD; } | shasum -a 256 | cut -d' ' -f1
}

# Install the pre-push hook for this clone the first time; idempotent afterwards.
if [ "$(git config core.hooksPath || true)" != ".githooks" ] && [ -d .githooks ]; then
  git config core.hooksPath .githooks
fi

before=$(digest)
n=0
step() {
  n=$((n + 1)); local name="$1"; shift
  echo; echo "▶ verify $n: $name"; echo "  $*"
  "$@"
  echo "✔ $name"
}

# shellcheck source=scripts/verify.steps.sh
source scripts/verify.steps.sh

after=$(digest)
if [ "$before" != "$after" ]; then
  echo "✘ verify: the tree changed while verifying (a step wrote to tracked files?)." >&2
  echo "  Commit or discard what changed, then run this again." >&2
  exit 1
fi
printf '%s\n' "$after" > "$(git rev-parse --absolute-git-dir)/verified"
echo; echo "✔ verify: all checks passed — receipt written for $(git rev-parse --short HEAD) ($after)."
echo "  git push is now allowed for exactly this tree."
