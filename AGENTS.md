# AGENTS.md

Guidance for AI coding agents working in `certmagic-s3`. It applies to the whole repository.

## Orientation

Org fork of the certmagic S3 storage backend (aws-sdk-go-v2). Gives Caddy `storage s3 { bucket region prefix endpoint }` so every spg task shares on-demand certificates through the per-pod cert bucket. Compiled into saas-gateway.

Part of the `cvhome-saas` organisation. Cross-repo routing, review and releases live in
`cvhome-saas/orchestrator`; this file is the repo's own rulebook. Entry points: storage.go, s3.go, README.md.

## Working conventions (org standard — the same in every cvhome-saas repo)

- **`main` is the integration branch.** Every change lands by PR into `main`; nobody commits or pushes to
  `main` directly. Versions are `vX.Y.Z` git tags cut by the orchestrator's `Release` workflow, never by hand,
  and no file in this repo carries a version.
- **Every change starts as a fresh worktree cut from up-to-date `main`, before the first file is written:**

  ```bash
  git fetch origin
  git worktree add --no-track .claude/worktrees/<type>-<short-name> -b <type>/<short-name> origin/main
  ```

  `<type>` ∈ `feat|fix|docs|chore|refactor|test`. Work, build and verify from inside that worktree; the
  primary checkout stays clean on `main`. `.claude/hooks/worktree-guard.mjs` denies any edit in the primary
  checkout (`ALLOW_MAIN_WRITES=1` is the person's deliberate escape hatch, never the agent's).
- **A plan is phases; a phase is one PR.** Anything bigger than one PR starts as
  `.agents/plans/<kebab-name>.md` (template: `.agents/plans/README.md`): context, why the design is what it
  is, then `## Phase N — <area> (PR N)` sections each small enough to review in one sitting, then
  deviations as built and verification. One plan, one worktree, one branch; each phase is committed and
  shipped as its own PR before the next begins (stacked if it must). A plan that touches another repo names
  it and hands that phase to the orchestrator (`cross-repo-change`).
- **Nothing is pushed until the gates have passed locally.** `scripts/verify.sh` runs exactly what CI runs
  (`scripts/verify.steps.sh`) and writes a receipt for the exact tree; `.githooks/pre-push` and
  `.claude/hooks/push-guard.mjs` refuse a push without it, a push to `main`, and `--no-verify`.
- **`/go` ships the working tree** (commit → verify → push → PR into `main`, template filled, changelog
  label); **`/reset` returns to a clean `main`** without losing work. Both in `.claude/commands/`.
- **PR body follows `.github/PULL_REQUEST_TEMPLATE.md`**: *Why → What → The parts that are not obvious →
  Deviations → Verification*. Label it: `type/enhancement|bug|documentation|test|chore|dependency-upgrade`,
  `warn/api-change|behavior-change|deprecation|regression|blocker`, `ignore-changelog`.
  `.github/release.yml` turns labels into release notes; the orchestrator turns them into the version bump.
- **QA is a file that travels with the code.** A user-visible or operator-visible behaviour is not done until
  it has a case in `qa/<area>-qa.md` (template: `qa/README.md`), tagged **[verified]** / **[not verified]**,
  with setup, steps and expected result. Tests prove a unit; the QA file proves the path a person takes.
- **A new screen starts in the design portal.** Before a new page or screen is implemented, a design canvas
  is produced (the orchestrator's `design` skill), reviewed, and recorded in
  `.agents/designs/<slug>.md` with the artifact URL and `approved: true`; the design-gate hook refuses new
  page files without it.
- **Commit messages**: `<type|area>: <what changed>`, imperative, plus a body when the change is not
  self-evident, ending with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.

## Build, run and verify

```bash
scripts/verify.sh        # runs, in order:
#   git diff --check
#   go build ./...
#   go vet ./...
#   go test ./...
```


## Completion gates

- [ ] `scripts/verify.sh` green for the exact tree being pushed
- [ ] New behaviour has an owning test and a QA case
- [ ] Docs in this repo that describe the changed behaviour are updated in the same PR
- [ ] Anything another cvhome-saas repo must change is named in the PR body under *Deviations*
