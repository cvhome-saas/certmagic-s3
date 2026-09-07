---
description: Commit the current changes, push, and open a PR into main
allowed-tools: Bash(scripts/verify.sh:*), Bash(git status:*), Bash(git diff:*), Bash(git log:*), Bash(git branch:*), Bash(git fetch:*), Bash(git switch:*), Bash(git checkout:*), Bash(git add:*), Bash(git commit:*), Bash(git push:*), Bash(gh pr create:*), Bash(gh pr view:*), Read, Glob, Grep
---

Ship the current working tree: commit → push → PR into `main`. Run from the worktree that holds the change —
each plan/feature lives in its own worktree cut from `origin/main` (see AGENTS.md, Working conventions).

## Context

- Branch: !`git rev-parse --abbrev-ref HEAD`
- Status: !`git status --short`
- Staged diff: !`git diff --cached --stat`
- Unstaged diff: !`git diff --stat`
- Recent commits: !`git log --oneline -10`

## Steps

1. **Nothing to do?** If the working tree is clean *and* the branch has no unpushed commits, say so and stop.

2. **Branch.** If HEAD is `main`, this working tree skipped the worktree rule — cut a fresh branch now (`git fetch && git switch -c <type>/<short-name>`, where `<type>` is one of `feat`/`fix`/`docs`/`chore`/`refactor`/`test` and `<short-name>` is a kebab-case summary), commit there, and remind that the next piece of work starts as `git worktree add --no-track .claude/worktrees/<type>-<short-name> -b <type>/<short-name> origin/main` (`--no-track`, or the branch tracks main and a bare push lands there). Never commit onto `main`. If already on a topic branch, keep it.

3. **Review before staging.** Read the actual diff (`git diff`, `git diff --cached`) so the commit message describes what changed, not what the file names suggest. Flag anything that shouldn't be committed — secrets, `.env`, build output, debug leftovers, `TODO` comments (checkstyle fails the build on those). Ask before committing anything suspicious.

4. **Commit.** Stage the intended files (`git add` by path — avoid blanket `git add -A` when untracked noise is present) and commit with a `<type|area>: <what changed>` subject, imperative, no trailing period, plus a short body when the change isn't self-evident. End the message with:

   ```
   Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
   ```

5. **Verify, then push.** Run `scripts/verify.sh` from the worktree — the whole pipeline locally: checkstyle, build, unit and integration tests, the coverage floors, both frontends' lint and tests. It writes the receipt the push hooks read; without a green run for exactly this tree, `git push` is refused (by `.githooks/pre-push` and by `.claude/hooks/push-guard.mjs`). Fix what is red and run it again; never `--no-verify`, never `SKIP_VERIFY=1` on the user's behalf. Then `git push -u origin HEAD`.

6. **PR.** `gh pr create --base main` with the body following `.github/PULL_REQUEST_TEMPLATE.md`: *Why* → *What* → *The parts that are not obvious* → *Deviations* → *Verification*, then the checklist with the untouched sections **deleted**. Fill Verification with what was actually run — if the gates (`./gradlew checkstyleMain checkstyleTest`, `./gradlew build -x test -x check`, module `:test`, `npm run build`) were not run in this session, say so plainly rather than ticking boxes. Add a changelog label: `--label type/enhancement` (or `type/bug`, `type/documentation`, `type/test`, `type/chore`, `type/dependency-upgrade`) — an unlabelled PR lands in "Other Changes".

7. Print the PR url.

$ARGUMENTS — if given, treat as the branch name, PR title, or extra instructions.
