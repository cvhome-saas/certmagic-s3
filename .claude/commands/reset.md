---
description: Switch to main and fast-forward it from origin — offering to save or discard local work first
allowed-tools: Bash(git status:*), Bash(git fetch:*), Bash(git branch:*), Bash(git log:*), Bash(git rev-list:*), Bash(git rev-parse:*), Bash(git switch:*), Bash(git merge:*), Bash(git diff:*), Bash(git add:*), Bash(git commit:*), Bash(git push:*), Bash(git restore:*), Bash(git stash:*), AskUserQuestion
---

Return to a clean `main` that matches origin. If the current branch holds work that only exists locally,
**stop and ask what to do with it** — never switch away from it silently, never discard it unasked.

## Context

- Branch: !`git rev-parse --abbrev-ref HEAD`
- Working tree: !`git status --porcelain`
- Upstream: !`git rev-parse --abbrev-ref --symbolic-full-name @{upstream} 2>/dev/null || echo "(none)"`
- Unpushed commits: !`git log --oneline @{upstream}..HEAD 2>/dev/null || git log --oneline origin/main..HEAD 2>/dev/null`

## Steps

1. **`git fetch origin`** first — every check below compares against the *current* remote, and a stale
   `origin/main` makes "already up to date" a lie.

2. **Classify what is local.** Two independent kinds, and they are not equally dangerous:

   - **Uncommitted changes** — any `git status --porcelain` line whose status is not `??`. Discarding these
     is irreversible; git has no copy anywhere.
   - **Unpushed commits** — `git rev-list --count @{upstream}..HEAD`, or `origin/main..HEAD` when there is
     no upstream. These are *not* lost by switching: they stay on their branch. Leaving them behind is safe.

   **Untracked files (`??`) are neither.** A branch switch and a fast-forward both leave them alone. List
   them as a note and otherwise ignore them.

3. **Nothing local?** Go straight to step 6.

4. **Uncommitted changes — ask.** Show the affected paths (`git status --short`) and a `git diff --stat`
   first, so the choice is made against the real diff, then use **AskUserQuestion** with these options:

   - **Branch, commit and push** *(recommended)* — if HEAD is `main`, cut
     `git switch -c <type>/<short-name>` first; then stage, commit with a `<type|area>: <what changed>`
     subject and the `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` trailer, and
     `git push -u origin HEAD`. Read the diff before writing the message. Mention that `/go` does the same
     thing and opens a PR, if that is what they actually want.
   - **Stash** — `git stash push -u -m "reset: <branch> <date>"`. Recoverable with `git stash pop`; tell them
     the stash name.
   - **Discard** — `git restore --staged --worktree .` on the tracked changes only. **Untracked files are
     left in place**; no `git clean` unless they ask for it in so many words. Before running it, state
     exactly how many files and lines go away and that it cannot be undone, and require an unambiguous yes.
   - **Cancel** — stop, change nothing.

5. **Unpushed commits — ask, but say plainly that nothing is at risk.** Show them with `git log --oneline`,
   then offer:

   - **Push them** *(recommended)* — `git push -u origin HEAD`, then continue to the switch.
   - **Leave them on this branch** — switch to `main` and carry on. The branch and its commits stay
     exactly where they are; this loses nothing, and it is the right answer for work in progress.
   - **Cancel** — stop, change nothing.

   Do not offer to delete the branch or hard-reset it. If the user wants that, they will say so.

6. **Switch.** `git switch main` (skip if already there). If the current directory is a worktree under
   `.claude/worktrees/`, its branch cannot be checked out twice — report that /reset applies to the primary
   checkout and offer to clean up instead: `lcl stop --stack <short-name>`, then from the primary checkout
   `git worktree remove <dir>` (only when its work is merged or pushed; never with local-only changes).

7. **Update.** `git merge --ff-only origin/main`. If it refuses, local `main` has diverged from origin
   — which should not happen given the never-commit-to-main rule. Stop and report the divergence rather
   than merging or resetting it away.

8. **Report** the resulting branch, `git log --oneline -1`, what was done with the local work, and whether
   `main` actually moved.

## Rules

- **Nothing is destroyed without an explicit choice.** No `git reset --hard`, no `git clean`, no force-push,
  ever — and `git restore` only as the answer to step 4's discard option, never as a shortcut around a
  refusal.
- Push only when the user picks a push option. Pushing is outward-facing; a reset command does not get to
  decide it.
- Cancel is a normal outcome. Report it and stop; do not look for another route to a clean `main`.

$ARGUMENTS — if given, treat as the branch to return to instead of `main`.
