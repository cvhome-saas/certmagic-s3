# Plans

One file per plan, `<kebab-name>.md`, written **before** its worktree exists. A plan is a sequence of
phases; each phase is one PR. Copy this skeleton:

```markdown
# <Title>

## Context
What exists today, with file:line evidence. What is wrong or missing.

## Why the design is what it is
The decisions, the alternatives rejected, the constraints (tenancy, security, contracts other repos rely on).

## Phase 1 — <area> (PR 1)
Files to touch, the change at the level of decisions, tests, QA cases, gates. Small enough to review in one sitting.

## Phase 2 — <area> (PR 2)
...

## Other repos
What cvhome-platform / load-testing / lcl / docs must change, in which order (handed to the orchestrator).

## Deviations, as built
Filled in while implementing: where reality differed from the plan and why.

## Verification
What was run, per phase. QA cases and their [verified] state.
```
