#!/usr/bin/env node
/**
 * Refuses any write to the primary checkout.
 *
 * AGENTS.md, "Working conventions": *every plan or feature starts as a fresh worktree cut from
 * up-to-date `main` — before the first file is written*. That rule was advisory, and advisory is
 * not enough: an agent whose context never happened to include AGENTS.md — Claude Code auto-loads
 * `CLAUDE.md`, and this repo's rules live in `AGENTS.md` — will read the request, open the files
 * it names, and start editing `main` without ever knowing the rule exists. That is exactly how
 * twenty files of a console-ui theme ended up uncommitted on `main`.
 *
 * So this is a `PreToolUse` gate rather than a paragraph. Exit 2 denies the tool call and hands
 * `stderr` back to the model, which is the one channel that reliably reaches it: the agent is told
 * *why* it was stopped and what to run instead, so it cuts the worktree and retries rather than
 * reporting a mysterious failure to the user.
 *
 * What is deliberately still allowed, because none of it is feature work and all of it belongs to
 * the primary checkout by definition:
 *
 *   .claude/worktrees/**   the worktrees themselves — the whole point
 *   .agents/plans/**       plans are written before a worktree exists (AGENTS.md, "Plans")
 *   .claude/plans/**       ...and plan mode writes here
 *   .claude/settings*.json this hook's own configuration, and the personal local override
 *   .claude/hooks/**       this script
 *   anything outside the repo — scratchpad, $HOME, /tmp
 *
 * Escape hatch: `ALLOW_MAIN_WRITES=1` for the rare deliberate case (a hotfix the user has
 * explicitly asked for on `main`). It is an env var rather than a flag the model can pass, so the
 * decision stays with the person running the session.
 */
import {readFileSync, realpathSync} from 'node:fs';
import {isAbsolute, relative, resolve} from 'node:path';
import {execFileSync} from 'node:child_process';

/** Paths under the primary checkout an agent may still write, relative to the repo root. */
const ALLOWED = [
  '.claude/worktrees',
  // Both plan directories: AGENTS.md puts plans in .AGENTS/plans, and Claude Code's plan mode
  // writes to .claude/plans. A plan is written before its worktree exists, by definition.
  '.agents/plans',
  '.claude/plans',
  '.claude/hooks',
  '.claude/settings.json',
  '.claude/settings.local.json',
];

/** Resolves symlinks where the path exists, so /tmp and /private/tmp compare equal on macOS. */
function canonical(path) {
  try {
    return realpathSync(path);
  } catch {
    return resolve(path);
  }
}

/** True when `child` is `parent` or sits underneath it. */
function contains(parent, child) {
  if (parent === child) {
    return true;
  }
  const rel = relative(parent, child);
  return rel !== '' && !rel.startsWith('..') && !isAbsolute(rel);
}

/** `stdin` is one JSON object: `{tool_name, tool_input: {file_path, ...}, ...}`. */
let input;
try {
  input = JSON.parse(readFileSync(0, 'utf8'));
} catch {
  // Unparseable stdin is this script's problem, not the agent's — never block on it.
  process.exit(0);
}

if (process.env['ALLOW_MAIN_WRITES'] === '1') {
  process.exit(0);
}

const target = input?.tool_input?.file_path ?? input?.tool_input?.path;
// Not a path-shaped tool call (Write always carries one; a future tool may not).
if (typeof target !== 'string' || target === '') {
  process.exit(0);
}

/*
 * The *primary* checkout, not the current one: `--git-common-dir` points at the shared `.git`
 * from inside every worktree, so its parent is the primary checkout wherever this runs.
 */
let primary;
try {
  const commonDir = execFileSync(
    'git',
    ['rev-parse', '--path-format=absolute', '--git-common-dir'],
    {cwd: process.cwd(), encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore']},
  ).trim();
  primary = canonical(resolve(commonDir, '..'));
} catch {
  // Not a git repo, or no git on PATH. Nothing to guard.
  process.exit(0);
}

const file = canonical(resolve(process.cwd(), target));

// Outside the repo entirely — scratchpad, $HOME, /tmp. Not our business.
if (!contains(primary, file)) {
  process.exit(0);
}

// Inside a worktree (or one of the meta paths above), which is where work is supposed to happen.
if (ALLOWED.some((allowed) => contains(canonical(resolve(primary, allowed)), file))) {
  process.exit(0);
}

const rel = relative(primary, file);
process.stderr.write(
  `Blocked: ${rel} is in the primary checkout.\n\n` +
    `AGENTS.md requires every plan or feature to start as a fresh worktree cut from an\n` +
    `up-to-date main, before the first file is written. The primary checkout stays clean.\n\n` +
    `Cut one and make this edit inside it:\n\n` +
    `  git fetch origin\n` +
    `  git worktree add --no-track .claude/worktrees/<type>-<short-name> -b <type>/<short-name> origin/main\n\n` +
    `Then re-apply this edit to\n` +
    `  .claude/worktrees/<type>-<short-name>/${rel}\n` +
    `and run the build, the lcl stack and the QA from in there too.\n\n` +
    `If edits are already stranded on main, move them rather than redoing them:\n` +
    `  git stash push -u -- <paths>\n` +
    `  git worktree add --no-track .claude/worktrees/<type>-<short-name> -b <type>/<short-name> origin/main\n` +
    `  git -C .claude/worktrees/<type>-<short-name> stash pop\n`,
);
process.exit(2);
