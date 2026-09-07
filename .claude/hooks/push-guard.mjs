#!/usr/bin/env node
/**
 * Refuses `git push` from an agent unless the tree has passed the local pipeline run.
 *
 * AGENTS.md, "Working conventions": *a push is gated on `scripts/verify.sh`*. The
 * git `pre-push` hook enforces that for everyone whose clone has the hook installed; this is the same
 * gate one layer earlier, as a `PreToolUse` check on the Bash tool, for two reasons. An agent's clone
 * may not have `core.hooksPath` set yet (the script sets it on first run — which is the run that
 * has not happened). And an agent that hits the git hook can reach for `--no-verify`; this hook
 * refuses that spelling outright, with the reason on stderr, which is the one channel that reliably
 * reaches the model.
 *
 * The receipt is `<git-dir>/verified`: a sha256 over HEAD, `git status --porcelain`, and
 * `git diff HEAD`, written by the script when every check passed. The same digest is recomputed here;
 * a mismatch means something changed since the green run — commit or edit — and the answer is to run
 * the script again, not to push and let the pipeline find out.
 *
 * Escape hatch: `SKIP_VERIFY=1` in the environment, the same one the git hook honours. An env var
 * rather than a flag so the decision stays with the person running the session.
 */
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {existsSync, readFileSync} from 'node:fs';
import {join} from 'node:path';

/** `stdin` is one JSON object: `{tool_name, tool_input: {command, ...}, ...}`. */
let input;
try {
  input = JSON.parse(readFileSync(0, 'utf8'));
} catch {
  process.exit(0);
}

const command = input?.tool_input?.command;
if (typeof command !== 'string') {
  process.exit(0);
}

/*
 * Only a real invocation counts: `git` at the start of a shell segment (the line, or after `;`, `&&`,
 * `||`, `|`, `(`), optionally `-C <dir>` or another global flag, then `push`. Matching the bare words
 * anywhere flagged heredocs and quoted strings that merely *mention* a push — this hook's own test
 * file being written through a heredoc, for one.
 */
const INVOCATION = /(?:^|[;|(]|&&|\|\|)\s*(?:env\s+\S+=\S+\s+)*git\s+(?:(?:-C\s+\S+|--\S+|-\w)\s+)*push\b([^|;&)]*)/gm;
const invocations = [...command.matchAll(INVOCATION)];
if (invocations.length === 0) {
  process.exit(0);
}

if (process.env['SKIP_VERIFY'] === '1') {
  process.exit(0);
}

/*
 * A push that only deletes remote refs has no tree to verify: `git push --delete origin x`,
 * `git push -d origin x`, or the refspec form `git push origin :x`. The git hook sees the same thing
 * as all-zero local SHAs on stdin. A command mixing a deletion with an update is still gated.
 */
const deleteOnly = (args) => {
  const tokens = args.trim().split(/\s+/).filter(Boolean);
  if (tokens.some((t) => t === '--delete' || t === '-d')) {
    return true;
  }
  const refspecs = tokens.filter((t) => !t.startsWith('-')).slice(1);
  return refspecs.length > 0 && refspecs.every((r) => r.startsWith(':'));
};
if (invocations.some((m) => /--no-verify\b/.test(m[1]))) {
  process.stderr.write(
    `Blocked: git push --no-verify.\n\n` +
      `The pre-push hook is the local pipeline run; skipping it is how a red pipeline happens.\n` +
      `Run scripts/verify.sh and push without --no-verify.\n`,
  );
  process.exit(2);
}

/*
 * The worktree the push comes from. A `git -C <dir>` or a leading `cd <dir> &&` names it; otherwise
 * it is the session's working directory.
 */
const dirMatch = /\bgit\s+-C\s+(\S+)/.exec(command) ?? /^\s*cd\s+(\S+)\s*(?:&&|;)/.exec(command);
const cwd = dirMatch ? dirMatch[1].replace(/^["']|["']$/g, '') : process.cwd();

function git(args) {
  return execFileSync('git', args, {cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore']});
}

/*
 * main only ever receives a PR merge, receipt or no receipt. An explicit target — `origin main`,
 * `HEAD:main`, `HEAD:refs/heads/main` — is refused outright. A bare `git push` is refused when the
 * branch's upstream is origin/main, which is exactly what `git worktree add -b x origin/main` sets up
 * when `--no-track` is forgotten: the new topic branch tracks main, and a bare push lands there.
 */
const MAIN_TARGET = /(?:^|\s|:)(?:refs\/heads\/)?main$/;
const targetsMain = (args) => {
  const tokens = args.trim().split(/\s+/).filter((t) => t && !t.startsWith('-'));
  const refspecs = tokens.slice(1);
  if (refspecs.length > 0) {
    return refspecs.some((r) => MAIN_TARGET.test(r.includes(':') ? r.slice(r.indexOf(':') + 1) : r));
  }
  try {
    return /^(?:origin|[^/]+)\/main$/.test(git(['rev-parse', '--abbrev-ref', '@{upstream}']).trim());
  } catch {
    return false;
  }
};
if (invocations.some((m) => targetsMain(m[1]))) {
  process.stderr.write(
    `Blocked: this push targets main.\n\n` +
      `main is the integration branch and only ever receives a PR merge (AGENTS.md, Working conventions).\n` +
      `If the branch tracks origin/main, the worktree was cut without --no-track — point it at its own\n` +
      `remote branch instead:\n\n` +
      `  git push -u origin HEAD\n`,
  );
  process.exit(2);
}

// Judged after the main check on purpose: deleting main is not a harmless deletion.
if (invocations.every((m) => deleteOnly(m[1]))) {
  process.exit(0);
}

let gitDir;
let current;
try {
  gitDir = git(['rev-parse', '--absolute-git-dir']).trim();
  const head = git(['rev-parse', 'HEAD']);
  const status = git(['status', '--porcelain=v1', '--untracked-files=all']);
  const diff = git(['diff', 'HEAD']);
  current = createHash('sha256').update(head + status + diff).digest('hex');
} catch {
  // Not a git repo from here, or no git on PATH: nothing to guard, and git itself will say so.
  process.exit(0);
}

const receipt = join(gitDir, 'verified');
if (existsSync(receipt) && readFileSync(receipt, 'utf8').trim() === current) {
  process.exit(0);
}

process.stderr.write(
  `Blocked: this tree has not passed the local pipeline run.\n\n` +
    (existsSync(receipt)
      ? `The last receipt is for a different tree — something was committed or edited since it was written.\n\n`
      : `No receipt exists for this worktree yet.\n\n`) +
    `Run the whole pipeline locally, then push:\n\n` +
    `  scripts/verify.sh\n\n` +
    `It runs checkstyle, the build, unit and integration tests, the coverage floors, and both frontends'\n` +
    `lint and tests — the same checks the pipeline runs — and writes the receipt the push hooks read.\n` +
    `Never --no-verify. SKIP_VERIFY=1 is the person's escape hatch, not the agent's.\n`,
);
process.exit(2);
