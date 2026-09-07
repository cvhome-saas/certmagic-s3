#!/usr/bin/env node
/**
 * A new screen starts in the design portal, not in an editor.
 *
 * PreToolUse gate on Write/Edit: creating a *new* page file — an Angular component under a feature or
 * pages directory, or a Next.js `page.tsx` — is refused unless `.agents/designs/<slug>.md` exists with
 * `approved: true`, where <slug> is the feature/page directory the file lives in (or any record whose
 * `covers:` list names it). The record carries the design canvas URL (the orchestrator's `design` skill)
 * and who approved it. Editing an existing page, non-page files (services, models, tests, styles), and
 * files outside the repo are never gated.
 *
 * Exit 2 denies the call and hands stderr back to the model, which then produces the design first.
 * Escape hatch: SKIP_DESIGN_GATE=1, for the person running the session, never the agent.
 */
import {existsSync, readFileSync, readdirSync} from 'node:fs';
import {isAbsolute, relative, resolve, sep} from 'node:path';
import {execFileSync} from 'node:child_process';

let input;
try {
  input = JSON.parse(readFileSync(0, 'utf8'));
} catch {
  process.exit(0);
}
if (process.env['SKIP_DESIGN_GATE'] === '1') process.exit(0);

const target = input?.tool_input?.file_path ?? input?.tool_input?.path;
if (typeof target !== 'string' || target === '') process.exit(0);
const file = resolve(process.cwd(), target);
if (existsSync(file)) process.exit(0); // editing an existing page is not a new screen

let root;
try {
  root = execFileSync('git', ['rev-parse', '--show-toplevel'], {cwd: process.cwd(), encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore']}).trim();
} catch {
  process.exit(0);
}
const rel = relative(root, file);
if (rel.startsWith('..') || isAbsolute(rel)) process.exit(0);
const parts = rel.split(sep);

/** Page-shaped files, and the directory that names the screen. */
const PAGE_PATTERNS = [
  // Angular: src/app/features/<feature>/**/*.component.ts (not spec), also pages/<page>/
  {test: (p) => /\.component\.ts$/.test(p.at(-1)) && !/\.spec\.ts$/.test(p.at(-1)) && (p.includes('features') || p.includes('pages')),
   slug: (p) => p[(p.lastIndexOf('features') !== -1 ? p.lastIndexOf('features') : p.lastIndexOf('pages')) + 1]},
  // Next.js app router: **/app/**/page.tsx — slug is the route directory
  {test: (p) => p.at(-1) === 'page.tsx' || p.at(-1) === 'page.jsx',
   slug: (p) => p.at(-2) === 'app' ? 'home' : p.at(-2)},
];
const match = PAGE_PATTERNS.find((pp) => pp.test(parts));
if (!match) process.exit(0);
const slug = (match.slug(parts) ?? '').replace(/^\[|\]$|^\(|\)$/g, '');
if (!slug) process.exit(0);

const designs = resolve(root, '.agents', 'designs');
const records = existsSync(designs) ? readdirSync(designs).filter((f) => f.endsWith('.md') && f !== 'README.md') : [];
const approved = records.some((f) => {
  const text = readFileSync(resolve(designs, f), 'utf8');
  const names = [f.replace(/\.md$/, ''), ...((/^covers:\s*\[?([^\]\n]*)\]?/m.exec(text)?.[1] ?? '').split(',').map((s) => s.trim()).filter(Boolean))];
  return names.includes(slug) && /^approved:\s*true\s*$/m.test(text);
});
if (approved) process.exit(0);

process.stderr.write(
  `Blocked: ${rel} is a new screen ("${slug}") with no approved design record.\n\n` +
    `AGENTS.md: a new page or screen starts in the design portal. Before implementing it:\n` +
    `  1. Produce the design canvas with the orchestrator's \`design\` skill (states: empty, loading, error, populated).\n` +
    `  2. Have the person review it in the artifact.\n` +
    `  3. Write .agents/designs/${slug}.md with the artifact URL and \`approved: true\` (template: .agents/designs/README.md).\n` +
    `Then re-apply this edit. (A record may list several screens under \`covers: [a, b]\`.)\n`,
);
process.exit(2);
