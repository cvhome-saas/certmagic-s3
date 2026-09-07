# QA

One file per area, `<area>-qa.md`, beside the code it tests. It is for people: a tester opens it and runs
it against a running stack. Machine-checkable checks stay in tests and `.http` files; this does not replace
them. Copy this skeleton:

```markdown
# QA — <area>

One paragraph: what this area owns.

- **Scope** — ...
- **Runs on** — how to bring it up (`lcl start -d --stack <name>` in cvhome; `make selftest`; `npx playwright test`; ...)
- **Cases** — N (x verified, y not verified)
- **Also see** — sibling QA files this flow crosses into

Each case is tagged **[verified]** (run end to end and passed) or **[not verified]** (never run by anyone —
where the bugs are).

## 00 — Before you start
Setup, logins, data.

## 01 — <theme>
### 01.1 <case name> [verified]
- Setup: ...
- Steps: ...
- Expect: ...

## REG — regression watchlist
Defects that already happened once.

## 99 — known gaps
Behaviour that looks wrong and is expected.
```
