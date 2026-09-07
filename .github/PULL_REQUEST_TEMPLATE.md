<!--
Title: `<type>: <what changed>` or `<area>: <what changed>` — e.g. `fix: duplicate SKU 500s`,
`console-ui: typed error handling, steps 1-2`. Imperative, no ticket prefix, no trailing period.

Label the PR before merge — `.github/release.yml` builds the changelog from labels, and an
unlabelled PR lands in ":question: Other Changes":
  type/enhancement · type/bug · type/documentation · type/test · type/chore · type/dependency-upgrade
  warn/api-change · warn/behavior-change · warn/deprecation · warn/regression · warn/blocker
  ignore-changelog

Branch cut from an up-to-date `origin/main` in its own worktree, merged into `main` by PR. Never push to `main`.
-->

## Why

<!-- The problem, in the reader's terms. What breaks, what is missing, what it costs today.
     Link the issue/plan (`.claude/plans/<name>.md`) if there is one. One paragraph is usually enough. -->

## What

<!-- The change, at the level of decisions rather than a file list — the diff already lists files.
     If it is a multi-step plan, say which steps this PR is and what is deliberately not wired yet. -->

## The parts that are not obvious

<!-- Optional but the most valuable section. Traps, orderings, and things a reviewer would
     otherwise have to re-derive: why this layer, why this fails closed, what the alternative cost.
     Delete the heading if the change genuinely has none. -->

## Deviations

<!-- Optional. Where this departs from the plan, the issue, or the neighbouring pattern — and why.
     "Not done" belongs here too, named explicitly rather than left for the reviewer to notice. -->

## Verification

<!-- What you actually ran, with the result. Not "tested locally".
     Baseline honesty: if a suite was already failing, say so with the before/after counts. -->

- [ ] `./gradlew checkstyleMain checkstyleTest` clean (warnings = errors)
- [ ] `./gradlew build -x test -x check` clean
- [ ] `./gradlew test` — or the touched module's `:test` — clean (Docker up for Testcontainers)
- [ ] Touched `-ui` module: `npm run build` clean (landing-ui: the **root** build chain, libs → templates → app)
- [ ] Exercised against a running stack (`lcl start -d`) where behaviour changed
- [ ] `<service>/qa/<module>-qa.md` updated for what changed, with each new case tagged

---

## Checklist

Full rationale in `CLAUDE.md` → *Feature checklist*. **Delete the sections this PR does not touch; a
section you keep is mandatory.** Every row here has a repo mechanism behind it that silently fails if skipped.

**Placement**
- [ ] Entities + `Readable*`/`Persistable*` DTOs in `<domain>-commons`; services/facades/populators/repositories in `<domain>-core`; controllers + `SecurityConfig` in `<domain>-service`
- [ ] New Gradle module in `settings.gradle`, applying a `build-logic` convention plugin
- [ ] No dependency on another pod's `-core`/`-service` — cross-pod calls go through its `-external-api`

**API**
- [ ] Endpoint takes `StoreMerchantId merchantStore` + `LanguageCode language` (unannotated)
- [ ] `@PreAuthorize("hasPermission(#merchantStore,'StoreMerchantId','STORE-POD.<DOMAIN>.<ACTION>')")` present (`STORE-CORE.*` for platform); no inline role/authority checks
- [ ] A genuinely new permission token has a `case` in `CustomPermissionEvaluator` **and** a method on `PermissionAccessChecker` — the evaluator denies by default, so a missing case is a silent 403
- [ ] Ids/codes use `store-commons/commons/.../domain/` value objects, not raw `String`/`Long`
- [ ] Request DTOs validated (`@Valid` + bean-validation annotations)
- [ ] Endpoint has a runnable block in `<service>/http/<api-class>.http` — gateway path form, not the service port; `?store={{STORE_ID}}&lang={{LANG}}`; a new url/id in `http-client.env.json` rather than inlined; at least one non-2xx block where the endpoint declares a failure mode
- [ ] User-visible behaviour has a case in `<service>/qa/<module>-qa.md` — the service's own QA file, appended to, never a new file per plan; tagged `[verified]` / `[unit only]` / `[not verified]` honestly

**Persistence**
- [ ] Table/column in the service's DDL (`schema.sql`, or `init-sql/schema.sql` for JPA pods) — an entity change alone is not a schema change
- [ ] New enum value added to the `varchar` `CHECK` constraint
- [ ] Query tenant-scoped by store; no cross-service FK, no cross-schema join

**Secrets**
- [ ] Tenant credentials encrypted in the mapper (`toEntity` encrypt / `toDTO` decrypt, guarded by `EncryptedValue.isEncrypted`) via `secret-crypto` — no plaintext column, never logged

**Errors** (`.claude/skills/project-structure/references/error-handling.md`)
- [ ] New failure mode = `ErrorCode` constant + one condition-named exception in that `-commons`, declared by name on the throwing method and on `I<Domain>Service` if exposed over HTTP
- [ ] No `throws BaseException` / category base, no `catch (BaseException)` + `switch (category())`
- [ ] No new `LEGACY.*`; a touched legacy throw site is migrated, not re-coded
- [ ] *Who failed* is right: ours → our code/status; peer service → `RemoteServiceException`; third party → `ExternalProviderException` with `providerCode`. A provider refusal (422) and no answer (502) do not share a `catch`
- [ ] Bodies only from `ProblemDetailFactory`; no hand-built `ProblemDetail`, no second `@ControllerAdvice`, no root-cause text in `detail`
- [ ] Ran the grep gates: generic `throws` over the touched module, old type names (comments included) after a rename

**Integration**
- [ ] Sync cross-service call = `@HttpExchange` interface in the provider's `-external-api`, implemented by its `External*Api` controller, consumed via `RestClientBuilder`
- [ ] `buildClient(...)` has an explicit error contract (`*ApiErrors.CATALOG`, or `RemoteErrorCatalog.none()`)
- [ ] Caller-side exception types on the **`@HttpExchange` interface's** `throws` (not the server one); reactive callers use `onErrorMap`
- [ ] Async work = domain event from an aggregate root, type in an `-events` module, `@OutboxHandler` **idempotent** (at-least-once delivery)
- [ ] uaa user management goes through `UserAccountService` (`uaa-client`), stamping `org` + `store`

**Configuration**
- [ ] Ports/hosts/namespaces changed in `common-config.yml` only; a new service registered in `common-config.yml` + `lcl-config.yml` + `fargate-config.yml`
- [ ] New route in `store-pod/spg/Caddyfile` or `GatewayRouteLocatorImpl`/`PodClient`, and in `configure-domain.sh` for a new local hostname
- [ ] Dependency versions in `gradle/libs.versions.toml`, referenced as `libs.*`

**Frontend**
- [ ] i18n keys in **every locale the app ships**, no orphans — console-ui `src/locale/{en,ar}.json`, landing-ui `locales/{en,ar,es,fr,ru}.json` (cua renders no pages and has no bundles)
- [ ] Angular: standalone components, `OnPush`, `inject()`, signals, HTTP in a service never in a component
- [ ] landing-ui: `libs/*` or `templates/*` changes built through the root `npm run build` chain; a new theme follows `references/new-landing-ui-template.md`
- [ ] AR checked as RTL — layout, not only the strings

**Always**
- [ ] No `TODO` comment (checkstyle `TodoComment` fails the build), no star import, no 140+ char line
- [ ] No hardcoded host/port/service URL — `common-config.yml` + `lb://<service>`
