# AGENTS.md

`sencrypt` publishes as `@namesmt/sencrypt` (SEncrypt — Stateful-salt Encryption): helpers for
building an encrypted secret system. It wraps [`@namesmt/shash`](https://github.com/NamesMT/shash)
(a peer dependency, `>=0.3.5`) to derive a per-secret key and leaves the cipher itself to the
caller. Node >= 22, ESM only, pnpm 12 workspace, [tsdown](https://github.com/rolldown/tsdown) build,
[Vitest](https://vitest.dev) tests.

## Docs

Three tiers, so a reader loads only what the task needs:

1. **`AGENTS.md`** (this file) — orientation and the rules that prevent defects. Read every session.
2. **`.agentDocs/`** — depth that would bloat this file: module rationale, traps with their causes,
   compatibility rules. Read on demand.
3. **`README.md` / `docs/`** — for a person using the package, not for an agent.

**There is no `.agentDocs/` here yet and none is needed at this size.** Create one when a section
above outgrows a screen or two: move the *reasoning* out and keep the *rule* here with a pointer to
it — nobody reads a file they do not open. Each document opens with a one-line scope, and this file
links it.

## Commands

```sh
pnpm run lint             # eslint (@antfu/eslint-config) — it also owns formatting
pnpm run test:types       # tsc --noEmit --skipLibCheck
pnpm run check            # lint + test:types + vitest run --coverage — the full gate
pnpm run build            # tsdown -> dist/index.mjs + dist/index.d.mts
pnpm run release:check    # validate a version against package.json: `pnpm run release:check 0.2.0`
pnpm run release:preview  # changelogen preview of the next release's changelog
pnpm exec vitest run      # one-shot suite (`pnpm run test` watches)
```

## Structure

- `src/index.ts` — the entry; re-exports `SEncrypt`, its two interfaces and the `SHash` types.
- `src/SEncrypt.ts` — the `SEncrypt` class and `SEncryptStorageInterface` / `SEncryptEncrypterInterface`.
- `src/utils.ts` — `validParams`, the shared empty/non-string argument check.
- `test/index.test.ts` + `test/utils/{storage,encrypter}` — the suite and its in-repo fakes; imports
  use the `#src/*` alias with a `.js` suffix (`#src/index.js`).
- `tsdown.config.ts`, `vitest.config.ts`, `eslint.config.js` — build, coverage and lint config.
- `playground/` — a private pnpm workspace member (Vite) linked to the package via `workspace:^`.
- `.github/workflows/` — `test.yml` (push/PR to `main`) and `release.yml` (manual, see below).

## Conventions

- Conventional commits (`feat:`, `fix:`, `chore:`, …) — the changelog is derived from them.
- ESLint via `@antfu/eslint-config` owns formatting: no Prettier, single quotes, 2-space indent. The
  `simple-git-hooks` pre-commit hook runs `lint-staged` (`eslint --fix`) on every commit.
- ESM only and ships only `dist` (`files`): `"type": "module"`, an `import`-only `exports` map,
  `main`/`module`/`types` into `dist/`, and `prepublishOnly` builds — never add a CJS build or publish a stale `dist`.
- Encryption is deliberately out of scope: callers pass their own `SEncryptEncrypterInterface`.
  AES-GCM is a dev dependency used by the tests and the README demo, not a runtime dependency.
- Argument order is fixed everywhere: `(salt, partition, id, …)`; `salt` is an app-wide secret, `partition` a group, `id` the per-secret lookup key.

## How to work here

Check callers before changing; say when impact is unclear. Never overwrite a large section you have not
understood. Surface what looks needed instead of inventing requirements. Report the risk, not only the
change: correctness, security, operational, integration. **Fix the root cause, not the instance** — a
copied helper, a rule stated twice, a guard bypassed by a second path is a class: one implementation,
one guard; that is the work. Verify before claiming and say what you checked. A green test proves only
what it asserts — break the thing it guards and watch it fail; if it still passes, either the
test is decoration or a different guard is running. Where a stub cannot answer the question,
drive the real thing. If recall is missing, read this file and `git log` first.

## Conciseness

Prune verbose, keep correctness — code, comments, docs alike. Comments only for non-obvious intent;
one idea per sentence; cut what would not change what a reader does. Delete history `git log` already
holds — the rule, not the story. Never drop a caveat to save a line.

## User-facing docs

`README.md` is the only person-facing doc — this repo has no `docs/`. Docs ship with the change, in the
same commit.

## Releasing

- Manual, version-first: dispatch **Actions → Release → Run workflow** with the version.
- It re-checks the version, runs `pnpm run check`, builds, then changelogen writes `CHANGELOG.md`, bumps `package.json`, commits and tags `v<version>`, then pushes, creates the GitHub release and publishes to npm over OIDC.
- `dry-run` skips only that push/GitHub release/npm publish — changelogen still writes the changelog, bumps `package.json` and creates the commit and tag on the runner.
- **Only this workflow publishes** — a pushed tag does nothing. One-time trusted-publisher setup: README.

## Gotchas

- CI (`test.yml`) runs only `pnpm test --coverage`; lint and type-check run only in `pnpm run check`.
- `dist/` is gitignored build output — a stale local copy may exist.
- Release runs Node 24 while `engines` and CI require Node >= 22.
- changelogen's `--clean` (release workflow) fails when `git status --porcelain` is dirty; ignored files such as `dist/` do not count.
- pnpm workspace (`pnpm-workspace.yaml` lists `playground`) — install from the root.
- Each method validates only what it consumes: `salt` is never checked, `partition`/`id` only via `SHash`, and `encrypt`/`decrypt` additionally reject empty plaintext/ciphertext — passing `''` is what throws.
- `decryptStoredFlash` clears the stored ciphertext by writing `''`, not by deleting the row; `decryptStored` on that id then throws `Ciphertext not found`.
