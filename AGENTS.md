# AGENTS.md

`sencrypt` publishes as `@namesmt/sencrypt` (SEncrypt — Stateful-salt Encryption): helpers for
building an encrypted secret system. It wraps [`@namesmt/shash`](https://github.com/NamesMT/shash)
(a peer dependency, `>=0.3.5`) to derive a per-secret key and leaves the cipher itself to the
caller. Node >= 22, ESM only, pnpm 12 workspace, [tsdown](https://github.com/rolldown/tsdown) build,
[Vitest](https://vitest.dev) tests.

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
