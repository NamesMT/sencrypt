# AGENTS.md

`sencrypt` publishes as `@namesmt/sencrypt` (SEncrypt — Stateful-salt Encryption): helpers for
building an encrypted secret system. It wraps [`@namesmt/shash`](https://github.com/NamesMT/shash)
(a peer dependency, `>=0.3.5`) to derive a per-secret key and leaves the cipher itself to the
caller. Node >= 22, ESM only, pnpm 12 workspace, [tsdown](https://github.com/rolldown/tsdown) build,
[Vitest](https://vitest.dev) tests.

## Docs

Where knowledge lives, and when to reach for each:

| tier | what it holds | when you use it |
| --- | --- | --- |
| `AGENTS.md` — this file | orientation and the rules that prevent defects | read every session; write when a rule is learned the hard way |
| `.agentDocs/` | depth: module rationale, traps with their causes, compatibility | read on demand, before touching that area; write when a rule needs its reasoning kept |
| `docs/` | how-to and reference for a person using this package | read when the task is user-facing; write in the same commit as the change |
| `README.md` | the first read, for a person | write alongside `docs/` |

- **One home per fact.** State the rule here, keep the reasoning in `.agentDocs/` and link it — never both.
- **A dead pointer is a bug.** If the target is gone, delete the pointer rather than leave it.
- Move depth behind a pointer once a section outgrows a screen or two; keep the rule inline.

## Commands

```sh
pnpm run lint             # eslint (@antfu/eslint-config) — it also owns formatting
pnpm run test:types       # tsc --noEmit --skipLibCheck
pnpm run check            # lint + test:types + vitest run --coverage — the full gate
pnpm run build            # tsdown -> dist/index.mjs + dist/index.d.mts
pnpm run release:check    # validate a version against package.json: `pnpm run release:check 0.2.0`
pnpm run release:preview  # changelogen preview of the next release's changelog
pnpm exec vitest run      # one-shot suite (`pnpm run test` watches)
pnpm run start            # NODE_ENV=dev tsx src/index.ts — no watch
pnpm run watch            # NODE_ENV=dev tsx watch src/index.ts
pnpm run dev             # alias of `pnpm run watch`
```

## Structure

- `src/index.ts` — the entry; re-exports `SEncrypt`, its two interfaces and the `SHash` types.
- `src/SEncrypt.ts` — the `SEncrypt` class and `SEncryptStorageInterface` / `SEncryptEncrypterInterface`.
- `src/utils.ts` — `validParams`, the shared empty/non-string argument check.
- `test/index.test.ts` + `test/utils/{storage,encrypter}` — the suite and its in-repo fakes; imports
  use the `#src/*` alias with a `.js` suffix (`#src/index.js`).
- `playground/` — a private pnpm workspace member (Vite) linked to the package via `workspace:^`.
- `.github/workflows/` — `test.yml` (push/PR to `main`) and `release.yml` (manual, see below).

## Conventions

- Conventional commits (`feat:`, `fix:`, `chore:`, …) — the changelog is derived from them.
- ESLint (`@antfu/eslint-config`) owns lint and formatting; the `simple-git-hooks` pre-commit hook runs `lint-staged` (`eslint --fix`).
- ESM only and ships only `dist` (`files`): `"type": "module"`, an `import`-only `exports` map,
  `main`/`module`/`types` into `dist/`, and `prepublishOnly` builds — never add a CJS build or publish a stale `dist`.
- Encryption is deliberately out of scope: callers pass their own `SEncryptEncrypterInterface`.
  AES-GCM is a dev dependency used by the tests and the README demo, not a runtime dependency.
- Argument order is fixed everywhere: `(salt, partition, id, …)`; `salt` is an app-wide secret, `partition` a group, `id` the per-secret lookup key.

## How to work here

- **Check the callers before you change anything.** Grep who uses it and which tests name it. If the
  impact is unclear, say so — do not guess.
- **Never overwrite or delete a large section you have not understood.** Read it, or say what you could
  not determine and ask.
- **Do not invent requirements.** Build what was asked; surface what else you notice and let it be
  decided.
- **Fix the class, not the instance.** A copied helper, a rule stated twice, a guard bypassed by a
  second path is one problem: one implementation, one guard. That is the work, not a follow-up to ask
  for. Stay inside the task rather than refactoring the world.
- **Verify before claiming, and say what you checked.** A passing test is not evidence it pins
  anything — **break the thing it guards and watch it fail.** If it still passes, either the test is
  decoration or a different guard is running; find out which. Where a stub cannot answer the question,
  drive the real thing.
- **Never write an identifier from memory.** A commit hash, path, line number or version must be quoted
  from the source; a plausible-looking invented one is worse than none.
- **A stated blocker is a hypothesis, not a fact.** Re-test "cannot install X" / "tool unavailable"
  before inheriting it, and never report a failure your own flag forced.
- **Report the risk with the change** — correctness, security, operational and integration; plus what
  you could not verify and every assumption you made. An unverified claim marked as such beats a
  confident one that is wrong.
- **Missing recall of this repo?** Read this file, `.agentDocs/` and `git log` before acting, then ask
  1–3 focused questions rather than guessing at intent.

## Conciseness

**Prune verbose, keep correctness** — code, comments, docs alike.

- Code: a comment only for non-obvious *intent*, never to restate the line, and never long. A block
  arguing for its own change is a commit message.
- Docs: one idea per sentence. Cut anything that would not change what a reader does.
- Delete history `git log` already holds — keep the *rule* that came out of it, not the story.
- **Never drop a caveat to save a line.** Concise means no filler, not fewer facts.

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
