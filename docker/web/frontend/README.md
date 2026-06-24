# BomLens web UI (developer notes)

React 18 + Vite + Tailwind + shadcn-style primitives. Built to a static SPA in
`dist/`, served by `docker/web/server.py`.

## UI rebuild — feature flag

The redesigned interface ships behind a flag so the classic UI stays the default
and keeps working while sections are migrated phase by phase.

- Classic UI: `/` (default).
- New shell: `/?ui=next`.

The flag is read once at mount (`src/lib/flags.ts`). Once a section reaches
parity it moves into the shell; when every section is migrated the flag becomes
the default and the classic path is removed.

### Shell anatomy

- `components/AppShell.tsx` — frame: sticky `TopBar` over a left `Sidebar` and a
  scrolling canvas. Auto-collapses the rail below 1024px.
- `components/Sidebar.tsx` — grouped, scan-type-adaptive navigation. The section
  model and adaptation live in `lib/nav.ts`; AI-only sections (Models &
  datasets, G7) appear only for AI/ANALYZE scans.
- `components/TopBar.tsx` — product mark, project context, language + theme.
- `components/ui/state.tsx` — shared Empty / Loading / Error / Skeleton states.

## Design tokens

All colours, spacing, radius, elevation and motion live as CSS custom
properties in `src/index.css` (light + `.dark`) and are mapped to utilities in
`tailwind.config.ts`. The brand accent is SKT (SK Red `--brand`, SK Orange
`--brand-accent`); the neutral `--primary` is intentionally separate.

Components never hardcode a colour — `npm run token:lint` enforces this.

## Tests & gates

| Command | What it checks |
| --- | --- |
| `npm run typecheck` | TypeScript |
| `npm run token:lint` | no hardcoded colours in components |
| `npm run i18n:check` | en and ko key sets match (no missing keys) |
| `npm run test:unit` | Vitest — data/display logic (`lib/*.test.ts`) |
| `npm run test:ui` | Playwright — functional + axe accessibility |
| `npm run test:visual` | Playwright — visual regression (`@visual`) |

### Visual baselines

Visual snapshots are platform-dependent, so they are generated and compared in
the pinned Playwright container (`mcr.microsoft.com/playwright:v1.49.1-jammy`),
matching CI. The CI `visual` job seeds baselines on the first run (uploading
them as the `visual-baselines` artifact) and runs a strict diff once the PNGs
under `tests/ui/*-snapshots/` are committed. To seed or refresh locally:

```sh
docker run --rm -v "$PWD:/work" -w /work \
  mcr.microsoft.com/playwright:v1.49.1-jammy \
  bash -lc 'npm ci && npm run test:visual -- --update-snapshots'
```
