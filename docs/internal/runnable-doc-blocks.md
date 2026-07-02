# Runnable documentation blocks

`tests/test-docs-walkthrough.sh` runs the user guides the way a reader does and
checks that the documented commands still work AND produce every artifact the
page promises. To avoid running illustrative snippets (placeholder URLs, the
`--ui` server, OS install steps), only blocks explicitly marked as runnable are
executed.

## Marking a block

Put an HTML comment on the line immediately before the opening fence. It is
invisible in the rendered docs:

```markdown
<!-- runnable -->
​```bash
./scripts/scan-sbom.sh --project "MyApp" --version "1.0.0" --target examples/nodejs --all --generate-only
​```
```

Rules:

- The marker must be on the line directly above the ```` ```bash ```` fence (no
  blank line between them), or it is ignored.
- All marked blocks on a page run in order, in one shell, from the page's
  workdir — a later block can read an earlier block's output (for example the
  `jq` check reads the `MyApp_1.0.0_bom.json` the scan wrote).
- Leave the long-running `--ui` server and OS install steps unmarked.
- Keep a page's English and `.ko.md` mirror in sync — the runnable blocks of
  the two files must be byte-identical (commands only; prose translates
  freely). Only the English page is executed.

## Registering a page (TARGETS)

A page is exercised once it has a line in the `TARGETS` manifest of
`tests/test-docs-walkthrough.sh`:

```
page-path :: prep-key :: image-kind
```

- `prep-key` `root` means no preparation and the page runs from the repo root
  (its commands use repo-relative paths like `examples/nodejs`). Any other
  value selects a `prep_page()` case, and the page runs in a fresh workdir
  under `tests/test-workspace/docs/`.
- `image-kind` `test` runs with `$SBOM_SCANNER_IMAGE` (default
  `sbom-scanner:test`). `published` means the page's blocks name
  `ghcr.io/sktelecom/bomlens:latest` verbatim; the page executes only when that
  exact tag is present (the CI docs job tags its freshly built image with it;
  the nightly user journey pulls the real one). Absent image → clean SKIP.

## The prep-hook pairing rule

When a page's prose names an input the reader is assumed to have (a supplier
ZIP, an SBOM handed over by a team, per-layer SBOMs from earlier steps), the
page's `prep_page()` case materializes exactly that object in the workdir. The
doc text stays verbatim.

- Renaming the placeholder in the doc without updating the hook (or vice
  versa) fails the harness. That is intended.
- Hooks build inputs only from in-repo material (`examples/`,
  `tests/fixtures/`) — never from the network.

## Promised artifacts (EXPECT)

Every artifact a page's tables or prose promise gets a line in the `EXPECT`
manifest:

```
page-path :: artifact-glob (relative to the workdir) :: optional jq assertion
```

Leave the jq field empty for existence-only checks; give files with a content
contract an assertion (for example `.bomFormat=="CycloneDX" and
.specVersion=="1.6"`). When you change a page's artifact table, change EXPECT
with it — a file that is in the table but not in EXPECT is an unverified
promise.

## Where it runs

The harness fails if a listed page has no runnable block (so dropping the
markers is caught), if a command exits non-zero, or if a promised artifact is
missing or violates its assertion. It runs in the `docs-walkthrough` job of the
heavy-e2e workflow (main pushes, manual dispatch, nightly), and
`scripts/verify-release.sh` runs it against the freshly published image at
release time — every page and assertion added here strengthens the release
gate automatically. Locally: `bash tests/test-docs-walkthrough.sh` (needs
Docker and the `sbom-scanner:test` tag; to exercise the published-image page,
`docker pull ghcr.io/sktelecom/bomlens:latest` first).
