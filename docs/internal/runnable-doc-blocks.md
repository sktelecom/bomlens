# Runnable documentation blocks

`tests/test-docs-walkthrough.sh` runs the getting-started guide the way a reader
does and checks the documented commands still work. To avoid running illustrative
snippets (placeholder URLs, the `--ui` server, OS install steps), only blocks
explicitly marked as runnable are executed.

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
- All marked blocks on a page run in order, in one shell, from the repo root —
  a later block can read an earlier block's output (for example the `jq` check
  reads the `MyApp_1.0.0_bom.json` the scan wrote).
- Mark only blocks that run verbatim from the repo root with no human input.
  Leave placeholder URLs (`github.com/org/repo`), the long-running `--ui`
  server, and OS install steps unmarked.
- Keep a page's English and `.ko.md` mirror in sync — the same commands should
  carry the same markers.

## Wiring

A page is exercised once it is listed in the `TARGETS` array of
`tests/test-docs-walkthrough.sh`, together with the artifact its walkthrough must
produce. The harness fails if a listed page has no runnable block (so dropping
the markers is caught), if a command exits non-zero, or if the promised artifact
is missing or not valid CycloneDX. It runs in the `docs-walkthrough` CI job
(pushes and manual dispatch), and skips cleanly when the scanner image is absent.
