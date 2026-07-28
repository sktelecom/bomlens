# Publishing and refreshing the read-only demo

The demo at `https://sktelecom.github.io/bomlens/demo/` is the real web UI with
its data source swapped: instead of calling `server.py`, it reads JSON captured
from a real scan. It costs nothing to host, because it rides along with the
documentation site already on GitHub Pages.

## How the pieces fit

The bundle is the same SPA as the app, built with two settings. `BASE_PATH`
tells Vite the site is served from a sub-path; `VITE_DEMO_DATA_BASE` points the
API layer at the captured files and, by being non-empty, turns on demo mode
(`docker/web/frontend/src/lib/demo.ts`). In demo mode the UI hides scanning,
upload, delete and SPDX export, shows a read-only banner, and swaps the "New
scan" button for a link to the install guide.

The data lives in `docs/demo/data/` and is committed. The bundle is not: CI
builds it into `docs/demo/` right before `mkdocs build`, and MkDocs copies the
whole folder into the site. `docs/demo/.gitignore` enforces that split, so a
local build cannot accidentally commit a bundle.

## Refreshing the data

Run the scans you want to publish into one folder, then capture them:

```bash
# One run per kind of result, so the list shows the range of inputs.
cd examples/java-maven && scripts/scan-sbom.sh \
    --project SpringBootDemo --version 1.0.0 \
    --license Apache-2.0 --generate-only -o ~/demo-scans

scripts/scan-sbom.sh --project NginxRuntimeImage --version 1.24-alpine \
    --target nginx:1.24-alpine --generate-only -o ~/demo-scans

scripts/scan-sbom.sh --project BertBaseUncased --version 1.0 \
    --model "google-bert/bert-base-uncased" --usage product \
    --generate-only -o ~/demo-scans

# The supplier review needs an SBOM to review, so scan something first and
# feed the result back in with --analyze.
scripts/capture-demo-data.sh ~/demo-scans
```

Pick runs whose *results* differ, not whose input flag differs. A GitHub URL, a
ZIP and a local folder all produce the same kind of source scan, so publishing
all three would fill the list with rows that look identical. Source, container,
AI model and supplier-SBOM review each land on a visibly different screen — the
container brings OS packages, the AI model a CycloneDX 1.7 ML-BOM with the G7
checks, the review a conformance verdict.

Firmware is the one kind the demo does not carry. Its image is built for amd64
only (see the `docker-publish` workflow), so capturing a firmware run needs an
amd64 machine — on Apple Silicon it would have to run under emulation, where the
unpacking tools are slow and unreliable. Capture it from an amd64 host if you
want that row.

`capture-demo-data.sh` starts the real `server.py` against that folder and saves
what it answers, so the captured shapes are the server's shapes by construction.
Writing the JSON by hand would drift the moment a field changes.

Two things to know when choosing what to publish.

Scan in **source mode** — from inside the project folder, without `--target` —
rather than pointing `--target` at a directory. A source scan declares its root
component as `application`, which is what makes the recent-scans list label it
"Source" instead of the generic "SBOM"; a directory target is read as a rootfs
scan and every row ends up looking the same. Source mode also resolves far more
of the dependency graph.

The capture would otherwise report whatever the capture machine can do, which is
the wrong thing to publish. The demo shows the scan form so visitors can see the
range of inputs BomLens accepts, so the script forces the input-side
capabilities on — firmware and AI-model scanning would look unsupported just
because the capture machine lacks those opt-in images. The run button is
disabled in demo mode, so nothing there can be acted on. Capabilities whose
control sits outside that form are forced off instead, because they would render
a button that does nothing: SPDX export converts server-side, `hfAuth` is a
token the demo never holds, and host paths do not exist on a static host.

Markdown reports are dropped from the capture, and their names are removed from
the two listings so no download link points at a missing file. The data folder
sits inside the MkDocs docs tree, where any `*.md` is treated as a page: it gets
rendered to HTML (the download would 404) and fails `mkdocs build --strict` for
not being in the nav. Each dropped report has an `.html` twin with the same
content, so nothing is lost. Adding a new artifact type is safe as long as it is
not Markdown.

## Checking it before you push

```bash
scripts/build-demo-bundle.sh

# Serve it the way Pages will, under the site's sub-path.
mkdir -p /tmp/demo-preview/bomlens
cp -R docs/demo /tmp/demo-preview/bomlens/demo
(cd /tmp/demo-preview && python3 -m http.server 8901)
# → http://127.0.0.1:8901/bomlens/demo/
```

Serving it at a host root instead would hide exactly the class of bug this
setup is prone to: an asset or data path that ignores the base path and works
only at `/`.

## What the demo deliberately does not do

It never runs a scan. Scanning builds the target project, so a public scan
endpoint would be arbitrary code execution on whoever hosts it — which is also
why the demo is a static page rather than a server.

The scan form is still reachable, because it is where the range of supported
inputs is visible and hiding it made the demo look like a results viewer rather
than a tool. Its run button is disabled with the reason stated next to it, and
that reason carries the link to the install guide. Disabled rather than hidden:
a missing button reads as a broken page, a disabled one with a reason reads as
a boundary.
