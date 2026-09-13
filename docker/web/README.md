# Web UI (server layer)

> **한국어**: [docker/web/README.ko.md](README.ko.md)

Contributor documentation for the backend and frontend of the BomLens web UI. If you
just want to use the web UI, see the site's [Scan with the web UI](https://sktelecom.github.io/bomlens/)
guide.

The web UI runs inside the scanner image with `MODE=UI`. The desktop app (`electron/`)
is a thin shell that starts this server as a container and wraps `localhost` in a
BrowserWindow. In other words, the browser UI and the desktop app share the same
server and the same screens.

## Layout

- `server.py` - An HTTP server built with the Python standard library only. It serves
  the built React SPA (`frontend/dist`) and runs `/usr/local/bin/run-scan` to drive
  scans. No external dependencies.
- `frontend/` - React 18 + Vite + Tailwind SPA. For UI development, testing, and
  design tokens, see [`frontend/README.md`](frontend/README.md).

## server.py summary

Main endpoints (see the comment block at the top of `server.py` for the full list):

- `GET /` - index.html (the React SPA)
- `GET /capabilities` - Reports which input types (firmware, docker) this image supports
- `GET /scan-stream?...` - Streams live scan logs and the final summary over Server-Sent Events
- `POST /upload?kind=...` - Stores an uploaded file and returns a token
- `GET /results`, `GET /file?name=...`, `GET /download-all` - Read and download generated artifacts

Each input type (the `source` parameter of `/scan-stream`) maps to a scan MODE.
`current-dir`, `git-url`, and `zip-upload` map to SOURCE; `rootfs-dir` maps to
ROOTFS; `sbom-upload` maps to ANALYZE; `docker-image` maps to IMAGE.
`firmware-upload` maps to FIRMWARE (only on images built with unblob), and
`ai-model` maps to AIBOM (only on the bomlens-aibom image).

Design principle: values such as the scan execution path (`SBOM_RUN_SCAN`) and image
names come only from server environment variables, never from request input. File
serving guards against path traversal.

## Running and testing locally

- To bring up the web UI from the source tree, run `./scripts/scan-sbom.sh --ui` from
  the repository root. The latest `server.py` and a freshly built frontend get
  mounted over the image.
- Contract tests (no Docker needed): `tests/test-web-ui.sh` plugs a stub scanner into
  `SBOM_RUN_SCAN` and verifies the `/scan-stream` SSE protocol and its JSON contract.
  Update this test whenever an endpoint or a response shape changes.
- The JSON contract the frontend consumes is mirrored in `frontend/src/lib/api.ts`,
  which tracks `server.py`. Keep both sides in sync whenever a server response changes.

For image build and deployment details, see the parent [`docker/README.md`](../README.md).
