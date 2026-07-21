---
description: Upload a generated SBOM to a Dependency-Track server or to TRUSCA's native ingest endpoint.
---

# Upload to Dependency-Track / TRUSCA

This guide covers how the scanner uploads a generated SBOM and how to target TRUSCA's native ingest endpoint.

After a scan, the SBOM is uploaded by default (`--generate-only` saves locally and skips the upload). Choose the destination with `UPLOAD_TARGET`.

- `dependency-track` (default): a regular Dependency-Track server. Authenticates with `API_URL` and `API_KEY` (`X-Api-Key`) and auto-creates the project.
- `trusca`: TRUSCA's native ingest endpoint. It is not Dependency-Track compatible, so the auth and inputs differ.

To upload to TRUSCA, prepare three things.

- `API_URL`: the TRUSCA server URL
- `API_KEY`: a Bearer token issued by TRUSCA (starts with `tos_`, developer role)
- project_id: the target TRUSCA project id (UUID). It must already exist; there is no auto-create.

```bash
API_URL="https://<TRUSCA host>" API_KEY="tos_..." \
  ./scripts/scan-sbom.sh \
  --project "MyApp" --version "1.2.3" --all \
  --trusca "<project_id>"
```

`--trusca <id>` is shorthand for `--upload-target trusca` plus `TRUSCA_PROJECT_ID`. Adjust the ref and release labels with `TRUSCA_REF` (default `main`) and `TRUSCA_RELEASE` (default the `--version` value). On acceptance it prints `202` and a scan id; track progress in the TRUSCA UI (`GET /v1/scans/{id}`).

> TRUSCA ingest fills components, vulnerabilities, declared licenses, the dependency graph, and the build gate. It cannot fill scancode-detected licenses (`--deep-license`), the cosign signature (`--sign`), or source preservation, since there is no source tree. Generate those locally with `--generate-only` if you need them.

## From the web UI

You can upload without the CLI. On the New scan form, turn on the **Upload** step, choose Dependency-Track or TRUSCA, and enter the server URL and access token (plus the project id for TRUSCA). The scan runs and then uploads in one step, using the same endpoints and authentication described above. The URL and token are used for that run only and are not saved. See the [Web UI reference](../reference/ui.md).
