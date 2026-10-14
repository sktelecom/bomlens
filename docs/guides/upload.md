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

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `TRUSCA upload needs API_URL, API_KEY (Bearer token), and TRUSCA_PROJECT_ID` | One of the three is missing. All three are required for `--trusca` / `UPLOAD_TARGET=trusca`; there is no partial mode. |
| `API_KEY and API_URL are required for upload` | Same requirement on the Dependency-Track path (the default target). |
| `Upload to <url> did not complete (curl exit N: no response)` | The server is unreachable — wrong URL, network/proxy, or the server is down. The scan itself already finished and its artifacts were saved; fix `API_URL` and re-upload, or add `--generate-only` to skip the upload step entirely. |
| `TRUSCA ingest failed (HTTP <code>)` | TRUSCA rejected the request. The response body printed alongside the error names the reason — a bad token, an unknown project id, or a malformed SBOM. |
| `Upload failed (HTTP <code>)` (Dependency-Track) | Same idea — the printed response body has the server's reason. A 401 usually means a wrong or expired `API_KEY`. |
| `Cannot reach Dependency Track at <url>` (a warning, not a failure) | A pre-flight check failed but the upload is attempted anyway, since some deployments block the version endpoint but still accept the BOM upload. If the upload itself then fails too, it is a real connectivity problem. |
| `Dependency-Track ... refused the CycloneDX 1.7 SBOM (HTTP 400)` (a warning) | Dependency-Track reads CycloneDX 1.7 from 4.14.4 and 5.1.0 on, and an older server refuses a 1.7 SBOM: one made with `--spec-version 1.7`, and an AI model or dataset SBOM (`--model`), which is 1.7 even at the default. When the server's `/api/version` names an older version, or names none, a 1.6 copy of the SBOM is sent once more; the saved SBOM stays 1.7. The copy also rewrites what 1.6 does not allow: a license list that mixes licenses and an expression becomes one expression joined with `AND` (or, when a license has no SPDX id, a list of licenses), and fields that only 1.7 has are removed. If the copy is refused too, both responses are printed. |
| `Dependency-Track <version> reads CycloneDX 1.7, so the refusal (HTTP 400) is not about the version` (a warning) | The server is 4.14.4 or later in 4.x, or 5.1.0 or later, and reads the 1.7 SBOM (`--spec-version 1.7` or `--model`), so no 1.6 copy is sent. The printed response body has the server's reason. |

For TRUSCA, `HTTP 202` only means the ingest was queued; tracking it to completion happens in the TRUSCA UI (`GET /v1/scans/{id}`), not in BomLens.

---

> **Related**: [CLI reference](../reference/cli.md) | [Web UI reference](../reference/ui.md) | [Generate notice, security & risk reports](reports.md)
