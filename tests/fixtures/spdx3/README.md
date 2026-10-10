# SPDX 3.0.1 schema and extract

`spdx-json-schema-extract.json` holds a small part of the SPDX 3.0.1 JSON schema: the property names and required lists of the classes `docker/lib/convert-to-spdx3-ai.py` writes, and the allowed values of the enumerated properties. `tests/test-spdx3-ai.sh` compares `docker/lib/spdx3-ai-map.json` against it, so a mapping that names a property or a value the specification does not define fails the test.

- Material: SPDX 3.0.1 JSON schema (`spdx-json-schema.json`), version 3.0.1
- Source: <https://spdx.org/schema/3.0.1/spdx-json-schema.json> (the SHA-256 of the file used is recorded in the extract as `sourceSha256`)
- Licence: Community Specification License 1.0, from the SPDX project ([spdx/spdx-3-model](https://github.com/spdx/spdx-3-model/blob/main/License.md)). The schema is redistributed with only its line endings changed, and the extract is derived from it; both are attributed here as the licence requires.

`spdx-json-schema.json` is the published schema itself, with its line endings changed from CRLF to LF and nothing else; `sourceSha256` is the hash of the file as downloaded. `tests/test-spdx3-ai.sh` validates a complete document against it when the `jsonschema` package is installed.

The published schema does not carry the narrowed cardinalities the specification pages give for `ai_AIPackage` and `dataset_DatasetPackage` (for example `releaseTime` 1..1). The converter enforces those itself, and the test keeps them as constants.

The SHACL model is checked separately, by the official validator (`spdx3-validate`) in `tests/test-spdx3-official.sh`. It runs in the nightly workflow with the hash-pinned packages in `tests/spdx3-validate-requirements.txt`, so no PR job installs it.

To regenerate after downloading the schema:

```bash
python3 tests/fixtures/spdx3/extract-spdx-schema.py spdx-json-schema.json \
  > tests/fixtures/spdx3/spdx-json-schema-extract.json
```
