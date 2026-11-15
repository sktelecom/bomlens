# Samples of other tools' AI BOMs

Used by tests/test-external-aibom.sh to check that BomLens reads them.

- `k8s-aibom-llama-cpp-chat.cdx.json` is copied unchanged from
  https://github.com/GoogleCloudPlatform/k8s-aibom (docs/integrations/fixtures/llama-cpp-chat.cdx.json),
  Apache License 2.0, Copyright Google LLC.
- `aisbom-model.cdx.json`, `cisco-aibom-app.cdx.json` and `aibomgen-cli-model.cdx.json` were written
  for these tests from each tool's public documentation and generator source (AIsbom: Lab700xOrg/aisbom,
  Cisco AI BOM: cisco-ai-defense/aibom, AIBoMGen CLI: idlab-discover/aibomgen-cli). They follow the field
  layout those sources describe and are not captured output of the tools. Names, hashes and
  identifiers in them are invented.
