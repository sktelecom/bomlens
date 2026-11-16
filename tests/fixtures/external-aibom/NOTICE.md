# Samples of other tools' AI BOMs

Used by tests/test-external-aibom.sh to check that BomLens reads them.

- `k8s-aibom-llama-cpp-chat.cdx.json` is copied unchanged from
  https://github.com/GoogleCloudPlatform/k8s-aibom (docs/integrations/fixtures/llama-cpp-chat.cdx.json),
  Apache License 2.0, Copyright Google LLC.
- `aisbom-model.cdx.json` and `aisbom-local-file.cdx.json` are output of aisbom-cli 1.7.0
  (Lab700xOrg/aisbom, Apache License 2.0). The first is a scan of hf://google/bert_uncased_L-2_H-128_A-2
  (Apache-2.0 model) cut to its first component; the second is a scan of a 16-byte local
  .safetensors file written for this purpose.
- `cisco-aibom-app.cdx.json` and `aibomgen-cli-model.cdx.json` were written for these tests from each
  tool's public documentation and generator source (Cisco AI BOM: cisco-ai-defense/aibom, AIBoMGen CLI:
  idlab-discover/aibomgen-cli). They follow the field layout those sources describe and are not captured
  output of the tools. Names, hashes and identifiers in them are invented.
