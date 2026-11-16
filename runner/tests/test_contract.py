# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
"""The result manifest reader (manifest.py)."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from _support import manifest, write_output

from bomlens_runner.errors import ContractError, ManifestMissing, OutputTooLarge, UnsupportedContractVersion
from bomlens_runner.manifest import load_manifest, parse_manifest, read_output

SCHEMA = Path(__file__).resolve().parents[2] / "schemas" / "engine-result-1.json"


class Manifest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, doc):
        (self.dir / "bomlens-result.json").write_text(json.dumps(doc))

    def test_parse_and_read_outputs(self):
        out = write_output(self.dir, "a_bom.json", {"bomFormat": "CycloneDX"}, "sbom.cyclonedx")
        self.write(manifest(outputs=[out]))
        result = load_manifest(self.dir)
        self.assertEqual(result.run_status, "succeeded")
        verified = read_output(self.dir, result.output("sbom.cyclonedx"))
        self.assertEqual(verified.document["bomFormat"], "CycloneDX")

    def test_statuses_match_the_schema(self):
        from bomlens_runner.manifest import RUN_STATUSES, STEP_STATUSES
        schema = json.loads(SCHEMA.read_text())
        self.assertEqual(sorted(schema["properties"]["run"]["properties"]["status"]["enum"]), sorted(RUN_STATUSES))
        self.assertEqual(sorted(schema["properties"]["steps"]["items"]["properties"]["status"]["enum"]),
                         sorted(STEP_STATUSES))

    def test_versions_and_names(self):
        with self.assertRaises(UnsupportedContractVersion):
            parse_manifest(manifest(version="2.0.0"))
        doc = manifest()
        doc["contract"]["name"] = "x"
        with self.assertRaises(ContractError):
            parse_manifest(doc)
        parse_manifest(manifest(version="1.9.0"))

    def test_unknown_statuses_refused_unknown_ids_kept(self):
        doc = manifest()
        doc["run"]["status"] = "partial"
        with self.assertRaises(ContractError):
            parse_manifest(doc)
        doc = manifest(steps=[{"id": "new-step", "status": "ok", "reason": "new-reason", "stage": 2,
                               "started_at": "2026-11-16T00:00:00Z", "ended_at": "2026-11-16T00:00:01Z"}])
        self.assertEqual(parse_manifest(doc).step("new-step").reason, "new-reason")
        doc["steps"][0]["status"] = "weird"
        with self.assertRaises(ContractError):
            parse_manifest(doc)

    def test_success_with_non_zero_exit(self):
        with self.assertRaises(ContractError):
            parse_manifest(manifest(exit_code=1))

    def test_missing_and_invalid(self):
        with self.assertRaises(ManifestMissing):
            load_manifest(self.dir)
        (self.dir / "bomlens-result.json").write_text("{")
        with self.assertRaises(ContractError):
            load_manifest(self.dir)
        (self.dir / "bomlens-result.json").write_text("[" * 100000 + "]" * 100000)
        with self.assertRaises(ContractError):
            load_manifest(self.dir)
        (self.dir / "bomlens-result.json").write_text('{"a": ' + "9" * 5000 + "}")
        with self.assertRaises(ContractError):
            load_manifest(self.dir)

    def test_manifest_link_and_size(self):
        (self.dir / "real.json").write_text(json.dumps(manifest()))
        os.symlink(self.dir / "real.json", self.dir / "bomlens-result.json")
        with self.assertRaises(ContractError):
            load_manifest(self.dir)
        os.unlink(self.dir / "bomlens-result.json")
        (self.dir / "bomlens-result.json").write_text(" " * (4 * 1024 * 1024 + 1))
        with self.assertRaises(OutputTooLarge):
            load_manifest(self.dir)

    def test_output_path_rules(self):
        out = write_output(self.dir, "a_bom.json", {"x": 1}, "sbom.cyclonedx")
        for bad in ("../a_bom.json", "sub/a_bom.json", ".", "", "a\\b", "a\0b"):
            doc = manifest(outputs=[dict(out, path=bad)])
            self.write(doc)
            with self.assertRaises(ContractError, msg=bad):
                read_output(self.dir, load_manifest(self.dir).outputs[0])

    def test_output_link_size_sha_and_object(self):
        out = write_output(self.dir, "a_bom.json", {"x": 1}, "sbom.cyclonedx")
        os.symlink(self.dir / "a_bom.json", self.dir / "link.json")
        self.write(manifest(outputs=[dict(out, path="link.json")]))
        with self.assertRaises(ContractError):
            read_output(self.dir, load_manifest(self.dir).outputs[0])
        self.write(manifest(outputs=[dict(out, bytes=out["bytes"] + 1)]))
        with self.assertRaises(ContractError):
            read_output(self.dir, load_manifest(self.dir).outputs[0])
        self.write(manifest(outputs=[dict(out, sha256="0" * 64)]))
        with self.assertRaises(ContractError):
            read_output(self.dir, load_manifest(self.dir).outputs[0])
        arr = write_output(self.dir, "arr.json", [1], "other")
        self.write(manifest(outputs=[arr]))
        with self.assertRaises(ContractError):
            read_output(self.dir, load_manifest(self.dir).outputs[0])

    def test_read_limit(self):
        out = write_output(self.dir, "a_bom.json", {"x": "y" * 1000}, "sbom.cyclonedx")
        self.write(manifest(outputs=[out]))
        with self.assertRaises(OutputTooLarge):
            read_output(self.dir, load_manifest(self.dir).outputs[0], limit=10)

    def test_messages_are_capped_and_clipped(self):
        doc = manifest()
        doc["run"]["status"] = "x" * 1000
        with self.assertRaises(ContractError) as cm:
            parse_manifest(doc)
        self.assertLessEqual(len(str(cm.exception)), 300)


if __name__ == "__main__":
    unittest.main()
