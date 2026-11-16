# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
"""Image scans (run_image_scan) and the stage 1 mirror prefix."""

import copy
import json
import unittest

from _support import FIXTURES, FakeBackend, Workspace

from bomlens_runner import backend as b
from bomlens_runner.errors import ImageNotAllowed, PolicyError, ScanTimedOut
from bomlens_runner.images import image_target, normalize_prefix, stage1_repositories
from bomlens_runner.orchestrator import run_image_scan, run_source_scan


class ImageTarget(unittest.TestCase):
    def test_accepts_references_and_returns_registry_scheme(self):
        for ref, want in (("alpine:3.20", "registry:alpine:3.20"), (" nginx ", "registry:nginx"),
                          ("ghcr.io/org/app:1@sha256:" + "a" * 64, "registry:ghcr.io/org/app:1@sha256:" + "a" * 64),
                          ("localhost:5000/x", "registry:localhost:5000/x")):
            self.assertEqual(image_target(ref), want)

    def test_refuses_without_echoing_the_value(self):
        for bad in ("Alpine", "docker://alpine", "a b", "x;rm -rf /", "", "a" * 600):
            with self.assertRaises(PolicyError) as cm:
                image_target(bad)
            if bad:
                self.assertNotIn(bad[:20], str(cm.exception))


class ImageScan(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace()
        self.backend = FakeBackend(self.ws.root)

    def tearDown(self):
        self.ws.cleanup()

    def scan(self, policy=None):
        return run_image_scan(policy or self.ws.policy(), self.backend, scan_id="i1", target="alpine:3.20",
                              project="alpine", version="3.20", scan_dir=self.ws.scan_dir)

    def test_one_hardened_container(self):
        result = self.scan()
        self.assertEqual(self.backend.components, ["engine-image"])
        spec = self.backend.spec("engine-image")
        self.assertEqual(spec.user, "1000:1000")
        self.assertEqual(spec.capabilities, ())
        self.assertEqual(spec.network, b.NETWORK_EGRESS)
        self.assertEqual(sorted(m.target for m in spec.mounts), ["/host-output", "/trivy-db"])
        env = spec.env
        self.assertEqual((env["MODE"], env["TARGET_IMAGE"], env["DEEP_LICENSE"]), ("IMAGE", "registry:alpine:3.20", "false"))
        self.assertFalse(any(k.startswith(("SYFT_", "DOCKER_")) or k == "TRIVY_PASSWORD" for k in env))
        self.assertEqual(result.manifest.run_status, "succeeded")
        self.assertEqual(result.as_metadata()["mode"], "image")

    def test_root_worker_is_refused(self):
        with self.assertRaises(PolicyError):
            self.scan(self.ws.policy(uid=None, gid=None))
        with self.assertRaises(PolicyError):
            self.scan(self.ws.policy(uid=0, gid=0))

    def test_proxy_by_name_loopback_dropped(self):
        self.scan(self.ws.policy(image_env={"HTTPS_PROXY": "http://p.corp:1", "HTTP_PROXY": "http://localhost:1"}))
        env = self.backend.spec("engine-image").env
        self.assertEqual(env["HTTPS_PROXY"], "http://p.corp:1")
        self.assertNotIn("HTTP_PROXY", env)

    def test_timeout(self):
        self.backend.outcomes["engine-image"] = b.ContainerOutcome(started=True, exit_code=137, timed_out=True)
        with self.assertRaises(ScanTimedOut):
            self.scan()


class Stage1ImagePrefix(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace()
        self.backend = FakeBackend(self.ws.root, plan_fixture="node-mirror-prefix")

    def tearDown(self):
        self.ws.cleanup()

    def scan(self, **kw):
        return run_source_scan(self.ws.policy(**kw), self.backend, scan_id="p1", project="demo", version="1.0",
                               scan_dir=self.ws.scan_dir, source=self.ws.source)

    def test_mirror_capture_differs_only_in_the_registry(self):
        a = json.loads((FIXTURES / "node-ok" / "bomlens-plan.json").read_text())
        m = json.loads((FIXTURES / "node-mirror-prefix" / "bomlens-plan.json").read_text())
        a2, m2 = copy.deepcopy(a), copy.deepcopy(m)
        a2["stages"][0]["image"] = m2["stages"][0]["image"] = "x"
        a2.pop("input_fingerprint", None), m2.pop("input_fingerprint", None)
        for s in a2["stages"] + m2["stages"]:
            s.pop("input_fingerprint", None)
        self.assertEqual(a2, m2)

    def test_prefix_reaches_plan_and_stage1_pulls_from_the_mirror(self):
        self.scan(stage1_image_prefix="registry.example/mirror/cdxgen")
        self.assertEqual(self.backend.spec("engine-plan").env["CDXGEN_IMAGE_PREFIX"], "registry.example/mirror/cdxgen/")
        self.assertTrue(self.backend.spec("engine-stage1").image.startswith("registry.example/mirror/cdxgen/"))

    def test_no_prefix_no_variable(self):
        self.backend.plan_fixture = "node-ok"
        self.scan()
        self.assertNotIn("CDXGEN_IMAGE_PREFIX", self.backend.spec("engine-plan").env)

    def test_prefix_forms(self):
        self.assertEqual(normalize_prefix("reg.example:5000/m"), "reg.example:5000/m/")
        self.assertIsNone(normalize_prefix(""))
        for bad in ("https://reg.example/m", "mirror/cdxgen", "reg.example/M A", "user:pw@reg.example/m"):
            with self.assertRaises(PolicyError) as cm:
                normalize_prefix(bad)
            self.assertNotIn("pw", str(cm.exception))

    def test_bad_prefix_fails_before_any_container(self):
        with self.assertRaises(PolicyError):
            self.scan(stage1_image_prefix="not a registry")
        self.assertEqual(self.backend.specs, [])

    def test_prefix_replaces_the_default(self):
        self.assertEqual(stage1_repositories((), "reg.example/m/"), ("reg.example/m/",))
        self.assertEqual(stage1_repositories(("ghcr.io/cdxgen/",), "reg.example/m/"), ("ghcr.io/cdxgen/", "reg.example/m/"))
        self.assertEqual(stage1_repositories((), None), ("ghcr.io/cdxgen/",))

    def test_public_registry_refused_when_a_prefix_is_set(self):
        self.backend.plan_fixture = "node-ok"
        with self.assertRaises(ImageNotAllowed):
            self.scan(stage1_image_prefix="registry.example/mirror/cdxgen")

    def test_prefix_path_itself_is_not_under_the_prefix(self):
        from bomlens_runner.images import require_allowed
        with self.assertRaises(ImageNotAllowed):
            require_allowed("registry.example/mirror/cdxgen", ("registry.example/mirror/cdxgen/",))


if __name__ == "__main__":
    unittest.main()
