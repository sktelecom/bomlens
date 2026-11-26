# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
"""Source scan orchestration (orchestrator.run_source_scan) with a fake backend."""

import os
import unittest

from _support import DEEP_LICENSE, ENGINE, FakeBackend, Workspace

from bomlens_runner import backend as b
from bomlens_runner.errors import (ContainerStillRunning, EngineError, EngineWroteNoResult, ImageNotAllowed,
                                   PlanRejected, PolicyError, ScanCancelled)
from bomlens_runner.orchestrator import STAGE1_LOG_NAME, is_loopback_proxy, project_token, run_source_scan
from bomlens_runner.policy import SecretRef


class Base(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace()
        self.backend = FakeBackend(self.ws.root)

    def tearDown(self):
        self.ws.cleanup()

    def scan(self, policy=None, **kw):
        args = dict(scan_id="s1", project="demo", version="1.0", scan_dir=self.ws.scan_dir, source=self.ws.source)
        args.update(kw)
        return run_source_scan(policy or self.ws.policy(), self.backend, **args)


class Order(Base):
    def test_order_is_plan_stage1_stage2_chown(self):
        result = self.scan()
        self.assertEqual(self.backend.components, ["engine-plan", "engine-stage1", "engine-stage2", "engine-chown"])
        self.assertEqual(result.manifest.run_status, "succeeded")
        self.assertEqual(result.plan_status, "ok")
        self.assertEqual(result.detected_ecosystem, "node")
        self.assertEqual(self.backend.leftovers, ["s1"])
        self.assertEqual(self.backend.preflights, 1)

    def test_on_stage_names(self):
        seen = []
        self.scan(on_stage=seen.append)
        self.assertEqual(seen, ["prep", "cdxgen", "postprocess"])

    def test_unsupported_plan_runs_plan_stage2_chown(self):
        self.backend.plan_fixture = "android-unsupported"
        result = self.scan()
        self.assertEqual(self.backend.components, ["engine-plan", "engine-stage2", "engine-chown"])
        env = self.backend.spec("engine-stage2").env
        self.assertEqual(env["BOMLENS_STAGE1_EXIT"], "127")
        log = (result.output_dir / STAGE1_LOG_NAME).read_text()
        self.assertIn("unsupported (android-sdk-image)", log)

    def test_failed_plan_gives_plan_then_chown(self):
        self.backend.outcomes["engine-plan"] = b.ContainerOutcome(started=True, exit_code=1)
        with self.assertRaises(EngineError):
            self.scan()
        self.assertEqual(self.backend.components, ["engine-plan", "engine-chown"])

    def test_plan_that_writes_no_plan(self):
        self.backend.outcomes["engine-plan"] = b.ContainerOutcome(started=True, exit_code=0)
        self.backend.plan_fixture = "missing"
        with self.assertRaises(Exception):
            self.scan()

    def test_no_manifest_is_engine_wrote_no_result(self):
        self.backend.write_manifest = False
        self.backend.outcomes["engine-stage2"] = b.ContainerOutcome(started=True, exit_code=2)
        with self.assertRaises(EngineWroteNoResult) as cm:
            self.scan()
        self.assertIn("exited 2", str(cm.exception))
        self.assertNotIn(str(self.ws.root), str(cm.exception))


class Hardening(Base):
    def test_networks(self):
        self.scan()
        net = {s.component: s.network for s in self.backend.specs}
        self.assertEqual(net, {"engine-plan": "none", "engine-stage1": "egress", "engine-stage2": "none",
                               "engine-chown": "none"})

    def test_read_only_root_and_its_switch(self):
        self.scan()
        self.assertTrue(all(s.read_only_root for s in self.backend.specs))
        self.backend.specs.clear()
        self.scan(policy=self.ws.policy(stage1_read_only_root=False))
        self.assertFalse(self.backend.spec("engine-stage1").read_only_root)
        self.assertTrue(self.backend.spec("engine-stage2").read_only_root)

    def test_capabilities_only_for_root_containers(self):
        self.scan()
        self.assertEqual(self.backend.spec("engine-plan").capabilities, ())
        self.assertEqual(self.backend.spec("engine-stage2").capabilities, ())
        self.assertIn("CHOWN", self.backend.spec("engine-stage1").capabilities)

    def test_non_root_user_for_plan_and_stage2(self):
        self.scan()
        self.assertEqual(self.backend.spec("engine-plan").user, "1000:1000")
        self.assertEqual(self.backend.spec("engine-stage2").user, "1000:1000")
        self.assertEqual(self.backend.spec("engine-stage1").user, "0:0")

    def test_labels(self):
        self.scan(policy=self.ws.policy(labels={"example.com/role": "bomlens-engine"}))
        for s in self.backend.specs:
            self.assertEqual(s.labels[b.LABEL_PART_OF], "bomlens-engine")
            self.assertEqual(s.labels[b.LABEL_COMPONENT], s.component)
            self.assertEqual(s.labels[b.LABEL_SCAN], "s1")
            self.assertEqual(s.labels[b.LABEL_NETWORK], s.network)
            self.assertEqual(s.labels["example.com/role"], "bomlens-engine")

    def test_stage1_image_is_pinned_under_cdxgen(self):
        self.scan()
        img = self.backend.spec("engine-stage1").image
        self.assertTrue(img.startswith("ghcr.io/cdxgen/") and "@sha256:" in img and ":13" not in img.split("@")[0])

    def test_mounts(self):
        self.scan()
        s1 = self.backend.spec("engine-stage1")
        self.assertEqual(sorted(m.target for m in s1.mounts),
                         ["/app", "/bomlens-state", "/out", "/tmp/build-prep.sh", "/tmp/identify-conda.py"])
        src1 = next(m for m in s1.mounts if m.target == "/app")
        self.assertFalse(src1.read_only)
        s2 = self.backend.spec("engine-stage2")
        src2 = next(m for m in s2.mounts if m.target == "/src")
        self.assertTrue(src2.read_only)
        trivy = next(m for m in s2.mounts if m.target == "/trivy-db")
        self.assertEqual((trivy.volume, trivy.read_only), (b.VOLUME_TRIVY_DB, True))
        for s in self.backend.specs:
            for m in s.mounts:
                if m.volume == b.VOLUME_WORKSPACE:
                    self.assertTrue(m.subpath.startswith("scan1/"), m)

    def test_plan_files_come_from_the_copy(self):
        self.scan()
        s1 = self.backend.spec("engine-stage1")
        pf = next(m for m in s1.mounts if m.target == "/tmp/build-prep.sh")
        self.assertTrue(pf.subpath.startswith("scan1/bomlens/plan-files/"))
        self.assertTrue(pf.read_only)

    def test_caller_mount_roles(self):
        cache = self.ws.root / "cache-m2"
        cache.mkdir()
        self.scan(policy=self.ws.policy(caller_mounts={"cache-maven": cache}))
        s1 = self.backend.spec("engine-stage1")
        self.assertIn(("cache-m2", "/tmp/sbomhome/.m2"), [(m.subpath, m.target) for m in s1.mounts])


class Env(Base):
    def test_stage1_env_names(self):
        self.scan()
        env = self.backend.spec("engine-stage1").env
        self.assertEqual(env["PROJECT_NAME"], "demo")
        self.assertEqual(env["BOMLENS_GUARD_ID"], "bomlens-s1")
        self.assertEqual(env["HOST_UID"], "1000")
        self.assertNotIn("MODE", env)

    def test_stage2_gets_stage1_trivy_and_image_values(self):
        self.scan()
        env = self.backend.spec("engine-stage2").env
        self.assertEqual(env["BOMLENS_STAGE1_EXIT"], "0")
        self.assertEqual(env["BOMLENS_STAGE1_OOM"], "false")
        self.assertEqual(env["BOMLENS_STAGE1_LOG"], STAGE1_LOG_NAME)
        self.assertEqual(env["TRIVY_CACHE_DIR"], "/trivy-db")
        self.assertEqual(env["TRIVY_SKIP_DB_UPDATE"], "true")
        self.assertEqual(env["BOMLENS_IMAGE_REF"], ENGINE.split("@")[0])
        self.assertEqual(env["MODE"], "POSTPROCESS")
        self.assertEqual(env["GENERATE_SECURITY"], "true")

    def test_plan_is_told_the_deep_license_stage2_image(self):
        self.backend.plan_override = lambda d: (d["stages"][1].update(image=DEEP_LICENSE.split("@")[0],
                                                                       image_digest=DEEP_LICENSE.split("@")[1]), d)[1]
        self.scan(policy=self.ws.policy(deep_license=True))
        env = self.backend.spec("engine-plan").env
        self.assertEqual(env["BOMLENS_IMAGE_REF"], DEEP_LICENSE.split("@")[0])
        self.assertEqual(self.backend.spec("engine-stage2").env["DEEP_LICENSE"], "true")
        self.assertTrue(self.backend.spec("engine-stage2").image.startswith("ghcr.io/sktelecom/bomlens-deep-license@"))

    def test_extra_ca_file_reaches_the_networked_stages_of_a_source_scan(self):
        ca = self.ws.scan_dir / "ca.pem"
        ca.write_text("-----BEGIN CERTIFICATE-----\n")
        self.scan(policy=self.ws.policy(extra_ca_file=ca, stage1_env={"BOMLENS_EXTRA_CA_CERTS": "/elsewhere.pem"}))
        for stage in ("engine-stage1", "engine-stage2"):
            spec = self.backend.spec(stage)
            mount = next(m for m in spec.mounts if m.target == "/bomlens-ca/extra.pem")
            self.assertTrue(mount.read_only)
            self.assertEqual(spec.env["BOMLENS_EXTRA_CA_CERTS"], "/bomlens-ca/extra.pem")
        plan = self.backend.spec("engine-plan")
        self.assertNotIn("/bomlens-ca/extra.pem", [m.target for m in plan.mounts])

    def test_caller_env_reaches_only_allowed_stages(self):
        policy = self.ws.policy(stage1_env={"HTTPS_PROXY": "http://proxy.corp:3128", "BOMLENS_NODE_FULL_GRAPH": "1"},
                                stage2_env={"NVD_API_KEY": SecretRef("bomlens", "nvd"), "ENRICH_EOL": "false"})
        self.scan(policy=policy)
        s1, s2 = self.backend.spec("engine-stage1").env, self.backend.spec("engine-stage2").env
        self.assertEqual(s1["HTTPS_PROXY"], "http://proxy.corp:3128")
        self.assertNotIn("HTTPS_PROXY", s2)
        self.assertEqual(s2["NVD_API_KEY"], SecretRef("bomlens", "nvd"))
        self.assertEqual(s2["ENRICH_EOL"], "false")
        self.assertEqual(self.backend.spec("engine-plan").env["BOMLENS_NODE_FULL_GRAPH"], "1")

    def test_registry_env_reaches_stage_1_only(self):
        env = {"NPM_CONFIG_REGISTRY": "https://mirror.example/npm/", "PIP_INDEX_URL": "https://mirror.example/pypi/simple",
               "PIP_TRUSTED_HOST": "mirror.example", "CARGO_REGISTRIES_CRATES_IO_PROTOCOL": "sparse",
               "GONOSUMDB": "*"}
        self.scan(policy=self.ws.policy(stage1_env=env))
        s1 = self.backend.spec("engine-stage1").env
        for name, value in env.items():
            self.assertEqual(s1[name], value)
            self.assertNotIn(name, self.backend.spec("engine-stage2").env)
            self.assertNotIn(name, self.backend.spec("engine-plan").env)

    def test_registry_secret_and_lowercase_names_reach_stage_1(self):
        ref = SecretRef("mirror", "url")
        self.scan(policy=self.ws.policy(stage1_env={"npm_config_registry": ref, "PIP_INDEX_URL": ref}))
        s1 = self.backend.spec("engine-stage1").env
        self.assertEqual((s1["npm_config_registry"], s1["PIP_INDEX_URL"]), (ref, ref))

    def test_credentials_in_urls_need_a_secret_ref(self):
        for env in ({"GOPROXY": "https://u:p@mirror.example/go,direct"},
                    {"PIP_EXTRA_INDEX_URL": "https://a.example/simple https://u:p@b.example/simple"}):
            with self.assertRaises(PolicyError):
                self.ws.policy(stage1_env=env)
        self.ws.policy(stage1_env={"NPM_CONFIG_REGISTRY": "https://mirror.example/repo/@org/",
                                   "GOPROXY": "https://mirror.example/go,direct"})

    def test_the_maven_wrapper_repository_reaches_stage_1(self):
        url = "https://mirror.example/maven2"
        self.scan(policy=self.ws.policy(stage1_env={"MVNW_REPOURL": url}))
        s1, s2 = self.backend.spec("engine-stage1").env, self.backend.spec("engine-stage2").env
        self.assertEqual(s1["MVNW_REPOURL"], url)
        self.assertNotIn("MVNW_REPOURL", s2)

    def test_registry_env_is_checked(self):
        with self.assertRaises(PolicyError):
            self.ws.policy(stage2_env={"NPM_CONFIG_REGISTRY": "https://mirror.example/"})
        with self.assertRaises(PolicyError):
            self.ws.policy(stage1_env={"GOFLAGS": "-toolexec=x"})
        with self.assertRaises(PolicyError):
            self.ws.policy(stage1_env={"CARGO_REGISTRIES_MIRROR_TOKEN": "x"})
        with self.assertRaises(PolicyError):
            self.ws.policy(stage1_env={"PIP_INDEX_URL": "https://user:pw@mirror.example/simple"})
        self.ws.policy(stage1_env={"PIP_INDEX_URL": SecretRef("mirror", "url"),
                                   "CARGO_REGISTRIES_MIRROR_INDEX": "sparse+https://mirror.example/index/"})

    def test_loopback_proxies_are_dropped(self):
        self.scan(policy=self.ws.policy(stage1_env={"HTTP_PROXY": "http://127.0.0.1:3128", "NO_PROXY": "localhost"}))
        env = self.backend.spec("engine-stage1").env
        self.assertNotIn("HTTP_PROXY", env)
        self.assertEqual(env["NO_PROXY"], "localhost")

    def test_runner_owned_and_unknown_names_are_refused(self):
        with self.assertRaises(PolicyError):
            self.ws.policy(stage2_env={"LD_PRELOAD": "x"})
        with self.assertRaises(PolicyError):
            self.ws.policy(stage1_env={"MODE": "SOURCE"})
        with self.assertRaises(PolicyError):
            self.ws.policy(stage2_env={"BOMLENS_STAGE1_EXIT": "0"})

    def test_worker_environment_never_reaches_a_container(self):
        os.environ["AWS_SECRET_ACCESS_KEY"] = "do-not-pass"
        os.environ["HTTPS_PROXY"] = "http://worker-proxy:1"
        try:
            self.scan()
        finally:
            del os.environ["AWS_SECRET_ACCESS_KEY"], os.environ["HTTPS_PROXY"]
        for s in self.backend.specs:
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", s.env)
            self.assertNotIn("HTTPS_PROXY", s.env)

    def test_project_tokens(self):
        self.assertEqual(project_token("my app/1", "project"), "my_app_1")
        self.assertEqual(project_token("src", "project"), "src-project")
        self.assertEqual(project_token("", "0"), "0")


class KillPaths(Base):
    def test_oom_runs_restore_then_stage2_sees_it(self):
        self.backend.logs["engine-stage1"] = ["resolving", "Killed"]
        self.backend.outcomes["engine-stage1"] = b.ContainerOutcome(started=True, exit_code=137, oom_killed=True)
        result = self.scan()
        self.assertEqual(self.backend.components,
                         ["engine-plan", "engine-stage1", "engine-restore", "engine-stage2", "engine-chown"])
        self.assertEqual(self.backend.spec("engine-restore").env["BOMLENS_GUARD_RESTORE_ONLY"], "1")
        self.assertEqual(self.backend.spec("engine-restore").network, "none")
        env = self.backend.spec("engine-stage2").env
        self.assertEqual((env["BOMLENS_STAGE1_EXIT"], env["BOMLENS_STAGE1_OOM"]), ("137", "true"))
        self.assertEqual((result.output_dir / STAGE1_LOG_NAME).read_text(), "resolving\nKilled\n")
        self.assertTrue(result.source_restored)
        self.assertTrue(result.oom_killed)

    def test_timeout_runs_restore(self):
        self.backend.outcomes["engine-stage1"] = b.ContainerOutcome(started=True, exit_code=137, timed_out=True)
        self.scan()
        self.assertIn("engine-restore", self.backend.components)

    def test_normal_failure_runs_no_restore(self):
        self.backend.outcomes["engine-stage1"] = b.ContainerOutcome(started=True, exit_code=1)
        self.scan()
        self.assertNotIn("engine-restore", self.backend.components)
        self.assertEqual(self.backend.spec("engine-stage2").env["BOMLENS_STAGE1_EXIT"], "1")

    def test_failed_restore_still_runs_stage2(self):
        self.backend.outcomes["engine-stage1"] = b.ContainerOutcome(started=True, exit_code=143)
        self.backend.outcomes["engine-restore"] = b.ContainerOutcome(started=True, exit_code=1)
        result = self.scan()
        self.assertFalse(result.source_restored)
        self.assertIn("engine-stage2", self.backend.components)

    def test_stuck_container_stops_the_scan(self):
        self.backend.raise_on["engine-stage1"] = ContainerStillRunning("still running")
        with self.assertRaises(ContainerStillRunning):
            self.scan()
        self.assertNotIn("engine-stage2", self.backend.components)
        # Nothing else is started on the same files once a container is stuck.
        self.assertEqual(self.backend.components[-1], "engine-stage1")

    def test_stage1_that_cannot_start_is_exit_127(self):
        self.backend.outcomes["engine-stage1"] = b.ContainerOutcome(start_error="Kubernetes: ImagePullBackOff")
        result = self.scan()
        self.assertEqual(self.backend.spec("engine-stage2").env["BOMLENS_STAGE1_EXIT"], "127")
        self.assertIn("did not start", (result.output_dir / STAGE1_LOG_NAME).read_text())


class Cancel(Base):
    def test_cancel_from_the_backend(self):
        self.backend.cancel_on = "engine-stage1"
        with self.assertRaises(ScanCancelled):
            self.scan()
        self.assertNotIn("engine-stage2", self.backend.components)

    def test_cancel_before_a_container(self):
        state = {"n": 0}

        def cancel():
            state["n"] += 1
            return state["n"] > 1
        with self.assertRaises(ScanCancelled):
            self.scan(cancel=cancel)
        self.assertEqual(self.backend.components[0], "engine-plan")
        self.assertNotIn("engine-stage1", self.backend.components)

    def test_on_stage_raising_cancels(self):
        def hook(name):
            if name == "cdxgen":
                raise ScanCancelled("cancelled")
        with self.assertRaises(ScanCancelled):
            self.scan(on_stage=hook)
        self.assertEqual(self.backend.components, ["engine-plan", "engine-chown"])


class Allowlists(Base):
    def test_image_from_a_disallowed_repository(self):
        self.backend.plan_override = lambda d: (d["stages"][0].update(image="docker.io/evil/node:1"), d)[1]
        with self.assertRaises(ImageNotAllowed):
            self.scan()
        self.assertNotIn("engine-stage1", self.backend.components)

    def test_prefix_entries_without_slash_are_ignored(self):
        self.backend.plan_override = lambda d: (d["stages"][0].update(image="ghcr.io/cdxevil/node:1"), d)[1]
        with self.assertRaises(ImageNotAllowed):
            self.scan(policy=self.ws.policy(stage1_repositories=("ghcr.io/cdx",)))

    def test_different_stage2_image(self):
        self.backend.plan_override = lambda d: (d["stages"][1].update(image="ghcr.io/sktelecom/bomlens:1.14.0"), d)[1]
        with self.assertRaises(PlanRejected):
            self.scan()

    def test_symbolic_links_and_paths_outside_the_workspace(self):
        link = self.ws.root / "link"
        os.symlink(self.ws.scan_dir, link)
        with self.assertRaises(PolicyError):
            self.scan(scan_dir=link)
        with self.assertRaises(PolicyError):
            self.scan(source=self.ws.trivy)

    def test_unpinned_engine_images_are_refused(self):
        from bomlens_runner.policy import Images
        for bad in ("ghcr.io/sktelecom/bomlens:1.15.0", "ghcr.io/sktelecom/bomlens:latest@sha256:" + "a" * 64,
                    "ghcr.io/sktelecom/bomlens@sha256:" + "a" * 64):
            with self.assertRaises(PolicyError):
                Images.parse(bad)

    def test_scan_id_must_be_a_name(self):
        with self.assertRaises(PolicyError):
            self.scan(scan_id="../x")


class ReviewFindings(Base):
    def test_plan_folder_link_does_not_leak_worker_files(self):
        secret = self.ws.root.parent / "worker-secret"
        secret.mkdir()
        (secret / "build-prep.sh").write_text("WORKER SECRET TOKEN")
        orig = self.backend.run

        def run(spec, on_line, cancelled):
            out = orig(spec, on_line, cancelled)
            if spec.component == "engine-plan":
                folder = self.backend.local(spec, "/host-output") / "bomlens-plan"
                import shutil
                shutil.rmtree(folder)
                os.symlink(secret, folder)
            return out
        self.backend.run = run
        with self.assertRaises(PlanRejected) as cm:
            self.scan()
        self.assertNotIn(str(self.ws.root), str(cm.exception))
        for path in self.ws.root.rglob("build-prep.sh"):
            self.assertNotIn("WORKER SECRET", path.read_text())

    def test_missing_plan_file_is_rejected_without_a_path(self):
        self.backend.plan_override = lambda d: (d["stages"][0]["mounts"].append(
            {"role": "plan-file", "source": "bomlens-plan/missing.sh", "target": "/tmp/missing.sh", "mode": "ro"}), d)[1]
        with self.assertRaises(PlanRejected) as cm:
            self.scan()
        self.assertNotIn("/", str(cm.exception).replace("bomlens-plan/", ""))

    def test_cancel_during_stage1_restores_the_source(self):
        self.backend.cancel_on = "engine-stage1"
        with self.assertRaises(ScanCancelled):
            self.scan()
        self.assertEqual(self.backend.components, ["engine-plan", "engine-stage1", "engine-restore", "engine-chown"])

    def test_stage1_job_that_cannot_be_created_still_runs_stage2(self):
        self.backend.raise_on["engine-stage1"] = EngineError("the Job could not be created (Invalid)")
        result = self.scan()
        self.assertIn("engine-stage2", self.backend.components)
        self.assertEqual(self.backend.spec("engine-stage2").env["BOMLENS_STAGE1_EXIT"], "127")
        self.assertIn("did not start", (result.output_dir / STAGE1_LOG_NAME).read_text())

    def test_stuck_restore_is_raised_and_nothing_else_starts(self):
        self.backend.outcomes["engine-stage1"] = b.ContainerOutcome(started=True, exit_code=137, oom_killed=True)
        self.backend.raise_on["engine-restore"] = ContainerStillRunning("still running")
        with self.assertRaises(ContainerStillRunning):
            self.scan()
        self.assertEqual(self.backend.components[-1], "engine-restore")

    def test_secret_names_need_a_secret_ref(self):
        with self.assertRaises(PolicyError):
            self.ws.policy(stage2_env={"NVD_API_KEY": "plain-key"})
        with self.assertRaises(PolicyError):
            self.ws.policy(stage1_env={"HTTPS_PROXY": "http://user:pw@proxy.corp:3128"})
        self.ws.policy(stage1_env={"HTTPS_PROXY": SecretRef("proxy", "url")})

    def test_runner_owned_names_refused_when_the_policy_is_made(self):
        for env in ({"HOST_UID": "0"}, {"BOMLENS_GUARD_ID": "x"}):
            with self.assertRaises(PolicyError):
                self.ws.policy(stage2_env=env)

    def test_source_that_overlaps_the_bomlens_folder(self):
        with self.assertRaises(PolicyError):
            self.scan(source=self.ws.scan_dir)

    def test_leftovers_removed_before_the_folder_is_replaced(self):
        old = self.ws.scan_dir / "bomlens"
        old.mkdir()
        (old / "marker").write_text("x")
        seen = []
        self.backend.remove_leftovers = lambda label: seen.append((old / "marker").exists())
        self.scan()
        self.assertEqual(seen, [True])
        self.assertFalse((old / "marker").exists())

    def test_claim_names(self):
        from bomlens_runner.policy import Volume
        for bad in ("a/b", "PVC", ""):
            with self.assertRaises(PolicyError):
                Volume(bad, self.ws.root)


class Helpers(unittest.TestCase):
    def test_loopback_matrix(self):
        for value in ("http://localhost:3128", "a.localhost", "127.0.0.1", "http://127.1:8080", "2130706433",
                      "0x7f000001", "0177.0.0.1", "[::1]:3128", "http://[::ffff:127.0.0.1]:1", "0.0.0.0", "localhost."):
            self.assertTrue(is_loopback_proxy(value), value)
        for value in ("http://proxy.corp:3128", "10.0.0.1:3128", "http://[2001:db8::1]:1"):
            self.assertFalse(is_loopback_proxy(value), value)


if __name__ == "__main__":
    unittest.main()
