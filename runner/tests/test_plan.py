# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
"""The execution plan reader (plan.py): what it accepts, drops and refuses."""

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

from _support import FIXTURES

from bomlens_runner.errors import ImageNotAllowed, PlanRejected
from bomlens_runner.plan import (CALLER_ROLES, MOUNT_ROLES, PROVIDED_ROLES, STAGE_ENV_ALLOWED,
                                 STAGE_PASSTHROUGH_ALLOWED, load_plan, parse_plan)

SCHEMA = Path(__file__).resolve().parents[2] / "schemas" / "engine-plan-1.json"


def fixture(name="node-ok"):
    return json.loads((FIXTURES / name / "bomlens-plan.json").read_text())


def stage(doc, n):
    return doc["stages"][n - 1]


def mount(doc, n, role):
    return next(m for m in stage(doc, n)["mounts"] if m["role"] == role)


class CapturedPlans(unittest.TestCase):
    def test_captured_plans_parse(self):
        plan = parse_plan(fixture())
        self.assertTrue(plan.supported)
        self.assertEqual([s.id for s in plan.stages], ["generate", "postprocess"])
        self.assertTrue(plan.stage(1).image_digest.startswith("sha256:"))
        self.assertEqual(plan.dropped_env, ())

    def test_unsupported_plan_has_no_stages(self):
        plan = parse_plan(fixture("android-unsupported"))
        self.assertFalse(plan.supported)
        self.assertEqual(plan.reason, "android-sdk-image")
        self.assertEqual(plan.stages, ())

    def test_vocabulary_equals_published_schema(self):
        schema = json.loads(SCHEMA.read_text())
        roles = schema["properties"]["stages"]["items"]["properties"]["mounts"]["items"]["properties"]["role"]["enum"]
        self.assertEqual(sorted(roles), sorted(MOUNT_ROLES))
        self.assertEqual(PROVIDED_ROLES | CALLER_ROLES, frozenset(MOUNT_ROLES))

    def test_captured_env_names_are_on_the_allowlist(self):
        doc = fixture()
        for n in (1, 2):
            self.assertLessEqual(set(stage(doc, n)["env"]), STAGE_ENV_ALLOWED[n])
            self.assertLessEqual(set(stage(doc, n)["env_passthrough"]), STAGE_PASSTHROUGH_ALLOWED[n])

    def test_go_cache_env_is_kept(self):
        env = parse_plan(fixture()).stage(1).env
        self.assertEqual(env["GOMODCACHE"], "/tmp/sbomhome/go/pkg/mod")


class Rejected(unittest.TestCase):
    def refuse(self, change, exc=PlanRejected):
        doc = copy.deepcopy(fixture())
        change(doc)
        with self.assertRaises(exc):
            parse_plan(doc)

    def test_host_path_on_a_folder_mount(self):
        self.refuse(lambda d: mount(d, 1, "source").update(source="/etc"))

    def test_plan_file_outside_bomlens_plan(self):
        for bad in ("../x.sh", "/tmp/x.sh", "bomlens-plan/../../x.sh"):
            self.refuse(lambda d, bad=bad: mount(d, 1, "plan-file").update(source=bad))

    def test_system_and_docker_sock_targets(self):
        for bad in ("/etc", "/usr/local/x", "/var/run/docker.sock", "/run/x", "/", "/a/../etc"):
            self.refuse(lambda d, bad=bad: mount(d, 1, "cache-maven").update(target=bad))

    def test_unknown_role(self):
        self.refuse(lambda d: stage(d, 1)["mounts"].append({"role": "docker", "target": "/d", "mode": "ro",
                                                              "optional": True}))

    def test_writable_stage2_source(self):
        self.refuse(lambda d: mount(d, 2, "source").update(mode="rw"))

    def test_writable_plan_file(self):
        self.refuse(lambda d: mount(d, 1, "plan-file").update(mode="rw"))

    def test_required_cache(self):
        self.refuse(lambda d: mount(d, 1, "cache-maven").update(optional=False))

    def test_guard_state_in_stage2(self):
        self.refuse(lambda d: stage(d, 2)["mounts"].append({"role": "guard-state", "target": "/g", "mode": "rw"}))

    def test_nested_folders(self):
        self.refuse(lambda d: mount(d, 1, "guard-state").update(target="/app/state"))

    def test_unpinned_latest_or_malformed_images(self):
        self.refuse(lambda d: stage(d, 1).update(image_digest=None), ImageNotAllowed)
        self.refuse(lambda d: stage(d, 1).update(image="ghcr.io/cdxgen/x:latest"), ImageNotAllowed)
        self.refuse(lambda d: stage(d, 1).update(image="GHCR.io/CDXGEN/X Y"), ImageNotAllowed)
        self.refuse(lambda d: stage(d, 1).update(image_digest="sha256:abc"), ImageNotAllowed)

    def test_non_numeric_user(self):
        for bad in ("root", "0:0\n", "1000:abc"):
            self.refuse(lambda d, bad=bad: stage(d, 1).update(user=bad))

    def test_non_shell_entrypoint(self):
        self.refuse(lambda d: stage(d, 1).update(entrypoint=["/usr/bin/python3"]))
        self.refuse(lambda d: stage(d, 1).update(entrypoint=["sh", "-c"]))

    def test_bad_output_file(self):
        for bad in ("../x_bom.json", "x.json", "demo_bom.json\n"):
            self.refuse(lambda d, bad=bad: d.update(output_file=bad))

    def test_bad_workdir(self):
        self.refuse(lambda d: stage(d, 2).update(workdir="/etc"))
        self.refuse(lambda d: stage(d, 2).pop("workdir"))

    def test_changed_stage2_required_values(self):
        self.refuse(lambda d: stage(d, 2)["env"].update(MODE="SOURCE"))
        self.refuse(lambda d: stage(d, 2)["env"].update(UPLOAD_ENABLED="true"))
        self.refuse(lambda d: stage(d, 2)["env"].update(BOMLENS_RUN_INPUT="other_bom.json"))

    def test_non_plain_env_values(self):
        self.refuse(lambda d: stage(d, 1)["env"].update(HOME="/tmp\nX=1"))
        self.refuse(lambda d: stage(d, 1)["env"].update(HOME=1))
        self.refuse(lambda d: stage(d, 1)["env"].update({"bad name": "x"}))

    def test_later_major_version(self):
        self.refuse(lambda d: d["contract"].update(version="2.0.0"))
        self.refuse(lambda d: d["contract"].update(name="other"))

    def test_unsupported_plan_with_stages(self):
        def change(d):
            d.update(status="unsupported", reason="android-sdk-image")
        self.refuse(change)

    def test_stage_order_and_bool_stage(self):
        self.refuse(lambda d: d["stages"].reverse())
        self.refuse(lambda d: stage(d, 1).update(stage=True))

    def test_trivy_role_only_read_only_at_trivy_db(self):
        self.refuse(lambda d: mount(d, 2, "trivy-db").update(mode="rw"))
        self.refuse(lambda d: mount(d, 2, "trivy-db").update(target="/db"))
        self.refuse(lambda d: mount(d, 2, "output").update(target="/trivy-db/x"))

    def test_settings_roles_required_or_in_stage2(self):
        self.refuse(lambda d: mount(d, 1, "maven-settings").update(optional=False))
        self.refuse(lambda d: stage(d, 2)["mounts"].append(
            {"role": "maven-settings", "target": "/s.xml", "mode": "ro", "optional": True}))

    def test_placement_under_tmp(self):
        # Not at /tmp itself, and a provided role may not sit under it.
        self.refuse(lambda d: mount(d, 1, "cache-maven").update(target="/tmp"))
        self.refuse(lambda d: mount(d, 1, "output").update(target="/tmp/out"))
        doc = copy.deepcopy(fixture())
        mount(doc, 1, "cache-maven").update(target="/tmp/sbomhome/.m2")
        parse_plan(doc)


class ReviewFindings(unittest.TestCase):
    def refuse(self, change):
        doc = copy.deepcopy(fixture())
        change(doc)
        with self.assertRaises(PlanRejected):
            parse_plan(doc)

    def test_doubled_slash_targets(self):
        self.refuse(lambda d: mount(d, 2, "source").update(target="//usr/local/lib/sbom"))
        self.refuse(lambda d: mount(d, 1, "output").update(target="//tmp/out"))
        self.refuse(lambda d: mount(d, 1, "guard-state").update(target="//app/x"))
        self.refuse(lambda d: mount(d, 1, "guard-state").update(target="/state//x"))

    def test_settings_roles_are_read_only(self):
        for role in ("maven-settings", "gradle-init-script", "gradle-init"):
            self.refuse(lambda d, role=role: mount(d, 1, role).update(mode="rw"))

    def test_uid_over_int32(self):
        self.refuse(lambda d: stage(d, 1).update(user="9999999999"))
        self.refuse(lambda d: stage(d, 1).update(user="0:4294967296"))

    def test_wrong_types_are_plan_rejected(self):
        self.refuse(lambda d: stage(d, 1).update(entrypoint=[["sh"]]))
        self.refuse(lambda d: stage(d, 2).update(workdir=["/host-output"]))

    def test_ecosystem_with_control_characters(self):
        doc = copy.deepcopy(fixture())
        doc["input"]["detected_ecosystem"] = "node\x1b[31m"
        self.assertEqual(parse_plan(doc).detected_ecosystem, "unknown")


class Dropped(unittest.TestCase):
    def test_off_list_env_and_passthrough_names_are_dropped(self):
        doc = copy.deepcopy(fixture())
        stage(doc, 1)["env"]["LD_PRELOAD"] = "/x.so"
        stage(doc, 1)["env_passthrough"].append("AWS_SECRET_ACCESS_KEY")
        plan = parse_plan(doc)
        self.assertNotIn("LD_PRELOAD", plan.stage(1).env)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", plan.stage(1).env_passthrough)
        self.assertEqual(set(plan.dropped_env), {"LD_PRELOAD", "AWS_SECRET_ACCESS_KEY"})

    def test_fields_the_plan_cannot_ask_for_are_never_read(self):
        doc = copy.deepcopy(fixture())
        stage(doc, 1).update(privileged=True, devices=["/dev/kvm"], cap_add=["SYS_ADMIN"],
                             network={"required": True, "name": "host"})
        plan = parse_plan(doc)
        self.assertFalse(hasattr(plan.stage(1), "privileged"))
        self.assertTrue(plan.stage(1).network_required)


class Loading(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_plan_that_is_a_symbolic_link(self):
        (self.dir / "real.json").write_text(json.dumps(fixture()))
        os.symlink(self.dir / "real.json", self.dir / "bomlens-plan.json")
        with self.assertRaises(PlanRejected):
            load_plan(self.dir)

    def test_oversized_plan(self):
        (self.dir / "bomlens-plan.json").write_text(" " * (256 * 1024 + 1))
        with self.assertRaises(PlanRejected):
            load_plan(self.dir)

    def test_missing_and_invalid_plan(self):
        with self.assertRaises(PlanRejected):
            load_plan(self.dir)
        (self.dir / "bomlens-plan.json").write_text("[" * 100000)
        with self.assertRaises(PlanRejected):
            load_plan(self.dir)


if __name__ == "__main__":
    unittest.main()
