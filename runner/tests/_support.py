# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
"""Test doubles: a backend that plays the engine's containers."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from bomlens_runner import backend as b  # noqa: E402
from bomlens_runner.policy import Images, RunnerPolicy, Volume  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"
ENGINE = "ghcr.io/sktelecom/bomlens:1.15.0@sha256:563fb0be1b188bbd550f504fcd77b3f2f062637d25104c3f9ac99bcfd61f2a51"
DEEP_LICENSE = "ghcr.io/sktelecom/bomlens-deep-license:1.15.0@sha256:" + "d" * 64
DEEP_CVE = "ghcr.io/sktelecom/bomlens-deep-cve:1.15.0@sha256:" + "c" * 64


def manifest(status="succeeded", exit_code=0, outputs=(), steps=None, version="1.4.0"):
    return {
        "contract": {"name": "bomlens-engine", "version": version},
        "engine": {"version": "1.15.0", "image": None, "image_digest": None},
        "input": {"kind": "source", "mode": "POSTPROCESS", "target": None},
        "run": {"status": status, "reason": None, "started_at": "2026-11-16T00:00:00Z",
                "ended_at": "2026-11-16T00:01:00Z", "exit_code": exit_code},
        "steps": steps if steps is not None else [
            {"id": "generate", "status": "ok", "reason": None, "stage": 1,
             "started_at": "2026-11-16T00:00:00Z", "ended_at": "2026-11-16T00:00:10Z"}],
        "tools": {}, "engines": ["trivy"], "data_sources": {},
        "outputs": list(outputs),
    }


def write_output(folder: Path, name: str, document: dict, role: str) -> dict:
    data = json.dumps(document).encode()
    (folder / name).write_bytes(data)
    return {"role": role, "path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


class FakeBackend:
    """Plays each container by its component, and records every spec."""

    reset_ownership = True

    def __init__(self, root: Path, plan_fixture: str = "node-ok", plan_override=None):
        self.root = Path(root)
        self.specs: list[b.ContainerSpec] = []
        self.outcomes: dict[str, b.ContainerOutcome] = {}
        self.plan_fixture = plan_fixture
        self.plan_override = plan_override
        self.write_manifest = True
        self.logs: dict[str, list[str]] = {}
        self.leftovers: list[str] = []
        self.preflights = 0
        self.cancel_on: str | None = None
        self.raise_on: dict[str, Exception] = {}

    def preflight(self):
        self.preflights += 1

    def remove_leftovers(self, scan_label):
        self.leftovers.append(scan_label)

    def local(self, spec: b.ContainerSpec, target: str) -> Path:
        m = next(m for m in spec.mounts if m.target == target)
        return self.root / m.subpath

    def run(self, spec, on_line, cancelled):
        self.specs.append(spec)
        if spec.component in self.raise_on:
            raise self.raise_on[spec.component]
        for line in self.logs.get(spec.component, []):
            on_line(line)
        if self.cancel_on == spec.component:
            return b.ContainerOutcome(started=True, cancelled=True)
        outcome = copy.copy(self.outcomes.get(spec.component, b.ContainerOutcome(started=True, exit_code=0)))
        if spec.component == "engine-plan" and outcome.exit_code in (0, 3):
            dst = self.local(spec, "/host-output")
            src = FIXTURES / self.plan_fixture
            doc = json.loads((src / "bomlens-plan.json").read_text())
            if self.plan_override:
                doc = self.plan_override(doc)
            (dst / "bomlens-plan.json").write_text(json.dumps(doc))
            if (src / "bomlens-plan").is_dir():
                shutil.copytree(src / "bomlens-plan", dst / "bomlens-plan")
        if spec.component == "engine-stage1" and outcome.exit_code == 0:
            out = self.local(spec, "/out")
            (out / "demo_1.0_bom.json").write_text('{"bomFormat":"CycloneDX"}')
        if spec.component in ("engine-stage2", "engine-image") and self.write_manifest:
            out = self.local(spec, "/host-output")
            outputs = [write_output(out, "demo_1.0_bom.json", {"bomFormat": "CycloneDX"}, "sbom.cyclonedx")]
            (out / "bomlens-result.json").write_text(json.dumps(manifest(outputs=outputs)))
        return outcome

    def spec(self, component) -> b.ContainerSpec:
        return next(s for s in self.specs if s.component == component)

    @property
    def components(self):
        return [s.component for s in self.specs]


class Workspace:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve() / "ws"
        self.root.mkdir()
        self.scan_dir = self.root / "scan1"
        self.scan_dir.mkdir()
        self.source = self.scan_dir / "src"
        self.source.mkdir()
        (self.source / "package.json").write_text('{"name":"x"}')
        self.trivy = Path(self.tmp.name).resolve() / "trivy"
        (self.trivy / "db").mkdir(parents=True)

    def cleanup(self):
        self.tmp.cleanup()

    def policy(self, **kw) -> RunnerPolicy:
        args = dict(images=Images.parse(ENGINE, DEEP_LICENSE, DEEP_CVE), workspace=Volume("pvc-workspace", self.root),
                    trivy_db=Volume("pvc-trivy", self.trivy), uid=1000, gid=1000)
        args.update(kw)
        return RunnerPolicy(**args)
