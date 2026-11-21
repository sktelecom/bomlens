# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""bomlens-runner: run one scan on Kubernetes from a JSON policy file.

    bomlens-runner source --policy policy.json --scan-id s1 --scan-dir /ws/s1 \
        --source /ws/s1/src --project app --version 1.0
    bomlens-runner image --policy policy.json --scan-id s2 --scan-dir /ws/s2 \
        --target alpine:3.20 --project alpine --version 3.20

The policy file is the RunnerPolicy and the backend options as JSON (see
docs/reference/engine-runner.md). With a "docker" object the scan runs on
the Docker daemon DOCKER_HOST names; otherwise on Kubernetes, through the
in-cluster API unless --api names another (for example a kubectl proxy at
http://127.0.0.1:8001). On Docker, a SecretRef {"name": n, "key": k} is
read from the runner's environment variable BOMLENS_SECRET_<N>_<K> (upper
case, other characters as "_"); those variables never reach a docker child
process.
The output folder and run status are printed as JSON; the exit code is 0 for
a run that succeeded or succeeded degraded, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import sys
import threading
from pathlib import Path

from . import _release
from .errors import BomLensError, PolicyError
from .docker import SECRET_ENV_PREFIX, DockerBackend, DockerOptions
from .kubernetes import KubeApi, KubernetesBackend, KubernetesOptions
from .orchestrator import run_image_scan, run_source_scan
from .policy import Images, Limits, RunnerPolicy, SecretRef, Timeouts, Volume


def _env(raw: dict | None) -> dict:
    out = {}
    for name, value in (raw or {}).items():
        out[name] = SecretRef(**value["secret"]) if isinstance(value, dict) and "secret" in value else value
    return out


def secret_env_name(ref: SecretRef) -> str:
    def part(text: str) -> str:
        return re.sub(r"[^A-Z0-9]", "_", text.upper())
    return f"{SECRET_ENV_PREFIX}{part(ref.name)}_{part(ref.key)}"


def _env_secret(ref: SecretRef) -> str:
    value = os.environ.get(secret_env_name(ref))
    if value is None:
        raise PolicyError(f"no environment value for the secret {ref.name}/{ref.key}")
    return value


def load_policy(path: Path) -> tuple[RunnerPolicy, "KubernetesOptions | DockerOptions"]:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise PolicyError("the policy file cannot be read as JSON") from None
    images = doc.get("images") or {}
    if not images.get("engine") and _release.ENGINE_IMAGE:
        images = {"engine": _release.ENGINE_IMAGE, "deep_license": _release.DEEP_LICENSE_IMAGE or None,
                  "deep_cve": _release.DEEP_CVE_IMAGE or None, **{k: v for k, v in images.items() if v}}
    if not images.get("engine"):
        raise PolicyError("the policy names no engine image")
    ws = doc.get("workspace") or {}
    trivy = doc.get("trivy_db")
    k8s = doc.get("kubernetes") or {}
    policy = RunnerPolicy(
        images=Images.parse(images["engine"], images.get("deep_license"), images.get("deep_cve")),
        workspace=Volume(ws.get("name", ""), Path(ws.get("local_root", "/"))),
        trivy_db=Volume(trivy["name"], Path(trivy.get("local_root", "/"))) if trivy else None,
        trivy_db_subpath=doc.get("trivy_db_subpath", ""),
        stage1_repositories=tuple(doc.get("stage1_repositories", ())),
        stage1_image_prefix=doc.get("stage1_image_prefix"),
        limits=Limits(**doc.get("limits", {})),
        timeouts=Timeouts(**doc.get("timeouts", {})),
        uid=doc.get("uid"), gid=doc.get("gid"),
        read_only_root=doc.get("read_only_root", True),
        stage1_read_only_root=doc.get("stage1_read_only_root", True),
        stage2_network=doc.get("stage2_network", False),
        labels=doc.get("labels", {}),
        stage1_env=_env(doc.get("stage1_env")), stage2_env=_env(doc.get("stage2_env")),
        image_env=_env(doc.get("image_env")),
        extra_ca_file=Path(doc["extra_ca_file"]) if doc.get("extra_ca_file") else None,
        caller_mounts={k: Path(v) for k, v in (doc.get("caller_mounts") or {}).items()},
        deep_license=doc.get("deep_license", False), deep_cve=doc.get("deep_cve", False),
    )
    if "docker" in doc:
        d = dict(doc["docker"] or {})
        d.pop("secrets", None)
        d["refuse_networks"] = tuple(d.get("refuse_networks", ()))
        try:
            return policy, DockerOptions(secrets=_env_secret, **d)
        except TypeError:
            raise PolicyError("the policy's docker object has an option the runner does not know") from None
    k8s.setdefault("workspace_claim", ws.get("name", ""))
    if trivy:
        k8s.setdefault("trivy_db_claim", trivy["name"])
    if "namespace" not in k8s:
        try:
            k8s["namespace"] = KubeApi.in_cluster_namespace()
        except OSError:
            raise PolicyError("the policy names no Kubernetes namespace") from None
    k8s["tolerations"] = tuple(k8s.get("tolerations", ()))
    k8s["image_pull_secrets"] = tuple(k8s.get("image_pull_secrets", ()))
    try:
        return policy, KubernetesOptions(**k8s)
    except TypeError:
        raise PolicyError("the policy's kubernetes object has an option the runner does not know") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bomlens-runner", description=__doc__.split("\n\n")[0])
    parser.add_argument("--version", action="version", version=_release.VERSION)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("source", "image"):
        p = sub.add_parser(name)
        p.add_argument("--policy", required=True, type=Path)
        p.add_argument("--api", help="Kubernetes API address (default: in-cluster)")
        p.add_argument("--token-file", type=Path)
        p.add_argument("--ca-file")
        p.add_argument("--scan-id", required=True)
        p.add_argument("--scan-dir", required=True, type=Path)
        p.add_argument("--project", required=True)
        p.add_argument("--version", dest="project_version", required=True)
        if name == "source":
            p.add_argument("--source", required=True, type=Path)
            p.add_argument("--no-fetch-license", action="store_true")
        else:
            p.add_argument("--target", required=True)
    args = parser.parse_args(argv)

    cancelled = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: cancelled.set())
    signal.signal(signal.SIGINT, lambda *_: cancelled.set())
    try:
        policy, options = load_policy(args.policy)
        if isinstance(options, DockerOptions):
            if args.api or args.token_file or args.ca_file:
                raise PolicyError("--api, --token-file and --ca-file are for Kubernetes; the policy names Docker")
            backend = DockerBackend(options)
        elif args.api:
            token = args.token_file.read_text(encoding="utf-8").strip() if args.token_file else None
            api = KubeApi(args.api, token=token, ca_file=args.ca_file, insecure_http=args.api.startswith("http://"))
            backend = KubernetesBackend(api, options)
        else:
            backend = KubernetesBackend(KubeApi.in_cluster(), options)
        log = lambda stage, line: print(f"[{stage}] {line}", file=sys.stderr, flush=True)  # noqa: E731
        common = dict(scan_id=args.scan_id, project=args.project, version=args.project_version,
                      scan_dir=args.scan_dir, on_log=log, cancel=cancelled.is_set)
        if args.command == "source":
            result = run_source_scan(policy, backend, source=args.source,
                                     fetch_license=not args.no_fetch_license, **common)
        else:
            result = run_image_scan(policy, backend, target=args.target, **common)
    except BomLensError as exc:
        print(json.dumps({"error": type(exc).__name__, "message": str(exc)}))
        return 1
    print(json.dumps({"output_dir": str(result.output_dir), **result.as_metadata()}))
    status = result.manifest.run_status if result.manifest else None
    return 0 if status in ("succeeded", "succeeded_degraded") else 1


if __name__ == "__main__":
    sys.exit(main())
