# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Reading and checking the execution plan (bomlens-plan.json).

The plan is written by the engine image, and the runner treats it as
untrusted input: it may only choose from what is listed here. Host paths,
networks, privileges and devices are never read from it. Names that a later
1.x engine adds are dropped (env) or refused when they would need a host
resource (a required mount role), so a newer image cannot widen what the
runner gives a container.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from .errors import PlanRejected
from .images import check_image

PLAN_FILE = "bomlens-plan.json"
PLAN_FILES_DIR = "bomlens-plan"
MAX_PLAN_BYTES = 256 * 1024
CONTRACT_NAME = "bomlens-engine-plan"
SUPPORTED_MAJOR = 1

PLAN_STATUSES = ("ok", "unsupported")
PLAN_REASONS = ("android-sdk-image", "no-pinned-digest")
STAGE_ORDER = (("generate", 1), ("postprocess", 2))

MOUNT_ROLES = (
    "source", "output", "plan-file", "guard-state", "cache-maven", "cache-gradle", "trivy-db",
    "maven-settings", "maven-settings-security", "maven-repository", "gradle-properties",
    "gradle-init-script", "gradle-init-script-kts", "gradle-init",
    "gradle-cache", "gradle-wrapper",
)
# The user's own files and folders, given read-only. maven-repository is the
# user's Maven local repository, which stage 1 only reads.
SETTINGS_ROLES = (
    "maven-settings", "maven-settings-security", "maven-repository", "gradle-properties",
    "gradle-init-script", "gradle-init-script-kts", "gradle-init",
)
# The user's own caches, read-only: the Gradle dependency cache (the folder
# that holds modules-2) and the Gradle wrapper's distributions.
GRADLE_USER_CACHE_ROLES = ("gradle-cache", "gradle-wrapper")
STAGE_ROLES = {
    1: frozenset(("source", "output", "plan-file", "guard-state", "cache-maven", "cache-gradle") + SETTINGS_ROLES
                 + GRADLE_USER_CACHE_ROLES),
    2: frozenset(("source", "output", "trivy-db")),
}
# Roles the runner itself provides. Any other role is the caller's to give
# (caches, settings files): it must be optional in the plan, and the runner
# mounts it only when the caller's policy names a folder or file for it.
PROVIDED_ROLES = frozenset(("source", "output", "plan-file", "guard-state", "trivy-db"))
CALLER_ROLES = frozenset(MOUNT_ROLES) - PROVIDED_ROLES

SYSTEM_TARGETS = (
    "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/proc", "/run", "/sbin",
    "/sys", "/usr", "/var",
)
RESERVED_TARGETS = ("/tmp", "/trivy-db")

_BUILD_PREP = (
    "BOMLENS_KEEP_BUILD_OUTPUT", "BOMLENS_MAVEN_FULL_GRAPH", "BOMLENS_ANDROID_FULL_GRAPH",
    "BOMLENS_GRADLE_FULL_GRAPH", "BOMLENS_GRADLE_USER_CACHE", "BOMLENS_NODE_FULL_GRAPH", "BOMLENS_PHP_FULL_GRAPH",
    "BOMLENS_NODE_INSTALLED_LOCK",
    "BOMLENS_INCLUDE_NON_SHIPPED", "BOMLENS_INCLUDE_DEV_DEPENDENCIES", "BOMLENS_NO_COPYRIGHT",
    "BOMLENS_NO_CARGO_LICENSE", "BOMLENS_NO_AI_USAGE", "BOMLENS_AI_USAGE_TIMEOUT", "BOMLENS_PREP_TIMEOUT", "BOMLENS_BUILD_TOOL",
    "BOMLENS_LICENSE_PROBE_TIMEOUT", "BOMLENS_LICENSE_FETCH_TIMEOUT",
    "BOMLENS_MAVEN_USER_REPOSITORY", "BOMLENS_MAVEN_PROBE_TIMEOUT", "BOMLENS_PYTHON_VENV",
)
PROXY_ENV_NAMES = ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy")
EXTRA_CA_ENV_NAMES = ("BOMLENS_EXTRA_CA_CERTS",)
_STAGE2_NETWORK = PROXY_ENV_NAMES + EXTRA_CA_ENV_NAMES + (
    "TRIVY_DB_REPOSITORY", "TRIVY_JAVA_DB_REPOSITORY", "TRIVY_SKIP_DB_UPDATE", "TRIVY_SKIP_JAVA_DB_UPDATE",
    "TRIVY_OFFLINE_SCAN", "TRIVY_USERNAME", "TRIVY_PASSWORD", "TRIVY_REGISTRY_TOKEN", "TRIVY_INSECURE",
    "BOMLENS_TRIVY_DB_MAX_AGE_DAYS", "BOMLENS_GRYPE_DB_MAX_AGE_DAYS", "GRYPE_DB_UPDATE_URL",
    "BOMLENS_GO_VULNDB", "BOMLENS_GO_VULNDB_PATH", "BOMLENS_GO_VULNDB_MAX_AGE_DAYS", "BOMLENS_GO_VULNDB_URL",
    "KEV_URL", "EPSS_API", "COCOAPODS_CDN_URL", "COCOAPODS_LICENSE_BUDGET",
)

# The fixed values each stage's env may hold, and the names it may ask the
# caller for. These are what docker/lib/make-plan.sh writes; the runner's
# drift test checks a plan from the image against them.
STAGE_ENV_ALLOWED = {
    1: frozenset((
        "HOME", "MAVEN_OPTS", "GOPATH", "GOMODCACHE", "GOCACHE", "FETCH_LICENSE",
        "PROJECT_NAME", "PROJECT_VERSION", "HOST_GOTOOLCHAIN",
    )),
    2: frozenset((
        "MODE", "SECURITY_ENRICH", "BOMLENS_RUN_INPUT", "HOST_OUTPUT_DIR", "PROJECT_NAME",
        "PROJECT_VERSION", "CYCLONEDX_SPEC_VERSION", "FETCH_LICENSE", "UPLOAD_ENABLED",
    )),
}
STAGE_PASSTHROUGH_ALLOWED = {
    1: frozenset(_BUILD_PREP + PROXY_ENV_NAMES + EXTRA_CA_ENV_NAMES + ("GOPROXY", "GOSUMDB", "HOST_UID", "HOST_GID")),
    2: frozenset(("HOST_UID", "HOST_GID", "SRC_TREE_EXCLUDE", "NVD_API_KEY") + _BUILD_PREP + _STAGE2_NETWORK),
}

# Package registry settings a caller gives stage 1 to point its resolvers at a
# mirror. They are not in the execution plan (the plan lists the names the
# image knows), so the runner passes them on its own: a name here is taken
# from the policy's stage1_env whatever the plan's env_passthrough says.
REGISTRY_ENV_NAMES = frozenset((
    "NPM_CONFIG_REGISTRY", "npm_config_registry", "YARN_NPM_REGISTRY_SERVER",
    "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_TRUSTED_HOST", "UV_INDEX_URL", "UV_DEFAULT_INDEX",
    "CARGO_REGISTRY_DEFAULT", "BUNDLE_MIRROR__RUBYGEMS__ORG",
    "GONOSUMDB", "GOPRIVATE", "GONOPROXY", "GOINSECURE",
))
_CARGO_REGISTRY_RE = re.compile(r"CARGO_REGISTRIES_[A-Z0-9_]{1,48}_(INDEX|PROTOCOL)")


def is_registry_env(name: str) -> bool:
    return name in REGISTRY_ENV_NAMES or _CARGO_REGISTRY_RE.fullmatch(name) is not None


_NAME_RE = re.compile(r"[A-Z_][A-Z0-9_]{0,63}")
_OUTPUT_FILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,200}_bom\.json")
_USER_RE = re.compile(r"[0-9]{1,10}(?::[0-9]{1,10})?")
_TARGET_RE = re.compile(r"/[A-Za-z0-9._/-]{1,200}")
_PLAN_FILE_RE = re.compile(rf"{PLAN_FILES_DIR}/[A-Za-z0-9][A-Za-z0-9._-]{{0,99}}")
SHELLS = frozenset(("sh", "/bin/sh", "bash", "/bin/bash"))
MAX_ARGS = 64
MAX_MOUNTS = 32
MAX_VALUE = 4096


@dataclass(frozen=True)
class Mount:
    role: str
    target: str
    read_only: bool
    optional: bool = False
    source: str | None = None  # plan-file only: a path under bomlens-plan/


@dataclass(frozen=True)
class Stage:
    id: str
    stage: int
    image: str
    image_digest: str
    user: str | None
    entrypoint: tuple[str, ...] | None
    args: tuple[str, ...]
    workdir: str | None
    mounts: tuple[Mount, ...]
    env: dict[str, str]
    env_passthrough: tuple[str, ...]
    network_required: bool

    def mount(self, role: str) -> Mount | None:
        return next((m for m in self.mounts if m.role == role), None)


@dataclass(frozen=True)
class Plan:
    contract_version: str
    status: str
    reason: str | None
    detected_ecosystem: str
    output_file: str
    stages: tuple[Stage, ...]
    dropped_env: tuple[str, ...] = field(default=())

    @property
    def supported(self) -> bool:
        return self.status == "ok"

    def stage(self, number: int) -> Stage:
        return next(s for s in self.stages if s.stage == number)


def contract_major(version: object) -> int:
    if not isinstance(version, str):
        raise PlanRejected("contract version is not a string")
    core = version.split("+", 1)[0].split("-", 1)[0]
    parts = core.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise PlanRejected("contract version is not MAJOR.MINOR.PATCH")
    return int(parts[0])


def _plain(value: object, what: str) -> str:
    if not isinstance(value, str) or len(value) > MAX_VALUE or any(c in value for c in "\0\n\r"):
        raise PlanRejected(f"{what} is not a plain string")
    return value


def _obj(value: object, what: str) -> dict:
    if not isinstance(value, dict):
        raise PlanRejected(f"{what} is not an object")
    return value


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def _parse_mount(raw: object, stage: int) -> Mount:
    raw = _obj(raw, "mount")
    role = raw.get("role")
    if role not in MOUNT_ROLES:
        raise PlanRejected("mount role is not known")
    if role not in STAGE_ROLES[stage]:
        raise PlanRejected(f"mount role {role} is not allowed in stage {stage}")
    target = raw.get("target")
    # "//etc" is its own normal form in POSIX, but the runtime mounts it at
    # /etc: a doubled slash anywhere is refused.
    if (not isinstance(target, str) or not _TARGET_RE.fullmatch(target) or "//" in target
            or posixpath.normpath(target) != target or target == "/" or ".." in target.split("/")
            or "docker.sock" in target):
        raise PlanRejected("mount target is not allowed")
    if any(_under(target, t) for t in SYSTEM_TARGETS):
        raise PlanRejected("mount target is a system folder")
    if _under(target, "/trivy-db"):
        if not (role == "trivy-db" and target == "/trivy-db"):
            raise PlanRejected("mount target /trivy-db is reserved")
    elif role == "trivy-db":
        raise PlanRejected("trivy-db must be mounted at /trivy-db")
    if _under(target, "/tmp"):
        under_ok = target != "/tmp" and ((role == "plan-file" and stage == 1) or role in CALLER_ROLES)
        if not under_ok:
            raise PlanRejected("mount target /tmp is reserved")
    mode = raw.get("mode")
    if mode not in ("ro", "rw"):
        raise PlanRejected("mount mode is not ro or rw")
    optional = raw.get("optional", False)
    if not isinstance(optional, bool):
        raise PlanRejected("mount optional is not a boolean")
    source = raw.get("source")
    if role == "plan-file":
        if not isinstance(source, str) or not _PLAN_FILE_RE.fullmatch(source):
            raise PlanRejected("plan file is not under bomlens-plan/")
        if mode != "ro":
            raise PlanRejected("plan file must be read-only")
    elif source is not None:
        raise PlanRejected("only a plan file mount may name a source")
    if role == "trivy-db" and mode != "ro":
        raise PlanRejected("trivy-db must be read-only")
    if role in SETTINGS_ROLES and mode != "ro":
        raise PlanRejected(f"{role} must be read-only")
    if role in GRADLE_USER_CACHE_ROLES and mode != "ro":
        raise PlanRejected(f"{role} must be read-only")
    if role == "source" and stage == 2 and mode != "ro":
        raise PlanRejected("stage 2 source must be read-only")
    if role in ("output", "guard-state") and mode != "rw":
        raise PlanRejected(f"{role} must be writable")
    if role not in PROVIDED_ROLES and not optional:
        raise PlanRejected(f"mount role {role} must be optional")
    return Mount(role, target, mode == "ro", optional, source)


def _check_mounts(mounts: list[Mount]) -> None:
    targets = [m.target for m in mounts]
    if len(set(targets)) != len(targets):
        raise PlanRejected("two mounts share a target")
    for role, limit in (("source", 1), ("output", 1)):
        if sum(m.role == role for m in mounts) != limit:
            raise PlanRejected(f"stage needs exactly one {role} mount")
    if sum(m.role == "guard-state" for m in mounts) > 1:
        raise PlanRejected("stage has more than one guard-state mount")
    folders = [m for m in mounts if m.role != "plan-file"]
    for a in folders:
        for b in folders:
            if a is not b and a.target.startswith(b.target + "/"):
                raise PlanRejected("a mount sits inside another mount")


def _parse_stage(raw: object, index: int, output_file: str, dropped: list[str]) -> Stage:
    raw = _obj(raw, "stage")
    sid, number = raw.get("id"), raw.get("stage")
    if isinstance(number, bool) or (sid, number) != STAGE_ORDER[index]:
        raise PlanRejected("stages are not generate then postprocess")
    if "image" not in raw or "image_digest" not in raw:
        raise PlanRejected("stage has no image")
    image, digest = raw.get("image"), raw.get("image_digest")
    if number == 1:
        check_image(image, digest)
    user = raw.get("user")
    if user is not None and (not isinstance(user, str) or not _USER_RE.fullmatch(user)
                             or any(int(p) > 2 ** 31 - 1 for p in user.split(":"))):
        raise PlanRejected("stage user is not a numeric uid[:gid]")
    entrypoint = raw.get("entrypoint")
    if entrypoint is not None:
        if (not isinstance(entrypoint, list) or len(entrypoint) != 1 or not isinstance(entrypoint[0], str)
                or entrypoint[0] not in SHELLS):
            raise PlanRejected("stage entrypoint is not a shell")
        entrypoint = tuple(entrypoint)
    args = raw.get("args")
    if not isinstance(args, list) or len(args) > MAX_ARGS:
        raise PlanRejected("stage args is not a short list")
    args = tuple(_plain(a, "stage argument") for a in args)
    mounts_raw = raw.get("mounts")
    if not isinstance(mounts_raw, list) or len(mounts_raw) > MAX_MOUNTS:
        raise PlanRejected("stage mounts is not a short list")
    mounts = [_parse_mount(m, number) for m in mounts_raw]
    _check_mounts(mounts)
    if "workdir" not in raw:
        raise PlanRejected("stage has no workdir")
    workdir = raw.get("workdir")
    if workdir is not None and not isinstance(workdir, str):
        raise PlanRejected("stage workdir is not a path")
    if workdir is not None and workdir not in {m.target for m in mounts if m.role in ("source", "output")}:
        raise PlanRejected("stage workdir is not its source or output mount")
    env_raw = _obj(raw.get("env"), "stage env")
    env: dict[str, str] = {}
    for name, value in env_raw.items():
        if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
            raise PlanRejected("stage env name is not valid")
        value = _plain(value, "stage env value")
        if name in STAGE_ENV_ALLOWED[number]:
            env[name] = value
        else:
            dropped.append(name)
    passthrough_raw = raw.get("env_passthrough", [])
    if not isinstance(passthrough_raw, list) or not all(isinstance(n, str) for n in passthrough_raw):
        raise PlanRejected("stage env_passthrough is not a list of names")
    passthrough = []
    for name in passthrough_raw:
        if name in STAGE_PASSTHROUGH_ALLOWED[number]:
            if name not in passthrough:
                passthrough.append(name)
        else:
            dropped.append(name)
    network = raw.get("network")
    required = False
    if network is not None:
        required = _obj(network, "stage network").get("required", False)
        if not isinstance(required, bool):
            raise PlanRejected("stage network.required is not a boolean")
    if number == 2:
        out = next(m.target for m in mounts if m.role == "output")
        expected = {"MODE": "POSTPROCESS", "BOMLENS_RUN_INPUT": output_file, "HOST_OUTPUT_DIR": out,
                    "UPLOAD_ENABLED": "false"}
        if any(env.get(k) != v for k, v in expected.items()):
            raise PlanRejected("stage 2 env does not hold its required values")
    return Stage(sid, number, image, digest, user, entrypoint, args, workdir, tuple(mounts), env,
                 tuple(passthrough), required)


def parse_plan(data: object) -> Plan:
    data = _obj(data, "plan")
    contract = _obj(data.get("contract"), "contract")
    if contract.get("name") != CONTRACT_NAME:
        raise PlanRejected("contract name is not bomlens-engine-plan")
    version = contract.get("version")
    if contract_major(version) != SUPPORTED_MAJOR:
        raise PlanRejected("contract major version is not supported")
    _obj(data.get("engine"), "engine")
    inp = _obj(data.get("input"), "input")
    if inp.get("kind") != "source" or not isinstance(inp.get("detected_ecosystem"), str):
        raise PlanRejected("plan input is not a source")
    status = data.get("status")
    if status not in PLAN_STATUSES:
        raise PlanRejected("plan status is not known")
    for key in ("reason", "detail"):
        if key not in data or not (data[key] is None or isinstance(data[key], str)):
            raise PlanRejected(f"plan {key} is missing")
    reason = data["reason"]
    if reason is not None:
        reason = _plain(reason, "plan reason")[:64]
    output_file = data.get("output_file")
    if not isinstance(output_file, str) or not _OUTPUT_FILE_RE.fullmatch(output_file):
        raise PlanRejected("plan output_file is not a BomLens SBOM name")
    stages_raw = data.get("stages")
    if not isinstance(stages_raw, list):
        raise PlanRejected("plan stages is not a list")
    dropped: list[str] = []
    if status == "unsupported":
        if stages_raw:
            raise PlanRejected("unsupported plan has stages")
        stages: tuple[Stage, ...] = ()
    else:
        if reason is not None:
            raise PlanRejected("supported plan has a reason")
        if len(stages_raw) != len(STAGE_ORDER):
            raise PlanRejected("plan does not have two stages")
        stages = tuple(_parse_stage(s, i, output_file, dropped) for i, s in enumerate(stages_raw))
    ecosystem = inp["detected_ecosystem"][:64]
    if not re.fullmatch(r"[A-Za-z0-9._+-]*", ecosystem):
        ecosystem = "unknown"
    return Plan(version, status, reason, ecosystem, output_file, stages,
                tuple(dict.fromkeys(dropped)))


def load_plan(plan_dir: Path) -> Plan:
    path = Path(plan_dir) / PLAN_FILE
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise PlanRejected("the engine wrote no execution plan") from None
    if not stat.S_ISREG(st.st_mode):
        raise PlanRejected("the execution plan is not a regular file")
    if st.st_size > MAX_PLAN_BYTES:
        raise PlanRejected("the execution plan is too large")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as fh:
            raw = fh.read(MAX_PLAN_BYTES + 1)
    except OSError:
        raise PlanRejected("the execution plan cannot be read") from None
    if len(raw) > MAX_PLAN_BYTES:
        raise PlanRejected("the execution plan is too large")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise PlanRejected("the execution plan is not JSON") from None
    return parse_plan(data)
