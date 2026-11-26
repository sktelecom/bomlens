# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Running a scan: the execution plan, stage 1, stage 2, and an image scan.

A source scan runs the containers the engine contract describes
(docs/reference/engine-contract.md, "Execution plan"):

1. MODE=PLAN, which writes bomlens-plan.json and is checked (plan.py).
2. Stage 1, the cdxgen language image the plan names, when the plan is
   supported. When it is killed (time limit, out of memory, cancelled), a
   restore run puts the source tree back.
3. Stage 2, the BomLens image in POSTPROCESS mode, whatever stage 1 did. It
   is told stage 1's exit code, whether it ran out of memory, and its log.
4. An ownership reset, when the backend asks for one.

Every container is removed before the next one starts, and before a function
here returns or raises. Errors never carry a workspace path: a failed file
operation is reported by its kind only.
"""

from __future__ import annotations

import errno
import ipaddress
import os
import re
import shutil
import socket
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from . import backend as b
from .errors import (BomLensError, ContainerStillRunning, EngineError, EngineWroteNoResult, PlanRejected,
                     PolicyError, ScanCancelled, ScanTimedOut)
from .images import _split, check_image, image_target, require_allowed
from .manifest import MANIFEST_NAME, EngineResult, load_manifest
from .plan import (PLAN_FILE, PLAN_FILES_DIR, PROXY_ENV_NAMES, STAGE_PASSTHROUGH_ALLOWED, Plan, Stage,
                   is_registry_env, load_plan)
from .policy import IMAGE_SCAN_NAMES, RUNNER_OWNED, SCAN_OPTION_NAMES, RunnerPolicy

STAGE1_LOG_NAME = "bomlens-stage1.log"
STAGE1_LOG_MAX = 2 * 1024 * 1024
LINE_MAX = 64 * 1024
LOG_BUDGET = 16 * 1024 * 1024
PLAN_FILE_MAX = 4 * 1024 * 1024
TRIVY_DB_TARGET = "/trivy-db"
EXTRA_CA_TARGET = "/bomlens-ca/extra.pem"
EXIT_NOT_RUN = 127

_TRIVY_OFFLINE = {"TRIVY_SKIP_DB_UPDATE": "true", "TRIVY_SKIP_JAVA_DB_UPDATE": "true",
                  "TRIVY_OFFLINE_SCAN": "true", "TRIVY_NO_PROGRESS": "true"}
_SCAN_ID_RE = b.SCAN_ID_RE
_PROJECT_TOKEN_RE = re.compile(r"[^A-Za-z0-9._-]+")
_LEGACY_IPV4_RE = re.compile(r"[0-9a-fA-FxX.]{1,64}")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)

OnLog = Callable[[str, str], None]
OnStage = Callable[[str], None]


# ---------------------------------------------------------------- helpers

def is_loopback_proxy(value: str) -> bool:
    """Whether a proxy address names the loopback interface (the container itself)."""
    text = value.strip()
    if "://" not in text:
        text = "http://" + text
    try:
        host = urlsplit(text).hostname
    except ValueError:
        return False
    host = (host or "").rstrip(".")
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not _LEGACY_IPV4_RE.fullmatch(host):
            return False
        try:
            address = ipaddress.IPv4Address(socket.inet_aton(host))
        except OSError:
            return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_loopback or address.is_unspecified


def project_token(value: str, default: str) -> str:
    """PROJECT_NAME / PROJECT_VERSION reduced to what BomLens names files with."""
    token = _PROJECT_TOKEN_RE.sub("_", value or "").strip("._-")[:100] or default
    return f"{token}-project" if token in ("src", "app") else token


def write_new_file(path: Path, data: bytes) -> None:
    """Write data as a new regular file, never through what a container left there."""
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        mode = None
    if mode is not None:
        if stat.S_ISDIR(mode):
            shutil.rmtree(path)
        else:
            path.unlink()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def read_plan_file(plan_dir: Path, rel: str) -> bytes:
    """A file under plan_dir/bomlens-plan/, opened one component at a time.

    The plan container wrote that folder, so neither the folder nor the file
    may be a link (a link to the worker's own files would be copied into a
    container). rel is "bomlens-plan/<name>", as plan.py allows it.
    """
    folder, name = rel.split("/")
    if folder != PLAN_FILES_DIR:
        raise PlanRejected("a plan file is not under bomlens-plan/")
    base = dfd = fd = -1
    try:
        base = os.open(plan_dir, os.O_RDONLY | _DIRECTORY)
        dfd = os.open(folder, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=base)
        fd = os.open(name, os.O_RDONLY | _NOFOLLOW, dir_fd=dfd)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PlanRejected("a plan file is not a regular file")
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            data = fh.read(PLAN_FILE_MAX + 1)
    except OSError:
        raise PlanRejected("a plan file is missing, or is a link") from None
    finally:
        for f in (fd, dfd, base):
            if f >= 0:
                os.close(f)
    if len(data) > PLAN_FILE_MAX:
        raise PlanRejected("a plan file is too large")
    return data


class _Log:
    """Feeds a container's output to the caller and keeps its last 2 MiB."""

    def __init__(self, on_log: OnLog | None, stage: str):
        self.on_log, self.stage = on_log, stage
        self.sent = 0
        self.tail = bytearray()

    def __call__(self, line: str) -> None:
        data = line.encode("utf-8", "replace")
        self.tail += data + b"\n"
        if len(self.tail) > STAGE1_LOG_MAX:
            del self.tail[: len(self.tail) - STAGE1_LOG_MAX]
        if self.on_log is None or self.sent >= LOG_BUDGET:
            return
        if len(data) > LINE_MAX:
            line = data[:LINE_MAX].decode("utf-8", "ignore")
        self.sent += min(len(data), LINE_MAX) + 1
        try:
            self.on_log(self.stage, line)
        except Exception:  # a caller's logging failure must not stop the scan
            pass


@dataclass
class StageRecord:
    container: str
    image: str
    started_at: str | None = None
    ended_at: str | None = None
    exit_code: int | None = None
    oom_killed: bool = False
    timed_out: bool = False
    cancelled: bool = False
    start_error: str | None = None


@dataclass
class RunResult:
    mode: str
    output_dir: Path
    manifest: EngineResult | None
    plan_status: str | None = None
    plan_reason: str | None = None
    detected_ecosystem: str | None = None
    source_restored: bool | None = None
    stages: dict[str, StageRecord] = field(default_factory=dict)
    dropped_plan_env: tuple[str, ...] = ()

    @property
    def contract_version(self) -> str | None:
        return self.manifest.contract_version if self.manifest else None

    @property
    def timed_out(self) -> bool:
        return any(s.timed_out for s in self.stages.values())

    @property
    def oom_killed(self) -> bool:
        return any(s.oom_killed for s in self.stages.values())

    def as_metadata(self) -> dict:
        return {
            "mode": self.mode,
            "contract_version": self.contract_version,
            "run_status": self.manifest.run_status if self.manifest else None,
            "plan_status": self.plan_status,
            "plan_reason": self.plan_reason,
            "detected_ecosystem": self.detected_ecosystem,
            "source_restored": self.source_restored,
            "stages": {k: vars(v).copy() for k, v in self.stages.items()},
        }


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _never() -> bool:
    return False


# ---------------------------------------------------------------- the runner

class _Scan:
    def __init__(self, policy: RunnerPolicy, backend: b.Backend, scan_id: str, scan_dir: Path,
                 on_log: OnLog | None, cancel: Callable[[], bool] | None):
        if not isinstance(scan_id, str) or not _SCAN_ID_RE.fullmatch(scan_id):
            raise PolicyError("scan id must be 1-32 lower-case letters, digits or '-'")
        self.policy, self.backend, self.scan_id = policy, backend, scan_id
        self.on_log = on_log
        self.cancel = cancel or _never
        self.root = Path(os.path.abspath(policy.workspace.local_root))
        self.scan_dir = self.confined(Path(scan_dir))
        self.engine_dir = self.scan_dir / "bomlens"
        self.count = 0
        # Set when a container could not be made to stop: nothing else may be
        # started on the same files after that.
        self.stuck = False

    def prepare(self) -> None:
        """Make scan_dir/bomlens fresh. Call after the backend removed leftovers."""
        self.fresh(self.engine_dir)

    # Paths ------------------------------------------------------------
    def confined(self, path: Path) -> Path:
        """path, which must sit under the workspace root with no link in it."""
        try:
            rel = Path(os.path.abspath(path)).relative_to(self.root)
        except ValueError:
            raise PolicyError("a scan folder is not in the workspace") from None
        current = self.root
        for part in rel.parts:
            current = current / part
            try:
                st = os.lstat(current)
            except OSError:
                raise PolicyError("a scan folder does not exist") from None
            if stat.S_ISLNK(st.st_mode):
                raise PolicyError("a scan folder contains a symbolic link")
        if not re.fullmatch(r"[A-Za-z0-9._/-]*", rel.as_posix() if rel.parts else ""):
            raise PolicyError("a scan folder path has characters the runner does not mount")
        return current

    def subpath(self, path: Path) -> str:
        rel = self.confined(path).relative_to(self.root)
        return rel.as_posix() if rel.parts else ""

    def fresh(self, path: Path) -> Path:
        try:
            try:
                st = os.lstat(path)
            except FileNotFoundError:
                st = None
            if st is not None:
                if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                    path.unlink()
                else:
                    shutil.rmtree(path)
            path.mkdir(mode=0o775)
        except OSError as exc:
            raise EngineError(f"a scan folder could not be prepared ({errno.errorcode.get(exc.errno, 'error')})") \
                from None
        return self.confined(path)

    def ws(self, path: Path, target: str, read_only: bool) -> b.MountSpec:
        return b.MountSpec(target, b.VOLUME_WORKSPACE, self.subpath(path), read_only)

    def trivy_mount(self) -> b.MountSpec | None:
        if self.policy.trivy_db is None:
            return None
        return b.MountSpec(TRIVY_DB_TARGET, b.VOLUME_TRIVY_DB, self.policy.trivy_db_subpath, True)

    # Env --------------------------------------------------------------
    def trust_extra_ca(self, mounts: list, env: dict) -> None:
        """Mount the policy's extra CA bundle read-only into a container that
        reaches the network, and point the engine at it."""
        if self.policy.extra_ca_file is not None:
            mounts.append(self.ws(Path(self.policy.extra_ca_file), EXTRA_CA_TARGET, True))
            env["BOMLENS_EXTRA_CA_CERTS"] = EXTRA_CA_TARGET

    def owner_env(self) -> dict[str, str]:
        if self.policy.uid is None:
            return {}
        return {"HOST_UID": str(self.policy.uid), "HOST_GID": str(self.policy.gid)}

    @staticmethod
    def caller_env(values: dict, allowed) -> dict:
        """The caller's values a container takes. RunnerPolicy already refused
        runner-owned and unknown names; this keeps what this container takes."""
        out = {}
        for name, value in values.items():
            if name in RUNNER_OWNED or name not in allowed:
                continue
            if name in PROXY_ENV_NAMES and name.lower() != "no_proxy" and isinstance(value, str) \
                    and is_loopback_proxy(value):
                continue
            out[name] = value
        return out

    @property
    def nonroot_user(self) -> str | None:
        if self.policy.uid is None:
            return None
        return f"{self.policy.uid}:{self.policy.gid}"

    # Containers -------------------------------------------------------
    def run(self, stage: str, component: str, image: str, *, user, entrypoint=None, args=(), workdir=None,
            env, mounts, network, read_only_root, root, timeout,
            cancel: Callable[[], bool] | None = None) -> tuple[b.ContainerOutcome, _Log, StageRecord]:
        """Run one container. The outcome may be cancelled; the caller decides."""
        if self.stuck:
            raise ContainerStillRunning("an earlier engine container is still running")
        cancel = self.cancel if cancel is None else cancel
        self.count += 1
        label = component.removeprefix("engine-")
        name = f"bomlens-{self.scan_id}-{self.count}-{label}"
        scratch = self.fresh(self.engine_dir / f"tmp-{self.count}-{label}")
        labels = dict(self.policy.labels)
        labels.update({b.LABEL_PART_OF: b.PART_OF, b.LABEL_COMPONENT: component, b.LABEL_SCAN: self.scan_id,
                       b.LABEL_NETWORK: network})
        spec = b.ContainerSpec(
            name=name, component=component, image=image, user=user, entrypoint=entrypoint, args=tuple(args),
            workdir=workdir, env=dict(env), mounts=tuple(m for m in mounts if m is not None), network=network,
            read_only_root=read_only_root, capabilities=tuple(self.policy.root_capabilities) if root else (),
            limits=self.policy.limits, timeout=timeout, labels=labels,
            scratch_subpath=self.subpath(scratch), pull_timeout=self.policy.timeouts.pull)
        log = _Log(self.on_log, stage)
        record = StageRecord(container=name, image=image, started_at=_now())
        try:
            outcome = self.backend.run(spec, log, cancel)
        except ContainerStillRunning:
            self.stuck = True
            raise
        record.ended_at = _now()
        record.exit_code, record.oom_killed = outcome.exit_code, outcome.oom_killed
        record.timed_out, record.start_error = outcome.timed_out, outcome.start_error
        record.cancelled = outcome.cancelled
        return outcome, log, record

    def run_or_cancel(self, *args, **kw):
        if self.cancel():
            raise ScanCancelled("the scan was cancelled")
        outcome, log, record = self.run(*args, **kw)
        if outcome.cancelled:
            raise ScanCancelled("the scan was cancelled")
        return outcome, log, record


def _stage_hook(on_stage: OnStage | None, name: str) -> None:
    if on_stage is not None:
        on_stage(name)


def _check_plan_images(plan: Plan, policy: RunnerPolicy) -> None:
    if not plan.supported:
        return
    s1 = plan.stage(1)
    require_allowed(check_image(s1.image, s1.image_digest), policy.stage1_allowed)
    s2 = plan.stage(2)
    want = policy.stage2_image
    if (s2.image, s2.image_digest) != (want.ref, want.digest):
        raise PlanRejected("stage 2 image is not the configured engine image")


def _overlaps(a: Path, b_: Path) -> bool:
    return a == b_ or a in b_.parents or b_ in a.parents


def _wrap_os_errors(fn):
    """A failed file operation is reported without its path."""
    def wrapper(*args, **kw):
        try:
            return fn(*args, **kw)
        except OSError as exc:
            raise EngineError(f"a workspace file operation failed ({errno.errorcode.get(exc.errno, 'error')})") \
                from None
    wrapper.__name__, wrapper.__doc__ = fn.__name__, fn.__doc__
    return wrapper


@_wrap_os_errors
def run_source_scan(policy: RunnerPolicy, backend: b.Backend, *, scan_id: str, project: str, version: str,
                    scan_dir: Path, source: Path, fetch_license: bool = True,
                    on_stage: OnStage | None = None, on_log: OnLog | None = None,
                    cancel: Callable[[], bool] | None = None) -> RunResult:
    """Scan a source tree. Returns once every container has been removed.

    on_stage is called with "prep", "cdxgen" and "postprocess" before each
    step; raising ScanCancelled from it (or cancel() turning true) stops the
    scan. on_log gets (stage, line) for every line a container prints.
    """
    backend.preflight()
    scan = _Scan(policy, backend, scan_id, scan_dir, on_log, cancel)
    source = scan.confined(Path(source))
    if not source.is_dir():
        raise PolicyError("the source is not a folder")
    if _overlaps(source, scan.engine_dir):
        raise PolicyError("the source and the scan's bomlens folder overlap")
    backend.remove_leftovers(scan_id)
    scan.prepare()
    name, ver = project_token(project, "project"), project_token(version, "0")
    owner = scan.owner_env()
    result = RunResult("source", scan.engine_dir / "out", None)
    s2_image = policy.stage2_image
    try:
        # 1. The execution plan -------------------------------------------
        _stage_hook(on_stage, "prep")
        plan_dir = scan.fresh(scan.engine_dir / "plan")
        env = {"MODE": "PLAN", "PROJECT_NAME": name, "PROJECT_VERSION": ver, "HOST_OUTPUT_DIR": "/host-output",
               "FETCH_LICENSE": "true" if fetch_license else "false",
               "BOMLENS_IMAGE_REF": s2_image.ref, "BOMLENS_IMAGE_DIGEST": s2_image.digest, **owner}
        if policy.stage1_image_prefix:
            env["CDXGEN_IMAGE_PREFIX"] = policy.stage1_image_prefix
        env.update(scan.caller_env(policy.plan_build_prep_env, set(policy.plan_build_prep_env)))
        cdx = policy.stage2_env.get("CYCLONEDX_SPEC_VERSION")
        if isinstance(cdx, str):
            env["CYCLONEDX_SPEC_VERSION"] = cdx
        outcome, _, rec = scan.run_or_cancel(
            "prep", "engine-plan", policy.images.engine.run_ref, user=scan.nonroot_user, workdir="/host-output",
            env=env, mounts=[scan.ws(source, "/src", True), scan.ws(plan_dir, "/host-output", False)],
            network=b.NETWORK_NONE, read_only_root=policy.read_only_root, root=False,
            timeout=policy.timeouts.plan)
        result.stages["plan"] = rec
        if outcome.start_error:
            raise EngineError(f"the engine image could not be started ({outcome.start_error})")
        if outcome.timed_out or outcome.exit_code not in (0, 3):
            raise EngineError(f"MODE=PLAN exited {outcome.exit_code}"
                              f"{' after its time limit' if outcome.timed_out else ''}")
        plan = load_plan(plan_dir)
        _check_plan_images(plan, policy)
        result.plan_status, result.plan_reason = plan.status, plan.reason
        result.detected_ecosystem, result.dropped_plan_env = plan.detected_ecosystem, plan.dropped_env

        out_dir = scan.fresh(scan.engine_dir / "out")
        result.output_dir = out_dir
        # The checked plan and its files go into the output folder for stage
        # 2, which reads them for the input fingerprint. Stage 1 mounts its
        # copies from a folder no container writes.
        files_dir = scan.fresh(scan.engine_dir / "plan-files")
        write_new_file(out_dir / PLAN_FILE, _read_plan_json(plan_dir))
        if plan.supported:
            (out_dir / PLAN_FILES_DIR).mkdir()
            (files_dir / PLAN_FILES_DIR).mkdir()
            for m in plan.stage(1).mounts:
                if m.role == "plan-file":
                    data = read_plan_file(plan_dir, m.source)
                    write_new_file(files_dir / m.source, data)
                    write_new_file(out_dir / m.source, data)

        # 2. Stage 1 -------------------------------------------------------
        s1_exit, s1_oom = EXIT_NOT_RUN, False
        if plan.supported:
            _stage_hook(on_stage, "cdxgen")
            s1_exit, s1_oom = _run_stage1(scan, plan.stage(1), source, out_dir, files_dir, name, ver,
                                          fetch_license, owner, result)
        else:
            write_new_file(out_dir / STAGE1_LOG_NAME,
                           f"stage 1 did not run: the execution plan is unsupported "
                           f"({plan.reason or 'no reason given'})\n".encode())

        # 3. Stage 2 -------------------------------------------------------
        _stage_hook(on_stage, "postprocess")
        s2_src, s2_out = "/src", "/host-output"
        env2: dict = {}
        if plan.supported:
            s2 = plan.stage(2)
            s2_src, s2_out = s2.mount("source").target, s2.mount("output").target
            env2.update(s2.env)
            allowed2 = set(s2.env_passthrough)
        else:
            allowed2 = set(STAGE_PASSTHROUGH_ALLOWED[2])
            env2["SECURITY_ENRICH"] = "false"
        env2.setdefault("GENERATE_SECURITY", "true")
        env2.update(scan.caller_env(dict(policy.stage2_env), allowed2 | SCAN_OPTION_NAMES))
        env2.update({"MODE": "POSTPROCESS", "BOMLENS_RUN_INPUT": plan.output_file, "HOST_OUTPUT_DIR": s2_out,
                     "UPLOAD_ENABLED": "false", "PROJECT_NAME": name, "PROJECT_VERSION": ver,
                     "BOMLENS_STAGE1_EXIT": str(s1_exit), "BOMLENS_STAGE1_OOM": "true" if s1_oom else "false",
                     "BOMLENS_STAGE1_LOG": STAGE1_LOG_NAME, "BOMLENS_IMAGE_REF": s2_image.ref,
                     "BOMLENS_IMAGE_DIGEST": s2_image.digest,
                     "DEEP_LICENSE": "true" if policy.deep_license else "false",
                     "DEEP_CVE": "true" if policy.deep_cve else "false", **owner})
        if policy.trivy_db is not None:
            env2.update({"TRIVY_CACHE_DIR": TRIVY_DB_TARGET, **_TRIVY_OFFLINE})
        mounts2 = [scan.ws(source, s2_src, True), scan.ws(out_dir, s2_out, False), scan.trivy_mount()]
        scan.trust_extra_ca(mounts2, env2)
        outcome, _, rec = scan.run_or_cancel(
            "postprocess", "engine-stage2", s2_image.run_ref, user=scan.nonroot_user, workdir=s2_out, env=env2,
            mounts=mounts2,
            network=b.NETWORK_EGRESS if policy.stage2_network else b.NETWORK_NONE,
            read_only_root=policy.read_only_root, root=False, timeout=policy.timeouts.stage2)
        result.stages["stage2"] = rec
        result.manifest = _require_result(out_dir, outcome, "stage 2")
        return result
    finally:
        _reset_ownership(scan, source)


def _read_plan_json(plan_dir: Path) -> bytes:
    """The plan load_plan checked (the plan container has ended)."""
    from .plan import MAX_PLAN_BYTES
    try:
        fd = os.open(plan_dir / PLAN_FILE, os.O_RDONLY | _NOFOLLOW)
        with os.fdopen(fd, "rb") as fh:
            data = fh.read(MAX_PLAN_BYTES + 1)
    except OSError:
        raise PlanRejected("the execution plan cannot be read") from None
    if len(data) > MAX_PLAN_BYTES:
        raise PlanRejected("the execution plan is too large")
    return data


def _run_stage1(scan: _Scan, s1: Stage, source: Path, out_dir: Path, files_dir: Path, name: str, ver: str,
                fetch_license: bool, owner: dict, result: RunResult) -> tuple[int, bool]:
    """Run stage 1 (and its restore when it was killed). Returns its exit code
    and out-of-memory state for stage 2; a stage 1 that could not start is
    exit 127, which stage 2 reads as cdxgen-unavailable."""
    policy = scan.policy
    if scan.cancel():
        raise ScanCancelled("the scan was cancelled")
    guard_dir = scan.fresh(scan.engine_dir / "guard-state")
    mounts = _stage1_mounts(scan, s1, source, out_dir, files_dir, guard_dir)
    env1 = dict(s1.env)
    env1.update({"PROJECT_NAME": name, "PROJECT_VERSION": ver, "FETCH_LICENSE": "true" if fetch_license else "false"})
    env1.update(scan.caller_env(
        dict(policy.stage1_env), set(s1.env_passthrough) | {k for k in policy.stage1_env if is_registry_env(k)}))
    env1.update({k: v for k, v in owner.items() if k in s1.env_passthrough})
    scan.trust_extra_ca(mounts, env1)
    if s1.mount("guard-state"):
        env1["BOMLENS_GUARD_ID"] = f"bomlens-{scan.scan_id}"
    image1 = f"{_split(s1.image)[0]}@{s1.image_digest}"
    run1 = dict(user=s1.user, entrypoint=s1.entrypoint, args=s1.args, workdir=s1.workdir, mounts=mounts,
                read_only_root=policy.stage1_read_only_root, root=s1.user is None or s1.user.split(":")[0] == "0")
    try:
        outcome, log1, rec = scan.run("cdxgen", "engine-stage1", image1, env=env1,
                                      network=b.NETWORK_EGRESS if s1.network_required else b.NETWORK_NONE,
                                      timeout=policy.timeouts.stage1, **run1)
    except ContainerStillRunning:
        raise
    except EngineError as exc:
        # The Job could not even be created: stage 2 still runs, on no SBOM.
        write_new_file(out_dir / STAGE1_LOG_NAME, f"stage 1 did not start: {exc}\n".encode())
        result.stages["stage1"] = StageRecord(container="", image=image1, start_error=str(exc))
        return EXIT_NOT_RUN, False
    result.stages["stage1"] = rec
    if outcome.start_error:
        write_new_file(out_dir / STAGE1_LOG_NAME, f"stage 1 did not start: {outcome.start_error}\n".encode())
        return EXIT_NOT_RUN, False
    write_new_file(out_dir / STAGE1_LOG_NAME, bytes(log1.tail))
    killed = outcome.killed or (outcome.cancelled and outcome.started)
    if killed and s1.mount("guard-state"):
        result.source_restored = _restore(scan, image1, run1, env1, result)
    if outcome.cancelled:
        raise ScanCancelled("the scan was cancelled")
    code = outcome.exit_code if outcome.exit_code is not None else 137
    return code, outcome.oom_killed


def _stage1_mounts(scan: _Scan, s1: Stage, source: Path, out_dir: Path, files_dir: Path,
                   guard_dir: Path) -> list[b.MountSpec]:
    mounts = []
    for m in s1.mounts:
        if m.role == "source":
            mounts.append(scan.ws(source, m.target, m.read_only))
        elif m.role == "output":
            mounts.append(scan.ws(out_dir, m.target, False))
        elif m.role == "plan-file":
            mounts.append(scan.ws(files_dir / m.source, m.target, True))
        elif m.role == "guard-state":
            mounts.append(scan.ws(guard_dir, m.target, False))
        elif m.role in scan.policy.caller_mounts:
            mounts.append(scan.ws(Path(scan.policy.caller_mounts[m.role]), m.target, m.read_only))
    return mounts


def _restore(scan: _Scan, image: str, run1: dict, env1: dict, result: RunResult) -> bool:
    """Put the source back after a killed stage 1. Runs even when the scan was
    cancelled: a cancelled scan must not leave the tree changed."""
    env = dict(env1, BOMLENS_GUARD_RESTORE_ONLY="1")
    try:
        outcome, _, rec = scan.run("cdxgen", "engine-restore", image, env=env, network=b.NETWORK_NONE,
                                   timeout=scan.policy.timeouts.restore, cancel=_never, **run1)
    except ContainerStillRunning:
        raise
    except BomLensError:
        return False
    result.stages["restore"] = rec
    return outcome.exit_code == 0 and not outcome.timed_out


def _reset_ownership(scan: _Scan, source: Path) -> None:
    policy = scan.policy
    if scan.stuck or not getattr(scan.backend, "reset_ownership", False) or not policy.uid:
        return
    if not os.path.isdir(scan.engine_dir):
        return
    script = f"chown -R -h {policy.uid}:{policy.gid} /w/engine /w/source 2>/dev/null; exit 0"
    try:
        scan.run("chown", "engine-chown", policy.images.engine.run_ref, user="0:0", entrypoint=("sh",),
                 args=("-c", script), env={}, mounts=[scan.ws(scan.engine_dir, "/w/engine", False),
                                                       scan.ws(source, "/w/source", False)],
                 network=b.NETWORK_NONE, read_only_root=True, root=True, timeout=policy.timeouts.chown,
                 cancel=_never)
    except ContainerStillRunning:
        raise
    except BomLensError:
        pass


def _require_result(out_dir: Path, outcome: b.ContainerOutcome, what: str) -> EngineResult:
    if not os.path.lexists(out_dir / MANIFEST_NAME):
        if outcome.start_error:
            why = f"could not start ({outcome.start_error})"
        elif outcome.timed_out:
            why = "was stopped at its time limit"
        elif outcome.oom_killed:
            why = "ran out of memory"
        else:
            why = f"exited {outcome.exit_code}"
        raise EngineWroteNoResult(f"{what} {why} without writing a result manifest")
    return load_manifest(out_dir)


@_wrap_os_errors
def run_image_scan(policy: RunnerPolicy, backend: b.Backend, *, scan_id: str, target: str, project: str,
                   version: str, scan_dir: Path, on_log: OnLog | None = None,
                   cancel: Callable[[], bool] | None = None) -> RunResult:
    """Scan a container image from its registry (MODE=IMAGE), one container."""
    ref = image_target(target)
    if not policy.uid:
        raise PolicyError("an image scan runs as a non-root uid; set uid and gid")
    backend.preflight()
    scan = _Scan(policy, backend, scan_id, scan_dir, on_log, cancel)
    backend.remove_leftovers(scan_id)
    scan.prepare()
    out_dir = scan.fresh(scan.engine_dir / "out")
    result = RunResult("image", out_dir, None)
    env = {"GENERATE_SECURITY": "true", "SECURITY_ENRICH": "false"}
    env.update(scan.caller_env(dict(policy.image_env), IMAGE_SCAN_NAMES))
    mounts = [scan.ws(out_dir, "/host-output", False), scan.trivy_mount()]
    scan.trust_extra_ca(mounts, env)
    env.update({"MODE": "IMAGE", "TARGET_IMAGE": ref, "PROJECT_NAME": project_token(project, "project"),
                "PROJECT_VERSION": project_token(version, "0"), "HOST_OUTPUT_DIR": "/host-output",
                "UPLOAD_ENABLED": "false", "DEEP_LICENSE": "false",
                "BOMLENS_IMAGE_REF": policy.images.engine.ref, "BOMLENS_IMAGE_DIGEST": policy.images.engine.digest,
                **scan.owner_env()})
    if policy.trivy_db is not None:
        env.update({"TRIVY_CACHE_DIR": TRIVY_DB_TARGET, **_TRIVY_OFFLINE})
    outcome, _, rec = scan.run_or_cancel(
        "trivy", "engine-image", policy.images.engine.run_ref, user=scan.nonroot_user, workdir="/host-output",
        env=env, mounts=mounts,
        network=b.NETWORK_EGRESS, read_only_root=policy.read_only_root, root=False, timeout=policy.timeouts.image)
    result.stages["image"] = rec
    if outcome.timed_out:
        raise ScanTimedOut("the image scan stopped at its time limit")
    result.manifest = _require_result(out_dir, outcome, "MODE=IMAGE")
    return result
