# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Docker backend: each container through the ``docker`` CLI.

The CLI talks to whatever DOCKER_HOST names, such as a socket proxy that
allows containers and images only. A container's values are never put on a
command line or into the CLI's environment (a container's HOME would change
which daemon the CLI reaches): they go into an env file readable by its owner
only, which is removed as soon as the container is created. A SecretRef is
resolved by the caller's ``secrets`` function at that moment and is never
kept.

After a container is created, the mounts and the settings the daemon
recorded are compared with the ones asked for, and a container that differs
is removed without being started. When ``run`` returns or raises, the
container has been removed, or ContainerStillRunning is raised.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Mapping

from . import backend as b
from .errors import BackendUnavailable, ContainerStillRunning, EngineError, PolicyError
from .policy import SecretRef

LABEL_DEADLINE = "bomlens.engine/deadline"
MIN_API_SUBPATH = (1, 45)
MIN_API = (1, 41)
SECRET_ENV_PREFIX = "BOMLENS_SECRET_"
_TOKEN_RE = re.compile(r"[A-Za-z0-9._/-]+")
_VOLUME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}")
_NETWORK_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_HEX_RE = re.compile(r"[0-9a-f]{6,64}")
_LABEL_KEY_RE = re.compile(r"([a-z0-9.-]{1,253}/)?[A-Za-z0-9]([A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?")
_LABEL_VALUE_RE = re.compile(r"([A-Za-z0-9]([A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?)?")
_FORBIDDEN_NETWORKS = frozenset(("host", "none", "bridge", "default"))
_NO_SUCH = ("no such object", "no such container", "not found")


@dataclass
class DockerOptions:
    #: "named": the workspace and Trivy volumes are Docker volumes, mounted
    #: by subpath (Docker API 1.45 or later). "bind": they are host folders.
    volume_strategy: str = "named"
    workspace: str = ""          # volume name, or absolute host folder for "bind"
    trivy_db: str | None = None  # volume name, or absolute host folder for "bind"
    #: The network a container with egress joins, by name. Never the
    #: worker's own.
    egress_network: str | None = None
    #: More networks to refuse by name (the worker's database network, say).
    refuse_networks: tuple[str, ...] = ()
    #: The worker's own container (name or id), to read its networks. By
    #: default the runner inspects its HOSTNAME when it runs in a container.
    worker_container: str | None = None
    #: Labels every container gets, and that scope leftover removal to this
    #: installation.
    instance_labels: Mapping[str, str] = field(default_factory=dict)
    #: Resolves a SecretRef to its value when a container is created.
    secrets: Callable[[SecretRef], str] | None = None
    exit_grace: int = 30
    reset_ownership: bool = True
    docker: str = "docker"


def _child_env() -> dict[str, str]:
    """The docker CLI's environment: the runner's, without its secrets."""
    return {k: v for k, v in os.environ.items() if not k.startswith(SECRET_ENV_PREFIX)}


class DockerCli:
    """The docker commands the backend uses. Replace it in tests."""

    def __init__(self, docker: str = "docker"):
        self.docker = docker

    def run(self, argv: list[str], timeout: float) -> subprocess.CompletedProcess:
        """docker <argv>. A command past its timeout comes back as exit -1."""
        try:
            return subprocess.run([self.docker, *argv], capture_output=True, check=False, timeout=timeout,
                                  env=_child_env())
        except FileNotFoundError:
            raise BackendUnavailable("the docker command is not installed") from None
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess([self.docker, *argv], -1, b"", b"timed out")

    def follow(self, container: str, since: str | None) -> subprocess.Popen:
        argv = [self.docker, "logs", "--follow", "--timestamps"]
        if since:
            argv += ["--since", since]
        return subprocess.Popen([*argv, container], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                env=_child_env())


def _text(done: subprocess.CompletedProcess) -> str:
    return (done.stdout or b"").decode("utf-8", "replace").strip()


def _err(done: subprocess.CompletedProcess) -> str:
    return (done.stderr or b"").decode("utf-8", "replace").lower()


def _api(version: str) -> tuple[int, int] | None:
    parts = version.split(".")
    if len(parts) != 2 or not all(p.isdigit() for p in parts):
        return None
    return int(parts[0]), int(parts[1])


class DockerBackend:
    def __init__(self, options: DockerOptions, cli: DockerCli | None = None,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep):
        o = options
        if o.volume_strategy not in ("named", "bind"):
            raise PolicyError("volume strategy must be named or bind")
        if not o.workspace:
            raise PolicyError("the Docker backend needs the workspace volume")
        for value in (o.workspace, o.trivy_db):
            if value is None:
                continue
            if o.volume_strategy == "named" and not _VOLUME_RE.fullmatch(value):
                raise PolicyError("a volume name is not valid")
            if o.volume_strategy == "bind" and (not value.startswith("/") or not _TOKEN_RE.fullmatch(value)
                                                or ".." in value.split("/")):
                raise PolicyError("a bind folder must be an absolute path without '..'")
        if o.egress_network is not None:
            net = o.egress_network
            # By name only: an id or an id prefix could name a network the
            # worker is on without matching its name.
            if (not _NETWORK_RE.fullmatch(net) or _HEX_RE.fullmatch(net)
                    or net.lower() in _FORBIDDEN_NETWORKS | {n.lower() for n in o.refuse_networks}):
                raise PolicyError("the egress network is not one the runner joins")
        for k, v in o.instance_labels.items():
            if not _LABEL_KEY_RE.fullmatch(k) or not _LABEL_VALUE_RE.fullmatch(v):
                raise PolicyError("an instance label is not valid")
        if o.worker_container is not None and not _NETWORK_RE.fullmatch(o.worker_container):
            raise PolicyError("the worker container is not a container name or id")
        self.opts = o
        self.cli = cli or DockerCli(o.docker)
        self.clock, self.sleep = clock, sleep
        self.reset_ownership = o.reset_ownership

    # Protocol ----------------------------------------------------------
    def preflight(self) -> None:
        done = self.cli.run(["version", "--format", "{{.Server.APIVersion}}"], 30)
        api = _api(_text(done)) if done.returncode == 0 else None
        need = MIN_API_SUBPATH if self.opts.volume_strategy == "named" else MIN_API
        if api is None or api < need:
            raise BackendUnavailable(f"the Docker API is unreachable or older than {need[0]}.{need[1]}")
        if self.opts.egress_network:
            own = self.own_networks()
            if own is None:
                raise BackendUnavailable("the worker's own networks could not be read")
            if self.opts.egress_network in own:
                raise PolicyError("the egress network is one the worker itself is on")

    @staticmethod
    def _in_container() -> bool:
        return os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")

    def own_networks(self) -> set[str] | None:
        """Names and ids of the networks this worker's container is on: empty
        when the worker is not a container, None when it cannot be told."""
        target = self.opts.worker_container
        if target is None:
            if not self._in_container():
                return set()
            target = os.environ.get("HOSTNAME") or ""
            if not _NETWORK_RE.fullmatch(target):
                return None
        done = self.cli.run(["container", "inspect", "--format", "{{json .NetworkSettings.Networks}}", target], 60)
        if done.returncode != 0:
            return None
        try:
            nets = json.loads(_text(done) or "{}")
        except ValueError:
            return None
        if not isinstance(nets, dict):
            return None
        out = set()
        for name, info in nets.items():
            out.add(name)
            if isinstance(info, dict) and isinstance(info.get("NetworkID"), str):
                out.add(info["NetworkID"])
        return out

    def _filters(self, scan_label: str) -> list[str]:
        argv = ["--filter", f"label={b.LABEL_PART_OF}={b.PART_OF}", "--filter", f"label={b.LABEL_SCAN}={scan_label}"]
        for k, v in sorted(self.opts.instance_labels.items()):
            argv += ["--filter", f"label={k}={v}"]
        return argv

    def remove_leftovers(self, scan_label: str) -> None:
        done = self.cli.run(["ps", "--all", "--quiet", *self._filters(scan_label)], 60)
        if done.returncode != 0:
            raise BackendUnavailable("the engine containers could not be listed")
        for cid in _text(done).split():
            self._remove(cid)

    def run(self, spec: b.ContainerSpec, on_line: Callable[[str], None],
            cancelled: Callable[[], bool]) -> b.ContainerOutcome:
        outcome = b.ContainerOutcome()
        if not self._ensure_image(spec):
            outcome.start_error = "Docker: the image could not be pulled"
            return outcome
        argv, env = self.create_argv(spec)
        cid = ""
        try:
            done = self._create(argv, env, spec.image)
            cid = _text(done).splitlines()[-1] if done.returncode == 0 and _text(done) else ""
            if not cid:
                outcome.start_error = "Docker: the container could not be created"
                return outcome
            if not self._config_matches(cid, spec):
                raise EngineError("the daemon did not record the mounts and settings the runner asked for")
            if self.cli.run(["start", cid], 120).returncode != 0:
                outcome.start_error = "Docker: the container did not start (does the workspace volume exist?)"
                return outcome
            outcome.started = True
            self._follow(spec, cid, on_line, cancelled, outcome)
            self._settle(cid, outcome)
            return outcome
        finally:
            if cid:
                self._remove(cid)
            else:
                # create may have made the container before it failed or
                # timed out: find it by its name and this scan's labels.
                self._remove_by_name(spec)

    # Internals -----------------------------------------------------------
    def _ensure_image(self, spec: b.ContainerSpec) -> bool:
        if self.cli.run(["image", "inspect", "--format", "{{.Id}}", spec.image], 60).returncode == 0:
            return True
        return self.cli.run(["pull", "--quiet", spec.image], spec.pull_timeout).returncode == 0

    def _create(self, argv: list[str], env: dict[str, str], image: str) -> subprocess.CompletedProcess:
        fd, env_file = tempfile.mkstemp(prefix="bomlens-env-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", errors="strict") as fh:
                fh.write("".join(f"{k}={v}\n" for k, v in env.items()))
            at = argv.index(image)
            return self.cli.run(["create", *argv[:at], "--env-file", env_file, *argv[at:]], 120)
        except UnicodeEncodeError:
            raise EngineError("a container value is not valid text") from None
        finally:
            os.unlink(env_file)

    def _volume(self, name: str) -> str:
        if name == b.VOLUME_WORKSPACE:
            return self.opts.workspace
        if name == b.VOLUME_TRIVY_DB and self.opts.trivy_db:
            return self.opts.trivy_db
        raise EngineError(f"no Docker volume is configured for the {name} volume")

    @staticmethod
    def _check_path(value: str) -> None:
        if not _TOKEN_RE.fullmatch(value) or ".." in value.split("/"):
            raise EngineError("a mount path has characters the runner does not mount")

    def _source(self, m: b.MountSpec) -> str:
        source = self._volume(m.volume)
        if self.opts.volume_strategy == "bind" and m.subpath:
            return os.path.join(source, m.subpath)
        return source

    def mount_args(self, m: b.MountSpec) -> str:
        self._check_path(m.target)
        if m.subpath:
            self._check_path(m.subpath)
        if self.opts.volume_strategy == "named":
            # nocopy: the image's own files are never copied into the workspace.
            arg = f"type=volume,src={self._source(m)},dst={m.target}"
            if m.subpath:
                arg += f",volume-subpath={m.subpath}"
            arg += ",volume-nocopy"
        else:
            arg = f"type=bind,src={self._source(m)},dst={m.target}"
        if m.read_only:
            arg += ",readonly"
        return arg

    def _all_mounts(self, spec: b.ContainerSpec) -> list[b.MountSpec]:
        mounts = list(spec.mounts)
        if spec.scratch_subpath and not any(m.target == "/tmp" for m in mounts):
            mounts.insert(0, b.MountSpec("/tmp", b.VOLUME_WORKSPACE, spec.scratch_subpath, False))
        return mounts

    def labels(self, spec: b.ContainerSpec) -> dict[str, str]:
        deadline = int(time.time()) + spec.pull_timeout + spec.timeout + 2 * self.opts.exit_grace
        return {**self.opts.instance_labels, **spec.labels, LABEL_DEADLINE: str(deadline)}

    def create_argv(self, spec: b.ContainerSpec) -> tuple[list[str], dict[str, str]]:
        """The create arguments (without the env file) and the values for it."""
        if spec.entrypoint and len(spec.entrypoint) != 1:
            raise EngineError("an entrypoint must be one program")
        argv = ["--name", spec.name]
        for k, v in sorted(self.labels(spec).items()):
            argv += ["--label", f"{k}={v}"]
        argv += ["--security-opt", "no-new-privileges", "--pids-limit", str(int(spec.limits.pids)),
                 "--cap-drop", "ALL"]
        for cap in spec.capabilities:
            argv += ["--cap-add", cap]
        mem = str(int(spec.limits.memory_bytes))
        argv += ["--memory", mem, "--memory-swap", mem, "--cpus", f"{float(spec.limits.cpus):g}"]
        if spec.read_only_root:
            argv.append("--read-only")
        argv += ["--network", self._network(spec)]
        if spec.user:
            argv += ["--user", spec.user]
        if spec.entrypoint:
            argv += ["--entrypoint", spec.entrypoint[0]]
        if spec.workdir:
            argv += ["--workdir", spec.workdir]
        for m in self._all_mounts(spec):
            argv += ["--mount", self.mount_args(m)]
        env: dict[str, str] = {}
        for name in sorted(spec.env):
            value = spec.env[name]
            if isinstance(value, SecretRef):
                if self.opts.secrets is None:
                    raise EngineError(f"{name} is a secret, and no secret resolver is configured")
                value = self.opts.secrets(value)
            if not isinstance(value, str) or any(c in value for c in "\0\n\r"):
                raise EngineError(f"the value for {name} is not a plain string")
            env[name] = value
        argv.append(spec.image)
        argv += list(spec.args)
        return argv, env

    def _network(self, spec: b.ContainerSpec) -> str:
        if spec.network != b.NETWORK_EGRESS:
            return "none"
        if not self.opts.egress_network:
            raise EngineError("a container needs the network, and no egress network is configured")
        return self.opts.egress_network

    def _inspect(self, cid: str) -> dict | None:
        for _ in range(3):
            done = self.cli.run(["inspect", "--format", "{{json .}}", cid], 60)
            if done.returncode == 0:
                try:
                    doc = json.loads(_text(done) or "{}")
                except ValueError:
                    doc = None
                if isinstance(doc, dict):
                    return doc
            elif any(s in _err(done) for s in _NO_SUCH):
                return {}
            self.sleep(1.0)
        return None

    def _config_matches(self, cid: str, spec: b.ContainerSpec) -> bool:
        doc = self._inspect(cid)
        if not doc:
            return False
        host = doc.get("HostConfig") or {}

        def key(typ, src, dst, ro, sub, nocopy):
            return (typ, src, dst, bool(ro), sub or "", bool(nocopy))
        named = self.opts.volume_strategy == "named"
        want = {key("volume" if named else "bind", self._source(m), m.target, m.read_only,
                    m.subpath if named else "", named) for m in self._all_mounts(spec)}
        have = set()
        got = host.get("Mounts") or []
        if not isinstance(got, list):
            return False
        for m in got:
            if not isinstance(m, dict):
                return False
            o = m.get("VolumeOptions") or {}
            have.add(key(m.get("Type"), m.get("Source"), m.get("Target"), m.get("ReadOnly"), o.get("Subpath"),
                         o.get("NoCopy")))
        if have != want:
            return False
        # The daemon records CHOWN as CAP_CHOWN.
        caps = {c.removeprefix("CAP_") for c in host.get("CapAdd") or [] if isinstance(c, str)}
        checks = (
            host.get("Privileged") is False,
            host.get("Memory") == int(spec.limits.memory_bytes),
            host.get("PidsLimit") == int(spec.limits.pids),
            host.get("NanoCpus") == int(float(spec.limits.cpus) * 1e9),
            bool(host.get("ReadonlyRootfs")) == spec.read_only_root,
            "ALL" in (host.get("CapDrop") or []),
            caps == set(spec.capabilities),
            "no-new-privileges" in (host.get("SecurityOpt") or []),
            host.get("NetworkMode") == self._network(spec),
            not host.get("Devices"), not host.get("Binds"), host.get("PidMode") in ("", None),
            host.get("IpcMode") in ("", None, "private", "shareable"), not host.get("VolumesFrom"),
        )
        return all(checks)

    def _follow(self, spec, cid, on_line, cancelled, outcome) -> None:
        """Pass the container's lines on until it ends, it times out or the
        scan is cancelled. A log stream that ends while the container still
        runs (a proxy or daemon closing it, a log driver that cannot be read)
        is followed again from the last line seen, or, when it keeps ending
        at once, the container's state is polled instead."""
        lines: list[str] = []
        lock = threading.Lock()
        last = {"ts": None}

        def reader(proc, since_key):
            assert proc.stdout is not None
            for raw in iter(lambda: proc.stdout.readline(65536), b""):
                text = raw.decode("utf-8", "replace").rstrip("\r\n")
                ts, sep, rest = text.partition(" ")
                if sep and ts[:4].isdigit() and "T" in ts:
                    k = _ts_key(ts)
                    if since_key is not None and k <= since_key:
                        continue
                    if last["ts"] is None or k > _ts_key(last["ts"]):
                        last["ts"] = ts
                    text = rest
                with lock:
                    lines.append(text)

        def flush():
            with lock:
                pending, lines[:] = lines[:], []
            for line in pending:
                on_line(line)

        start = self.clock()
        quick_ends = 0
        proc = thread = None
        try:
            while True:
                if thread is None or not thread.is_alive():
                    if proc is not None:
                        proc.wait()
                    state = (self._inspect(cid) or {}).get("State") or {}
                    if proc is not None and not state.get("Running"):
                        break
                    if quick_ends < 3:
                        since = last["ts"]
                        began = self.clock()
                        proc = self.cli.follow(cid, since)
                        thread = threading.Thread(target=reader, args=(proc, _ts_key(since) if since else None),
                                                  daemon=True)
                        thread.start()
                        thread.join(timeout=1.0)
                        if not thread.is_alive() and self.clock() - began < 2:
                            quick_ends += 1
                    else:
                        # The log cannot be followed: watch the state.
                        if not state.get("Running"):
                            break
                        self.sleep(1.0)
                flush()
                if cancelled():
                    outcome.cancelled = True
                    break
                if self.clock() - start > spec.timeout:
                    outcome.timed_out = True
                    break
                if thread is not None and thread.is_alive():
                    thread.join(timeout=1.0)
        finally:
            if outcome.cancelled or outcome.timed_out:
                self.cli.run(["kill", cid], 60)
            if thread is not None:
                thread.join(timeout=self.opts.exit_grace)
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.wait()
            flush()

    def _settle(self, cid: str, outcome: b.ContainerOutcome) -> None:
        def state():
            doc = self._inspect(cid)
            return None if doc is None else (doc.get("State") or {})
        s = state()
        deadline = self.clock() + self.opts.exit_grace
        while (s is None or s.get("Running")) and self.clock() < deadline:
            self.sleep(1.0)
            s = state()
        if s is None or s.get("Running"):
            self.cli.run(["kill", cid], 60)
            deadline = self.clock() + self.opts.exit_grace
            while (s is None or s.get("Running")) and self.clock() < deadline:
                self.sleep(1.0)
                s = state()
        if s is None or s.get("Running"):
            raise ContainerStillRunning("an engine container was still running after it was killed")
        code = s.get("ExitCode")
        outcome.exit_code = code if isinstance(code, int) and not isinstance(code, bool) else None
        outcome.oom_killed = bool(s.get("OOMKilled"))
        if outcome.timed_out and outcome.exit_code in (None, 0):
            outcome.exit_code = 137

    def _remove(self, cid: str) -> None:
        """Remove a container and confirm it is gone."""
        deadline = self.clock() + self.opts.exit_grace
        while True:
            self.cli.run(["rm", "--force", cid], 60)
            done = self.cli.run(["inspect", "--format", "{{.Id}}", cid], 60)
            if done.returncode != 0 and any(s in _err(done) for s in _NO_SUCH):
                return
            if self.clock() > deadline:
                raise ContainerStillRunning("an engine container could not be confirmed removed")
            self.sleep(1.0)

    def _remove_by_name(self, spec: b.ContainerSpec) -> None:
        scan = spec.labels.get(b.LABEL_SCAN, "")
        done = self.cli.run(["ps", "--all", "--quiet", "--filter", f"name=^/{spec.name}$", *self._filters(scan)], 60)
        if done.returncode != 0:
            raise ContainerStillRunning("an engine container that may have been created could not be looked up")
        for cid in _text(done).split():
            self._remove(cid)


def _ts_key(ts: str) -> str:
    """An RFC 3339 time with its fraction padded, so keys compare as text."""
    head, _, frac = ts.rstrip("Z").partition(".")
    return head + "." + (frac + "000000000")[:9]
