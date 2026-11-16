# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Kubernetes backend: each container is a Job of one Pod.

It needs, in its namespace: jobs (create, get, list, delete), pods (get,
list, delete) and pods/log (get). It creates no NetworkPolicy, Secret or
other object: a cluster gives the engine Pods their network rules by the
labels in backend.py (LABEL_NETWORK, LABEL_COMPONENT), and secret values by
SecretRef.

The Pods share the caller's workspace PersistentVolumeClaim, each mounting
only the subpaths the spec names; the Trivy database is a second claim,
read-only. /tmp is an emptyDir.
"""

from __future__ import annotations

import http.client
import json
import os
import queue
import ssl
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Mapping
from urllib.parse import quote, urlencode, urlsplit

from . import backend as b
from .errors import BackendUnavailable, ContainerStillRunning, EngineError
from .policy import SecretRef

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
CONTAINER = "engine"
_FATAL_WAIT = frozenset(("InvalidImageName", "CreateContainerConfigError", "CreateContainerError",
                         "ErrImageNeverPull", "RunContainerError"))
_PULL_WAIT = frozenset(("ErrImagePull", "ImagePullBackOff"))


class KubeApi:
    """A minimal client for the Kubernetes REST API (standard library only)."""

    def __init__(self, server: str, token: str | None = None, ca_file: str | None = None,
                 timeout: float = 30.0, insecure_http: bool = False):
        parts = urlsplit(server)
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise BackendUnavailable("the Kubernetes API address is not valid")
        if parts.scheme == "http" and not insecure_http:
            raise BackendUnavailable("the Kubernetes API address is plain HTTP; allow it only for kubectl proxy")
        self.scheme, self.host, self.port = parts.scheme, parts.hostname, parts.port
        self.base = parts.path.rstrip("/")
        self.token, self.timeout = token, timeout
        self.ctx = None
        if self.scheme == "https":
            self.ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()

    @classmethod
    def in_cluster(cls) -> "KubeApi":
        host, port = os.environ.get("KUBERNETES_SERVICE_HOST"), os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        if not host:
            raise BackendUnavailable("not running in a Kubernetes cluster")
        with open(os.path.join(SA_DIR, "token"), encoding="utf-8") as fh:
            token = fh.read().strip()
        host = f"[{host}]" if ":" in host else host
        return cls(f"https://{host}:{port}", token=token, ca_file=os.path.join(SA_DIR, "ca.crt"))

    @staticmethod
    def in_cluster_namespace() -> str:
        with open(os.path.join(SA_DIR, "namespace"), encoding="utf-8") as fh:
            return fh.read().strip()

    def _conn(self, timeout: float | None):
        if self.scheme == "https":
            return http.client.HTTPSConnection(self.host, self.port, timeout=timeout, context=self.ctx)
        return http.client.HTTPConnection(self.host, self.port, timeout=timeout)

    def _headers(self, body: bool) -> dict:
        h = {"Accept": "application/json"}
        if body:
            h["Content-Type"] = "application/json"
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def request(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        conn = self._conn(self.timeout)
        try:
            data = json.dumps(body).encode() if body is not None else None
            conn.request(method, self.base + path, body=data, headers=self._headers(data is not None))
            resp = conn.getresponse()
            raw = resp.read(32 * 1024 * 1024)
        except (OSError, http.client.HTTPException):
            raise BackendUnavailable("the Kubernetes API could not be reached") from None
        finally:
            conn.close()
        try:
            doc = json.loads(raw) if raw else {}
        except ValueError:
            doc = {}
        return resp.status, doc if isinstance(doc, dict) else {}

    def stream_lines(self, path: str, on_line: Callable[[str], None], stop: threading.Event) -> None:
        """Read a streaming response line by line until it ends or stop is set."""
        conn = self._conn(None)
        try:
            conn.request("GET", self.base + path, headers=self._headers(False))
            resp = conn.getresponse()
            if resp.status != 200:
                return
            while not stop.is_set():
                line = resp.readline(65536)
                if not line:
                    return
                on_line(line.decode("utf-8", "replace").rstrip("\r\n"))
        except (OSError, http.client.HTTPException):
            return
        finally:
            conn.close()


@dataclass
class KubernetesOptions:
    namespace: str
    workspace_claim: str
    trivy_db_claim: str | None = None
    service_account: str | None = None
    image_pull_secrets: tuple[str, ...] = ()
    node_selector: Mapping[str, str] = field(default_factory=dict)
    tolerations: tuple[dict, ...] = ()
    priority_class: str | None = None
    fs_group: int | None = None
    request_cpu: str = "100m"
    request_memory: str = "512Mi"
    ttl_after_finished: int = 600
    poll_interval: float = 1.0
    delete_grace: int = 30
    log_grace: float = 60.0
    api_patience: float = 120.0
    reset_ownership: bool = True


def _quantity_bytes(n: int) -> str:
    return str(int(n))


def _user(spec_user: str | None) -> tuple[int | None, int | None]:
    if not spec_user:
        return None, None
    uid, _, gid = spec_user.partition(":")
    return int(uid), (int(gid) if gid else None)


def job_manifest(spec: b.ContainerSpec, opts: KubernetesOptions) -> dict:
    """The Job for one container spec. Pure, so it can be checked in tests."""
    uid, gid = _user(spec.user)
    env = []
    for name in sorted(spec.env):
        value = spec.env[name]
        if isinstance(value, SecretRef):
            env.append({"name": name, "valueFrom": {"secretKeyRef": {"name": value.name, "key": value.key}}})
        else:
            env.append({"name": name, "value": value})
    claims = {b.VOLUME_WORKSPACE: opts.workspace_claim, b.VOLUME_TRIVY_DB: opts.trivy_db_claim}
    used = sorted({m.volume for m in spec.mounts})
    volumes, mounts = [], []
    for vol in used:
        if not claims.get(vol):
            raise EngineError(f"no claim is configured for the {vol} volume")
        volumes.append({"name": vol, "persistentVolumeClaim": {"claimName": claims[vol],
                                                                "readOnly": vol == b.VOLUME_TRIVY_DB}})
    volumes.append({"name": "tmp", "emptyDir": {"sizeLimit": _quantity_bytes(spec.limits.tmp_bytes)}})
    mounts.append({"name": "tmp", "mountPath": "/tmp"})
    for m in spec.mounts:
        entry = {"name": m.volume, "mountPath": m.target, "readOnly": m.read_only}
        if m.subpath:
            entry["subPath"] = m.subpath
        mounts.append(entry)
    container_sc: dict = {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": spec.read_only_root,
        "capabilities": {"drop": ["ALL"], **({"add": list(spec.capabilities)} if spec.capabilities else {})},
    }
    if uid is not None:
        container_sc["runAsUser"] = uid
        container_sc["runAsNonRoot"] = uid != 0
        if gid is not None:
            container_sc["runAsGroup"] = gid
    container = {
        "name": CONTAINER, "image": spec.image, "imagePullPolicy": "IfNotPresent",
        "env": env, "volumeMounts": mounts, "securityContext": container_sc,
        "resources": {
            "limits": {"memory": _quantity_bytes(spec.limits.memory_bytes),
                       "cpu": f"{max(1, int(spec.limits.cpus * 1000))}m"},
            "requests": {"memory": opts.request_memory, "cpu": opts.request_cpu},
        },
    }
    if spec.entrypoint:
        container["command"] = list(spec.entrypoint)
    if spec.args:
        container["args"] = list(spec.args)
    if spec.workdir:
        container["workingDir"] = spec.workdir
    pod_sc: dict = {"seccompProfile": {"type": "RuntimeDefault"}}
    if opts.fs_group is not None:
        pod_sc["fsGroup"] = opts.fs_group
    pod_spec: dict = {
        "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
        "securityContext": pod_sc, "containers": [container], "volumes": volumes,
        "terminationGracePeriodSeconds": 5,
    }
    if opts.service_account:
        pod_spec["serviceAccountName"] = opts.service_account
    if opts.image_pull_secrets:
        pod_spec["imagePullSecrets"] = [{"name": n} for n in opts.image_pull_secrets]
    if opts.node_selector:
        pod_spec["nodeSelector"] = dict(opts.node_selector)
    if opts.tolerations:
        pod_spec["tolerations"] = [dict(t) for t in opts.tolerations]
    if opts.priority_class:
        pod_spec["priorityClassName"] = opts.priority_class
    labels = dict(spec.labels)
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": spec.name, "labels": labels},
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": spec.pull_timeout + spec.timeout + 60,
            "ttlSecondsAfterFinished": opts.ttl_after_finished,
            "template": {"metadata": {"labels": labels}, "spec": pod_spec},
        },
    }


class KubernetesBackend:
    def __init__(self, api: KubeApi, options: KubernetesOptions, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.api, self.opts = api, options
        self.clock, self.sleep = clock, sleep
        self.reset_ownership = options.reset_ownership
        ns = quote(options.namespace, safe="")
        self._jobs = f"/apis/batch/v1/namespaces/{ns}/jobs"
        self._pods = f"/api/v1/namespaces/{ns}/pods"

    # Protocol ----------------------------------------------------------
    def preflight(self) -> None:
        status, _ = self.api.request("GET", self._jobs + "?limit=1")
        if status != 200:
            raise BackendUnavailable(f"the runner cannot list Jobs in its namespace (HTTP {status})")

    def remove_leftovers(self, scan_label: str) -> None:
        selector = urlencode({"labelSelector": f"{b.LABEL_PART_OF}={b.PART_OF},{b.LABEL_SCAN}={scan_label}"})
        status, doc = self.api.request("GET", f"{self._jobs}?{selector}")
        if status != 200:
            raise BackendUnavailable(f"the runner cannot list Jobs (HTTP {status})")
        for item in doc.get("items", []):
            name = item.get("metadata", {}).get("name")
            if isinstance(name, str):
                self._delete(name)

    def run(self, spec: b.ContainerSpec, on_line: Callable[[str], None],
            cancelled: Callable[[], bool]) -> b.ContainerOutcome:
        status, doc = self.api.request("POST", self._jobs, job_manifest(spec, self.opts))
        if status not in (200, 201):
            message = doc.get("reason") if isinstance(doc.get("reason"), str) else f"HTTP {status}"
            raise EngineError(f"the Job could not be created ({message})")
        logs = _Follower(self)
        try:
            return self._watch(spec, logs, on_line, cancelled)
        finally:
            logs.drain(on_line)
            logs.stop.set()
            self._delete(spec.name)

    # Internals -----------------------------------------------------------
    def _pod(self, job: str) -> tuple[bool, dict | None]:
        """(answered, pod): answered is False when the API did not answer."""
        selector = urlencode({"labelSelector": f"job-name={job}"})
        try:
            status, doc = self.api.request("GET", f"{self._pods}?{selector}")
        except BackendUnavailable:
            return False, None
        if status != 200:
            return False, None
        items = [p for p in doc.get("items", []) if isinstance(p, dict)]
        return True, (items[0] if items else None)

    @staticmethod
    def _container_status(pod: dict) -> dict:
        for cs in pod.get("status", {}).get("containerStatuses", []) or []:
            if cs.get("name") == CONTAINER:
                return cs
        return {}

    def _watch(self, spec, logs: "_Follower", on_line, cancelled) -> b.ContainerOutcome:
        outcome = b.ContainerOutcome()
        created = self.clock()
        started_at: float | None = None
        failures = 0
        while True:
            logs.drain(on_line)
            if cancelled():
                outcome.cancelled = True
                return outcome
            answered, pod = self._pod(spec.name)
            if not answered:
                # A busy or restarting API server is not the container's
                # failure: keep the container and ask again.
                failures += 1
                if failures * max(self.opts.poll_interval, 1.0) > self.opts.api_patience:
                    raise BackendUnavailable("the Kubernetes API stopped answering during the scan")
                self.sleep(self.opts.poll_interval)
                continue
            failures = 0
            if pod is None:
                if outcome.started:
                    # Evicted, or its node went away: the container was killed.
                    outcome.exit_code = 137
                    outcome.extra["pod_lost"] = True
                    logs.finish(self.opts.log_grace)
                    return outcome
                if self.clock() - created > spec.pull_timeout:
                    outcome.start_error = "Kubernetes: the Pod was not created"
                    return outcome
                self.sleep(self.opts.poll_interval)
                continue
            cs = self._container_status(pod)
            state = cs.get("state", {}) if cs else {}
            pod_name = pod.get("metadata", {}).get("name", "")
            if "terminated" in state:
                outcome.started = True
                logs.ensure(pod_name)
                term = state["terminated"]
                code = term.get("exitCode")
                outcome.exit_code = code if isinstance(code, int) else None
                outcome.oom_killed = term.get("reason") == "OOMKilled"
                logs.finish(self.opts.log_grace)
                return outcome
            if "running" in state:
                if started_at is None:
                    started_at = self.clock()
                    outcome.started = True
                logs.ensure(pod_name)
                if self.clock() - started_at > spec.timeout:
                    outcome.timed_out = True
                    outcome.exit_code = 137
                    return outcome
            elif not outcome.started:
                waiting = state.get("waiting", {}) if state else {}
                reason = waiting.get("reason")
                if reason in _FATAL_WAIT:
                    outcome.start_error = f"Kubernetes: {reason}"
                    return outcome
                if pod.get("status", {}).get("phase") == "Failed" and not cs:
                    outcome.start_error = "Kubernetes: the Pod failed before its container started"
                    return outcome
                if self.clock() - created > spec.pull_timeout:
                    outcome.start_error = (f"Kubernetes: {reason}" if reason in _PULL_WAIT
                                           else "Kubernetes: the Pod did not start in time")
                    return outcome
            self.sleep(self.opts.poll_interval)

    def log_path(self, pod_name: str, since: str | None) -> str:
        query = {"container": CONTAINER, "follow": "true", "timestamps": "true"}
        if since:
            query["sinceTime"] = since
        return f"{self._pods}/{quote(pod_name, safe='')}/log?{urlencode(query)}"

    def _delete(self, job: str) -> None:
        """Delete the Job and its Pod, and return only once no container of it
        runs. Raises ContainerStillRunning when that cannot be confirmed."""
        name = quote(job, safe="")
        selector = urlencode({"labelSelector": f"job-name={job}"})
        deadline = self.clock() + self.opts.delete_grace + 30
        job_deleted = False
        while True:
            try:
                if not job_deleted:
                    status, _ = self.api.request("DELETE", f"{self._jobs}/{name}", {
                        "kind": "DeleteOptions", "apiVersion": "v1", "propagationPolicy": "Background"})
                    job_deleted = status in (200, 202, 404)
                status, doc = self.api.request("GET", f"{self._pods}?{selector}")
            except BackendUnavailable:
                status, doc = 0, {}
            if status == 200:
                running = []
                for pod in (p for p in doc.get("items", []) if isinstance(p, dict)):
                    meta = pod.get("metadata", {})
                    pname = meta.get("name")
                    if not meta.get("deletionTimestamp") and isinstance(pname, str):
                        try:
                            self.api.request("DELETE", f"{self._pods}/{quote(pname, safe='')}",
                                             {"kind": "DeleteOptions", "apiVersion": "v1", "gracePeriodSeconds": 1})
                        except BackendUnavailable:
                            pass
                    if pod.get("status", {}).get("phase") in ("Pending", "Running", "Unknown"):
                        running.append(pod)
                if not running and job_deleted:
                    return
            if self.clock() > deadline:
                raise ContainerStillRunning("an engine Pod could not be confirmed stopped after it was deleted")
            self.sleep(self.opts.poll_interval)


class _Follower:
    """Follows a Pod's log in a thread, reconnecting where it left off.

    Lines carry the API server's timestamps; on a reconnect the lines at or
    before the last one seen are skipped, so a dropped stream neither loses
    nor repeats output.
    """

    def __init__(self, backend: KubernetesBackend):
        self.backend = backend
        self.queue: queue.Queue[str] = queue.Queue()
        self.stop = threading.Event()
        self.thread: threading.Thread | None = None
        self.last_ts: str | None = None
        self.last_key: str | None = None
        self.resume: str | None = None
        self.pod: str | None = None

    @staticmethod
    def _key(ts: str) -> str:
        """RFC 3339 time with its fraction padded, so keys compare as text."""
        head, dot, frac = ts.rstrip("Z").partition(".")
        return head + "." + (frac + "000000000")[:9]

    def _line(self, raw: str) -> None:
        ts, sep, text = raw.partition(" ")
        if not sep or not ts[:4].isdigit():
            self.queue.put(raw)
            return
        key = self._key(ts)
        if self.resume is not None and key <= self.resume:
            return
        if self.last_key is None or key > self.last_key:
            self.last_ts, self.last_key = ts, key
        self.queue.put(text)

    def ensure(self, pod_name: str) -> None:
        """Start following, or follow again when the stream has ended."""
        if self.thread is not None and self.thread.is_alive():
            return
        self.pod = pod_name
        self.resume = self.last_key
        path = self.backend.log_path(pod_name, self.last_ts)
        self.thread = threading.Thread(target=self.backend.api.stream_lines, args=(path, self._line, self.stop),
                                       daemon=True)
        self.thread.start()

    def finish(self, grace: float) -> None:
        """Wait for the stream of an ended container to deliver its last lines."""
        if self.thread is not None:
            self.thread.join(timeout=grace)

    def drain(self, on_line) -> None:
        while True:
            try:
                on_line(self.queue.get_nowait())
            except queue.Empty:
                return
