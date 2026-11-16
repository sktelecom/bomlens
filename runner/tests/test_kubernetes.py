# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
"""The Kubernetes backend: the Job it writes and how it follows the Pod."""

import unittest

import _support  # noqa: F401  (puts src on the path)

from bomlens_runner import backend as b
from bomlens_runner.errors import BackendUnavailable, ContainerStillRunning, EngineError
from bomlens_runner.kubernetes import KubeApi, KubernetesBackend, KubernetesOptions, job_manifest
from bomlens_runner.policy import Limits, SecretRef


def spec(**kw):
    args = dict(name="bomlens-s1-2-stage1", component="engine-stage1",
                image="ghcr.io/cdxgen/node@sha256:" + "a" * 64, user="0:0", entrypoint=("sh",),
                args=("/tmp/build-prep.sh", "/app"), workdir=None,
                env={"HOME": "/tmp/sbomhome", "NVD_API_KEY": SecretRef("bomlens", "nvd")},
                mounts=(b.MountSpec("/app", b.VOLUME_WORKSPACE, "scan1/src", False),
                        b.MountSpec("/tmp/build-prep.sh", b.VOLUME_WORKSPACE, "scan1/bomlens/plan-files/x", True),
                        b.MountSpec("/trivy-db", b.VOLUME_TRIVY_DB, "", True)),
                network="egress", read_only_root=True, capabilities=("CHOWN",), limits=Limits(), timeout=100,
                labels={b.LABEL_COMPONENT: "engine-stage1", b.LABEL_NETWORK: "egress"}, pull_timeout=50)
    args.update(kw)
    return b.ContainerSpec(**args)


OPTS = KubernetesOptions(namespace="scan", workspace_claim="pvc-workspace", trivy_db_claim="pvc-trivy",
                         poll_interval=0, delete_grace=1)


class JobManifest(unittest.TestCase):
    def test_pod_is_hardened(self):
        job = job_manifest(spec(), OPTS)
        pod = job["spec"]["template"]["spec"]
        c = pod["containers"][0]
        self.assertEqual(job["spec"]["backoffLimit"], 0)
        self.assertEqual(job["spec"]["activeDeadlineSeconds"], 50 + 100 + 60)
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertFalse(pod["enableServiceLinks"])
        self.assertEqual(pod["restartPolicy"], "Never")
        self.assertEqual(pod["securityContext"]["seccompProfile"], {"type": "RuntimeDefault"})
        sc = c["securityContext"]
        self.assertEqual(sc["capabilities"], {"drop": ["ALL"], "add": ["CHOWN"]})
        self.assertFalse(sc["allowPrivilegeEscalation"])
        self.assertTrue(sc["readOnlyRootFilesystem"])
        self.assertEqual((sc["runAsUser"], sc["runAsGroup"], sc["runAsNonRoot"]), (0, 0, False))
        for key in ("hostNetwork", "hostPID", "hostIPC"):
            self.assertNotIn(key, pod)
        self.assertNotIn("privileged", sc)

    def test_labels_on_job_and_pod(self):
        job = job_manifest(spec(), OPTS)
        self.assertEqual(job["metadata"]["labels"][b.LABEL_NETWORK], "egress")
        self.assertEqual(job["spec"]["template"]["metadata"]["labels"][b.LABEL_COMPONENT], "engine-stage1")

    def test_volumes_and_subpaths(self):
        pod = job_manifest(spec(), OPTS)["spec"]["template"]["spec"]
        vols = {v["name"]: v for v in pod["volumes"]}
        self.assertEqual(vols["workspace"]["persistentVolumeClaim"], {"claimName": "pvc-workspace", "readOnly": False})
        self.assertEqual(vols["trivy-db"]["persistentVolumeClaim"], {"claimName": "pvc-trivy", "readOnly": True})
        self.assertIn("emptyDir", vols["tmp"])
        mounts = {m["mountPath"]: m for m in pod["containers"][0]["volumeMounts"]}
        self.assertEqual(mounts["/app"]["subPath"], "scan1/src")
        self.assertTrue(mounts["/tmp/build-prep.sh"]["readOnly"])
        self.assertNotIn("subPath", mounts["/trivy-db"])
        self.assertEqual(mounts["/tmp"]["name"], "tmp")

    def test_secret_values_are_references(self):
        env = job_manifest(spec(), OPTS)["spec"]["template"]["spec"]["containers"][0]["env"]
        nvd = next(e for e in env if e["name"] == "NVD_API_KEY")
        self.assertEqual(nvd, {"name": "NVD_API_KEY", "valueFrom": {"secretKeyRef": {"name": "bomlens", "key": "nvd"}}})

    def test_non_root_and_image_user(self):
        sc = job_manifest(spec(user="1000:1000", capabilities=()), OPTS)["spec"]["template"]["spec"]["containers"][0]["securityContext"]
        self.assertEqual((sc["runAsUser"], sc["runAsNonRoot"]), (1000, True))
        self.assertEqual(sc["capabilities"], {"drop": ["ALL"]})
        sc = job_manifest(spec(user=None), OPTS)["spec"]["template"]["spec"]["containers"][0]["securityContext"]
        self.assertNotIn("runAsUser", sc)

    def test_missing_claim(self):
        with self.assertRaises(EngineError):
            job_manifest(spec(), KubernetesOptions(namespace="scan", workspace_claim="pvc-workspace"))

    def test_entrypoint_and_args(self):
        c = job_manifest(spec(entrypoint=None, args=()), OPTS)["spec"]["template"]["spec"]["containers"][0]
        self.assertNotIn("command", c)
        self.assertNotIn("args", c)


class FakeApi:
    """Plays the API server: a list of pod states returned in turn."""

    def __init__(self, states, pods_after_delete=None):
        self.states = list(states)
        self.calls = []
        self.deleted = False
        self.pods_after_delete = pods_after_delete or []
        self.lines = []

    def request(self, method, path, body=None):
        self.calls.append((method, path))
        if method == "POST":
            return 201, {}
        if method == "DELETE":
            self.deleted = True
            return 200, {}
        if "/jobs" in path:
            return 200, {"items": []}
        if self.deleted:
            return 200, {"items": self.pods_after_delete}
        state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        if state is None:
            return 200, {"items": []}
        return 200, {"items": [{"metadata": {"name": "p1"}, "status": state}]}

    def stream_lines(self, path, on_line, stop):
        # Like the API server: sinceTime is inclusive, so a reconnect sends
        # the last line again.
        self.streams = getattr(self, "streams", 0) + 1
        for line in self.lines:
            on_line(line)


def cs(state, phase="Running"):
    return {"phase": phase, "containerStatuses": [{"name": "engine", "state": state}]}


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += 10


class Follow(unittest.TestCase):
    def run_spec(self, api, **kw):
        clock = Clock()
        backend = KubernetesBackend(api, OPTS, clock=clock, sleep=clock.sleep)
        lines = []
        out = backend.run(spec(**kw), lines.append, lambda: False)
        return out, lines

    def test_exit_code_and_logs(self):
        api = FakeApi([None, cs({"running": {}}), cs({"terminated": {"exitCode": 3}}, "Failed")])
        api.lines = ["2026-11-16T00:00:01.1Z one", "2026-11-16T00:00:01.12Z two"]
        out, lines = self.run_spec(api)
        self.assertEqual((out.started, out.exit_code, out.oom_killed), (True, 3, False))
        self.assertEqual(lines, ["one", "two"])
        self.assertTrue(api.deleted)

    def test_reconnect_neither_loses_nor_repeats_lines(self):
        api = FakeApi([cs({"running": {}}), cs({"running": {}}), cs({"running": {}}),
                       cs({"terminated": {"exitCode": 0}}, "Succeeded")])
        api.lines = ["2026-11-16T00:00:01.5Z a", "2026-11-16T00:00:01.523456789Z b"]
        out, lines = self.run_spec(api)
        self.assertGreater(api.streams, 1)
        self.assertEqual(lines.count("a"), 1)
        self.assertEqual(lines.count("b"), 1)

    def test_api_error_after_start_keeps_the_container(self):
        class Flaky(FakeApi):
            def request(self, method, path, body=None):
                if method == "GET" and "/pods" in path and not self.deleted and getattr(self, "n", 0) in (1, 2):
                    self.n += 1
                    return 503, {}
                if method == "GET" and "/pods" in path and not self.deleted:
                    self.n = getattr(self, "n", 0) + 1
                return super().request(method, path, body)
        api = Flaky([cs({"running": {}}), cs({"terminated": {"exitCode": 0}}, "Succeeded")])
        clock = Clock()
        clock.t = 10_000  # long past the pull timeout
        backend = KubernetesBackend(api, OPTS, clock=clock, sleep=clock.sleep)
        out = backend.run(spec(pull_timeout=50), lambda line: None, lambda: False)
        self.assertIsNone(out.start_error)
        self.assertEqual(out.exit_code, 0)

    def test_pod_that_disappears_after_start_is_killed(self):
        api = FakeApi([cs({"running": {}}), None])
        out, _ = self.run_spec(api)
        self.assertIsNone(out.start_error)
        self.assertEqual(out.exit_code, 137)
        self.assertTrue(out.killed)

    def test_api_that_stops_answering(self):
        class Down(FakeApi):
            def request(self, method, path, body=None):
                if method == "GET" and "/pods" in path:
                    return 503, {}
                return super().request(method, path, body)
        with self.assertRaises((BackendUnavailable, ContainerStillRunning)):
            self.run_spec(Down([None]))

    def test_delete_that_cannot_be_confirmed(self):
        class NoList(FakeApi):
            def request(self, method, path, body=None):
                if method == "GET" and "/pods" in path and self.deleted:
                    return 403, {}
                return super().request(method, path, body)
        with self.assertRaises(ContainerStillRunning):
            self.run_spec(NoList([cs({"terminated": {"exitCode": 0}}, "Succeeded")]))

    def test_oom(self):
        api = FakeApi([cs({"terminated": {"exitCode": 137, "reason": "OOMKilled"}}, "Failed")])
        out, _ = self.run_spec(api)
        self.assertTrue(out.oom_killed and out.killed)

    def test_timeout_kills(self):
        api = FakeApi([cs({"running": {}})])
        out, _ = self.run_spec(api, timeout=30)
        self.assertTrue(out.timed_out)
        self.assertEqual(out.exit_code, 137)
        self.assertTrue(api.deleted)

    def test_image_pull_failure_is_a_start_error(self):
        api = FakeApi([cs({"waiting": {"reason": "ImagePullBackOff"}}, "Pending")])
        out, _ = self.run_spec(api)
        self.assertFalse(out.started)
        self.assertEqual(out.start_error, "Kubernetes: ImagePullBackOff")

    def test_fatal_wait_is_immediate(self):
        api = FakeApi([cs({"waiting": {"reason": "CreateContainerConfigError"}}, "Pending")])
        out, _ = self.run_spec(api)
        self.assertEqual(out.start_error, "Kubernetes: CreateContainerConfigError")

    def test_cancel(self):
        api = FakeApi([cs({"running": {}})])
        backend = KubernetesBackend(api, OPTS, clock=Clock(), sleep=lambda s: None)
        out = backend.run(spec(), lambda line: None, lambda: True)
        self.assertTrue(out.cancelled)
        self.assertTrue(api.deleted)

    def test_pod_still_running_after_delete(self):
        api = FakeApi([cs({"terminated": {"exitCode": 0}}, "Succeeded")],
                      pods_after_delete=[{"metadata": {"name": "p1", "deletionTimestamp": "x"}, "status": {"phase": "Running"}}])
        with self.assertRaises(ContainerStillRunning):
            self.run_spec(api)

    def test_job_create_refused(self):
        class Refusing(FakeApi):
            def request(self, method, path, body=None):
                if method == "POST":
                    return 403, {"reason": "Forbidden"}
                return super().request(method, path, body)
        with self.assertRaises(EngineError):
            self.run_spec(Refusing([None]))

    def test_preflight(self):
        class Denied(FakeApi):
            def request(self, method, path, body=None):
                return 403, {}
        with self.assertRaises(BackendUnavailable):
            KubernetesBackend(Denied([None]), OPTS).preflight()


class Api(unittest.TestCase):
    def test_plain_http_only_when_allowed(self):
        with self.assertRaises(BackendUnavailable):
            KubeApi("http://127.0.0.1:8001")
        KubeApi("http://127.0.0.1:8001", insecure_http=True)
        with self.assertRaises(BackendUnavailable):
            KubeApi("ftp://x")


if __name__ == "__main__":
    unittest.main()
