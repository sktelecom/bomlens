# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
"""The Docker backend with a fake docker CLI."""

import io
import json
import os
import subprocess
import threading
import unittest

import _support  # noqa: F401  (puts src on the path)

from bomlens_runner import backend as b
from bomlens_runner.docker import LABEL_DEADLINE, DockerBackend, DockerCli, DockerOptions
from bomlens_runner.errors import BackendUnavailable, ContainerStillRunning, EngineError, PolicyError
from bomlens_runner.policy import Limits, SecretRef


def spec(**kw):
    args = dict(name="bomlens-s1-2-stage1", component="engine-stage1",
                image="ghcr.io/cdxgen/node@sha256:" + "a" * 64, user="0:0", entrypoint=("sh",),
                args=("/tmp/build-prep.sh", "/app"), workdir=None,
                env={"HOME": "/tmp/sbomhome", "HTTPS_PROXY": SecretRef("proxy", "url")},
                mounts=(b.MountSpec("/app", b.VOLUME_WORKSPACE, "scan1/src", False),
                        b.MountSpec("/tmp/build-prep.sh", b.VOLUME_WORKSPACE, "scan1/bomlens/plan-files/x", True),
                        b.MountSpec("/trivy-db", b.VOLUME_TRIVY_DB, "", True)),
                network="egress", read_only_root=True, capabilities=("CHOWN",), limits=Limits(), timeout=100,
                labels={b.LABEL_COMPONENT: "engine-stage1", b.LABEL_SCAN: "s1", "example.com/role": "engine"},
                scratch_subpath="scan1/bomlens/tmp-2-stage1", pull_timeout=50)
    args.update(kw)
    return b.ContainerSpec(**args)


def opts(**kw):
    args = dict(workspace="scan-workspace", trivy_db="scan-trivy", egress_network="scan-egress",
                secrets=lambda ref: "http://user:pw@proxy.corp:3128", exit_grace=2,
                instance_labels={"example.com/instance": "prod"})
    args.update(kw)
    return DockerOptions(**args)


def done(code=0, out="", err=""):
    return subprocess.CompletedProcess([], code, out.encode(), err.encode())


class FakeCli:
    """Plays the daemon: one container, its state, mounts and logs."""

    def __init__(self, state=None, lines=(), running_polls=0, block=False, stream_ends_early=0,
                 rm_fails=False, create_result=None, host_config=None, kill_works=True):
        self.calls = []
        self.state = state or {"Running": False, "ExitCode": 0, "OOMKilled": False}
        self.lines = list(lines)
        self.running_polls = running_polls
        self.block = block
        self.stream_ends_early = stream_ends_early
        self.rm_fails = rm_fails
        self.create_result = create_result
        self.host_config = host_config
        self.kill_works = kill_works
        self.removed = False
        self.follows = 0
        self.proc = None

    def run(self, argv, timeout):
        self.calls.append(argv)
        cmd = argv[0]
        if cmd == "version":
            return done(out="1.47")
        if cmd == "image":
            return done()
        if cmd == "create":
            path = argv[argv.index("--env-file") + 1]
            with open(path) as fh:
                self.env_file = fh.read()
            self.env_mode = os.stat(path).st_mode & 0o777
            return self.create_result or done(out="cid123")
        if cmd == "kill":
            if self.kill_works:
                self.running_polls = 0
                if self.proc:
                    self.proc.kill()
            return done()
        if cmd == "rm":
            if not self.rm_fails:
                self.removed = True
            return done()
        if cmd == "ps":
            return done(out="cid-left\n")
        if cmd == "inspect":
            if self.removed:
                return done(1, err="Error: No such object: cid123")
            if argv[2] == "{{.Id}}":
                return done(out="cid123")
            if self.running_polls > 0:
                self.running_polls -= 1
                return done(out=json.dumps({"State": {"Running": True}, "HostConfig": self.expected_host()}))
            return done(out=json.dumps({"State": self.state, "HostConfig": self.expected_host()}))
        return done()

    def expected_host(self):
        if self.host_config is not None:
            return self.host_config
        s, be = self.current_spec, self.backend
        named = be.opts.volume_strategy == "named"
        mounts = [{"Type": "volume" if named else "bind", "Source": be._source(m), "Target": m.target,
                   "ReadOnly": m.read_only,
                   "VolumeOptions": {"Subpath": m.subpath or None, "NoCopy": True} if named else None}
                  for m in be._all_mounts(s)]
        return {"Mounts": mounts, "Privileged": False, "Memory": int(s.limits.memory_bytes),
                "PidsLimit": int(s.limits.pids), "NanoCpus": int(s.limits.cpus * 1e9),
                "ReadonlyRootfs": s.read_only_root, "CapDrop": ["ALL"], "CapAdd": [f"CAP_{c}" for c in s.capabilities] or None,
                "SecurityOpt": ["no-new-privileges"], "NetworkMode": be._network(s), "IpcMode": "private"}

    def follow(self, cid, since):
        self.follows += 1
        block = self.block and self.follows > self.stream_ends_early
        lines = self.lines if self.follows == 1 else []

        class Stream:
            def __init__(self):
                self.buf = io.BytesIO("".join(f"{line}\n" for line in lines).encode())
                self.killed = threading.Event()

            def readline(self, n):
                line = self.buf.readline(n)
                if not line and block:
                    self.killed.wait(5)
                return line

        class P:
            def __init__(self):
                self.stdout = Stream()

            def kill(self):
                self.stdout.killed.set()

            def wait(self):
                return 0

            def poll(self):
                return 0 if self.stdout.killed.is_set() else None
        self.proc = P()
        return self.proc

    def argv(self, cmd):
        return next(c for c in self.calls if c[0] == cmd)


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        self.t += 0.5
        return self.t

    def sleep(self, s):
        self.t += s


def make(s=None, cli_kw=None, **kw):
    clock = Clock()
    backend = DockerBackend(opts(**kw), clock=clock, sleep=clock.sleep)
    cli = FakeCli(**(cli_kw or {}))
    cli.backend, cli.current_spec = backend, s or spec()
    backend.cli = cli
    return backend, cli


def run(backend, s=None, cancel=lambda: False):
    lines = []
    out = backend.run(s or spec(), lines.append, cancel)
    return out, lines


class CreateArgs(unittest.TestCase):
    def test_hardening_flags(self):
        backend, cli = make()
        run(backend)
        argv = cli.argv("create")
        for flag in (["--security-opt", "no-new-privileges"], ["--cap-drop", "ALL"], ["--cap-add", "CHOWN"],
                     ["--network", "scan-egress"], ["--user", "0:0"], ["--entrypoint", "sh"]):
            self.assertTrue(any(argv[i:i + 2] == flag for i in range(len(argv))), flag)
        self.assertIn("--read-only", argv)
        self.assertEqual(argv[argv.index("--memory-swap") + 1], argv[argv.index("--memory") + 1])
        for bad in ("--privileged", "--device", "--pid", "--ipc", "--userns", "--volumes-from", "--env"):
            self.assertNotIn(bad, argv)

    def test_values_go_to_an_owner_only_env_file(self):
        backend, cli = make()
        run(backend)
        argv = cli.argv("create")
        joined = " ".join(argv)
        self.assertNotIn("pw@proxy", joined)
        self.assertNotIn("/tmp/sbomhome", joined)
        self.assertIn("HTTPS_PROXY=http://user:pw@proxy.corp:3128\n", cli.env_file)
        self.assertIn("HOME=/tmp/sbomhome\n", cli.env_file)
        self.assertEqual(cli.env_mode, 0o600)
        self.assertFalse(os.path.exists(argv[argv.index("--env-file") + 1]))

    def test_invalid_text_value(self):
        backend, cli = make(secrets=lambda ref: "\ud800")
        with self.assertRaises(EngineError):
            run(backend)

    def test_labels_instance_and_deadline(self):
        backend, cli = make()
        run(backend)
        argv = cli.argv("create")
        labels = [argv[i + 1] for i, a in enumerate(argv) if a == "--label"]
        self.assertIn("example.com/role=engine", labels)
        self.assertIn("example.com/instance=prod", labels)
        self.assertTrue(any(lab.startswith(LABEL_DEADLINE + "=") for lab in labels))

    def test_named_volume_subpaths_nocopy_and_scratch(self):
        backend, cli = make()
        run(backend)
        argv = cli.argv("create")
        mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "--mount"]
        self.assertIn("type=volume,src=scan-workspace,dst=/tmp,volume-subpath=scan1/bomlens/tmp-2-stage1,"
                      "volume-nocopy", mounts)
        self.assertIn("type=volume,src=scan-trivy,dst=/trivy-db,volume-nocopy,readonly", mounts)

    def test_bind_strategy_and_its_verification(self):
        backend, cli = make(volume_strategy="bind", workspace="/srv/ws", trivy_db="/srv/trivy")
        mounts = [backend.mount_args(m) for m in spec().mounts]
        self.assertIn("type=bind,src=/srv/ws/scan1/src,dst=/app", mounts)
        self.assertIn("type=bind,src=/srv/trivy,dst=/trivy-db,readonly", mounts)
        out, _ = run(backend)
        self.assertTrue(out.started)

    def test_bind_paths_must_be_absolute_and_plain(self):
        for bad in ("ws", "/srv/../etc", "/srv/a,b"):
            with self.assertRaises(PolicyError):
                DockerBackend(opts(volume_strategy="bind", workspace=bad, trivy_db=None))
        backend, _ = make(volume_strategy="bind", workspace="/srv/ws", trivy_db=None)
        with self.assertRaises(EngineError):
            backend.mount_args(b.MountSpec("/app", b.VOLUME_WORKSPACE, "../../etc", False))

    def test_no_network(self):
        s = spec(network="none")
        backend, cli = make(s)
        run(backend, s)
        argv = cli.argv("create")
        self.assertEqual(argv[argv.index("--network") + 1], "none")

    def test_entrypoint_must_be_one_program(self):
        backend, _ = make()
        with self.assertRaises(EngineError):
            backend.create_argv(spec(entrypoint=("sh", "-c")))


class Verification(unittest.TestCase):
    def test_mounts_the_daemon_dropped(self):
        backend, cli = make(cli_kw={"host_config": {"Mounts": []}})
        with self.assertRaises(EngineError):
            run(backend)
        self.assertNotIn(["start", "cid123"], cli.calls)
        self.assertTrue(cli.removed)

    def test_settings_the_daemon_changed(self):
        for change in ({"Privileged": True}, {"Memory": 0}, {"CapAdd": ["SYS_ADMIN"]}, {"NetworkMode": "host"},
                       {"ReadonlyRootfs": False}, {"SecurityOpt": []}, {"PidMode": "host"}):
            backend, cli = make()
            cli.host_config = {**cli.expected_host(), **change}
            with self.assertRaises(EngineError, msg=change):
                run(backend)
            self.assertNotIn(["start", "cid123"], cli.calls)


class Running(unittest.TestCase):
    def test_exit_code_logs_and_removal(self):
        backend, cli = make(cli_kw={"state": {"Running": False, "ExitCode": 3},
                                    "lines": ["2026-11-16T00:00:01.5Z a", "2026-11-16T00:00:02Z b"]})
        out, lines = run(backend)
        self.assertEqual((out.started, out.exit_code), (True, 3))
        self.assertEqual(lines, ["a", "b"])
        self.assertTrue(cli.removed)

    def test_oom(self):
        backend, _ = make(cli_kw={"state": {"Running": False, "ExitCode": 137, "OOMKilled": True}})
        out, _ = run(backend)
        self.assertTrue(out.oom_killed and out.killed)

    def test_stream_that_ends_while_the_container_runs_is_not_a_kill(self):
        # The log stream ends at once every time (a log driver that cannot be
        # read); the container keeps running, then exits 0 by itself.
        backend, cli = make(cli_kw={"running_polls": 12})
        out, _ = run(backend)
        self.assertEqual(out.exit_code, 0)
        self.assertFalse(out.timed_out or out.cancelled)
        self.assertNotIn(["kill", "cid123"], cli.calls)
        self.assertGreaterEqual(cli.follows, 2)

    def test_cancel_kills(self):
        backend, cli = make(cli_kw={"block": True, "running_polls": 2})
        out, _ = run(backend, cancel=lambda: True)
        self.assertTrue(out.cancelled)
        self.assertIn(["kill", "cid123"], cli.calls)
        self.assertTrue(cli.removed)

    def test_timeout_kills(self):
        s = spec(timeout=3)
        backend, cli = make(s, cli_kw={"block": True, "running_polls": 10 ** 6})
        out, _ = run(backend, s)
        self.assertTrue(out.timed_out)
        self.assertEqual(out.exit_code, 137)
        self.assertIn(["kill", "cid123"], cli.calls)

    def test_stuck_container(self):
        s = spec(timeout=3)
        backend, cli = make(s, cli_kw={"running_polls": 10 ** 6, "kill_works": False})
        with self.assertRaises(ContainerStillRunning):
            run(backend, s)

    def test_removal_that_cannot_be_confirmed(self):
        backend, cli = make(cli_kw={"rm_fails": True})
        with self.assertRaises(ContainerStillRunning):
            run(backend)

    def test_create_that_fails_still_looks_for_the_container(self):
        backend, cli = make(cli_kw={"create_result": done(-1, err="timed out")})
        out, _ = run(backend)
        self.assertEqual(out.start_error, "Docker: the container could not be created")
        ps = next(c for c in cli.calls if c[0] == "ps")
        self.assertIn("name=^/bomlens-s1-2-stage1$", ps)
        self.assertIn("label=example.com/instance=prod", ps)
        self.assertIn(["rm", "--force", "cid-left"], cli.calls)

    def test_missing_secret_resolver(self):
        backend, _ = make(secrets=None)
        with self.assertRaises(EngineError):
            run(backend)


class Setup(unittest.TestCase):
    def test_forbidden_networks(self):
        for net in ("host", "none", "bridge", "db net", "app-internal", "4f3a2b1c", "a" * 64):
            with self.assertRaises(PolicyError, msg=net):
                DockerBackend(opts(egress_network=net, refuse_networks=("app-internal",)))

    def test_old_api(self):
        backend, cli = make()
        cli.run = lambda argv, timeout: done(out="1.44")
        with self.assertRaises(BackendUnavailable):
            backend.preflight()
        backend, cli = make(volume_strategy="bind", workspace="/srv/ws", trivy_db=None)
        cli.run = lambda argv, timeout: done(out="1.44")
        backend.own_networks = lambda: set()
        backend.preflight()

    def test_worker_network_refused(self):
        backend, cli = make()
        backend.own_networks = lambda: {"scan-egress"}
        with self.assertRaises(PolicyError):
            backend.preflight()
        backend.own_networks = lambda: None
        with self.assertRaises(BackendUnavailable):
            backend.preflight()

    def test_own_networks_parsing(self):
        backend, cli = make(worker_container="worker-1")
        cli.run = lambda argv, timeout: done(out=json.dumps({"app": {"NetworkID": "abc123"}, "scan-x": {}}))
        self.assertEqual(backend.own_networks(), {"app", "abc123", "scan-x"})
        cli.run = lambda argv, timeout: done(1, err="no such container")
        self.assertIsNone(backend.own_networks())
        cli.run = lambda argv, timeout: done(out="[1]")
        self.assertIsNone(backend.own_networks())

    def test_leftovers_scoped_by_instance_labels(self):
        backend, cli = make()
        backend.remove_leftovers("s1")
        ps = cli.calls[0]
        self.assertIn("label=example.com/instance=prod", ps)
        self.assertIn(f"label={b.LABEL_SCAN}=s1", ps)
        self.assertIn(["rm", "--force", "cid-left"], cli.calls)

    def test_bad_options(self):
        with self.assertRaises(PolicyError):
            DockerBackend(opts(volume_strategy="volumes_from"))
        with self.assertRaises(PolicyError):
            DockerBackend(opts(workspace="a,b"))
        with self.assertRaises(PolicyError):
            DockerBackend(opts(instance_labels={"bad key": "x"}))


class Cli(unittest.TestCase):
    def test_timeout_is_an_exit_code(self):
        result = DockerCli("sleep").run(["5"], 0.2)
        self.assertEqual(result.returncode, -1)

    def test_secrets_never_reach_a_docker_child(self):
        from bomlens_runner.docker import _child_env
        os.environ["BOMLENS_SECRET_PROXY_URL"] = "x"
        try:
            self.assertNotIn("BOMLENS_SECRET_PROXY_URL", _child_env())
        finally:
            del os.environ["BOMLENS_SECRET_PROXY_URL"]

    def test_cli_secret_names(self):
        from bomlens_runner.cli import secret_env_name
        self.assertEqual(secret_env_name(SecretRef("bomlens", "nvd-key")), "BOMLENS_SECRET_BOMLENS_NVD_KEY")


if __name__ == "__main__":
    unittest.main()
