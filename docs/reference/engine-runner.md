---
description: The Python package that runs the BomLens scan engine on Kubernetes or Docker for another program, following the engine contract.
---

# Engine runner

A program that uses BomLens as its scan engine can run the engine's containers itself, following the [engine contract](engine-contract.md), or call the engine runner. The runner is a Python package (`bomlens-runner`, standard library only, Python 3.10 or later) that does the part every such program would otherwise write:

- it runs `MODE=PLAN`, reads the execution plan and checks it against what it allows;
- it runs stage 1 and stage 2 as Kubernetes Jobs or Docker containers, passes stage 1's exit code, out-of-memory state and log to stage 2, and runs the source restore after a killed stage 1;
- it checks the result manifest and the output files it lists;
- it removes every Job and Pod before it returns.

The runner of a release knows that release's plan and manifest, so a program that moves to a new runner version gets the engine changes of that release without changing its own code.

## Installing

From the first release that ships the runner, each final release (`MAJOR.MINOR.PATCH`, not a pre-release tag) puts the package on PyPI with the release's version:

```bash
pip install bomlens-runner==<version>
```

Each release's notes list the SHA-256 of the published files and the image digests the package names, so a program can pin both. Before that release, install it from a commit on `main`:

```bash
pip install "git+https://github.com/sktelecom/bomlens@<commit>#subdirectory=runner"
```

A package installed from a commit has no release images: give `images` to the command, or `Images.parse(...)` to `RunnerPolicy`.

The command `bomlens-runner` runs one scan from a JSON policy file. A program calls the package instead.

## Running a source scan

```python
from pathlib import Path
from bomlens_runner import Images, RunnerPolicy, Volume, run_source_scan
from bomlens_runner.kubernetes import KubeApi, KubernetesBackend, KubernetesOptions

policy = RunnerPolicy(
    images=Images.parse("ghcr.io/sktelecom/bomlens:1.15.1@sha256:fae9b3b6e1e023534470f6092a65b61af821b68a0f432d96f27945e96d334e17"),
    workspace=Volume("pvc-workspace", Path("/workspace")),   # the claim, and where this process sees it
    trivy_db=Volume("pvc-trivy", Path("/trivy")),
    uid=1000, gid=1000,
    labels={"example.com/app": "scanner"},
)
backend = KubernetesBackend(KubeApi.in_cluster(),
                            KubernetesOptions(namespace="scan", workspace_claim="pvc-workspace",
                                              trivy_db_claim="pvc-trivy"))
result = run_source_scan(policy, backend, scan_id="a1b2c3", project="app", version="1.0",
                         scan_dir=Path("/workspace/a1b2c3"), source=Path("/workspace/a1b2c3/src"),
                         on_log=lambda stage, line: print(stage, line))
print(result.manifest.run_status, result.output_dir)
```

`run_image_scan` scans an image from its registry in one container (`MODE=IMAGE`); it needs a non-root `uid`. Both return a `RunResult`: the output folder, the checked manifest (`EngineResult`), the plan's status and reason, the detected ecosystem, and each container's exit code, time-out and out-of-memory state (`as_metadata()` gives them as a dictionary). Read the outputs with `read_output`, which checks each file's size and sha256 against the manifest and reads it once.

| Argument | Meaning |
|---|---|
| `scan_id` | 1 to 32 lower-case letters, digits or `-`. Names the Jobs and labels them, so a later call with the same id removes what an interrupted one left |
| `scan_dir` | a folder under the workspace root for this scan. The runner keeps its files in `scan_dir/bomlens/` and replaces that folder |
| `source` | the source tree, under the workspace root |
| `on_stage` | called with `prep`, `cdxgen` and `postprocess` before each step. Raising `ScanCancelled` from it stops the scan |
| `on_log` | called with `(stage, line)` for every line a container prints (lines over 64 KiB are cut, at most 16 MiB per container). This is the only place container output goes: no exception message holds a line of it, or a path |
| `cancel` | a function the runner polls; when it returns true, the running container is stopped and removed and `ScanCancelled` is raised |

## The policy

The runner never reads its own environment for a container. Each value a container gets is fixed by the runner, fixed by the checked plan, or set in the policy and allowed for that container.

| Field | Meaning |
|---|---|
| `images` | the engine image and, when used, the `deep_license` and `deep_cve` images, each as `repository:tag@sha256:...`. `latest` and an image without a digest are refused |
| `workspace`, `trivy_db` | the claim name and where this process sees it. Every path the runner mounts must be under `workspace.local_root` with no symbolic link in it |
| `stage1_repositories`, `stage1_image_prefix` | where the stage 1 image may come from (`ghcr.io/cdxgen/` by default). A mirror prefix replaces the default and is passed to `MODE=PLAN` as `CDXGEN_IMAGE_PREFIX` |
| `limits`, `timeouts` | memory, CPU and `/tmp` size per container; the time limit of each container and of an image pull |
| `uid`, `gid` | the user the plan, stage 2 and image containers run as, and `HOST_UID`/`HOST_GID` for the files stage 1 writes. Give the runner's own user: the files it writes for the containers are readable by their owner only |
| `stage1_env`, `stage2_env`, `image_env` | values for each container, by name. A name the runner sets itself, or one the container does not take, is refused. A value can be a `SecretRef` to a Kubernetes Secret key, so it is never written into a Job; `NVD_API_KEY`, `TRIVY_USERNAME`, `TRIVY_PASSWORD`, `TRIVY_REGISTRY_TOKEN` and a proxy address with a user name or password are taken only that way |
| `extra_ca_file` | a PEM file of extra CA certificates under the workspace volume, for a proxy that inspects TLS. An image scan mounts it read-only and sets `BOMLENS_EXTRA_CA_CERTS` to it. An image scan also takes `BOMLENS_TRIVY_DB_MAX_AGE_DAYS` in `image_env`, for a network that only reaches an old copy of the Trivy database |
| `caller_mounts` | folders or files for the plan's caller roles (`cache-maven`, `cache-gradle`, `maven-settings` and the other settings roles) |
| `labels` | added to every Job and Pod |
| `stage2_network` | gives stage 2 the `egress` label, for lookups that need the network (stage 2 has none by default) |
| `deep_license`, `deep_cve` | run stage 2 in the deep-license or deep-cve image (not both) |

## What it checks

In the plan, the runner refuses: another contract name or major version; stages other than `generate` then `postprocess`; a stage 1 image that is not pinned or not from an allowed repository; a stage 2 image other than the configured one; an unknown mount role, or one in the wrong stage; a mount target that is a system folder, `/`, under `/tmp` or `/trivy-db` (with the documented exceptions) or holds `..`; a plan file outside `bomlens-plan/`; a required caller role; a non-numeric user; an entrypoint other than a shell; a stage 2 env without its required values. Env names off its list are dropped and reported in `RunResult.dropped_plan_env`.

In the result manifest, it refuses: a file that is a symbolic link or over 4 MiB; another contract name or major version; an unknown run or step status; a successful run with a non-zero exit code. An output is refused when its path is not a plain file name, it is over 256 MiB, or its size or sha256 differs from the manifest. Unknown step ids, reasons and roles are kept.

## Kubernetes setup

The runner creates Jobs only. What the cluster provides:

- A namespace whose Pod Security level allows stage 1: it runs as root (`0:0`) with `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETGID` and `SETUID`, because the dependency resolvers install packages and write lock files. `baseline` allows it; `restricted` does not. The other containers run as the policy's non-root user with every capability dropped.
- A Role for the runner's service account: `jobs` (create, get, list, delete), `pods` (get, list, delete) and `pods/log` (get).
- The workspace claim, `ReadWriteMany` when the runner and the Jobs can be on different nodes, and a claim for the Trivy database.
- NetworkPolicies selected by the labels below. The runner does not create them, so it needs no permission on them.

| Label | Values |
|---|---|
| `app.kubernetes.io/part-of` | `bomlens-engine` |
| `app.kubernetes.io/component` | `engine-plan`, `engine-stage1`, `engine-restore`, `engine-stage2`, `engine-image`, `engine-chown` |
| `bomlens.engine/network` | `none` for every container but stage 1 and the image scan, which are `egress` (and stage 2 with `stage2_network`) |
| `bomlens.engine/scan` | the scan id |

A policy that denies all traffic to `bomlens.engine/network: none`, and one that allows DNS and the internet, without the cluster's private ranges, to `egress`, give the containers the same network the CLI does. A CNI that enforces NetworkPolicy is needed. Every Pod has a seccomp profile of `RuntimeDefault`, no service account token, no service links, a read-only root file system and an `emptyDir` at `/tmp`. Kubernetes has no per-Pod process limit, so `limits.pids` applies only where the node's `podPidsLimit` is set.

CI runs the runner against a [kind](https://kind.sigs.k8s.io/) cluster with the image built from the commit (`tests/test-engine-runner-kind.sh`): a source scan, a cancelled scan, an image scan, and the network labels under the two policies above.

## Docker setup

`DockerBackend` runs the same containers through the `docker` CLI, on the daemon `DOCKER_HOST` names. A socket proxy that allows only the container and image endpoints is enough: the runner uses `version`, `image inspect`, `pull`, `create`, `inspect`, `start`, `logs`, `kill`, `rm` and `ps`.

```python
from bomlens_runner.docker import DockerBackend, DockerOptions

backend = DockerBackend(DockerOptions(
    workspace="scan-workspace",         # a named volume, mounted by subpath
    trivy_db="scan-trivy",
    egress_network="scan-egress",       # the network stage 1 and image scans join
    refuse_networks=("app-internal",),  # never joined, whatever the options say
    instance_labels={"example.com/instance": "prod"},
    secrets=lambda ref: read_secret(ref.name, ref.key),
))
```

| Option | Meaning |
|---|---|
| `volume_strategy` | `named` (default): the workspace and Trivy volumes are Docker volumes mounted by subpath, which needs Docker API 1.45 or later. `bind`: they are host folders (API 1.41 or later) |
| `workspace`, `trivy_db` | the volume names, or the absolute host folders with `bind`. The policy's `workspace.local_root` is where the runner sees the same files |
| `egress_network` | the network a container with the `egress` label joins, by name (an id is refused). `host`, `none`, `bridge`, `refuse_networks` and the networks of the worker's own container are refused |
| `worker_container` | the worker's container, to read its networks. By default the runner inspects its `HOSTNAME` when it runs in a container |
| `instance_labels` | labels every container gets, and that scope the removal of an earlier attempt's containers to this installation |
| `secrets` | turns a `SecretRef` into its value when a container is created |

A container's values never reach a command line or the docker CLI's environment: they are written to an env file readable by its owner only, which is removed once the container is created. After a container is created, the mounts and settings the daemon recorded are compared with the ones asked for, and a container that differs is removed without being started. Every container has `--security-opt no-new-privileges`, `--cap-drop ALL` (and the root capabilities for the root containers), memory with no extra swap, a CPU and process limit, a read-only root (stage 1 unless `stage1_read_only_root` is off), `--network none` unless it has the `egress` label, and a `bomlens.engine/deadline` label with the time after which it may be removed. Named volumes are mounted with `volume-nocopy`. `/tmp` is a fresh workspace folder. When `run` returns, the container has been removed, or `ContainerStillRunning` is raised.

The `bomlens-runner` command uses Docker when the policy file has a `docker` object with these options (`secrets` aside). It reads a `SecretRef` `{"secret": {"name": "proxy", "key": "url"}}` from the runner's environment variable `BOMLENS_SECRET_PROXY_URL` (the name and key in upper case, other characters as `_`); those variables are not passed to the `docker` commands.

CI runs the Docker backend on the runner's daemon (`tests/test-engine-runner-docker.sh`): a source scan with a host folder and with a named volume, a cancelled scan, a runner killed during stage 1 whose container is then listed and removed, and an image scan.

## Removing containers a killed worker left

When the process that calls the runner is killed (`SIGKILL`, a hard time limit), the runner's own removal never runs and the container it was following stays. A later call with the same `scan_id` removes it; for the others, a program can clean up on a schedule:

```python
for c in backend.list_engine_containers():
    if c.deadline is None or c.deadline < time.time() or scan_has_ended(c.scan_id):
        backend.remove_engine_container(c.name)
```

`list_engine_containers(labels=None)` returns an `EngineContainer` for each engine container in the backend's scope, running or not: its `name`, `scan_id`, `component`, `deadline` (Unix time) and `running`. A field the platform did not record, or recorded in a form the runner does not write, is `None`. Docker lists the containers with the `instance_labels`; Kubernetes lists the Jobs in the namespace, with a deadline of the Job's start time plus its `activeDeadlineSeconds`. `labels` narrows the list further. Which containers to remove is the program's decision.

`remove_engine_container(name)` removes one container (Docker) or Job and its Pod (Kubernetes) and returns once it is gone, or raises `ContainerStillRunning`. It returns `False` and removes nothing when no engine container in scope has that name. On Kubernetes, Jobs also end at their `activeDeadlineSeconds` and are deleted `ttl_after_finished` seconds later without this.

## Versions

The package has the version of the BomLens release it comes with, and the images of that release. When `images` is not given to the command, it uses them; `release_images()` gives them to a program. A runner reads the contract major version it was made for (1) and refuses another.
