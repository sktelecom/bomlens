# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""What a container platform must do for the runner.

The orchestrator decides every container completely (ContainerSpec); a
backend only runs it. A backend must not add privileges, devices, host paths
or networks the spec does not name, and when ``run`` returns or raises, the
container must have ended and been removed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Mapping, Protocol

from .policy import Limits, SecretRef

# Labels every container carries. A cluster selects on them, for example a
# NetworkPolicy that denies all traffic to network=none.
LABEL_PART_OF = "app.kubernetes.io/part-of"
LABEL_COMPONENT = "app.kubernetes.io/component"
LABEL_SCAN = "bomlens.engine/scan"
LABEL_NETWORK = "bomlens.engine/network"
PART_OF = "bomlens-engine"
COMPONENTS = ("engine-plan", "engine-stage1", "engine-restore", "engine-stage2", "engine-image", "engine-chown")
NETWORK_NONE = "none"
NETWORK_EGRESS = "egress"

VOLUME_WORKSPACE = "workspace"
VOLUME_TRIVY_DB = "trivy-db"


@dataclass(frozen=True)
class MountSpec:
    target: str
    volume: str          # VOLUME_WORKSPACE or VOLUME_TRIVY_DB
    subpath: str         # relative to the volume root, "" for the root
    read_only: bool


@dataclass(frozen=True)
class ContainerSpec:
    name: str
    component: str
    image: str           # repository@sha256:...
    user: str | None     # "uid:gid", or None for the image's own user
    entrypoint: tuple[str, ...] | None
    args: tuple[str, ...]
    workdir: str | None
    env: Mapping[str, "str | SecretRef"]
    mounts: tuple[MountSpec, ...]
    network: str         # NETWORK_NONE or NETWORK_EGRESS
    read_only_root: bool
    capabilities: tuple[str, ...]   # added after every capability is dropped
    limits: Limits
    timeout: int
    labels: Mapping[str, str]
    # A writable /tmp the container needs. The subpath is a fresh, empty
    # workspace folder a backend may use for it; a backend with memory or
    # node-local scratch (tmpfs, emptyDir) may ignore it.
    scratch_subpath: str = ""
    pull_timeout: int = 1800


@dataclass
class ContainerOutcome:
    started: bool = False
    exit_code: int | None = None
    oom_killed: bool = False
    timed_out: bool = False
    cancelled: bool = False
    # Why the container never started (an image that could not be pulled).
    # Short, never a path or a value from the caller.
    start_error: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def killed(self) -> bool:
        return self.timed_out or self.oom_killed or self.exit_code in (137, 143)


class Backend(Protocol):
    #: Whether the orchestrator should run its ownership-reset container
    #: after a source scan (files stage 1 wrote as root).
    reset_ownership: bool

    def preflight(self) -> None:
        """Raise BackendUnavailable when the platform cannot run the scan."""

    def remove_leftovers(self, scan_label: str) -> None:
        """Remove containers an earlier attempt of this scan left behind."""

    def run(self, spec: ContainerSpec, on_line: Callable[[str], None],
            cancelled: Callable[[], bool]) -> ContainerOutcome:
        """Run spec to its end, feeding each output line to on_line.

        Stops the container when cancelled() turns true or the timeout passes.
        Returns only once the container has ended and been removed; raises
        ContainerStillRunning if it could not be made to end.
        """
