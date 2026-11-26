# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""What the caller decides: images, storage, limits, environment, labels.

The runner never reads its own process environment for a container. Every
value a container gets is either fixed by the runner, fixed by the checked
plan, or named here by the caller and allowed for that container.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from .errors import PolicyError
from .images import PinnedImage, normalize_prefix, stage1_repositories
from .plan import _BUILD_PREP, PROXY_ENV_NAMES, STAGE_PASSTHROUGH_ALLOWED, is_registry_env


@dataclass(frozen=True)
class SecretRef:
    """A value kept in the platform's secret store (a Kubernetes Secret key).

    The runner never sees the value; the container reads it at start.
    """

    name: str
    key: str

    def __post_init__(self):
        if not re.fullmatch(r"[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?", self.name or ""):
            raise PolicyError("secret name is not valid")
        if not re.fullmatch(r"[-._a-zA-Z0-9]{1,253}", self.key or ""):
            raise PolicyError("secret key is not valid")


@dataclass(frozen=True)
class Volume:
    """Storage the worker sees at local_root and containers mount by name.

    name is what the backend mounts: a PersistentVolumeClaim on Kubernetes, a
    named volume or a host folder on Docker.
    """

    name: str
    local_root: Path

    def __post_init__(self):
        if not re.fullmatch(r"[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?", self.name or ""):
            raise PolicyError("volume name is not a claim name")
        object.__setattr__(self, "local_root", Path(self.local_root))


@dataclass(frozen=True)
class Images:
    engine: PinnedImage
    deep_license: PinnedImage | None = None
    deep_cve: PinnedImage | None = None

    @classmethod
    def parse(cls, engine: str, deep_license: str | None = None, deep_cve: str | None = None) -> "Images":
        return cls(PinnedImage.parse(engine),
                   PinnedImage.parse(deep_license) if deep_license else None,
                   PinnedImage.parse(deep_cve) if deep_cve else None)


@dataclass(frozen=True)
class Limits:
    memory_bytes: int = 4 * 1024 ** 3
    cpus: float = 2.0
    pids: int = 4096
    tmp_bytes: int = 8 * 1024 ** 3


@dataclass(frozen=True)
class Timeouts:
    plan: int = 300
    stage1: int = 1800
    restore: int = 600
    stage2: int = 1800
    image: int = 1800
    chown: int = 300
    pull: int = 1800

    def __post_init__(self):
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or not 10 <= value <= 21600:
                raise PolicyError(f"timeout {name} must be 10..21600 seconds")


# Stage 2 (and image scan) options a caller may set: report and lookup
# switches documented in docs/reference/docker-image.md. Names a later
# release adds reach a container only once the runner of that release lists
# them, so an old runner never passes a switch it does not know.
SCAN_OPTION_NAMES = frozenset((
    "GENERATE_SECURITY", "GENERATE_NOTICE", "GENERATE_REPORT", "SECURITY_ENRICH", "SECURITY_NVD_VERIFY",
    "ENRICH_EOL", "ENRICH_MALICIOUS", "ENRICH_OS_CONTEXT", "ENRICH_DISTRO_SUPPLIER", "ENRICH_UPSTREAM_PURL",
    "ENRICH_GITHUB_CPE", "ENRICH_MAVEN_CPE", "ENRICH_INTERPRETER_CPE", "ENRICH_HF_SECURITY",
    "BOMLENS_OS_LICENSES", "BOMLENS_EVENTS", "BOMLENS_DEEP_LICENSE_ALL", "DEEP_LICENSE_MAX_FILES",
    "DEEP_LICENSE_TIMEOUT", "LICENSE_REGISTRY", "LICENSE_REGISTRY_API", "LICENSE_REGISTRY_BUDGET",
    "LICENSE_REGISTRY_VERIFY", "STALENESS_ENRICH", "PURL_RESOLVE", "PURL_RESOLVE_BUDGET",
    "PURL_RESOLVE_IGNORE", "MODEL_RESOLVE", "MODEL_RESOLVE_BUDGET", "MODEL_RESOLVE_MAX", "REACHABILITY",
    "CYCLONEDX_SPEC_VERSION", "CYCLONEDX_SPEC_VERSIONS", "SPDX_SPEC_VERSIONS", "NS_ADVISORY_TYPES",
))

# What an image scan (MODE=IMAGE) takes beyond the scan options: a proxy, an
# extra CA bundle and the age limit of the Trivy database, for a network that
# only reaches an old copy of it.
IMAGE_SCAN_NAMES = SCAN_OPTION_NAMES | frozenset((
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
    "BOMLENS_EXTRA_CA_CERTS", "BOMLENS_TRIVY_DB_MAX_AGE_DAYS",
))

_VALUE_MAX = 4096

# Names the runner sets itself. A caller value for one is refused.
RUNNER_OWNED = frozenset((
    "MODE", "PROJECT_NAME", "PROJECT_VERSION", "HOST_OUTPUT_DIR", "HOST_UID", "HOST_GID", "BOMLENS_RUN_INPUT",
    "BOMLENS_IMAGE_REF", "BOMLENS_IMAGE_DIGEST", "BOMLENS_STAGE1_EXIT", "BOMLENS_STAGE1_OOM",
    "BOMLENS_STAGE1_LOG", "BOMLENS_STAGE1_REUSED", "BOMLENS_STAGE1_REASON", "BOMLENS_GUARD_ID",
    "BOMLENS_GUARD_RESTORE_ONLY", "TARGET_IMAGE", "UPLOAD_ENABLED", "DEEP_LICENSE", "DEEP_CVE",
    "TRIVY_CACHE_DIR", "CDXGEN_IMAGE_PREFIX", "FETCH_LICENSE",
))
# Names whose value is a credential. They are taken only as a SecretRef, so
# the value is never written into a Job.
SECRET_NAMES = frozenset(("NVD_API_KEY", "TRIVY_PASSWORD", "TRIVY_REGISTRY_TOKEN", "TRIVY_USERNAME"))
_PROXY_ADDRESS_NAMES = frozenset(("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"))


def _has_userinfo(value: str) -> bool:
    """Whether a URL (or a list of them) in a setting carries a user name or password."""
    for token in re.split(r"[\s,|]+", value):
        if "://" not in token:
            continue
        try:
            parts = urlsplit(token)
            if parts.username is not None or parts.password is not None:
                return True
        except ValueError:
            return True
    return False


def _check_env(env: Mapping[str, object], allowed: frozenset[str], what: str,
               registry: bool = False) -> dict[str, object]:
    out: dict[str, object] = {}
    for name, value in (env or {}).items():
        if name in RUNNER_OWNED:
            raise PolicyError(f"{what} env {name} is set by the runner")
        is_registry = registry and is_registry_env(name)
        if name not in allowed and not is_registry:
            raise PolicyError(f"{what} env {name} is not one the runner passes")
        if isinstance(value, SecretRef):
            out[name] = value
            continue
        if not isinstance(value, str) or len(value) > _VALUE_MAX or any(c in value for c in "\0\n\r"):
            raise PolicyError(f"{what} env {name} is not a plain string")
        if name in SECRET_NAMES:
            raise PolicyError(f"{what} env {name} is a credential; give it as a SecretRef")
        if (name in _PROXY_ADDRESS_NAMES or is_registry or name == "GOPROXY") and _has_userinfo(value):
            raise PolicyError(f"{what} env {name} holds a user name or password; give it as a SecretRef")
        out[name] = value
    return out


@dataclass(frozen=True)
class RunnerPolicy:
    images: Images
    workspace: Volume
    trivy_db: Volume | None = None
    trivy_db_subpath: str = ""
    stage1_repositories: tuple[str, ...] = ()
    stage1_image_prefix: str | None = None
    limits: Limits = field(default_factory=Limits)
    timeouts: Timeouts = field(default_factory=Timeouts)
    # The uid:gid files are handed back to (HOST_UID/HOST_GID), and the user
    # the plan, stage 2 and image containers run as. None runs them as the
    # image's own user and skips the ownership reset.
    uid: int | None = None
    gid: int | None = None
    read_only_root: bool = True
    stage1_read_only_root: bool = True
    # Capabilities a container that runs as root (stage 1, its restore run,
    # the ownership reset) keeps after every other one is dropped.
    root_capabilities: tuple[str, ...] = ("CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID")
    stage2_network: bool = False
    labels: Mapping[str, str] = field(default_factory=dict)
    stage1_env: Mapping[str, object] = field(default_factory=dict)
    stage2_env: Mapping[str, object] = field(default_factory=dict)
    image_env: Mapping[str, object] = field(default_factory=dict)
    # Folders or files for the caller's mount roles (cache-maven,
    # maven-settings, ...), under the workspace volume.
    caller_mounts: Mapping[str, Path] = field(default_factory=dict)
    # A PEM file of extra CA certificates under the workspace volume, for a
    # proxy that inspects TLS. An image scan, and stage 1 and stage 2 of a
    # source scan, mount it read-only and point BOMLENS_EXTRA_CA_CERTS at it.
    extra_ca_file: Path | None = None
    deep_license: bool = False
    deep_cve: bool = False

    def __post_init__(self):
        object.__setattr__(self, "stage1_image_prefix", normalize_prefix(self.stage1_image_prefix))
        if self.deep_license and not self.images.deep_license:
            raise PolicyError("deep license needs the deep-license image")
        if self.deep_cve and not self.images.deep_cve:
            raise PolicyError("deep CVE needs the deep-cve image")
        if self.deep_license and self.deep_cve:
            raise PolicyError("deep license and deep CVE cannot be combined in one run")
        for value, what in ((self.uid, "uid"), (self.gid, "gid")):
            if value is not None and (not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 2 ** 31):
                raise PolicyError(f"{what} is not a number")
        if (self.uid is None) != (self.gid is None):
            raise PolicyError("uid and gid are set together")
        for cap in self.root_capabilities:
            if not re.fullmatch(r"[A-Z_]{2,32}", cap) or cap in ("SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "ALL"):
                raise PolicyError("root capability is not allowed")
        sub = self.trivy_db_subpath
        if sub and (sub.startswith("/") or ".." in sub.split("/") or not re.fullmatch(r"[A-Za-z0-9._/-]+", sub)):
            raise PolicyError("trivy database subpath is not valid")
        for key, value in self.labels.items():
            if not re.fullmatch(r"([a-z0-9.-]{1,253}/)?[A-Za-z0-9]([A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?", key):
                raise PolicyError("label name is not valid")
            if not re.fullmatch(r"([A-Za-z0-9]([A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?)?", value):
                raise PolicyError("label value is not valid")
            if key.startswith(("app.kubernetes.io/", "bomlens.engine/")):
                raise PolicyError("label name is reserved by the runner")
        object.__setattr__(self, "stage1_env", _check_env(
            self.stage1_env, STAGE_PASSTHROUGH_ALLOWED[1], "stage 1", registry=True))
        object.__setattr__(self, "stage2_env", _check_env(
            self.stage2_env, STAGE_PASSTHROUGH_ALLOWED[2] | SCAN_OPTION_NAMES, "stage 2"))
        object.__setattr__(self, "image_env", _check_env(
            self.image_env, IMAGE_SCAN_NAMES, "image scan"))
        from .plan import CALLER_ROLES
        for role in self.caller_mounts:
            if role not in CALLER_ROLES:
                raise PolicyError(f"mount role {role} is not one the caller provides")

    @property
    def stage1_allowed(self) -> tuple[str, ...]:
        return stage1_repositories(self.stage1_repositories, self.stage1_image_prefix)

    @property
    def stage2_image(self) -> PinnedImage:
        if self.deep_license:
            return self.images.deep_license
        if self.deep_cve:
            return self.images.deep_cve
        return self.images.engine

    @property
    def plan_build_prep_env(self) -> dict[str, object]:
        """The build-prep options MODE=PLAN reads for the input fingerprint."""
        return {k: v for k, v in self.stage1_env.items() if k in _BUILD_PREP}
