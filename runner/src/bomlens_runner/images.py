# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Image references: pinned by digest, from allowed repositories."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .errors import ImageNotAllowed, PolicyError

_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
_HOST = r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*(?::[0-9]{1,5})?)"
_TAG = r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
# [host/]path[:tag], the repository part of an image reference.
_REPO_RE = re.compile(rf"(?:{_HOST}/)?{_COMPONENT}(?:/{_COMPONENT})*")
_IMAGE_RE = re.compile(rf"(?P<repo>{_REPO_RE.pattern})(?::(?P<tag>{_TAG}))?")
_PREFIX_RE = re.compile(rf"{_HOST}(?:/{_COMPONENT})*/?")


def _split(ref: str) -> tuple[str, str | None]:
    m = _IMAGE_RE.fullmatch(ref)
    if not m:
        raise ImageNotAllowed("image reference is not valid")
    repo, tag = m.group("repo"), m.group("tag")
    first = repo.split("/", 1)[0]
    if "/" in repo and not ("." in first or ":" in first or first == "localhost"):
        # A first part that is not a host must be a lower-case path component.
        if not re.fullmatch(_COMPONENT, first):
            raise ImageNotAllowed("image reference is not valid")
    return repo, tag


def check_image(image: str, digest: str | None) -> str:
    """Return the repository of image, refusing anything not pinned."""
    if not isinstance(image, str) or not isinstance(digest, str):
        raise ImageNotAllowed("image is not pinned by digest")
    repo, tag = _split(image)
    if tag == "latest":
        raise ImageNotAllowed("image tag 'latest' is not allowed")
    if not DIGEST_RE.fullmatch(digest):
        raise ImageNotAllowed("image is not pinned by digest")
    return repo


@dataclass(frozen=True)
class PinnedImage:
    """An image as ``repository:tag@sha256:...``."""

    ref: str
    digest: str

    @classmethod
    def parse(cls, value: str) -> "PinnedImage":
        if not isinstance(value, str) or "@" not in value:
            raise PolicyError("engine image must be given as repository:tag@sha256:digest")
        ref, digest = value.rsplit("@", 1)
        try:
            _, tag = _split(ref)
            check_image(ref, digest)
        except ImageNotAllowed as exc:
            raise PolicyError(f"engine image is not valid: {exc}") from None
        if not tag:
            raise PolicyError("engine image must have a tag")
        return cls(ref, digest)

    @property
    def repository(self) -> str:
        return _split(self.ref)[0]

    @property
    def run_ref(self) -> str:
        """What a container runs: the repository at the digest."""
        return f"{self.repository}@{self.digest}"

    def __str__(self) -> str:
        return f"{self.ref}@{self.digest}"


DEFAULT_STAGE1_REPOSITORIES = ("ghcr.io/cdxgen/",)


def normalize_prefix(value: str | None) -> str | None:
    """A registry mirror prefix as ``host[/path]/``, or None when unset."""
    if value is None or value == "":
        return None
    if not isinstance(value, str) or len(value) > 200 or not _PREFIX_RE.fullmatch(value):
        raise PolicyError("stage 1 image prefix is not a registry path")
    host = value.split("/", 1)[0]
    if not ("." in host or ":" in host or host == "localhost"):
        raise PolicyError("stage 1 image prefix must start with a registry host")
    return value if value.endswith("/") else value + "/"


def stage1_repositories(listed: tuple[str, ...] | list[str] | None, prefix: str | None) -> tuple[str, ...]:
    """Allowed stage 1 repository prefixes.

    Entries that do not end in "/" are ignored, so "ghcr.io/cdx" cannot allow
    "ghcr.io/cdxevil/...". With a mirror prefix the default is replaced: a
    scan that goes through a mirror must not fall back to the public registry.
    """
    kept = tuple(p for p in (listed or ()) if isinstance(p, str) and p.endswith("/") and len(p) > 1)
    if prefix:
        return tuple(dict.fromkeys(kept + (prefix,)))
    return kept or DEFAULT_STAGE1_REPOSITORIES


def require_allowed(repository: str, allowed: tuple[str, ...]) -> None:
    candidate = repository + "/"
    for prefix in allowed:
        if candidate.startswith(prefix) and len(candidate) > len(prefix):
            return
    raise ImageNotAllowed("stage 1 image is not from an allowed repository")


_TARGET_RE = re.compile(rf"{_IMAGE_RE.pattern}(?:@{DIGEST_RE.pattern})?")


def image_target(reference: str) -> str:
    """An image to scan, as ``registry:<reference>``. The value is never echoed."""
    if not isinstance(reference, str):
        raise PolicyError("image reference is not valid")
    ref = reference.strip()
    if not ref or len(ref) > 512 or not _TARGET_RE.fullmatch(ref):
        raise PolicyError("image reference is not valid")
    try:
        _split(ref.split("@", 1)[0])
    except ImageNotAllowed:
        raise PolicyError("image reference is not valid") from None
    return f"registry:{ref}"
