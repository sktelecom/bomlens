# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Reading and checking the result manifest (bomlens-result.json).

Read it only after every container of the scan has ended: a running engine
still owns the output folder. Files are opened without following links and
read once, so the bytes that were checked are the bytes the caller keeps.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .errors import ContractError, ManifestMissing, OutputTooLarge, UnsupportedContractVersion

MANIFEST_NAME = "bomlens-result.json"
CONTRACT_NAME = "bomlens-engine"
SUPPORTED_MAJOR = 1
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_BYTES = 256 * 1024 * 1024

RUN_STATUSES = ("succeeded", "succeeded_degraded", "failed", "cancelled")
STEP_STATUSES = ("ok", "degraded", "failed", "skipped", "disabled")

ROLE_SBOM_CYCLONEDX = "sbom.cyclonedx"
ROLE_VULNERABILITIES_TRIVY = "vulnerabilities.trivy"
ROLE_LICENSE_SCAN_SCANCODE = "license-scan.scancode"


def clip(value: object, limit: int = 64) -> str:
    text = "".join(c if c.isprintable() else "?" for c in str(value))
    return text if len(text) <= limit else text[: limit - 3] + "..."


@dataclass(frozen=True)
class Step:
    id: str
    status: str
    reason: str | None
    stage: int
    started_at: datetime
    ended_at: datetime
    detail: str | None = None
    counts: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class Output:
    role: str
    path: str
    sha256: str
    bytes: int


@dataclass(frozen=True)
class EngineResult:
    contract_version: str
    engine_version: str | None
    image: str | None
    image_digest: str | None
    input_kind: str
    input_mode: str
    run_status: str
    run_reason: str | None
    exit_code: int
    started_at: datetime
    ended_at: datetime
    steps: tuple[Step, ...]
    outputs: tuple[Output, ...]
    tools: dict[str, str]
    engines: tuple[str, ...]

    def step(self, step_id: str) -> Step | None:
        return next((s for s in self.steps if s.id == step_id), None)

    def output(self, role: str) -> Output | None:
        return next((o for o in self.outputs if o.role == role), None)


@dataclass(frozen=True)
class VerifiedOutput:
    role: str
    name: str
    sha256: str
    data: bytes
    document: dict[str, Any]


def contract_major(version: str) -> int | None:
    head = version.split("+", 1)[0].split("-", 1)[0]
    parts = head.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return None
    return int(parts[0])


def _require(mapping: Any, key: str, where: str) -> Any:
    if not isinstance(mapping, dict) or key not in mapping:
        raise ContractError(f"result manifest is missing {where}.{key}")
    return mapping[key]


def _str(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise ContractError(f"result manifest field {where} is not a string")
    return value


def _opt_str(value: Any, where: str) -> str | None:
    return None if value is None else _str(value, where)


def _when(value: Any, where: str) -> datetime:
    text = _str(value, where)
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise ContractError(f"result manifest field {where} is not a timestamp") from None
    if moment.tzinfo is None:
        raise ContractError(f"result manifest field {where} has no time zone")
    return moment


def _int(value: Any, where: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ContractError(f"result manifest field {where} is not an integer")
    return value


def _parse_step(raw: Any, index: int) -> Step:
    where = f"steps[{index}]"
    step_id = _str(_require(raw, "id", where), f"{where}.id")
    status = _str(_require(raw, "status", where), f"{where}.status")
    if status not in STEP_STATUSES:
        raise ContractError(f"result manifest step {clip(step_id)!r} has unknown status {clip(status)!r}")
    reason = _opt_str(_require(raw, "reason", where), f"{where}.reason")
    stage = _require(raw, "stage", where)
    if isinstance(stage, bool) or stage not in (1, 2):
        raise ContractError(f"result manifest field {where}.stage is not 1 or 2")
    detail = raw.get("detail")
    counts_raw = raw.get("counts") or {}
    counts = ({str(k): v for k, v in counts_raw.items() if isinstance(v, int) and not isinstance(v, bool)}
              if isinstance(counts_raw, dict) else {})
    return Step(step_id, status, reason, stage,
                _when(_require(raw, "started_at", where), f"{where}.started_at"),
                _when(_require(raw, "ended_at", where), f"{where}.ended_at"),
                detail if isinstance(detail, str) else None, counts)


def _parse_output(raw: Any, index: int) -> Output:
    where = f"outputs[{index}]"
    size = _int(_require(raw, "bytes", where), f"{where}.bytes")
    if size < 0:
        raise ContractError(f"result manifest field {where}.bytes is not a size")
    return Output(_str(_require(raw, "role", where), f"{where}.role"),
                  _str(_require(raw, "path", where), f"{where}.path"),
                  _str(_require(raw, "sha256", where), f"{where}.sha256").lower(), size)


def parse_manifest(document: Any) -> EngineResult:
    """Check a decoded manifest. The contract version is checked first."""
    contract = _require(document, "contract", "manifest")
    if _require(contract, "name", "contract") != CONTRACT_NAME:
        raise ContractError("not a BomLens engine result manifest")
    version = _str(_require(contract, "version", "contract"), "contract.version")
    if contract_major(version) != SUPPORTED_MAJOR:
        raise UnsupportedContractVersion(f"engine contract {clip(version)} is not supported")
    engine = _require(document, "engine", "manifest")
    if not isinstance(engine, dict):
        raise ContractError("result manifest field engine is not an object")
    run_input = _require(document, "input", "manifest")
    run = _require(document, "run", "manifest")
    run_status = _str(_require(run, "status", "run"), "run.status")
    if run_status not in RUN_STATUSES:
        raise ContractError(f"result manifest has unknown run status {clip(run_status)!r}")
    exit_code = _int(_require(run, "exit_code", "run"), "run.exit_code")
    if run_status in ("succeeded", "succeeded_degraded") and exit_code != 0:
        raise ContractError(f"result manifest says {run_status} with exit code {exit_code}")
    raw_steps = _require(document, "steps", "manifest")
    raw_outputs = _require(document, "outputs", "manifest")
    if not isinstance(raw_steps, list) or not isinstance(raw_outputs, list):
        raise ContractError("result manifest steps or outputs is not a list")
    tools_raw = document.get("tools") or {}
    engines_raw = document.get("engines") or []
    return EngineResult(
        contract_version=version,
        engine_version=_opt_str(engine.get("version"), "engine.version"),
        image=_opt_str(engine.get("image"), "engine.image"),
        image_digest=_opt_str(engine.get("image_digest"), "engine.image_digest"),
        input_kind=_str(_require(run_input, "kind", "input"), "input.kind"),
        input_mode=_str(_require(run_input, "mode", "input"), "input.mode"),
        run_status=run_status,
        run_reason=_opt_str(run.get("reason"), "run.reason"),
        exit_code=exit_code,
        started_at=_when(_require(run, "started_at", "run"), "run.started_at"),
        ended_at=_when(_require(run, "ended_at", "run"), "run.ended_at"),
        steps=tuple(_parse_step(s, i) for i, s in enumerate(raw_steps)),
        outputs=tuple(_parse_output(o, i) for i, o in enumerate(raw_outputs)),
        tools={str(k): v for k, v in tools_raw.items() if isinstance(v, str)} if isinstance(tools_raw, dict) else {},
        engines=tuple(e for e in engines_raw if isinstance(e, str)) if isinstance(engines_raw, list) else (),
    )


def decode_json(data: bytes, what: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ContractError(f"{what} is not valid JSON") from None
    except RecursionError:
        raise ContractError(f"{what} is nested too deeply to read") from None
    except ValueError:
        raise ContractError(f"{what} holds a value too large to read") from None


def _plain_name(name: str) -> bool:
    return bool(name) and name not in (".", "..") and not any(c in name for c in "/\\\0")


def read_file(folder: Path, name: str, limit: int, what: str) -> bytes:
    """A regular file directly in folder, opened without following links, read once."""
    if not _plain_name(name):
        raise ContractError(f"{what} is not a file name")
    path = Path(folder) / name
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise ContractError(f"{what} is not in the output folder") from None
    if not stat.S_ISREG(st.st_mode):
        raise ContractError(f"{what} is not a regular file")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise ContractError(f"{what} cannot be opened") from None
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise ContractError(f"{what} is not a regular file")
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise OutputTooLarge(f"{what} is larger than the runner reads")
    return data


def load_manifest(output_dir: Path) -> EngineResult:
    if not os.path.lexists(Path(output_dir) / MANIFEST_NAME):
        raise ManifestMissing("the engine wrote no result manifest; it was stopped before it finished")
    data = read_file(output_dir, MANIFEST_NAME, MAX_MANIFEST_BYTES, "result manifest")
    return parse_manifest(decode_json(data, "result manifest"))


def read_output(output_dir: Path, output: Output, *, limit: int | None = None) -> VerifiedOutput:
    """Read one output once and check its size and sha256 against the manifest."""
    what = f"output for {clip(output.role)}"
    ceiling = MAX_OUTPUT_BYTES if limit is None else min(limit, MAX_OUTPUT_BYTES)
    data = read_file(output_dir, output.path, ceiling, what)
    if len(data) != output.bytes:
        raise ContractError(f"{what} is {len(data)} bytes; the manifest recorded {output.bytes}")
    digest = hashlib.sha256(data).hexdigest()
    if digest != output.sha256:
        raise ContractError(f"{what} does not match the sha256 the manifest recorded")
    document = decode_json(data, what)
    if not isinstance(document, dict):
        raise ContractError(f"{what} is not a JSON object")
    return VerifiedOutput(output.role, output.path, digest, data, document)
