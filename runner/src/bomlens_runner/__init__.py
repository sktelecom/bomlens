# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Run the BomLens scan engine from another program.

The runner reads the engine's execution plan, runs its containers through a
backend (Kubernetes Jobs or Docker containers), and checks the result manifest, following the
engine contract (docs/reference/engine-contract.md). See
docs/reference/engine-runner.md.
"""

from . import _release
from .backend import (COMPONENTS, LABEL_COMPONENT, LABEL_NETWORK, LABEL_PART_OF, LABEL_SCAN, NETWORK_EGRESS,
                      NETWORK_NONE, PART_OF, Backend, ContainerOutcome, ContainerSpec, EngineContainer, MountSpec)
from .errors import (BackendUnavailable, BomLensError, ContainerStillRunning, ContractError, EngineError,
                     EngineWroteNoResult, ImageNotAllowed, ManifestMissing, OutputTooLarge, PlanRejected,
                     PolicyError, ScanCancelled, ScanTimedOut, UnsupportedContractVersion)
from .images import PinnedImage, image_target
from .manifest import EngineResult, Output, Step, VerifiedOutput, load_manifest, read_output
from .orchestrator import RunResult, StageRecord, run_image_scan, run_source_scan
from .plan import Plan, load_plan
from .policy import Images, Limits, RunnerPolicy, SecretRef, Timeouts, Volume

__version__ = _release.VERSION


def release_images() -> Images:
    """The images of this runner's release, pinned by digest."""
    if not _release.ENGINE_IMAGE:
        raise PolicyError("this runner was not published with a release; name the images in the policy")
    return Images.parse(_release.ENGINE_IMAGE, _release.DEEP_LICENSE_IMAGE or None, _release.DEEP_CVE_IMAGE or None)


__all__ = [
    "BackendUnavailable", "Backend", "BomLensError", "COMPONENTS", "ContainerOutcome", "ContainerSpec",
    "ContainerStillRunning", "ContractError", "EngineContainer", "EngineError", "EngineResult", "EngineWroteNoResult",
    "ImageNotAllowed", "Images", "LABEL_COMPONENT", "LABEL_NETWORK", "LABEL_PART_OF", "LABEL_SCAN", "Limits",
    "ManifestMissing", "MountSpec", "NETWORK_EGRESS", "NETWORK_NONE", "Output", "OutputTooLarge", "PART_OF",
    "PinnedImage", "Plan", "PlanRejected", "PolicyError", "RunResult", "RunnerPolicy", "ScanCancelled",
    "ScanTimedOut", "SecretRef", "StageRecord", "Step", "Timeouts", "UnsupportedContractVersion",
    "VerifiedOutput", "Volume", "image_target", "load_manifest", "load_plan", "read_output", "release_images",
    "run_image_scan", "run_source_scan",
]
