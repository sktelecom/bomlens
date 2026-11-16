# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Exceptions raised by the runner.

Every message is meant to be shown to a user as it is: it never holds a
workspace path, a value the caller passed in (an image reference, a proxy
address) or a line of container output. The raw output only ever leaves the
runner through the caller's ``on_log`` callback.
"""

MAX_MESSAGE = 300


class BomLensError(Exception):
    """Base of everything the runner raises."""

    def __init__(self, message: str):
        message = " ".join(str(message).split())
        if len(message) > MAX_MESSAGE:
            message = message[: MAX_MESSAGE - 3] + "..."
        super().__init__(message)


class EngineError(BomLensError):
    """A container could not be run, or did not end as it should."""


class BackendUnavailable(EngineError):
    """The container platform cannot be reached or is too old."""


class ContainerStillRunning(EngineError):
    """A container was still running after it was told to stop."""


class EngineWroteNoResult(EngineError):
    """The scan ended without writing its result manifest."""


class ScanTimedOut(EngineError):
    """A single-container scan stopped at its time limit."""


class ScanCancelled(BomLensError):
    """The caller cancelled the scan. Every container has been removed."""


class ContractError(BomLensError, ValueError):
    """A file the engine wrote does not follow the engine contract."""


class PlanRejected(ContractError):
    """The execution plan asks for something the runner does not allow."""


class ImageNotAllowed(PlanRejected):
    """An image is not pinned, or not from an allowed repository."""


class ManifestMissing(ContractError):
    """There is no result manifest in the output folder."""


class UnsupportedContractVersion(ContractError):
    """The engine contract major version is one this runner does not read."""


class OutputTooLarge(ContractError):
    """An output file is over the size the runner reads."""


class PolicyError(BomLensError, ValueError):
    """The caller's policy is not valid."""
