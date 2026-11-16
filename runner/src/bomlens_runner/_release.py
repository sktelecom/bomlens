# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""The BomLens release this runner was published with.

The release workflow fills these in when it publishes the package, after the
images are pushed, so a runner always names the images of its own release.
A checkout has no release and leaves them empty.
"""

VERSION = "0.0.0.dev0"
ENGINE_IMAGE = ""
DEEP_LICENSE_IMAGE = ""
DEEP_CVE_IMAGE = ""
