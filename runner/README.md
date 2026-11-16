# bomlens-runner

Runs the [BomLens](https://github.com/sktelecom/bomlens) SBOM scan engine on Kubernetes or Docker for another program. It runs the engine's execution plan, stage 1 and stage 2 as Jobs or containers, checks the result manifest, and removes every container before it returns. Standard library only, Python 3.10 or later.

The package version is the BomLens release it comes with, and it carries that release's image digests (`bomlens_runner.release_images()`).

Documentation: [Engine runner](https://sktelecom.github.io/bomlens/reference/engine-runner/) and the [engine contract](https://sktelecom.github.io/bomlens/reference/engine-contract/).

Tests: `cd runner/tests && python3 -m unittest`, `tests/test-engine-runner-docker.sh` for a Docker daemon, and `tests/test-engine-runner-kind.sh` for a kind cluster.

Licensed under the Apache License, Version 2.0.
