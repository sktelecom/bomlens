# Contributing

> **한국어**: [CONTRIBUTING.md](CONTRIBUTING.md)

Thanks for your interest in BomLens! Contributions of any kind are welcome — bug fixes, documentation improvements, new language support, and more.

> **Related**: [Architecture](docs/concepts/architecture.md) | [Testing guide](docs/contribute/testing.md) | [Adding a package manager](docs/contribute/package-managers.md)

## Contents

- [Code of conduct](#code-of-conduct)
- [Ways to contribute](#ways-to-contribute)
- [Development setup](#development-setup)
- [Pull request process](#pull-request-process)
- [Coding style](#coding-style)
- [Commit message convention](#commit-message-convention)
- [Issues and discussions](#issues-and-discussions)

## Code of conduct

This project follows a [Code of Conduct](CODE_OF_CONDUCT.en.md) based on the [Contributor Covenant](https://www.contributor-covenant.org/). By participating, you agree to abide by it. Report security vulnerabilities privately per the [Security Policy](SECURITY.en.md).

## Ways to contribute

| Type | How |
|------|-----|
| Bug fix | Find and fix a bug from [Issues](https://github.com/sktelecom/sbom-tools/issues) |
| New language support | See [adding a package manager](docs/contribute/package-managers.md) |
| Documentation | Fix typos, add examples, improve explanations |
| Tests | See the [testing guide](docs/contribute/testing.md) |
| Feature proposal | Discuss first in [Discussions](https://github.com/sktelecom/sbom-tools/discussions) |

When writing or editing Korean documentation, follow the [Korean style guide](docs/korean-style-guide.md).

## Development setup

### Prerequisites

- Docker 20.10+
- Git
- bash (Linux/macOS) or Git Bash (Windows)

### Clone and prepare

```bash
git clone https://github.com/sktelecom/sbom-tools.git
cd sbom-tools

# Build the Docker image (when changing it locally)
cd docker && docker build -t sbom-scanner:local .

# Smoke test
cd examples/nodejs
../../scripts/scan-sbom.sh --project "NodeExample" --version "1.0.0" --generate-only
```

## Pull request process

1. Before a new feature or bug fix, open a related issue first, or note your intent on an existing one.

2. Fork the repository and create a purpose-named branch.
   ```bash
   git checkout -b feat/add-kotlin-support
   git checkout -b fix/java-gradle-detection
   ```

3. Make your changes and confirm all tests pass.
   ```bash
   ./tests/test-scan.sh
   ```

4. Submit a PR that clearly describes the change. Confirm the checklist below.

5. Respond to reviewer feedback and make the needed adjustments.

### PR checklist

- [ ] I added tests for the change.
- [ ] `./tests/test-scan.sh` passes.
- [ ] I updated the relevant documentation.
- [ ] My commit messages follow the [convention](#commit-message-convention).

## Coding style

### Shell scripts

- First line: `#!/usr/bin/env bash`
- Global variables: `UPPER_SNAKE_CASE`, local variables: `lower_snake_case`
- Function names: `lower_snake_case`
- Error handling: `set -euo pipefail` at the top of the script
- Prefer long options over short ones (`--verbose` over `-v`)

```bash
#!/usr/bin/env bash
set -euo pipefail

readonly PROJECT_NAME="${1:-}"

function validate_input() {
    local project_name="$1"
    if [[ -z "$project_name" ]]; then
        echo "ERROR: Project name is required" >&2
        return 1
    fi
}
```

### Dockerfile

- Use official base images
- Combine `RUN` commands to minimize layers
- Add a clear comment to each install step

## Commit message convention

Follow the [Conventional Commits](https://www.conventionalcommits.org/) format.

```
<type>(<scope>): <subject>

[body]

[footer]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | A new feature |
| `fix` | A bug fix |
| `docs` | Documentation changes |
| `test` | Adding or fixing tests |
| `refactor` | Refactoring (no feature/bug change) |
| `chore` | Build, dependencies, and other changes |

### Example

```
feat(scanner): add Kotlin/Gradle support

Add support for Kotlin projects using Gradle build system.
Uses cdxgen with KOTLIN_HOME environment variable.

Closes #42
```

## Issues and discussions

### Bug reports

Please use [GitHub Issues](https://github.com/sktelecom/sbom-tools/issues). Including the following helps us resolve it faster.

- Environment: OS, Docker version, script version
- Reproduction: the minimal steps that reproduce the bug
- Expected vs actual result (include error messages)

### Feature proposals

Discuss first in [GitHub Discussions](https://github.com/sktelecom/sbom-tools/discussions), then move to an issue.

---

Contact: [opensource@sktelecom.com](mailto:opensource@sktelecom.com)
