# Go Example

> **English**: A sample project for trying SBOM generation. The scan commands below are language-neutral; for English docs see [getting started](../../docs/getting-started.en.md) and the [usage guide](../../docs/usage-guide.en.md).

This example demonstrates SBOM generation for Go projects using Go modules.

## Project Structure

- `go.mod`: Go module definition with dependencies
- `main.go`: Gin web server with Cobra CLI
- Popular Go libraries: Gin, Cobra, Logrus

## Dependencies

- **Gin** (v1.9.1): High-performance HTTP web framework
- **Cobra** (v1.8.0): CLI application framework
- **Logrus** (v1.9.3): Structured logger
- Plus transitive dependencies

## Generate SBOM

> **Windows**: `scan-sbom.sh` 대신 `..\..\scripts\scan-sbom.bat`를 실행하세요(Git Bash 필요). 명령줄 없이 쓰려면 `scripts\sbom-ui.bat`을 더블클릭 — [시작하기](../../docs/getting-started.md) 참고.

```bash
cd examples/go
../../scripts/scan-sbom.sh --project "GoExample" --version "1.0.0" --generate-only
```

## Expected Output

The scan generates `GoExample_1.0.0_bom.json` containing:
- ~30-40 total components (including transitive dependencies)
- Gin and its dependencies (net/http2, validator, etc.)
- Cobra and its dependencies (pflag)
- Logrus and dependencies
- Standard library references

### Sample Components

- github.com/gin-gonic/gin v1.9.1
- github.com/spf13/cobra v1.8.0
- github.com/sirupsen/logrus v1.9.3
- github.com/go-playground/validator/v10
- golang.org/x/sys
- golang.org/x/net

## Build and Run (Optional)

```bash
# Download dependencies
go mod download

# Build
go build -o app

# Run
./app
# Server will start on :8080

# Test
curl http://localhost:8080/
curl http://localhost:8080/health
```

## Validate Results

```bash
# Count components
jq '.components | length' GoExample_1.0.0_bom.json

# View Gin entry
jq '.components[] | select(.name | contains("gin"))' GoExample_1.0.0_bom.json

# List all modules
jq -r '.components[] | select(.name | startswith("github.com")) | .name' GoExample_1.0.0_bom.json | sort -u
```

## Common Issues

### go.sum Missing

The scan may generate `go.sum` automatically during dependency resolution.

**Solution:** This is normal. Go modules will be downloaded during the scan.

### Module Download Fails

If you see module download errors:

**Solution:** Ensure internet connectivity. The Docker container needs to access proxy.golang.org.

## Next Steps

- Add more dependencies to `go.mod`
- Try with Go workspace (multi-module projects)
- Compare SBOM with vendored dependencies (`go mod vendor`)
