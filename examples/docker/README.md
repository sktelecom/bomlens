# Docker Image Example

> **English**: A sample project for trying SBOM generation. The scan commands below are language-neutral; for English docs see [getting started](../../docs/start/first-scan.md) and the [usage guide](../../docs/reference/cli.md).

This example builds a multi-stage Docker image for a Node.js application and scans the built image, rather than scanning source code directly. The base image is `node:18-alpine`.

## Project Structure

- `Dockerfile`: a two-stage build; the builder stage runs `npm install --omit=dev`, and the runtime stage copies only `node_modules`, `package*.json`, and `index.js` onto a fresh `node:18-alpine` base
- `package.json` and `index.js`: not committed here; they are copied in from `../nodejs` before building

## Dependencies

The image combines two layers, and the SBOM covers both:

- Alpine Linux OS packages from the `node:18-alpine` base image
- The production npm dependencies from `../nodejs` (Express, Helmet, CORS, Morgan, Lodash, Moment, Winston, and others); `--omit=dev` in the Dockerfile excludes devDependencies such as Jest and ESLint

## Generate SBOM

> **Windows**: run `..\..\scripts\scan-sbom.bat` instead of `scan-sbom.sh` (Git Bash required). For no command line, double-click `scripts\sbom-ui.bat`; see [getting started](../../docs/start/first-scan.md).

Build the image first, since this example scans a built image rather than a source folder:

```bash
cd examples/docker
cp ../nodejs/package*.json ../nodejs/index.js .
docker build -t sbom-example:latest .
```

Then scan the image:

```bash
../../scripts/scan-sbom.sh \
  --target "sbom-example:latest" \
  --project "DockerImageExample" \
  --version "1.0.0" \
  --generate-only
```

## Expected Output

The scan writes its outputs into a `DockerImageExample_1.0.0/` folder (`DockerImageExample_1.0.0_bom.json` and related files). The SBOM lists roughly 100-150 components:
<!-- expected-components: 100-150 -->

- Alpine Linux system packages (about 20-30)
- Node.js runtime files (about 10-20)
- npm packages from the production dependency set (about 70-100)

### Sample Components

- express
- helmet
- cors
- winston
- an Alpine base package such as musl or busybox

## Build and Run (Optional)

```bash
docker run -p 3000:3000 sbom-example:latest
curl http://localhost:3000/
curl http://localhost:3000/health
```

## Validate Results

```bash
# Count components
jq '.components | length' DockerImageExample_1.0.0/DockerImageExample_1.0.0_bom.json

# List OS packages
jq -r '.components[] | select(.type == "operating-system") | "\(.name)@\(.version)"' DockerImageExample_1.0.0/DockerImageExample_1.0.0_bom.json

# List npm packages
jq -r '.components[] | select(.purl | contains("npm")) | "\(.name)@\(.version)"' DockerImageExample_1.0.0/DockerImageExample_1.0.0_bom.json
```

## Common Issues

### Image not found

```bash
docker images | grep sbom-example
```

**Solution:** confirm the build step above completed before running the scan.

### Docker socket permission denied

The scanner needs access to `/var/run/docker.sock`.

```bash
ls -la /var/run/docker.sock
sudo usermod -aG docker $USER
```

Log out and back in after adding your user to the `docker` group.

### Generating an SBOM with Syft directly

For a quick check without BomLens:

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
syft sbom-example:latest -o cyclonedx-json > bom.json
```

## Next Steps

- Scan a registry image (for example `nginx:alpine`) or a tar file saved with `docker save`, by passing that name or path to `--target`; private registries need `docker login` first
- Add another npm dependency in `../nodejs`, rebuild the image, and rescan
- Compare this SBOM with a source scan of `../nodejs` alone; the OS-layer components are the difference
