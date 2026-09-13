# Node.js Example

> **English**: A sample project for trying SBOM generation. The scan commands below are language-neutral; for English docs see [getting started](../../docs/start/first-scan.md) and the [usage guide](../../docs/reference/cli.md).

This example demonstrates SBOM generation for a Node.js project using npm, an Express-based REST API with common middleware and utility packages.

## Project Structure

- `package.json`: npm dependencies
- `index.js`: an Express app with a few JSON endpoints

## Dependencies

- **Express** (^4.18.2): web framework
- **Helmet** (^7.1.0): security headers
- **CORS** (^2.8.5): cross-origin support
- **Morgan** (^1.10.0): request logging
- **Winston** (^3.11.0): application logging
- **Lodash** (^4.17.21) and **Moment** (^2.29.4): utilities
- **Axios** (^1.6.2): HTTP client
- dotenv (^16.3.1) and compression (^1.7.4): environment config and gzip response compression
- devDependencies (Jest, ESLint, Prettier, nodemon, supertest) are excluded from the scan; see Common Issues

## Generate SBOM

> **Windows**: run `..\..\scripts\scan-sbom.bat` instead of `scan-sbom.sh` (Git Bash required). For no command line, double-click `scripts\sbom-ui.bat`; see [getting started](../../docs/start/first-scan.md).

```bash
cd examples/nodejs
../../scripts/scan-sbom.sh --project "NodeJsExpressExample" --version "1.0.0" --generate-only
```

## Expected Output

The scan writes its outputs into a `NodeJsExpressExample_1.0.0/` folder. The main SBOM, `NodeJsExpressExample_1.0.0/NodeJsExpressExample_1.0.0_bom.json`, lists roughly 100-140 components (production plus transitive dependencies):
<!-- expected-components: 100-140 -->

- Express stack: express, body-parser, cookie-parser, serve-static
- Security: helmet, cors
- Utilities: lodash, moment, dotenv
- Logging: morgan, winston
- HTTP: axios, http-errors
- Compression: compression

### Sample Components

- express
- helmet
- cors
- lodash
- winston

## Build and Run (Optional)

```bash
npm install
npm start
# Visit http://localhost:3000
```

## Validate Results

```bash
# Count components
jq '.components | length' NodeJsExpressExample_1.0.0/NodeJsExpressExample_1.0.0_bom.json

# View the Express entry
jq -r '.components[] | select(.name | contains("express")) | "\(.name)@\(.version)"' NodeJsExpressExample_1.0.0/NodeJsExpressExample_1.0.0_bom.json
```

## Common Issues

### package-lock.json missing

The scan still reads dependencies from `package.json` without a lock file, but a committed `package-lock.json` pins exact versions for a reproducible SBOM.

**Solution:** run `npm install --package-lock-only` (or a full `npm install`) first.

### devDependencies missing from the SBOM

This is expected: the scan is filtered to the production dependency set, so `jest`, `eslint`, `prettier`, `nodemon`, and `supertest` are dropped and the result reflects what actually ships.

### SBOM is empty

```bash
ls -la package.json
npm list
```

**Solution:** confirm `package.json` is where the scan expects it, and that its dependencies are installed or at least resolvable.

### npm install fails

```bash
npm cache clean --force
rm -rf node_modules package-lock.json
npm install
```

### Generating an SBOM with cyclonedx-npm instead

```bash
npx @cyclonedx/cyclonedx-npm --output-file bom.json
```

## Next Steps

- Add more npm dependencies and re-scan
- Commit `package-lock.json` for a reproducible, fully pinned SBOM
- Try a Yarn (`yarn.lock`) or pnpm (`pnpm-lock.yaml`) project; the same command works, just point `--project` at your own name
