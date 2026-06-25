# PHP Example

> **English**: A sample project for trying SBOM generation. The scan commands below are language-neutral; for English docs see [getting started](../../docs/start/first-scan.md) and the [usage guide](../../docs/reference/cli.md).

This example demonstrates SBOM generation for a Composer-based PHP project (a Slim micro-framework app).

## Project Structure

- `composer.json`: Composer dependencies
- `index.php`: a small Slim HTTP app

## Dependencies

- **Slim** (^4.12): PSR-7 micro web framework
- **Monolog** (^3.5): structured logging
- **Guzzle** (^7.8): HTTP client
- Plus transitive dependencies

## Generate SBOM

> **Windows**: run `..\..\scripts\scan-sbom.bat` instead of `scan-sbom.sh` (Git Bash required). For no command line, double-click `scripts\sbom-ui.bat` — see [getting started](../../docs/start/first-scan.md).

```bash
cd examples/php
../../scripts/scan-sbom.sh --project "PHPExample" --version "1.0.0" --generate-only
```

## Expected Output

The scan generates `PHPExample_1.0.0_bom.json` containing:

- Slim and its PSR-7 dependencies (psr/http-message, nikic/fast-route, etc.)
- Monolog and psr/log
- Guzzle and its dependencies (guzzlehttp/psr7, guzzlehttp/promises)
- Plus transitive dependencies

### Sample Components

- slim/slim
- monolog/monolog
- guzzlehttp/guzzle
- psr/http-message
- guzzlehttp/psr7

## Build and Run (Optional)

```bash
composer install
php -S localhost:8080 index.php
curl http://localhost:8080/
```

## Validate Results

```bash
# Count components
jq '.components | length' PHPExample_1.0.0_bom.json

# View the Slim entry
jq '.components[] | select(.name | contains("slim"))' PHPExample_1.0.0_bom.json

# List all packages
jq -r '.components[].name' PHPExample_1.0.0_bom.json | sort -u
```

## Common Issues

### composer.lock missing

cdxgen reads `composer.json`, but a committed `composer.lock` pins exact versions. If it is absent, run `composer install` first for the most precise SBOM.

## Next Steps

- Add more Composer packages and re-scan
- Compare the SBOM with and without `composer.lock`
