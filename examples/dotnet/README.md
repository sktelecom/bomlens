# .NET Example

> **English**: A sample project for trying SBOM generation. The scan commands below are language-neutral; for English docs see [getting started](../../docs/getting-started.en.md) and the [usage guide](../../docs/usage-guide.en.md).

SBOM generation for .NET projects using NuGet.

## Dependencies

- **Newtonsoft.Json** (13.0.3): JSON library
- **Serilog.AspNetCore** (8.0.0): Logging
- **EntityFrameworkCore** (8.0.0): ORM

## Generate SBOM

> **Windows**: `scan-sbom.sh` 대신 `..\..\scripts\scan-sbom.bat`를 실행하세요(Git Bash 필요). 명령줄 없이 쓰려면 `scripts\sbom-ui.bat`을 더블클릭 — [시작하기](../../docs/getting-started.md) 참고.

```bash
cd examples/dotnet
../../scripts/scan-sbom.sh --project "DotNetExample" --version "1.0.0" --generate-only
```

## Expected Components

~50-60 NuGet packages

## Validate

```bash
jq '.components | length' DotNetExample_1.0.0_bom.json
```
