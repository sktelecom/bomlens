# .NET Example

> **English**: A sample project for trying SBOM generation. The scan commands below are language-neutral; for English docs see [getting started](../../docs/start/first-scan.md) and the [usage guide](../../docs/reference/cli.md).

This example demonstrates SBOM generation for a .NET (net8.0) web project using NuGet.

## Project Structure

- `DotNetExample.csproj`: NuGet package references (net8.0)
- `Program.cs`: a minimal ASP.NET Core app

## Dependencies

- **Newtonsoft.Json** (13.0.3): JSON framework
- **Serilog.AspNetCore** (8.0.0): structured logging
- **Microsoft.EntityFrameworkCore.SqlServer** (8.0.0): EF Core SQL Server provider
- Plus transitive dependencies

## Generate SBOM

> **Windows**: run `..\..\scripts\scan-sbom.bat` instead of `scan-sbom.sh` (Git Bash required). For no command line, double-click `scripts\sbom-ui.bat` — see [getting started](../../docs/start/first-scan.md).

```bash
cd examples/dotnet
../../scripts/scan-sbom.sh --project "DotNetExample" --version "1.0.0" --generate-only
```

## Expected Output

The scan generates `DotNetExample_1.0.0_bom.json` with roughly 50–60 NuGet packages:

- Newtonsoft.Json
- Serilog and Serilog.AspNetCore with its sinks
- EntityFrameworkCore and the SqlServer provider, with transitive `Microsoft.*` packages
- Plus transitive dependencies

### Sample Components

- Newtonsoft.Json
- Serilog.AspNetCore
- Microsoft.EntityFrameworkCore.SqlServer
- Microsoft.Data.SqlClient

## Build and Run (Optional)

```bash
dotnet restore
dotnet run
```

## Validate Results

```bash
# Count components
jq '.components | length' DotNetExample_1.0.0_bom.json

# List all packages
jq -r '.components[].name' DotNetExample_1.0.0_bom.json | sort -u
```

## Common Issues

### Restore required for transitive packages

For complete transitive resolution, run `dotnet restore` first so the full package graph is available to the scan.

## Next Steps

- Add more NuGet packages and re-scan
- Compare the SBOM before and after `dotnet restore`
