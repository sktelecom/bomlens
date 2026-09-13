# Modelica Example

> **English**: A sample project for trying SBOM generation. The scan commands below are language-neutral; for English docs see [getting started](../../docs/start/first-scan.md) and the [usage guide](../../docs/reference/cli.md).

This example demonstrates dependency identification for a Modelica (`.mo`) project. cdxgen has no Modelica cataloger, so BomLens instead parses the `annotation(uses(...))` block a `.mo` package declares its dependencies in directly.

## Project Structure

- `Example.mo`: a minimal package with no model body, only a `uses()` declaration

## Dependencies

- **Modelica** (4.0.0): the Modelica Standard Library
- **Buildings** (13.0.0): the Modelica Buildings Library

This is a direct declaration, not a resolved dependency graph: there is no Modelica lockfile to read, so only the libraries a `.mo` file names in its own `uses()` block are identified, with no transitive dependencies.

## Generate SBOM

> **Windows**: run `..\..\scripts\scan-sbom.bat` instead of `scan-sbom.sh` (Git Bash required). For no command line, double-click `scripts\sbom-ui.bat`; see [getting started](../../docs/start/first-scan.md).

```bash
cd examples/modelica
../../scripts/scan-sbom.sh --project "ModelicaExample" --version "1.0.0" --generate-only
```

## Expected Output

The scan writes its outputs into a `ModelicaExample_1.0.0/` folder (`ModelicaExample_1.0.0_bom.json` and related files). The SBOM lists the 2 libraries declared in `Example.mo`'s `uses()` block: Modelica and Buildings.
<!-- expected-components: 2-2 -->

### Sample Components

- Modelica 4.0.0
- Buildings 13.0.0

## Build and Run (Optional)

Not applicable: `Example.mo` has no model body, only a `uses()` declaration, and Modelica has no general-purpose build tool the way the other examples do. There is nothing to compile or run here.

## Validate Results

```bash
# Count components
jq '.components | length' ModelicaExample_1.0.0/ModelicaExample_1.0.0_bom.json

# List the declared libraries
jq -r '.components[].name' ModelicaExample_1.0.0/ModelicaExample_1.0.0_bom.json
```

## Common Issues

### SBOM has 0 components

The scan only finds what a `.mo` file names in its own `uses()` block. If `annotation(uses(...))` is missing, or the file uses a different top-level construct (`model` without a `uses()` annotation, for instance), there is nothing for BomLens to identify.

**Solution:** add a `uses()` annotation naming each library and its version, as in `Example.mo`.

### Transitive dependencies are not resolved

Modelica has no lockfile, so only the libraries declared directly in `uses()` show up; libraries that Modelica or Buildings themselves depend on are not identified.

## Next Steps

- Add another library to the `uses()` annotation and re-scan
- Try a `.mo` file with a `model` body alongside the `uses()` declaration; the model's own components, parameters, and connections are not open-source dependency data, so they are left out of the SBOM
