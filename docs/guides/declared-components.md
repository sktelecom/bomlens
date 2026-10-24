---
description: List the components a scan cannot find, such as your own executables, libraries and firmware or a vendor's binaries, in a CycloneDX file, so a source scan adds them to the SBOM with hashes and file properties and the result can be checked against BSI TR-03183-2.
---

# Declaring your own components

A source scan reads package managers and lock files, so it finds the open source a project depends on. It cannot find what you built yourself, or what was put into the tree by hand. A declaration file lists those components. A source scan adds them to the SBOM and reads the hashes and file properties from the build outputs you name, so nobody has to type them in.

This is what the `bsi-tr-03183-2` conformance profile measures, and what lets your own components pass a submission review without a purl. Both are covered at the end of this page.

## What goes in the file?

Only what the scan cannot find. Typically:

- your own executables, libraries, firmware images and archives, one component per delivered program or file
- binaries a vendor supplied, such as a chip vendor's driver or a prebuilt library
- source copied into the tree without a package manager, such as a HAL or an RTOS

Open source that a package manager or lock file brings in is found by the scan and does not belong in the file. Scan once without a declaration file and list only what is missing from that SBOM. A component listed in both places is kept twice (the scan warns when the two have the same purl). For open source copied into C/C++ source, [`--identify-vendored`](identify-vendored.md) can identify part of it from the files themselves.

## Where does the file go?

A source scan reads `sbom-declared.cdx.json` at the root of the scan target when that file exists. To keep the file elsewhere, or to split it, pass `--components <file>`; repeat the option for several files, for example one per module in a monorepo or one per vendor directory. With `--components`, the file at the root is not read.

Whichever file a component is written in, a `bomlens:artifact` path is relative to the scan target root, not to the declaration file.

`--no-components` skips the file at the root, for a scan made before the build outputs it names exist. It cannot be combined with `--components`.

Declaration files are read by source scans and by a Yocto build directory given as `--target` (see [A Yocto image](#a-yocto-image)); a firmware, image, binary or `--analyze` run stops with an error when given `--components`. The web UI has no `--components` option: put `sbom-declared.cdx.json` at the root of the folder you scan, a source tree or a Yocto build directory. Its **Read sbom-declared.cdx.json** switch under Result quality, on by default, is the UI's `--no-components`. When the file is refused, the failed scan lists the reasons and offers the `_bom.refused.json` to view or download, and in a finished scan the Components section marks each declared component with a "first-party" or "third-party" badge. See the [web UI reference](../reference/ui.md).

## What does the file look like?

The file is a CycloneDX document that holds only `components` (and, if you want, `dependencies`). Field names are the standard CycloneDX ones.

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {
      "type": "application",
      "name": "media-daemon",
      "supplier": { "name": "Example Corp", "url": ["https://example.com"] },
      "licenses": [ { "license": { "name": "LicenseRef-ExampleCorp-Proprietary" } } ],
      "properties": [
        { "name": "bomlens:origin", "value": "first-party" },
        { "name": "bomlens:artifact", "value": "out/bin/media-daemon" }
      ]
    },
    {
      "type": "library",
      "name": "vendor-hal",
      "version": "4.2.0",
      "supplier": { "name": "Example Chip Vendor", "url": ["https://chip.example.com"] },
      "licenses": [ { "license": { "id": "BSD-3-Clause" } } ],
      "properties": [
        { "name": "bomlens:origin", "value": "third-party" }
      ]
    }
  ]
}
```

`bomFormat` must be `CycloneDX` and `components` must be an array; `specVersion` is optional.

Every component needs the property `bomlens:origin`, given once, with the value `first-party` (built by you) or `third-party` (received from someone else). There is no default value. With a default, a vendor binary left unmarked could count as your own and skip the purl requirement described below.

A `first-party` component without a `version` takes the product version (`--version`). A `third-party` component must give the version it was received at.

`bomlens:artifact` names a build output, as a path relative to the scan target root with forward slashes. It is optional, and may repeat when a component is delivered as several files. Leave it out for a component that has no file of its own, such as a HAL or RTOS compiled into the firmware.

`bomlens:distribution-url` is optional: where the delivered file can be downloaded, as an http or https URL or a relative path inside the delivery. Without it, the build output's path is used.

`dependencies` is optional. Each `ref` must be a component of the same file, and `dependsOn` may name a component of any declaration file or one the scan found, by `bom-ref`. A component without a `bom-ref` gets `declared:<name>@<version>`.

### Which CycloneDX fields can a component use?

`name`, `version`, `bom-ref`, `group`, `description`, `copyright`, `cpe`, `purl`, `publisher`, `author`, `mime-type`, `type`, `scope`, `tags`, `supplier`, `manufacturer`, `authors`, `hashes`, `licenses`, `externalReferences` and `properties`. Each is checked against the shape the CycloneDX 1.6 schema gives it. Any other field, nested `components` included, is refused by name rather than copied into the SBOM unchecked. List every component at the top level of the file.

### How are licences written?

A licence `id` must be on the SPDX License List. For a licence the list does not hold, such as your own proprietary terms, use `name` with a `LicenseRef-` value made of letters, digits, `.` and `-`, for example `LicenseRef-ExampleCorp-Proprietary`. A plain name such as `Proprietary` is accepted by the scan, but the BSI profile reads only an SPDX id, an expression or a `LicenseRef-` name. One SPDX `expression` can be given instead of a list.

A licence given without an `acknowledgement` is written as `concluded`, the licence the component is distributed under, which is the distribution licence BSI TR-03183-2 asks for. An `acknowledgement` the file gives is kept.

## What does BomLens fill in?

For a component with one build output, read from the file itself:

- the SHA-512 and SHA-256 hashes
- `bsi:component:filename`, the file name without its path
- `bsi:component:executable` (`executable` for an ELF program or shared library, a PE file or a Mach-O binary), `bsi:component:archive` (`archive` for zip, tar, gzip, bzip2, xz, zstd, lz4, 7z, rar, ar and deb, rpm, cpio and ISO 9660) and `bsi:component:structured` (`structured` for an archive that lists its contents, a compressed tar included; a plain program, a firmware image and a single compressed stream are `unstructured`)
- an `externalReferences` entry of type `distribution` carrying the SHA-512, with `bomlens:distribution-url` or the build output's path as its `url`

A value the file gives for one of the three `bsi:component:*` properties is kept instead of the one read from the build output. A hash the file gives must match the build output.

A component with several build outputs gets one nested component of type `file` per output, each with its own hashes, properties and `distribution` entry, and carries no hashes itself, since one set of hashes cannot describe several files.

The product depends on each declared component (in a file with `dependencies`, on each one nothing else depends on), so the dependency graph reaches all of them. Every component added this way carries `bomlens:declared` `true`.

## What is refused, and why?

A file that breaks a rule is refused. The scan prints every reason with the file and component, stops before the SBOM is normalized, signed or uploaded, and exits 1. The SBOM written up to that point is kept as `{Project}_{Version}_bom.refused.json`, not `_bom.json`, so a later step that picks up `_bom.json` cannot take the incomplete one. The next scan of the same project and version removes it.

| Refused | Why |
|---|---|
| `bomlens:origin` missing, given twice, or not `first-party` or `third-party` | without it a vendor's binary could pass as your own and skip the purl requirement |
| a `third-party` component without `version` | the version received is what vulnerabilities are matched against, and the scan cannot guess it |
| a `bomlens:artifact` file that does not exist | a file that silently drops out is the same omission as writing the list by hand. When the file at the scan root was read by default, the message points to `--no-components`; a file under an `--exclude` path is reported as excluded |
| a `bomlens:artifact` path that is absolute, contains `..` or a backslash, leads out through a symbolic link, or is not a regular file | the build output has to be inside what was scanned |
| the same `name` and `version` in two places, in one file or across files | one component, one entry |
| a `bom-ref` already used by a component the scan found, or used twice | references must point to one component |
| a field outside the list above, nested `components`, or a value of the wrong shape | the file is outside input, and nothing goes into the SBOM unchecked |
| a licence `id` not on the SPDX License List | use a `LicenseRef-` name instead (the message suggests one) |
| a hash that does not match the build output, a BLAKE3 hash, or hashes on a component with several build outputs | a hash that cannot be checked against the file is not trusted |
| a `bsi:component:*` value other than the ones BSI TR-03183-2 defines, or one given for a component with several build outputs | each value describes one file |
| a `bomlens:distribution-url` that is neither an http(s) URL nor a relative path inside the delivery, or one given for a component with several build outputs | each build output is named by its own path |
| a `dependencies` entry naming a component that is neither declared nor found by the scan | the graph must stay connected |
| a file over 4 MiB, with more than 10,000 components, not UTF-8 JSON, or not a CycloneDX document | the file has to be a CycloneDX document of a size the scan can check |

## When does a first-party component need no purl?

Your own build outputs are not published to a package repository, so they have no purl. In every conformance profile, `skt-submission` included, a declared component is left out of the PURL coverage, "Traceable PURL (no pkg:generic)" and "No upstream purl" rows when all of these hold:

- its `bomlens:origin` is `first-party`
- it has a `supplier` with a name or URL
- it has a SHA-512, which BomLens computes from its `bomlens:artifact` file (or every one of its nested files has one)
- it was added by the declaration file in this same scan

Such components are listed by name on the advisory row "First-party components identified by supplier and SHA-512 instead of a purl". A `third-party` component still needs a purl, and nothing is exempted when an SBOM is checked with `--analyze`, even one that marks components `first-party`. See [Reading the conformance check report](supplier-sbom.md#reading-the-conformance-check-report).

## Checking the SBOM against BSI TR-03183-2

```bash
./scripts/scan-sbom.sh --project MediaBox --version 2.1.0 \
  --conformance-profile bsi-tr-03183-2 --fail-on-conformance \
  --supplier "Example Corp <https://example.com>" \
  --sbom-author "Example Corp <sbom@example.com>" \
  --license LicenseRef-ExampleCorp-Proprietary
```

The profile measures BSI TR-03183-2 v2.1.0. It requires CycloneDX 1.6 or later (the default output), and:

- an SBOM creator with an email address or URL: `--sbom-author "Name <email>"` writes it to `metadata.authors`
- the product (`metadata.component`) with a creator that has a URL or email (`--supplier "Name <https://...>"` or `"Name <email>"`), a name, a version (`--version`), and a concluded licence (`--license`, an SPDX identifier, expression or `LicenseRef-` name, written as `concluded`)
- a dependency graph that reaches every component from the product. The row warns when the SBOM does not state its completeness (`compositions`)
- for each declared component, a supplier or manufacturer with a URL or contact email, a name and version, and a concluded licence as an SPDX identifier, expression or `LicenseRef-` name
- for each declared component that names a build output, its file name, SHA-512 and the three file properties, which BomLens fills from `bomlens:artifact`

A declared `library` or `framework` with no file of its own (linked into another component) is listed on an advisory row instead of failing the file rows. A declared component of any other type without a file, an application or firmware for example, fails them. The components the scan found are measured on one advisory row, with counts and each component's gaps, and do not change the result. PURL coverage is advisory in this profile.

A row that fails makes the report say "fail"; `--fail-on-conformance` turns that into exit code 2. The full rule list is in the [CLI reference](../reference/cli.md#options-reference) under `--conformance-profile`.

## Examples by platform

The examples show only the `components` entries; put them in a file shaped like the one above.

### A Linux application in C/C++

A C/C++ application with a Conan lock file: the scan reads `conan.lock` for the open source, and the declaration file lists the programs the build writes to `out/bin/`.

```json
{
  "type": "application",
  "name": "media-daemon",
  "supplier": { "name": "Example Corp", "url": ["https://example.com"] },
  "licenses": [ { "license": { "name": "LicenseRef-ExampleCorp-Proprietary" } } ],
  "properties": [
    { "name": "bomlens:origin", "value": "first-party" },
    { "name": "bomlens:artifact", "value": "out/bin/media-daemon" }
  ]
}
```

Run the build before the scan, so `out/bin/media-daemon` exists when it is read.

### An Android device build

Scan the tree that holds `out/`. Vendor binaries that come prebuilt are `third-party` with the version the vendor gave; a service you build yourself is `first-party`.

```json
{
  "type": "library",
  "name": "libvendor-camera",
  "version": "3.4.1",
  "supplier": { "name": "Example Chip Vendor", "url": ["https://chip.example.com"] },
  "licenses": [ { "license": { "name": "LicenseRef-ExampleChipVendor-Binary" } } ],
  "properties": [
    { "name": "bomlens:origin", "value": "third-party" },
    { "name": "bomlens:artifact", "value": "out/target/product/<device>/vendor/lib64/libvendor-camera.so" }
  ]
},
{
  "type": "application",
  "name": "example-camera-service",
  "supplier": { "name": "Example Corp", "url": ["https://example.com"] },
  "licenses": [ { "license": { "name": "LicenseRef-ExampleCorp-Proprietary" } } ],
  "properties": [
    { "name": "bomlens:origin", "value": "first-party" },
    { "name": "bomlens:artifact", "value": "out/target/product/<device>/vendor/bin/hw/example-camera-service" }
  ]
}
```

Replace `<device>` with the product name of the build. When the vendor directories have different owners, keep one declaration file per directory and pass each with `--components`.

### A Zephyr application

The build writes the firmware to `build/zephyr/zephyr.elf`. The scan does not read `west.yml`, so the Zephyr kernel and the modules it pins are listed by hand, with the revision `west.yml` pins as the version. They are compiled into the firmware, so they have no file of their own.

```json
{
  "type": "firmware",
  "name": "sensor-node-fw",
  "supplier": { "name": "Example Corp", "url": ["https://example.com"] },
  "licenses": [ { "license": { "name": "LicenseRef-ExampleCorp-Proprietary" } } ],
  "properties": [
    { "name": "bomlens:origin", "value": "first-party" },
    { "name": "bomlens:artifact", "value": "build/zephyr/zephyr.elf" }
  ]
},
{
  "type": "library",
  "name": "zephyr",
  "version": "4.1.0",
  "supplier": { "name": "Zephyr Project", "url": ["https://www.zephyrproject.org"] },
  "licenses": [ { "license": { "id": "Apache-2.0" } } ],
  "properties": [ { "name": "bomlens:origin", "value": "third-party" } ]
}
```

Add one `third-party` entry like the second for each module in `west.yml` that ends up in the firmware, such as a vendor HAL.

### Bare-metal firmware with a vendored HAL and RTOS

The vendor HAL and the RTOS are copied into the tree and compiled into `build/firmware.bin`. The firmware names its file; the HAL and the RTOS are `third-party` libraries without `bomlens:artifact`.

```json
{
  "type": "firmware",
  "name": "motor-controller-fw",
  "supplier": { "name": "Example Corp", "url": ["https://example.com"] },
  "licenses": [ { "license": { "name": "LicenseRef-ExampleCorp-Proprietary" } } ],
  "properties": [
    { "name": "bomlens:origin", "value": "first-party" },
    { "name": "bomlens:artifact", "value": "build/firmware.bin" }
  ]
},
{
  "type": "library",
  "name": "freertos-kernel",
  "version": "11.1.0",
  "supplier": { "name": "FreeRTOS", "url": ["https://www.freertos.org"] },
  "licenses": [ { "license": { "id": "MIT" } } ],
  "properties": [ { "name": "bomlens:origin", "value": "third-party" } ]
},
{
  "type": "library",
  "name": "example-mcu-hal",
  "version": "1.8.0",
  "supplier": { "name": "Example Chip Vendor", "url": ["https://chip.example.com"] },
  "licenses": [ { "license": { "id": "BSD-3-Clause" } } ],
  "properties": [ { "name": "bomlens:origin", "value": "third-party" } ]
}
```

Under the BSI profile the two libraries appear on the advisory row for declared libraries with no file of their own.

### A Yocto image

A Yocto build records its packages in its own SPDX output, which BomLens reads from the build directory (see [Yocto images](supplier-sbom.md#yocto-images) in the supplier SBOM guide). The packages are already there, with their versions, purls and file hashes, so a declaration names the recipe (PN) in `bomlens:yocto-recipe` instead of a build output, and adds what the build does not know: the supplier, the concluded licence and the origin.

```json
{
  "type": "application",
  "name": "media-daemon",
  "supplier": { "name": "Example Corp", "url": ["https://example.com"] },
  "licenses": [ { "license": { "name": "LicenseRef-ExampleCorp-Proprietary" } } ],
  "properties": [
    { "name": "bomlens:origin", "value": "first-party" },
    { "name": "bomlens:yocto-recipe", "value": "media-daemon" }
  ]
},
{
  "type": "firmware",
  "name": "vendor-dsp",
  "supplier": { "name": "Example Chip Vendor", "url": ["https://chip.example.com"] },
  "licenses": [ { "license": { "name": "LicenseRef-Vendor-Binary" } } ],
  "properties": [
    { "name": "bomlens:origin", "value": "third-party" },
    { "name": "bomlens:yocto-recipe", "value": "vendor-dsp" }
  ]
}
```

```bash
./scripts/scan-sbom.sh --project MediaBox --version 2.1.0 \
  --target build --components sbom-declared.cdx.json \
  --conformance-profile bsi-tr-03183-2
```

Every package the image installs from that recipe, such as `media-daemon` and `media-daemon-cli`, gets the declared type, supplier, licence and origin, and keeps its own name, version, purl and CPE. The files the build recorded for each package are nested under it with their hashes (SHA-512 from Yocto 6.1). A version may be left out; one that differs from the build's is refused. On the command line a Yocto build directory has no default file, so `--components` is always given. The web UI, which cannot name a file, reads `sbom-declared.cdx.json` at the root of the build directory picked with the Directory input. A multilib or SDK variant such as `lib32-media-daemon` is a recipe of its own and is declared separately. A recipe the image did not install, or a component added by name with the name of an installed package, is refused.

## Using it in CI

The declaration file belongs in the repository, next to the build that produces the files it names. A CI job builds first, then scans; see [Declared components in CI](ci-cd.md#declared-components-in-ci) for a GitHub Actions example.

---

> **Related**: [CLI reference](../reference/cli.md) | [Artifacts](../reference/artifacts.md) | [Use in CI/CD](ci-cd.md) | [Supplier SBOM validation](supplier-sbom.md)
