# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v1.11.6] - 2026-09-01

### Added

- `GET /image-status` now reports the version baked into a firmware/AI-model/deep-CVE sibling image that is already on disk, read via `docker image inspect`. The scan form's "ready" indicator shows it, so a stale cached sibling image (one a `docker pull` never refreshed) is visible even when the app's own version is current.

## [v1.11.5] - 2026-08-31

### Added

- The web UI and desktop app now show the running BomLens version as an always-visible badge, not only inside the help menu. A build from `latest` stamps the real commit id instead of the literal string "latest", and the same value is mirrored into the image's OCI version label.
- The Windows settings file (`bomlens.settings.txt`) now accepts `UI_BIND_ADDRESS`, matching what the launcher scripts already read.

## [v1.11.4] - 2026-08-29

### Fixed

- The desktop app now refreshes its bundled scanner image when a newer one is published to the registry, instead of staying pinned to whatever was pulled once.

- A malformed or unusual SBOM (a mistyped CycloneDX `specVersion`, or one mixing multiple OS package types) no longer causes the security scan to silently return zero findings; the scan retries after normalizing or splitting the input.

- A CVE without grype's primary identifier is now recovered through its aliases instead of being dropped.

- The curated CPE maps used to attach NVD-only CVEs to GitHub- and Maven-coordinate components were expanded and corrected: Tor's release-tag prefix is stripped before matching, Go's "go1.x" tag no longer floods every Go CVE into scan results, several mismapped Maven groupIds now resolve to their real NVD vendor, and projects NVD has split across more than one CPE vendor over their history (Spring Framework, Spring Security, Jetty) now carry every relevant vendor's CVEs. Apache ActiveMQ's Artemis and Classic lines, which share a Maven groupId but are different NVD products, are now told apart by artifact name.

### Added

- Firmware scans now read the kernel version from outside the root filesystem when the kernel image lives there, so kernel CVE identification no longer silently comes up empty for those images.

## [v1.11.3] - 2026-08-20

### Fixed

- A Python component whose installed license file bundles a primary license followed by third-party notices in the same file (numpy, pandas, and similarly-packaged distributions) could resolve to a bundled license instead of its own. The scanner now reads only the leading license block and cross-checks it against the PyPI license classifier before accepting it. A batched `pip install -r` failure on one pinned dependency no longer drops installed-license evidence for every other dependency in the same file; each line is retried individually and pip's own error reaches the scan log.

## [v1.11.2] - 2026-08-17

The local web UI now answers only on the machine that started it.

### Changed

- `scan-sbom.sh --ui`, `sbom-ui.bat` and the desktop app publish the web UI on 127.0.0.1 rather than on every interface of the host. The UI container is given the engine socket so that it can start sibling scan containers for firmware and AI-model inputs, which makes reaching that port enough to start a scan. If you open the UI from another machine, set `UI_BIND_ADDRESS=0.0.0.0` and put something that authenticates in front of it; both launchers read the variable, and the Windows settings file accepts it as a key. (reference/ui.md)

- The scanner image carries syft 1.51.0 and grype 0.117.0.

### Added

- A release carries `bomlens-source-<version>.cdx.json`, a CycloneDX SBOM of what the source bundles ship, and `SHA256SUMS.txt` comes with a keyless signature (`.sig` and `.pem`) from the release workflow. The checksum file already covers every asset, so verifying that one signature covers the release. The scanner image keeps its own signed SBOM attestation.

## [v1.11.1] - 2026-08-16

Reading a scan result, rather than producing one. The components table on a
real image was hard to work through: Korean headers split down the middle of a
word, rows changed height with their contents, and scrolling right lost track
of which row was which. The controls above it had grown into four stacked
lines with no common axis.

An AI model scan also had its own section come up empty. A model SBOM names the
model as the document's own component and lists only its datasets underneath,
and both the scan list and the model view read the list alone.

### Fixed

- The Models & datasets section renders the model card when the model is the document's own component rather than an entry in the component list, which is the shape a model scan actually produces. The section showed its empty state on exactly the scans it exists for, while the rail badge beside it counted one.

- The scan list labels such a scan as an AI model scan and counts the model, instead of calling it a plain SBOM and reporting one component fewer than the scan's own page.

- Table headers stay on one line. Korean text breaks between any two characters, so a two-character header in a narrow column stacked itself vertically.

- Rows keep an even height. A component carrying many licences wrapped its badges over several lines; the first few are shown now, with the rest folded into a count that the expanded row already spells out in full.

### Added

- The name column stays in place while the table scrolls sideways, so a wide table can be read across without losing the row.

- Columns can be hidden from a menu, and the choice is remembered in the browser for next time — the same local storage the theme and the language already use.

- The overview names the components carrying the most risk and links into what put them there, instead of stopping at a count. It states how many affected components sit behind the list, and is absent when nothing carries a vulnerability.

- The comparison with the previous scan of the same project moves from a line of text into a card, and the scan list carries it too: the change in component count and the direction of the worst severity, on the rows that have an earlier run to compare against.

- Empty sections say why they are empty. A vulnerability list that ran and found nothing now reads differently from one that was never produced — the second says so, because an empty section is not the same as a clean result.

### Changed

- The components toolbar is a single row: search, the type and licence filters, the filter and column menus, the export button, and the row count. The state toggles moved into the filter menu, and the ones that are on appear as removable chips under it.

- A truncated component list says how many rows it is showing rather than only that it was truncated.

## [v1.11.0] - 2026-08-15

The web UI is the headline. A scan result was already thorough; this release is
about what a reader can do with one — reach it by keyboard, narrow it and send
someone the link, take a filtered list into a spreadsheet, and read the source
it was built from. Alongside that, an AI model file can now be scanned directly
from disk rather than only by HuggingFace id.

Three accessibility defects are fixed rather than added to: a progress bar that
announced nothing, and two labels rendering under the contrast minimum.

### Changed

- The Components and Vulnerabilities sections link to each other. A component's expanded detail opens the vulnerability list filtered to that component, and a vulnerability's detail opens the component list filtered to its package. Moving between the two lists meant retyping the name into the other section's search box. The links sit in the expanded detail because each table row is itself the expand control, and a control nested inside a control is not announced reliably by screen readers.

- The source viewer highlights what it is showing. A scanned file was rendered as numbered plain text, which is readable but says nothing about what is code and what is a comment. Grammars load only when a file that has one is opened, so a session that never opens a file carries none of them, and a file with no grammar — a licence, a binary, an unfamiliar extension — is shown as plain text rather than guessed at.

- Severity labels read from design tokens rather than colours written into the badge component. The five severity badges and the muted one each carried a light shade and a dark one as palette classes, kept in step by hand; the colours are unchanged, but they now live where every other colour in the app lives.

- The top bar has a help menu: documentation, the live demo, and the version that is running. Every link out of the app was inside a scan form before, so getting to the docs meant starting a scan first. The version comes from the running image; a local build that carries no version stamp says so rather than showing a blank.

- Korean text in the web UI is set in Pretendard, bundled with the app. It fell back to whatever the operating system supplied — Apple SD Gothic on macOS, Malgun Gothic on Windows — so a Korean screen looked different on each platform and its letterforms did not line up with the Latin text beside them. Latin still uses Inter; Korean falls through to Pretendard, which is drawn to match it. The face is split across unicode ranges, so a screen loads the ranges it actually shows.

- The Components and Vulnerabilities lists export to CSV, carrying whatever the table is currently showing rather than everything. Getting a filtered list into a spreadsheet meant copying rows out of the browser by hand. The file is written in the browser, so nothing about the scan leaves the machine, and it opens with the right characters in Excel.

- The dependency graph has zoom, fit-to-view and save-as-PNG controls. It could only be driven by a trackpad gesture before, which left a mouse or keyboard user with no way to change what was in view.

- Collapsible sections show that they can be opened. The conformance crosswalk row and its "Met with:" and "Example:" toggles were bare text with no chevron, so the way to see which requirements a count stood for was to guess that the label was clickable. Every folding surface in the app now carries the same turning chevron.

- Sections with nothing to show say so the same way everywhere. The dependency graph's "no relationships" and "too large" notes, its error, and the empty artifacts list were bare paragraphs while the rest of the app used a shared empty state.

- A file can be dropped onto the upload sources instead of picked through a dialog, and the upload reports how far along it is. The field was a bare file input: the firmware images and model weights these sources take run to gigabytes, and once the run started there was nothing on screen to say whether anything was moving. The chosen file now shows its name and size with a way to replace or remove it, and a percentage while it uploads.

- The progress bar reports its position to screen readers. It was rendered without its value reaching the underlying control, so it moved on screen while announcing nothing — this affected the scan progress bar as well.

- A narrowed table is somewhere you can return to. Filtering, searching or sorting the Components, Vulnerabilities or Licenses list writes that state into the URL, so reloading keeps it and the address can be handed to someone else as a link to exactly that view — "the critical CVEs in this scan" rather than "open this scan, then filter". The filters were held in memory before, so a reload dropped them and there was no way to point at a filtered view at all. Typing in a search box replaces the address rather than pushing it, which keeps the Back button meaning the previous screen instead of the previous keystroke.

- The global search takes Cmd/Ctrl+K from anywhere in the app and shows that shortcut in the box, and its results walk with the arrow keys. Reaching the search needed a mouse or a long tab sequence, and the result list could only be clicked: it carried a listbox role but no options to move between, so a keyboard user could type a query and then have nowhere to go. The list follows the ARIA combobox pattern now — focus stays in the input and the active result is named by `aria-activedescendant` — with Home and End for either end, Escape to close, and Enter still taking the first result when nothing is active.

- The fixed-version column reads in a darker green. The previous shade measured 3.77:1 against the light background, below the 4.5:1 minimum.

- The model integrity check reads in the same green as every other success mark. It used a shade that measured 3.77:1 on the light background, under the 4.5:1 minimum, and carried no dark-mode pair at all, so it stayed dark green against the near-black canvas.

- Deleting a scan asks for confirmation first, naming the scan it is about to remove. The delete control in the scan table and the one in the top bar's scan menu both removed a scan's output folder on a single click, and because the files are gone from disk with no copy kept, a mis-click could not be taken back. The prompt opens on Cancel, and a confirmed delete says so. Modal dialogs also hold the keyboard now: focus moves into the panel when one opens, Tab stays inside it, and it returns to whatever opened the dialog on close.

### Added

- A scanned AI model file is checked for whether loading it runs code. Pickle-format weights (`.pkl`, and the pickle inside a PyTorch archive or an `object`-dtype `.npz` member) are analyzed with picklescan, now installed in the base image, and the verdict feeds the file-security axis of the model risk assessment: a dangerous global reads `caution`, globals that need a human reads `review`, and a format that cannot execute code on load reads `ok`. BomLens reported this for models on HuggingFace by reading the Hub's own scan; a file that was never published had no such record and therefore no verdict at all. A clean result states its scope — it is a pickle analysis, not a malware scan — and a scan that could not run leaves no security axis rather than implying the file is safe.

- An AI model file can be scanned directly: `--model-file <path>` on the CLI, or the Model file tile in the web UI (up to 8 GB). The file's own header is read — GGUF, safetensors, PyTorch, pickle, npz, npy and ONNX are recognized by their magic bytes rather than their extension — and the result is the same CycloneDX 1.7 ML-BOM, with the same G7 conformance check and risk assessment, produced offline in the base image. Until now an AI SBOM required a HuggingFace model id, which left out weights a supplier delivers, internal models that were never published, and machines with no network. What each format can fill differs and is reported as such: GGUF declares a name, a license and an architecture, safetensors usually declares only tensor shapes, and a field the file does not carry is left empty rather than guessed. Every format contributes a SHA-256 over the whole file.

## [v1.10.5] - 2026-08-12

### Changed

Three changes alter what an AI-model scan writes, so a consumer of those artifacts sees different output than it did on v1.10.4. They are corrections rather than new behaviour, which is why this is a patch, but they are listed first because a tool reading the output has to know.

- The model is the subject of the ML-BOM. It moves to `metadata.component`, where CycloneDX names what a document describes, and the datasets it references stay under `components[]`. The generator had put its own scan job (`job-<timestamp>`) at the subject and left the model in the component list, so the document stated that it described a generator run. A tool that looked for the model in `components[]` has to look at the subject instead.

- The conformance report distinguishes a check with nothing to judge from one that is unmet. Such a check carries `naKind: "not-applicable"` in the JSON and leaves both sides of every coverage fraction, so the denominators move: an SBOM whose only subject is a model no longer collects format checks for having no packages to measure. Reports and the web UI label the state separately and count it on its own line.

- A model card whose license is `other` now carries the license the card declares, as a license name with a link to the file, rather than an SPDX identifier.

- Updated cdxgen to 12.8.3, which carries the BSD license-name correction from v1.10.4 in its own data: `0BSD` now covers only "Zero-Clause BSD", and "new BSD" resolves to `BSD-3-Clause`. BomLens still corrects the tables before a scan, because the sibling images pinned to an earlier cdxgen release ship the old ones. Running the correction against the 12.8.3 tables leaves both files byte-identical.

### Fixed

- A dataset a model card declares carries the repository owner as its producer. The owner was recorded only inside `componentData.governance`, which the conformance checks do not read, so every dataset arrived without one. The effect ran backwards: a card that declared its training data added a component per dataset with no producer and scored lower on the 2026 minimum elements than a card that declared none.

- The license of a model card tagged `other` is no longer guessed from the LICENSE text. With no identifier to copy, the generator matched its mapping table against the file body as a substring, and `mit` matches the `limited`, `submit` and `submitted` that ordinary license prose contains — an Apache-2.0-derived custom license was emitted as MIT, dropping the obligations the real terms carry. The discarded value is kept as a property so the correction is traceable.

- Dataset names scraped out of a model card's prose no longer count as declared training data. The generator fills `modelCard.modelParameters.datasets` from the card text, so a sentence reading "pretrained on approximately 12.5 trillion tokens" left a dataset named `approximately`, and a footnote left `only`; neither is a repository. A name survives when the card frontmatter declares it or the datasets API resolves it, and what was dropped is recorded on the model.

- An AI SBOM that follows the CycloneDX shape — a supplier submission, or a hand-written one, naming the model as the document's subject — is analyzed as an AI SBOM. Every model lookup expected the generator's layout, so such a document fell through all of them and was treated as ordinary software: no G7 minimum-element checks, no model risk assessment, no AI compliance profile.

- A dependency-graph check no longer fails a document that has no parts to relate, and the stale dependency root the generator emitted — keyed on an identifier nothing in the document defines — is folded into the model's own entry. A document that does have parts and no edges still fails.

- An SPDX document with no packages reports its name+version and PURL coverage as not-applicable, the way a CycloneDX document with no components does. Both checks had stayed "met" on an empty denominator, so a document that named nothing counted toward coverage on one format but not the other.

- A model card that publishes an evaluation table can satisfy the operational-KPI element. The check read its own path over `components[]`, which is the one place the model no longer sits now that it is the subject of its own ML-BOM, so no card could meet it.

- A Python component's license and version come from the installed distribution's own metadata, read through `importlib`, rather than from a filesystem guess at the `.dist-info` directory name.

## [v1.10.4] - 2026-08-10

### Fixed

- A BSD-3-Clause component is no longer reported as 0BSD. The two license-name tables the SBOM generator resolves against both mapped the generic BSD names — "BSD", "BSD License", "new BSD" — onto 0BSD, a license that carries no conditions at all, so components that require the copyright notice and license text to be shipped came out requiring nothing, and the notice generated from them left that attribution out. PyPI files every BSD variant under the single classifier "BSD License", which put most Python projects in reach of this; Maven poms naming "New BSD License" put Java ones there too. The tables are corrected before generation runs, which is the only point where the original name still exists — once the SBOM is written, a mislabelled component is indistinguishable from one that really is 0BSD. "new BSD" now resolves to BSD-3-Clause. "BSD" and "BSD License" resolve to nothing: the clause count cannot be known from those strings, so they reach the SBOM as a license name for a person to settle rather than as a wrong identifier.

- A Python component's license is settled on the installed distribution's own metadata — its PEP 639 license expression, the license text it ships, then its declared license name, in that order — rather than on the summary PyPI serves. That summary's license field increasingly holds the entire license text, which the generator scanned for the first license name it recognised: numpy and pandas were reported as Apache-2.0, off a bundled-dependency notice inside a BSD-3-Clause file. Evidence that settles on more than one answer, as a genuinely dual-licensed component does, keeps the upstream value for a person to read. Where a license was settled this way, the component records what settled it.

- The notice marks a license group whose name is not an SPDX identifier — "BSD License", "Dual License" — as unverified, instead of printing prose where a license belongs.

## [v1.10.3] - 2026-08-08

### Added

- The regulatory crosswalk's framework row opens to the requirements it counted. The table stated four numbers per framework and left the reader to work out which requirement each one was; the rows were already in the payload and nothing read them.

- A conformance element that is already met is one line. Its description and the values that satisfied it are folded away rather than dropped, because a reader who has just been told the element is met is not reading either again. Measured on an AI SBOM, the section went from 12,999 to 11,379 pixels — the elements that need attention had been sharing the page with forty that did not.

- The conformance screen leads with what blocks the SBOM. A line at the top says how many mandatory checks failed, how many advisory elements are short, and how many need a person, and the mandatory checks themselves now come first — they used to sit below every advisory row, which on an AI SBOM meant the bottom of a page twelve thousand pixels long. The rail badge counts the mandatory checks too, so it means the same thing on every scan instead of showing AI coverage on one and every-check passes on another.

- The 2026 SBOM minimum elements are their own block on that screen, grouped the way the guidance groups them, and their rows carry what the AI elements have carried all along: how the value was established, the fragment that would satisfy it, and — for the elements no scan can settle — what a person has to check. They had been rendering as three bare lines in the middle of the format list, because a row only did any of that for elements whose id began "g7-". Each of the 23 elements also has a plain-language description of what it is and what would satisfy it, in English and Korean.

### Fixed

- The regulatory crosswalk no longer reports failures as advisories. The table showed four counts and derived one of them as the remainder of the other three, which is the failure count; it was labelled "advisory", so the most serious category appeared under the mildest name on the page.

- The conformance report's regulatory crosswalk states how many requirements an SBOM fails, as its own column. The table carried present, gap and review, so a failure fell outside all three and the columns did not add up to the total. The four counts now account for every mapped requirement, and a regression test holds them to it.

- The conformance report explains what a person still has to check, and does so in the markdown as well as the HTML. The signing this tool offers is detached — the signature is a file beside the SBOM — and a report that reads one file cannot see it, so that row now says as much instead of reading as unsigned. A signature carried inside the document is still read and credited. The same notes cover the four practices no scan can settle: whether the SBOM covers everything, how corrections are issued, how it reaches the people who need it, and how often it is reissued.

- A binary or firmware SBOM now records the hash of the file that was scanned, on the component the SBOM is about. A recipient can hash their copy and tell whether it is the copy the SBOM describes. Scans with no single artifact — a source tree, a container image, an installed OS package spread across a root filesystem — record no hash rather than one computed over something that is not the artifact.

- The conformance report measures the target component alongside the components enumerated under it. The 2026 minimum elements describe their data fields over both, and measuring only the enumerated ones let an unidentified root pass without mention. The component hash algorithm is now checked against the recognized algorithm names rather than only for being non-empty, since a digest labelled with something unrecognized cannot be recomputed.

- A generated SBOM now states why a field is empty when it is empty. The 2026 minimum elements ask an author to distinguish a value they could not establish from one they are withholding, and a scan only ever produces the first — it writes what it managed to read and has no second set of findings to hold back. The statement is made once for the document rather than repeated on every empty field, which on a firmware image would mean thousands of properties saying the same thing. The conformance element that asks for it is measured automatically now instead of being left to a human reader, so a received SBOM that says nothing about its absences is reported as a gap.

- A component whose version the scan could not establish is no longer counted twice. Such a component is already marked as present with its version unestablished, and that marking is exactly the statement the minimum elements ask for, so the component-version element reads it instead of listing the component as missing the field.

- The conformance report now measures an SBOM against the 2026 SBOM minimum elements — 17 data fields and 6 practices, published by CISA, the NSA and the FBI with fifteen international partners including Germany's BSI, Japan's METI and Korea's KISA, replacing the NTIA elements of 2021. Every CycloneDX SBOM is measured, not only AI ones. The elements are advisory and none of them changes the pass or fail verdict, which stays with the submission criteria. Five of the six practices describe how an organisation operates rather than what a document contains, so they are surfaced as needing human review instead of being scored or quietly dropped.

- What counts as identifying a component is wider under this baseline than under the submission criteria: a PURL, a CPE, or an intrinsic identifier such as a hash. A firmware file entry that carries only a hash is identified here even though the submission criteria still ask for a PURL, so the report can say both things at once instead of only the stricter one.

- The regulatory crosswalk's US baseline was rewritten for the 2026 document. It previously mapped the 2021 elements onto the format checks; those mappings moved to the new elements, so a requirement is counted once rather than once per row.

- Every generated SBOM now records at which lifecycle phase it was produced, and with which tool at which version. A scan that reads source manifests is marked `pre-build` and one that reads a built artifact — an image, a binary, a firmware image, a root filesystem, a model — is marked `post-build`, which is the distinction a reader needs to know what the component data can mean. BomLens names itself among the tools that produced the document, alongside the scanners it drove, and a tool whose version was not recorded now says so instead of leaving the field empty. A merged SBOM claims no phase, because its inputs may each have had a different one.

- `--sbom-author` (or `SBOM_AUTHOR`) records the organisation or person that generated the SBOM. This is the entity running the scan, which is neither the tool nor the author of the software being scanned, and nothing in a scan can discover it. Left unset, the field is omitted rather than filled with a placeholder — and the generator's own default, which named the SBOM tool's publisher as the document's author, is no longer carried through.

### Fixed

- A binary or firmware SBOM is no longer marked short on fields its file entries cannot carry. Such a scan lists the delivered files alongside the packages it identified, and a file on disk has no package version and no PURL type, yet every one of them sat in the denominator of the name/version and PURL coverage checks. A firmware image whose packages were all identified reported 10% PURL coverage on that basis, and a binary reported 39 of 415 components named. Measured over the packages alone, the same two SBOMs report 18% and 39 of 39. Files are still expected to be identified, by the identifier they do carry: a new recommended check reports how many of them have a hash, and names the ones that do not.

- An SBOM whose only components are files now fails instead of passing. Once file entries stopped counting toward package coverage, a scan that recovered nothing but a file listing had an empty denominator and was reported as fully covered — the checks would have certified an SBOM that identified no package, which is what the submission criteria are asking about. An SBOM with no components at all, or one whose components are all datasets, is unaffected and reports no coverage complaint, as before.

## [v1.10.2] - 2026-08-05

### Added

- A desktop application's codec plugins now yield the libraries linked into them. A player ships each codec as a plugin that links the library statically, so the library is not a file of its own and nothing catalogs it — but the library stamps its own name and version into the plugin. Four such stamps are read now: a subtitle codec, a Dirac codec, the Theora reference library, and the runtime compiler the Dirac plugin carries inside it. Only the Theora entry carries a vulnerability identifier; the other three name products that exist in the vulnerability index as something else entirely, and attaching those would hand a codec another project's advisories.

### Fixed

- A firmware image shipped as a zip can now be uploaded through the web UI. Vendors commonly distribute firmware that way and the CLI has always unpacked it, but the upload form refused the extension while accepting every other compressed form, so a scan the CLI could run had no path through the UI at all.

- A component whose release could not be read is no longer reported as if its version were known. The scanner writes `UNKNOWN` in that case — a kernel module with no version in its metadata, a Go binary built without module information — and carrying it through made the conformance report count those components as versioned. The field is removed now and the component is marked as present with its version not established. On one switch OS this moves 3,581 components out of the "version known" count, where they never belonged. Which components are reported, and which vulnerabilities, is unchanged.

- A firmware SBOM now carries the dependency graph. What each installed package depends on is read out of the package database, but the step that assembles the SBOM from several identification passes took only the components, so the graph was dropped and the conformance report failed its transitive-dependency row on every firmware scan. References are followed to the record that survived the merge, and an edge whose endpoint did not survive is dropped rather than left pointing at nothing. The SPDX export carries it too.

## [v1.10.1] - 2026-08-04

### Added

- Firmware analysis opens more of what an image carries. Besides a container image store, a second filesystem with its own package database and an interpreter's installed library set are now cataloged when they sit beside the root filesystem rather than inside it. Each is recognized by the record of what is installed in it, not by a directory name. Set `FW_EXTRA_ROOTS=false` to read only the root filesystem.

- The frameworks an iOS app ships are now identified. A package holds one bundle per framework, each stating its name and version, and those are read as components. A framework that is the app's own code split into a bundle is marked with `bomlens:appOwnedFramework` rather than dropped, because the identifier that decides it is written by hand and can be spelled in a way the rule misses. No package identifier is written, since nothing in the bundle says which ecosystem the framework came from.

- An Android or iOS app package is now unpacked and read instead of being treated as one file, and the libraries an Android app declares about itself are identified. Gradle records each library that ships in the package under `META-INF`, one file per library holding its version, which gives a Maven coordinate the vulnerability step can use. Pass the `.apk` or `.ipa` as the target; the opt-in firmware image does the unpacking, and without it the scan says so.

### Fixed

- The conformance report no longer calls a package identifier without a version malformed. The version is optional in the identifier format, so a syntax check has nothing to say about a missing one, and two other rows already report it — one as a required failure, one as a warning that the identifier cannot be traced. A firmware image whose kernel modules carry versionless identifiers was failing a syntax row that had nothing to do with syntax.

- An SPDX export of a firmware scan now carries the container images the device holds and the distribution it runs. The converter writes a package only for what it counts as software, so both were absent, and so was the record of which container each package belongs to. They are packages in the SPDX file now, and the membership is a `CONTAINS` relationship. Which software the two formats list is unchanged.

- Packages installed inside a container carried by a firmware image are now matched against vulnerability data. A package database read out of a container layer gives a name and a version but no package identifier, because the identifier depends on which distribution the container runs and that is recorded inside the layer rather than at the root of what was scanned. The distribution is now read from the layer and the identifier written from it, including the source package the advisories are keyed on. Which components a scan reports is unchanged.

- A scan that cannot reach the upload server now says so and keeps its artifacts. It used to end on the transport's own exit code with nothing but a warning, which read as a failed scan even though every file had been written. The message names the server and says how to scan without uploading. A reply that carries no status code is reported the same way instead of ending the run mid-comparison.

## [v1.10.0] - 2026-08-03

### Added

- Yocto builds are analysed from the build directory itself, not only from an SPDX file handed over separately. The CLI takes the directory, the web UI recognizes one picked in the browser, and an uploaded SPDX archive is accepted. Where a build published no usable SPDX 3.0, the SPDX 2.x manifests it deploys are read instead.
- A firmware image's container image store is now catalogued. When the store sits beside the root filesystem rather than inside it — the usual layout on a switch OS, where most of what runs is in a container — its packages reach the SBOM, and each one records the container image and layer it came from. The images themselves appear as `container` components. `FW_EXTRA_ROOTS=false` reads only the root filesystem.
- Components a firmware carries but does not version are now reported. A library linked into someone else's binary is read from the symbols that binary exports; a program is read from the name it is installed under; the C library filling a `libc` slot is named from the marker inside its own file; a version stamped in an RCS keyword is read; and FRRouting is told apart from the quagga it forked from. Each judgement records the evidence behind it, and a component with no version recovered is marked as such so a clean vulnerability result is not read as covering it.
- Components that are known-malicious packages are flagged separately from vulnerabilities, since the response is removal and credential rotation rather than an upgrade. The check runs offline from a bundled snapshot of the advisories OSV publishes and matches by PURL only. `ENRICH_MALICIOUS=false` skips it. Each flag records the advisory id and the snapshot date.
- Dependencies are checked against the licence the project itself ships under, so a combination that cannot legally ship is visible before delivery. Declare it with `--license <spdx-id>` or `PROJECT_LICENSE`; every component gains a verdict with the reasoning recorded, and the risk report and the web UI list the clashes. Advisory only — nothing is stamped when no outbound licence is declared, and an absent verdict means "not assessed".
- The web UI accepts a build artifact where it previously accepted only source: `.jar`, `.war`, `.ear`, `.deb`, `.rpm` and `.whl`. A supplier who cannot hand over a source tree can often hand over what they ship.
- The result screens show what a scan looked at. The Source tree section pairs the file list with the file itself, for source trees, directory and rootfs scans, firmware, container images and archives. The capture is bounded — text only, per-file and total size caps — and says what it left out and why.
- A scan of someone else's SBOM now describes that document: its format and spec version, name and identifier, creation time, producing tool and the supplier it names, read before conversion. Fields the supplier left empty are omitted rather than shown blank.
- The Overview says what was scanned, and the left rail names the way out of a scan.
- Firmware analysis, AI-model SBOMs and deep CVE matching each need their own image, and the web UI and desktop app now offer to download it before the feature is used, with the download size and a count of the layers done. An unpulled image is still fetched on first use, and that download reports layer counts too.
- Installers are unpacked instead of read as a single file: `.exe`, `.msi` and `.dmg`, in the CLI and as a web-UI upload. What such a file carries is inside it, so the components were not visible before. Unpacking uses the opt-in firmware image; without it the file is read as before and the scan says what it looked at and what unpacking needs.
- Kernel advisories are matched. The bundled CPE index now also carries the Linux kernel, which every root filesystem holds. They are reported apart from the severity figures and in a list of their own, because a kernel accumulates thousands of advisories and most concern subsystems a given device never built.
- OS-context synthesis covers Debian/Ubuntu and Alpine packages as well as rpm, so OS packages in a supplier SBOM or rootfs scan get distro vulnerability matches.
- The documentation site's demo covers a container image, an AI model and a firmware image.

### Changed

- Vulnerability severity grades and licence classification names stay in English on the Korean UI and in the Korean report. They are the vocabulary of the advisory and of the classification itself, the generated reports already printed them untranslated, and the screen and the report now agree. The surrounding Korean is unchanged.
- Every distribution ships this project's own LICENSE and NOTICE, and the web UI reproduces the notices of the npm packages it bundles.
- The Android SDK images are no longer published, because publishing them redistributed the SDK. Build one locally, or point `ANDROID_IMAGE_PREFIX` at an image built elsewhere; the images published up to v1.9.0 are left in place so released versions keep working.

### Fixed

- Firmware unpacking reaches images it previously walked past: a filesystem image that was carved out but never extracted, a vendor squashfs whose magic is byte-swapped, an extraction that aborted on extended attributes, a Windows installer, and an image whose text carries one byte that will not decode. An archive is routed by what it holds rather than by its extension, and an empty result now says which of the possible reasons it was.
- A firmware image that nests bundled sub-packages is read from the real root filesystem rather than from whichever candidate the filesystem happened to list first, which was neither depth order nor stable between machines.
- Firmware identification no longer reports the same component twice, no longer carries an identifier built out of a kernel module's own name, and lets a versionless judgement yield to a versioned one even when the two spell the name differently. The caps whose warnings tell you to raise them now actually reach the scan.
- The NOTICE lists what a notice is for. A firmware's kernel modules fold into one line per licence naming their count and their kernel, and the file entries a scan records as inventory fold the same way instead of appearing as components with no attribution beneath them.
- A source scan no longer modifies the project it scans. Files the resolvers own are snapshotted and put back, and build directories that were not there before are removed; nothing that already existed is deleted, and the restore runs on an aborted scan too. `BOMLENS_KEEP_BUILD_OUTPUT=1` keeps the resolved tree. The generated SBOM is no longer written into the scanned tree first.
- Web UI corrections: the licence list is back in the Licenses section, the rail no longer clips "SBOM conformance", a scan is typed by what it scanned rather than by its SBOM's root, the risk colour tokens work with an opacity modifier, the licence distribution tint is softer, the regulatory crosswalk shows its advisory count, the result subtitle drops a redundant word, and the demo's install link follows the UI language.
- A CPE upstream-version pattern was wrong, and the message about a PURL failure now says when the components carry a CPE instead. The unpack path no longer leaks into firmware component names, and zstd's broken-pipe noise stays out of the scan log.
- The demo bundle and the release assets no longer publish the contents of other people's files or the scratch directories a build leaves behind.
- `--help` no longer runs a command while printing its own text, and the words it dropped are back.
- Vulnerability matching by CPE covers every component that carries one, not just those the signature pass identified, and reaches the components a purl cannot serve. Version comparison is stricter: release prefixes such as `go1.25.6` and `v0.37.0` are read as the numbers they are, and a value that cannot be compared as a version no longer satisfies every advisory bound.

## [v1.9.0] - 2026-07-25

### Added

- `--model` scans now carry a risk assessment beside the inventory: each model and dataset is given a usability verdict — `ok`, `conditional`, `caution` or `review` — so a development team can tell at a glance whether a HuggingFace model is usable and under what conditions. Three axes feed the verdict. The license axis matches every HuggingFace license tag against a curated terms registry (`docker/lib/ai-risk-knowledge.json`) that records whether commercial use, redistribution and derivatives are allowed, the conditions that apply, and a link to the license text; a `license: other` model has its LICENSE file read and any restrictive wording quoted verbatim, and a fine-tune whose declared license conflicts with an inheritable base-model license (Llama, Gemma, the RAIL family, non-commercial CC) is flagged. The file-security axis reads HuggingFace's own per-file scan results (ClamAV and picklescan) over the metadata API without downloading a weight, and records whether the weights use a pickle-format that can execute code on load. The datasets axis rolls up each referenced dataset's license and its declared risk markers (personal data, access-restricted repositories). `--usage internal|product|redistribute|outputs-only` tailors the verdict to how the model will actually be used, so only the conditions that bind that scenario decide it. The verdicts are stamped into the SBOM as `bomlens:assessment:*` properties, summarized in the AI compliance profile and shown as grade badges in the web UI, always with the note that the assessment is guidance, not legal advice. An unrecognized license always falls to `review`, never a guess. (#473, #474, #475, #476, #478, #479)
- The conformance report now maps every SBOM — not only AI ones — to the EU Cyber Resilience Act (through BSI TR-03183-2) and the NTIA minimum SBOM elements, so a plain software SBOM shows which baseline documentation elements it already satisfies. Reference only; it does not certify compliance. (#462)
- An AI model card names its training datasets and stops there. BomLens now resolves each id against the HuggingFace datasets API into its own CycloneDX `data` component — the declared license, content digests and upstream provenance — linked to the model as a dependency, which is what the G7 dataset cluster asks for and what a provider writes an EU AI Act training-content summary from. A dataset that cannot be read (withdrawn, renamed, or private to someone else) is kept with an explicit unresolved marker rather than a fabricated license. (#456)
- The AI compliance profile's rollup — G7 status by cluster, the regulatory crosswalk and the licenses flagged for review — now opens the conformance report itself, so the two artifacts no longer restate each other; the standalone AI-profile HTML is gone while the JSON and Markdown digests remain. (#455)
- The conformance HTML report was reworked to be read at a glance: numbered rows, a distinct colour for review-only elements, each requirement's regulatory provisions carried on its own row, and the fill-in guidance shown inline per row instead of in a separate section. The web UI conformance section is labelled "SBOM conformance" and states that a single mandatory-format failure — not an advisory G7 gap — is what fails an SBOM. (#454, #463)
- The conformance and AI compliance profile reports render in Korean with `--lang ko` (`REPORT_LANG=ko`); the machine-readable JSON stays English as a contract. (#447)
- The open-source risk report (`_risk-report.md`/`.html`) now renders in English by default and in Korean with `--lang ko`, matching the conformance and AI-profile reports. A global user no longer receives a Korean-only risk report, and the model risk assessment disclaimer prints in both languages.
- `--deep-cve` recovers NVD-only Maven CVEs that Trivy misses for older Java libraries, matching by CPE with grype in an opt-in `bomlens-deep-cve` image pulled on demand. Findings not verified against the live NVD version range are flagged version-unverified in the report. The web UI offers the same deep CVE matching for an uploaded SBOM. (#465, #472)
- A supplier SBOM that lists every rpm/deb package but omits the operating-system component now gets one synthesized from the dominant distro PURL, so Trivy can select the right advisory database instead of returning zero findings for valid PURLs. Skipped for AI SBOMs; disable with `ENRICH_OS_CONTEXT=false`. (#464)
- Supplier SBOM analysis (`--analyze`) now accepts UTF-16 and BOM-prefixed files and SPDX 3.0 JSON-LD, so an SBOM exported by a tool that writes those parses instead of failing. (#468)
- The Windows launchers (`sbom-ui.bat`, `check-setup.bat`) now speak English as well as Korean, following the same rule as the desktop app: `SBOM_LANG` wins, otherwise the Windows display language, and anything that is not Korean gets English. This also removes the boxes-instead-of-text problem on a Japanese console, where the font has no Hangul glyphs and no codepage can help.
- `bomlens.settings.example.txt`: environment variables do not survive a double-click, so `UI_PORT`, `SBOM_LANG`, `SBOM_PULL`, `SBOM_IMAGE_TAR`, `SBOM_SCANNER_IMAGE`, `SBOM_OUTPUT_DIR` and `SBOM_UI_MOUNT_DIR` are now also read from a text file beside the scripts (or `%USERPROFILE%\.bomlens\settings.txt`). A real environment variable still wins.
- Offline install: `SBOM_IMAGE_TAR` loads a `docker save` tar instead of pulling, and a `bomlens-image.tar` next to the scripts is picked up automatically. With `SBOM_PULL=never` the launcher never touches the network — a USB stick with the `.bat` and the `.tar` needs no registry, no command line and no proxy setup. `SBOM_PULL=always` refreshes a cached `:latest`, which previously stayed pinned forever once pulled.
- `sbom-ui.bat` picks a free port instead of failing: a busy **or Hyper-V/WSL-reserved** port now moves to the next free one. The reserved-range case was the common false green light — nothing is listening, yet Docker still cannot bind.
- The desktop app shows aggregate pull progress (layers complete, elapsed time) with a heartbeat, so the multi-GB first download no longer looks frozen during the long silent stretches, and both start screens gained an "Open log folder" button so a failing user can hand over `startup.log`.
- Pull failures are now classified (proxy, DNS, auth, disk, timeout) and the screen explains the actual fix. The proxy text states the thing that trips people up: the image is fetched by the Docker daemon, so setting proxy variables for the app has no effect.

### Changed

- Updated cdxgen to 12.8.0 and syft to 1.48.0. (#432, #433)
- Documentation: the AI model guide gained a worked conformance example with openable sample reports and now covers the model risk assessment, `--deep-cve` and the generalized regulatory crosswalk are documented, the architecture and pipeline diagrams were redrawn as authored SVG legible at page width, and the getting-started pages and environment-variable reference were synced across English and Korean. (#443, #445, #446, #448, #449, #469, #470, #471, #477, #481)

### Fixed

- Web UI / desktop firmware and AI-model scans no longer report failure after generating every artifact. These run as a sibling container, which inherited the entrypoint's upload-on default and then exited with "API_KEY and API_URL are required" because no credentials were forwarded — so the scan stream reported `ok:false` despite a complete result set. The sibling is now told generate-only by default (matching the in-process path); when an upload is configured, the destination is forwarded with the API key by name only, keeping it off the argv.
- `--identify-vendored` (SCANOSS) no longer reports a false "no vendored open source found" when the search response could not be processed. One malformed record in the remote response (a `purl` returned as a string) aborted the whole transform, discarding every genuine match and labelling the result "no-match"; the fields are now guarded and an unprocessable response reports "search didn't complete" so the user retries.
- `--sign` now fails loudly instead of exiting 0 when cosign cannot produce a signature (wrong or encrypted key), rather than leaving the user to believe an unsigned SBOM is signed.
- Firmware unpackers (unblob, BANG, unsquashfs, binwalk) run under a wall-clock `timeout` (`FW_UNPACK_TIMEOUT`, default 900s) so a decompression-bomb or malformed image cannot hang the scan; firmware input is attacker-supplied.
- The CLI forwards `API_KEY`, `SCANOSS_API_KEY` and `COSIGN_PASSWORD` to the container by name only, so a scan secret no longer sits on the `docker run` argv where a local `ps` could read it — matching the web-server path.
- The web UI no longer hangs or breaks its recent-scans list on a malformed uploaded SBOM. A supplier SBOM (the untrusted ANALYZE input) with a non-object component — or a component whose `properties`/`licenses` is not a list — made the result-summary raise, so the scan never reported completion and one poisoned scan folder crashed the whole recent-scans sidebar. Malformed component entries are now skipped, valid ones still summarize, and the scan stream always terminates. The uploaded docker-image reference is validated like every other scan target, and the tarball-upload guard now also rejects a symlink member whose target escapes the extraction directory.
- The AI model risk assessment badges read consistently: the `ok` grade now uses the same visual weight as the other grade badges, so the risk colour draws the eye rather than a solid-green "ok" outshouting a "caution" beside it.
- `THIRD_PARTY_LICENSES.md` now attributes grype and the `bomlens-deep-cve` opt-in image (Apache-2.0) added for `--deep-cve`, which had shipped without an entry.
- The downloadable CLI bundles (`bomlens-cli-linux.tar.gz`, `bomlens-cli-windows.zip`) now carry the host-side files `scan-sbom.sh` needs — `docker/lib/source-detect.sh` (sourced on the host) and `build-prep.sh` — so an extracted bundle runs standalone. A bundle was previously missing `source-detect.sh`, so even `scan-sbom.sh --help` exited before any scan; the release build now extracts each bundle and runs it as a gate so this class of packaging gap cannot ship again.
- Conformance no longer fails PURL coverage when there is nothing to measure. An SBOM whose only components are datasets (no packages) counted an empty denominator as 0% and failed an otherwise complete AI SBOM. (#457)
- The first-run download figure is now the measured one. Every surface said the scanner image is "about 3-4 GB", which is its uncompressed size on disk rather than what is transferred: the registry manifest puts the actual download at about 250 MB. The launchers, the desktop app and the docs now say 250 MB, and they add the part that was missing — the first scan of a project fetches a language image as well (0.6-1.7 GB, once per language). The AI model guide's comparison figure was corrected the same way (3.5 GB to download).
- Container start failures no longer leak Korean strings into the English UI. `lib/container.mjs` threw hardcoded Korean text that bypassed i18n, so an ordinary port conflict or start timeout produced `Startup failed: docker run 실패: ...` for a non-Korean user. Errors now carry a code that `i18n.mjs` translates, and a test asserts no Hangul in the English dictionary.
- `sbom-ui.bat` no longer closes its window silently. Any failure after the Docker check — port conflict, bad mount, container crash — used to vanish instantly with no message; every path now explains itself and holds the window, and the container exit code is reported.
- A stopped Docker engine is no longer reported as "Docker is not installed" by the Windows launchers, which sent users off to reinstall Docker they already had.
- `SBOM_UI_MOUNT_DIR` handling: a trailing backslash mangled the whole `-v` argument, and a path containing `&` was executed as a command rather than printed. Trailing separators are stripped and unsafe paths are rejected with an explanation.
- No timeouts existed on the desktop app's Docker calls, so a wedged daemon or a firewalled registry hung on a live-looking window forever. Status checks are now bounded and the pull aborts when it genuinely stops making progress (a stall timeout, not an absolute one, so a slow but healthy download is not killed).
- The desktop app falls back to known Docker install paths when `docker` is missing from `PATH`. Installing Rancher Desktop without restarting Explorer left the app reporting "Docker isn't installed" while the engine ran visibly in the tray.
- `check-setup.bat` and `bomlens.settings.example.txt` now ship in the Windows release zip. The launchers' own error messages tell users to double-click `check-setup.bat`, which was not in the archive.
## [v1.8.3] - 2026-07-20

### Added

- AI-model scans can now read a private or gated HuggingFace repository. Set `HF_TOKEN` (read scope; `HUGGING_FACE_HUB_TOKEN` is accepted as an alias) and `--model` resolves repositories that are not public yet — the case that matters when you are checking your own model before publishing it. The value is passed to the container by name only, so it never appears in the process list, the SBOM, or any report. The web UI inherits the variable from the environment that launched it rather than accepting a token over HTTP, and `/capabilities` exposes only a boolean saying whether one is present. (#434)
- The conformance report now says how to close each G7 gap, not just which elements are missing. For every advisory element that has an automated source and is absent, `_conformance.md` and `.html` print the CycloneDX fragment that would satisfy it plus a link to the authoritative documentation, and `_conformance.json` carries the same under an optional `guidance` key. The guidance registry lives in `docker/lib/g7-guidance.json` (override with `G7_GUIDANCE`), keyed by element id like the regulatory crosswalk, and is the single source the web UI now reads too. Passing and review-only elements are excluded, so a well-documented model adds no section at all. The AI compliance profile lists the same gaps with their reference links and points at the conformance report for the fragments. (#435)
- Every component in the generated SBOM now carries a `bomlens:licenseClass` property with its copyleft-strength class (`network-copyleft`, `strong-copyleft`, `weak-copyleft`, `permissive`, `uncategorized`), mirroring the classification the web UI shows, and the risk report gains a per-class count table plus the network/strong-copyleft components driving the exposure. Unknown licenses are never assumed permissive. A test guard keeps the UI and scanner classifications from silently diverging. (#420)

### Fixed

- An AI-model scan whose model could not be read no longer reports success. The OWASP generator swallows a failed HuggingFace fetch, logs a warning, and fills the model card with generic defaults (`transformer`, `text-generation`, string in and out), so a `401` — or an id that does not exist at all — produced exit 0, a full artifact set, and a conformance report reading `result=pass` with 19 G7 checks satisfied, for a model nobody could open. Since that fabricated card is not empty, the existing card-present gate let it through. BomLens now inspects the generator's own log, refuses the run, deletes the output, and says the values were placeholders rather than the model; a `401` or `403` gets a hint that differs by whether a credential was supplied. A pending organizational token produces exactly this case. (#438)
- The CLI completion summary now lists the artifacts actually on disk instead of one line per requested flag, so a step that failed to deliver no longer announces a file the user does not have. Running `--spdx` or `--all` against a pre-v1.8.0 scanner image was the common case: no SPDX step exists, none runs, and the summary still named an SPDX artifact. (#425)
- `--model` no longer ships an empty security report. Both guides and the web UI state that an AI-model scan skips it because a model has no package dependencies to match CVEs against, but the CLI's risk-report defaults re-enabled security for every mode, so Trivy ran against an ML-BOM and wrote a `_security.*` set containing nothing. (#426)

### Changed

- SPDX export moved out of the New scan form and into the results. The toggle asked users to decide, before any scan ran, whether they would need SPDX later, and answering wrong meant a full rescan. A scan now always writes CycloneDX, and the SBOM card in the Artifacts section offers "Export as SPDX 2.3", which converts the finished BOM and starts the download right away; the converted file joins the artifact list and the ZIP bundle. Both paths run the same conversion helper, so the result is identical to the CLI's `--spdx`, which is unchanged along with `--all`. Signing remains CLI-only, and the button is hidden where no converter is reachable. (#439)
- The New scan form now seeds the version field with `1.0.0` when the source states no version of its own, so a first-time user who accepts the autofilled project name and presses Run no longer bounces off version validation. A version the source does carry — a docker tag, a `name-1.2.3` file, SBOM metadata — still wins, and an edit is never overwritten. (#429)
- The New scan validation summary no longer tells you to enter a project name that is already filled. Since the inline messages identify the offending fields, the line by the Run button became a neutral pointer to them, and the Korean copy lost a translationese parenthetical. (#428)
- The components table now renders large SBOMs with recycled row chunks: the whole filtered set (up to the 2,000-row server cap) is reachable by plain scrolling, offscreen rows are replaced by measured spacers so the DOM stays small, and the "Show more" button is gone. (#421)
- A failed upload or token stash on the New scan form now shows a situation-specific message (file too large, server unreachable, server error, rejected input) in both languages instead of the raw exception text; the technical detail moves to fine print. (#414)
- The nightly "macOS real scan (Colima)" job was retired: its last 19 runs all failed deterministically at Colima startup (the hosted arm64 runner boots neither the vz nor the qemu backend), so the scan never actually ran. The evidence and the re-add condition are recorded in the workflow; macOS coverage remains a maintainer-run local check. (#422)

### CI

- Example scan jobs reclaim about 25 GB of runner disk before any image work, dropping preinstalled toolchains the project never uses. The dotnet, swift and rust examples pull a language SDK image on top of the scanner image and were intermittently exhausting the runner's free space, failing with "no space left on device" before an SBOM was written. (#430)
- The Dockerfile lint (hadolint) is now blocking at error level, and the external-link check's advisory status is documented inline. (#413)
- A Korean prose style gate now lints the public docs on every PR (`scripts/ko-style/`): translation-ese patterns and the repository's terminology decisions (디렉터리/배지 spellings, 컬럼→열, 리포트→보고서, no coined words), with a self-test proving the linter still detects violations. Applying it fixed six live violations. (#417)
- The SPDX checks the Windows verification round left to a human eye — the SPDX chip and the chip addressing the `.spdx.json` artifact — are now Playwright specs, now covering the on-demand export flow that replaced the scan-form toggle. (#419)

### Documentation

- The AI-model path is now visible from the entry points. The landing intro listed inputs as source, container, binary or a received SBOM — omitting firmware and AI models entirely — so a visitor looking for a G7 or EU AI Act SBOM tool found nothing on the front page. (#427)
- The AI model guide now says where `scan-sbom.sh` comes from. It opened with `docker pull` and then invoked the script without linking any installation page, which left a reader arriving from an external guide unable to run the first command. (#440)
- Documented the SPDX export toggle in the web UI reference pages. (#436)
- The README demo GIF is now reproducible: a tagged Playwright spec drives a stubbed scan through the walkthrough and the recording is made in the same pinned container as the guide screenshots. The previous hand recording predated the regulatory crosswalk, license classification and current New scan form, and rotted silently whenever the UI moved. (#424)
- Synced the docs site and README with features shipped across v1.5–v1.8 that were undocumented, thin, or inaccurate: the web UI upload step (Dependency-Track/TRUSCA), the Maven/Node full-graph opt-outs (`BOMLENS_MAVEN_FULL_GRAPH`, `BOMLENS_NODE_FULL_GRAPH`), the conformance spec-version overrides (`CYCLONEDX_SPEC_VERSIONS`, `AI_CYCLONEDX_SPEC_VERSIONS`, `SPDX_SPEC_VERSIONS`), the `ENRICH_EOL` and `STALENESS_ENRICH` variables, the AI compliance profile card and `_ai-profile.*` artifacts, and the `--ui --mount` host-folder option. Corrected the `--all` description, which omitted the `--spdx` it also implies, and the "(CLI only)" note on `--byte-stable`, which has a web UI toggle as well. (#409)
- Added a CI gate (`scripts/check-doc-env-coverage.sh`) that fails when a user-facing environment variable in `scan-sbom.sh --help` is documented in neither the CLI nor the Docker-image reference — the code-to-docs counterpart of the existing docs-to-code drift check. Applying it documented the previously missing `SBOM_AIBOM_IMAGE` override. (#410)
- Korean pages: fixed translationese and coined terms concentrated in the web UI reference and the vendored-OSS guide, unified three drifting notations (디렉터리, 배지, 보고서), and recorded the terminology decisions in the style guide. (#415)
- English pages: a native-quality pass fixed two real defects — firmware-guide links mislabeled "(Korean)" and stale tool version pins in the architecture page — plus literal collocations, run-on passages, and naming consistency. (#418)
- Guide screenshots were regenerated in the pinned Playwright container, so the conformance section and New scan form images match the shipped UI (regulatory crosswalk, AI compliance card, SPDX toggle). (#416)

## [v1.8.2] - 2026-07-15

### Changed

- Supplier-SBOM conformance no longer fails outright on `pkg:generic` or custom PURLs. These were a mandatory check, so a single untraceable component failed the whole verdict even when every other requirement was met — common for embedded and firmware supplier SBOMs. The `no-generic` check is now advisory (a warning, not folded into the recommended-coverage warnings), the count stays visible through a new `untraceableComponents` field and a report line, and the overall pass/fail is left to the remaining mandatory checks.

### Fixed

- The SPDX conformance transitive-dependency check now counts `DEPENDENCY_OF` relationships as well as `DEPENDS_ON`. Syft writes OS-package dependency edges in SPDX as the reverse relationship `DEPENDENCY_OF` (for example `NetworkManager-libnm DEPENDENCY_OF NetworkManager`), never `DEPENDS_ON`, while the same scan's CycloneDX carries `dependsOn`. The check only asks whether dependency edges exist, so it now accepts both directions; previously every Syft-generated SPDX submission received a false transitive failure despite a fully populated dependency graph. Both the SPDX JSON and Tag-Value paths are covered; the CycloneDX path is unchanged.
- Post-processing modes now fail closed when the finished SBOM never reaches the host. The host-output verification was gated on `--generate-only`, so the default path — including ANALYZE — printed "Analysis Complete!" over an empty folder when the `/host-output` mount did not reach the host (an output directory outside Docker Desktop file sharing, or under `/tmp` on Colima, where only the home directory is shared to the VM). Every post-processing mode writes the output file, so its absence now reports the failure in all modes.
- Source-tree enrichment is confined to source-scan modes. The vendored-OSS (SCANOSS) and CocoaPods steps read the mounted source root with no mode guard, and the web UI mounts its host directory for every mode, so an ANALYZE of a supplier SBOM could discover a stray `Podfile.lock` in that tree and merge unrelated components into the result. Both steps are now gated on the scan mode, so ANALYZE, MERGE, IMAGE, BINARY, ROOTFS, FIRMWARE, and AIBOM no longer scan a mounted source tree.
- Empty file components from SPDX conversion are dropped. Syft's SPDX-to-CycloneDX conversion turns each SPDX file entry into a `file` component with no name and no PURL — an unidentifiable row with no CVE match, license, or attribution. A supplier SPDX with a large file section added thousands of these, skewing the notice count and the UI inventory. A normalize filter now drops only components that are both a file and carry neither name nor PURL; real packages and named or PURL-bearing file components are untouched.

## [v1.8.1] - 2026-07-15

### Added

- Regulatory crosswalk on the AI SBOM conformance report: each G7 minimum element that maps to a regulation is linked to the documentation obligation it touches, so a reviewer can see which regulatory requirement a missing element concerns. Two frameworks are mapped — the EU AI Act's Annex IV technical documentation (Regulation (EU) 2024/1689, Article 11(1)) and the Korean AI Framework Act (제31/32/33·34/35조). It is informational only: it never changes a check's status or the overall result, and the report states that BomLens does not certify compliance with any regulation. The mapping lives in `docker/lib/regulation-crosswalk.json`, keyed by G7 element id and validated against the registry so it cannot drift silently.
- AI compliance profile: for an AI SBOM, a one-page profile (`{prefix}_ai-profile.{json,md,html}`) re-aggregates the G7 status by cluster, the regulatory crosswalk, and the components whose license is flagged for review (AI behavioral-use or non-commercial). It runs no scan, makes no compliance determination, and is a no-op for a non-AI SBOM.
- Web UI: the Conformance section now shows the regulatory crosswalk as a sub-block (per-framework present/gap/review with the no-certification disclaimer) and a compact AI compliance summary card, and the AI profile reports are listed and downloadable.

### Changed

- The repository and tool identifiers were renamed from sbom-tools to bomlens; references across the docs, configuration, and image names were updated.

## [v1.8.0] - 2026-07-13

### Added

- Components past their published end-of-life are now flagged, offline by default. A bundled endoflife.date snapshot is matched by PURL coordinate (accuracy-first closed mapping — an unmapped component is left untouched, never guessed), and the result is surfaced in the web UI results. A runtime or framework past EOL receives no upstream fixes, so this answers a supply-chain question distinct from CVEs.
- Component version currency: the same snapshot reports when a component is behind the newest patch of its own release line (offline, default on — a safe in-cycle upgrade signal). With `STALENESS_ENRICH=true`, deps.dev is queried per package (opt-in, default off) for the absolute newest version, releases-behind, and last-release date across npm, PyPI, Maven, Go, Cargo, NuGet, and RubyGems.
- Opt-in SPDX output: `--spdx` (env `GENERATE_SPDX`, included in `--all`) additionally exports the finished BOM as SPDX 2.3 JSON (`{prefix}_bom.spdx.json`) after every enrichment step, with its own signature under `--sign` and byte-stable output under `--byte-stable`. The web UI gains an "SPDX export" toggle. CycloneDX remains the working and upload format; CycloneDX-only data (vulnerabilities, `bomlens:*` properties) is not carried over.
- The web UI can scan directories outside the launch folder — including the running host OS. `scan-sbom.sh --ui --mount <dir>` (repeatable; `SBOM_UI_MOUNT_DIR` for the Windows launcher) mounts each directory read-only and the Directory path input offers them as scan locations. The desktop app adds an in-app folder picker that persists the mounts across restarts. Scanning a live `/` excludes `/proc`, `/sys`, `/dev`, and `/run`.
- The sidebar rail and the overview jump card now show the conformance coverage figure (G7 element coverage for AI SBOMs, passed/total format checks otherwise), like the component and vulnerability counts.
- THIRD_PARTY_LICENSES.md now records the web UI's bundled fonts (Inter and JetBrains Mono, both OFL-1.1) with the attribution the license requires.

### Changed

- Supplier-SBOM conformance now enforces two more submission requirements as mandatory checks: the spec version must be in the accepted range (CycloneDX 1.3–1.6 and SPDX 2.2–2.3, overridable via `CYCLONEDX_SPEC_VERSIONS`/`SPDX_SPEC_VERSIONS`; AI SBOMs also accept CycloneDX 1.7, which the AIBOM toolchain emits), and every PURL must follow the standard `pkg:type/name@version` shape — colon coordinates, a missing `pkg:` prefix, a missing version, or raw spaces now fail with the offending PURLs listed. Previously only PURL presence and the `pkg:generic` ban were enforced, so a schema-valid SBOM with malformed PURLs passed.
- Firmware CVE matching no longer bundles cve-bin-tool's ~1.5 GB NVD database, which could not be built reliably — cve-bin-tool's NVD `api2` fetch is rate-limited into multi-hour stalls (and blocked outright from cloud runner IPs), and its `json-mirror` source is dead. cve-bin-tool now only identifies firmware binaries; their CPEs are matched against a compact index (~130 MB) distilled at build time from the NVD data feeds (`fkie-cad/nvd-json-data-feeds`, a plain git clone with no rate limit or API key). The firmware image builds on standard cloud runners again — no NVD key, no BuildKit secret, and no self-hosted runner — while offline/air-gap matching and the security-report contract are unchanged.

### Fixed

- `scan-sbom.sh --ui` no longer requires a TTY, so the documented web UI entry point works from CI, pipes, and wrappers instead of dying with `the input device is not a TTY`.
- When a zip created by PowerShell `Compress-Archive` is rejected by the container's `unzip` (backslash-separated entries), the scan now explains the cause and suggests re-zipping with Explorer instead of printing a bare `unzip failed`.
- Web UI layout defects found in a full-screen visual audit: the new-scan settings panel fits one screen again (advanced options and upload are collapsed disclosures with an enabled-count badge), large dependency graphs snap to a legible zoom instead of rendering as a dot cloud (the snap handler was attached after the synchronous initial layout and never fired), small result tables no longer pad to an empty 256px box, the overview card grid no longer leaves a lopsided empty tail, and the security artifact card no longer shows two identical "JSON" chips.

## [v1.7.0] - 2026-07-08

### Added

- iOS apps are now supported: a CocoaPods `Podfile.lock` or a Swift Package Manager `Package.resolved` is read into the SBOM with the full transitive pod/package set, and — for CocoaPods — the dependency graph reconstructed from the lockfile. Resolution is lockfile-first, so it runs offline and needs neither the `pod` CLI nor macOS. (cdxgen's own CocoaPods path requires `pod`, which the Swift image does not carry, and it aborted the scan when a `Podfile` was present.)
- The web UI can upload the generated SBOM to a Dependency-Track or TRUSCA server (previously CLI-only). New scan has an optional Upload section for the destination, server URL, API token, and — for TRUSCA — the project id. The token is stashed single-use and the server URL and token are used for that run only, never stored.
- New scan exposes a "Reproducible output" toggle in the advanced options, surfacing the byte-stable mode that was previously CLI-only. When on, re-scanning the same source produces a byte-for-byte identical SBOM. The toggle is hidden for supplier-SBOM analysis and AI model scans, where it does not apply.

### Changed

- Best-effort post-processing steps (normalize, CPE and AIBOM enrichment, conformance, vendored-OSS suggestion) no longer swallow real failures. They kept the never-abort guarantee by ending in `|| true`, which also hid genuine errors; each step now logs a WARN and stamps `bomlens:pipeline-step-failed` on the SBOM when it fails, so a degraded run is visible instead of silently incomplete.

### Fixed

- Maven source scans no longer inflate the SBOM with the test and provided toolchain (junit, lombok, etc.). The scan is scoped to the deployable runtime set using cdxgen's resolved scope tags — compile and runtime dependencies are kept, test and provided ones are dropped — the Maven analogue of the Android and npm release-scope fixes. Set `BOMLENS_MAVEN_FULL_GRAPH=1` to keep the full graph.
- Android product-flavor projects now scope to the release runtime classpath instead of silently falling back to the full build + test graph. The release-config selection dropped every candidate when a project had no plain `releaseRuntimeClasspath` (only flavored variants such as `freeReleaseRuntimeClasspath`), so flavored apps were reported with their whole toolchain. It now prefers the plain classpath and otherwise takes the first flavored release variant.
- Node.js (npm) source scans no longer inflate the SBOM with the `devDependencies` tree (jest, eslint, the Babel toolchain, etc.). The scan is scoped to the deployed `dependencies`, so build and test tooling the app never ships is excluded — the npm analogue of the Android release-scope fix. Set `BOMLENS_NODE_FULL_GRAPH=1` to keep the dev + prod superset.
- Android (AGP) source scans no longer inflate the SBOM with the build and test toolchain. The scan is scoped to the deployable release runtime classpath, so only the components shipped in the APK are recorded.
- Firmware scans no longer silently report zero CVEs from a vulnerability database that lacks NVD data. The build gate now rejects a bundled CVE database without a real NVD advisory corpus instead of shipping it.
- Native Windows source scans work under Git for Windows: docker bind mounts and the Git Bash resolution in `scan-sbom.bat` were corrected so a Windows (MSYS) shell can run a scan instead of failing at container start.
- Windows web/desktop UI source scans resolve transitive dependencies again. The cdxgen (and firmware/AIBOM) sibling containers were bind-mounted by a Windows drive path (`C:/…`) that the in-container Linux docker CLI cannot consume, so the scan silently fell back to syft (direct dependencies only). The siblings now inherit the UI container's mounts with `--volumes-from`, so they run on every host OS — verified on Windows, where UI and CLI scans now produce identical SBOMs.
- Firmware security reports are no longer empty. The bundled Trivy could not decode the firmware SBOM's `firmware` root component type and failed the whole scan; Trivy is now retried on an input copy whose root type is coerced to one it accepts, so the vulnerability report is populated while the delivered SBOM keeps its accurate `firmware` type.

## [v1.6.0] - 2026-07-03

### Added

- AI SBOM conformance now covers the full G7 minimum-elements checklist: seven clusters rendered as 51 checks, each tagged as read from the SBOM, inferred from signals, or requiring human review. The web UI groups the results by cluster, and the AI model guide explains what the checklist is, its EU AI Act context, and how to read the report.
- The desktop app checks for a newer release on startup and offers the download page.
- The desktop app recovers without a relaunch: the Docker-missing and failure screens have retry buttons, a scanner container that dies after the UI loads is detected and reported, containers left behind by a crash are cleaned up on the next start, and a second launch focuses the running window instead of starting a duplicate.
- Desktop quality of life: the version is visible on the start screen and About panel, window size and position are remembered, startup progress is written to a log file, and the start screens support light mode, a language toggle, and per-OS Docker installation guidance.
- New scan prefills the project name and version from the scan source (git URL, Docker image tag, uploaded file name, or SBOM metadata), marks required fields, and validates them inline.
- The macOS installer is universal: it now runs on Intel Macs as well as Apple Silicon.
- The desktop installers are covered by the release's `SHA256SUMS.txt`, so downloads can be integrity-checked.

### Changed

- Advanced scan option labels lead with what they do ("Per-file license scan", "Detect copied-in open source", "More vulnerability advisories"); the tool names moved into the hints.
- The desktop app pulls the documented image tag (`ghcr.io/sktelecom/bomlens`) — the same image it used before, under its current name.
- Installer code signing and notarization turn on automatically once certificates are registered as CI secrets; installers remain unsigned until then.

### Fixed

- OS package CVE matching in SBOM security scans was restored.
- syft output is pinned to CycloneDX 1.6 because Trivy 0.70 cannot read 1.7; security scans of syft-generated SBOMs work again.
- A failed security scan is now marked as failed in the report instead of silently reporting zero findings.
- PyPI version ranges no longer duplicate the installed version as a lower bound.
- The `--deep-license` image builds and runs again.

## [v1.5.5] - 2026-07-01

### Fixed

- Maven and Gradle source scans now record their direct dependencies in the SBOM dependency graph. The root component previously carried an empty `dependsOn`, so tools reading the graph classified every direct dependency as transitive. npm was unaffected.

## [v1.5.4] - 2026-06-28

### Added

- The result Overview leads with the section jump cards and shows Security and License classification side by side; clicking a band opens that section pre-filtered.
- Licenses are graded by copyleft strength (network / strong / weak / permissive), with separate review-needed and uncategorized classes; an unrecognised license is never assumed permissive.
- The home screen is now Scan management: search past scans, filter by scan type, and see total / at-risk / project counts, with the at-risk card doubling as a filter.
- Global search across components and CVEs from the top bar.
- Re-scan: re-run a finished scan with the same target and options from the top bar.
- The SCANOSS client ships in the base image, so vendored open-source identification works out of the box (still opt-in at scan time).
- Running firmware and AI scans can be cancelled.

### Changed

- New scan and Recent moved into the top bar, so the left rail is purely the current scan's sections.
- New scan's advanced analysis toggles moved into their own Advanced scan options section, with clearer copy and SCANOSS free-tier guidance.
- Generated HTML reports were restyled to match the web UI.
- The scan progress bar follows the real pipeline stages, and the Scan management table columns are sortable.
- The dependency rail badge shows the direct/transitive split.

### Fixed

- A source scan that falls back to syft is labelled "Source" instead of "SBOM", and now says so when the fallback was caused by Docker running out of disk.
- Fonts are self-hosted so the desktop content-security policy keeps the intended typography.

## [v1.5.3] - 2026-06-27

### Added

- The dependency graph view was redesigned to read like a commercial graph explorer.
- License distribution is shown as proportional bars, with the charts animating in on first render.
- Each scan now shows how it compares to the previous run of the same project.

### Changed

- Interactive result cards lift on hover, with motion that honours the operating system's reduced-motion setting.

### Fixed

- `SECURITY_ENRICH=false` now reaches the post-process container, so the EPSS and CISA KEV opt-out works from the host CLI for air-gapped runs.
- `--analyze`/`--sbom` combined with `--model` is now rejected instead of silently running in ANALYZE mode.
- AI SBOM generation fails closed when the model card cannot be collected (offline, or an unknown/private model id) instead of writing an empty stub ML-BOM as a valid output.
- Supplier SBOM analysis now produces the conformance report for well-formed SPDX Tag-Value inputs; a zero-count grep had aborted the Tag-Value checks.
- Reopening a past scan from history no longer shows an empty run-log panel.
- A release stays a draft until the release gate verifies it, so it is never published before its entry points are checked.

### Documentation

- Corrected the supplier-SBOM conversion note (SPDX is converted to CycloneDX 1.6; CycloneDX inputs keep their original spec version), removed the unimplemented drag-resizable columns claim from the UI reference, fixed the Node.js lock-file guidance, and added page descriptions to five navigation pages.

## [v1.5.2] - 2026-06-26

### Added

- Per-run output isolation: each scan now lands in its own `{Project}_{Version}/` subfolder, so the files from one run stay together and the CLI never litters the source tree it scans. New `--output-dir`/`-o` and `--timestamp` flags choose the base directory and keep repeat runs side by side.
- Release gate: a release is created as a draft and only published after its recommended entry points are verified for that exact release — the desktop installers are attached and the documented first-scan command produces a valid SBOM on the actual published image.
- Onboarding CI gates that keep the docs and the tool in step: a doc/tool drift check (flags, environment variables, image names, the desktop download name), an internal-link check for the getting-started pages, machine UX checks (no silent error exits, parity between the setup scripts, a complete `--help`), a desktop-app boot smoke on Windows and macOS, and a walkthrough that runs the documented first-scan command on the published image.

### Changed

- Scan outputs default to a `{Project}_{Version}/` subfolder of the current directory instead of being written flat. Set `SBOM_OUTPUT_FLAT=1` for the previous flat layout.

### Fixed

- `--byte-stable` is now reproducible: it no longer resolves dependency licenses over the network, a lookup whose success varied between runs and made two otherwise-identical scans differ.
- Source scans no longer leave root-owned build files (for example `node_modules`) in the scanned project folder or the git/zip ingestion temp directory on Linux; the scanned tree is handed back to the host user.
- The README pointed at a renamed desktop installer; the download links now use `BomLens-Setup.exe` and `BomLens-Setup.dmg`.
- Documented the `--ref` alias for `--branch`.

## [v1.5.1] - 2026-06-26

### Added

- Desktop app firmware and AI-model scans: the desktop app now runs firmware and AI-model (AIBOM) scans by launching the matching scanner image as a sibling container, pulling it on first use.
- Source file tree without ScanCode: source scans emit a `_files.json` file inventory, and the web UI shows a source tree from it when no ScanCode result is present.
- SBOM conformance is now a first-class result section, with per-element G7 evidence, examples and guidance links.
- Determinate firmware CVE-database download progress: a real percentage bar during the cve-bin-tool database fetch, falling back to the previous approximation when a scan reports no progress.

### Changed

- Web UI design-language refresh: a redesigned visual language, a Recent-scans home, and neutralized report wording.
- Release assets are unified under the BomLens name (for example `BomLens-Setup.*`), and the release notes link to the documentation site.
- The AI-model scan form now explains the open-source Notice option.

### Fixed

- Firmware scans matched zero CVEs because the published firmware image shipped an empty cve-bin-tool database. The image now bundles a populated database with a runtime refresh, the build fails if the database ends up empty, and the database path matches the location cve-bin-tool actually uses.

## [v1.5.0] - 2026-06-25

### Added

- Redesigned web UI: a new shell with Overview, Components, Dependencies, Vulnerabilities, Licenses, AI (Models & datasets / G7), and Artifacts sections; a single-card New scan form; and local Recent scans (list, re-open, delete; newest 20 shown). Every navigation element is a real link, so the logo, New scan, sidebar sections, recent scans and jump cards open in a new tab (Cmd/Ctrl/middle click) via URL-hash routing.
- AI-model SBOM (AIBOM): generate a CycloneDX ML-BOM for a HuggingFace model id — with G7 minimum-element conformance — from the web UI's AI model input. Published as the new `bomlens-aibom` image (legacy alias `sbom-scanner-aibom`).
- EPSS exploit probability and CISA KEV (actively exploited) surfaced on vulnerabilities.
- Component detail: click a component row to see its PURL, source/download location, copyright, licenses and vulnerabilities.
- License explorer: click a license to list its components, with copyleft/reciprocal licenses highlighted.
- Vulnerability view: click the severity bar to filter, plus a search box; all result tables are drag-resizable.
- Firmware analysis: cve-bin-tool now matches CVEs online (the firmware image bundles the vulnerability DB), and an enrichment step fills CPEs and SPDX licenses for a curated whitelist of well-known OSS (busybox, dropbear, dnsmasq, …) so Trivy and the notice can use them. Compressed firmware images (`.img.gz`, `.tar.xz`, …) can be uploaded.
- Open-source notice: per-component source/download location and copyright line, plus an optional PDF rendering (`SBOM_PDF` build).
- SCANOSS: a token input for the OSSKB endpoint (the free anonymous endpoint is rate-limited), and a result note that distinguishes "search unavailable" from "nothing found".

### Changed

- Advanced scan options (deep license / SCANOSS) appear only for source scans; AI-model scans drop the deep-license toggle and the (always-empty) security report.
- G7 conformance moved under the AI group, with per-element "what it is / how to satisfy" guidance.
- The live run log now appears only on the Overview, not under every section.
- The scan banner and UI startup logs are unified to "BomLens".

### Fixed

- SCANOSS found nothing on uploaded/cloned sources because they extract under a dot-prefixed `.uploads` path that scanoss-py skips by default (`--all-hidden`).
- The firmware component merge hit the command-line length limit on large rootfs images (jq now reads arrays from files via `--slurpfile`).
- The dependency graph drew edgeless SBOMs (e.g. firmware) as overlapping dots — it now shows a note — and framed large graphs too far out to read.
- AI scans were labelled by the generator's `job-<timestamp>` instead of the model name.
- The scan done-event listed every artifact in the output folder instead of only the current scan's.
- Leaving a running scan no longer lets the backgrounded scan finish and hijack the screen (the live SSE stream is closed on navigation).

## [v1.4.0] - 2026-06-23

### Added

- Identify open source copied (vendored) into C/C++ source that has no package manager. `--identify-vendored` matches file fingerprints against the SCANOSS/OSSKB knowledge base and records copied-in open source as named components (name, version, PURL, and a CPE where one exists), so the security report can surface their CVEs. It is off by default, with a one-line suggestion shown automatically when a scan looks like C/C++ embedded source, and is available in the web UI under Advanced. Matches are reconciled against the package-manager scan, so enabling it on a managed project does not duplicate dependencies or inflate the vulnerability count. Hardened with an adversarial CLI + UI test campaign (CPE-grammar safety, large-tree handling, over-detection, injection). (#168, #169)

### Changed

- The published `bomlens` image now bundles the (MIT-licensed) SCANOSS client, so `--identify-vendored` works out of the box without a custom build. (#168)

## [v1.3.1] - 2026-06-22

### Added

- Server delivery SBOM: scan a server's layers separately (OS rootfs and application) and combine them with `--merge`, which merges several CycloneDX SBOMs into one; the web UI accepts a rootfs directory as input. (#161)

### Changed

- GHCR package names are unified under the `bomlens` brand; `sbom-generator` and `sbom-scanner` remain aliases of the same digest. (#156)
- The Android image pull defaults to the published `bomlens` name. (#157, #158)
- Documentation is restructured by intent with English as the canonical language, sidebar labels shortened, and the landing pages use the web UI demo gif. (#154, #155, #160)

### Fixed

- Source scans no longer leak `src@latest` as the root component name, which became a non-unique codelocation in some SBOM import platforms and blocked unrelated imports. The caller's project name is now passed to cdxgen and stamped into the root component, and the pipeline fails closed if stamping does not take. (#166)
- `--merge` preserves each input's dependency graph so the merged BOM stays CycloneDX-conformant. (#164)
- Follow-ups from the v1.3.0 verification pass (V13-1/2/3). (#159)
- Corrected the first-scan link in the Korean server-delivery guide and modeled static linking as a blind spot rather than a separate layer. (#162, #163)

## [v1.3.0] - 2026-06-14

### Added

- `--trusca <project_id>` (or `--upload-target trusca`) uploads the generated SBOM to TRUSCA's native ingest endpoint as an alternative to the default Dependency-Track upload. (#148, #149)
- Vulnerability rows in the web UI expand in place to show the CVSS score and vector, the full advisory description, and reference links — surfacing data already in the Trivy report without an extra fetch.
- The components table in the web UI can now sort by name, version, or type and filter by component type and license, alongside the existing search.
- The vulnerabilities table can be filtered by severity, and the summary tab shows a license distribution (component count per license, plus unlicensed).
- The dependency graph is now interactive: click a node to see its details (version, type, licenses, direct/indirect), and search to highlight matching packages.
- Documentation site: a Release notes link in the nav (pointing at GitHub Releases) and opt-in, cookieless analytics (GoatCounter) that stays off until a site code is configured.

### Changed

- Unified the web UI's empty, loading, and error states into shared primitives so every result view looks and behaves the same, and added a retry action to the dependency and source-tree views.

### Fixed

- Dependency graph node labels were unreadable in dark mode (fixed dark text on a dark canvas); graph colors now follow the light/dark theme tokens.
- Small dependency graphs no longer over-zoom into huge, overlapping labels; zoom is capped and node spacing widened so a handful of nodes stays readable.

## [v1.2.2] - 2026-06-13

### Added

- BomLens brand identity: aperture logo, app icons, and favicon across the docs site, web UI, and desktop app. (#125, #127, #128, #130)
- Rendered documentation site (sktelecom.github.io/bomlens) with sidebar navigation, search, and a one-click Windows download, replacing repo-only docs. (#112, #113, #114, #115, #116)
- New documentation pages on the site: use the Docker image directly, architecture, and the two contributing guides, each with an English translation. (#126)
- English translations for the five previously Korean-only guides. (#117)

### Changed

- Renamed the product display name to BomLens; technical identifiers and download URLs are unchanged. (#120)
- The web UI header shows the BomLens brand with an SBOM generator descriptor. (#124)
- The post-process image is co-published as `ghcr.io/sktelecom/bomlens`; `sbom-generator` and `sbom-scanner` remain aliases of the same digest. (#121, #122)
- Reworked the Korean guides for readability and kept the synced English pages aligned; wide architecture diagrams now stack vertically. (#123, #129)
- The docs home leads with a headline, a Get started primary button, and a product screenshot; the header brand links to the home page. (#131, #132)

### Fixed

- The desktop app startup screen background matches the web UI dark token. (#118)

## [v1.2.1] - 2026-06-12

### Security

- The web UI cleanup endpoint validates the provided token before removing staged uploads, and CI workflows run with least-privilege permissions. (#106)
- Pinned base image digests so the supply chain is verifiable (Scorecard pinned-dependencies). (#107)

### Fixed

- The NOTICE dedupes appended SPDX license texts and normalizes the Expat alias to MIT, so each license text appears once. (#108)
- The SBOM stamps `metadata.component` from the input project name and version instead of leaving it unset. (#108)
- Stabilized byte-stable SBOM output and coerced null components to empty arrays, preventing spurious diffs and parse failures. (#108)

## [v1.2.0] - 2026-06-11

### Added

- Web UI source scans (current directory, Git URL, ZIP upload) now resolve transitive dependencies through cdxgen language images, matching the CLI. The web UI previously used syft, which captured only directly declared dependencies; a Spring Boot sample went from 8 to 91 components. (#95)
- Scan results gained Components and Vulnerabilities tabs with searchable, sortable tables, next to the existing summary. (#96)
- Source scans now fetch dependency licenses (`FETCH_LICENSE`, on by default), so components and the NOTICE carry real license data instead of NOASSERTION. Set `FETCH_LICENSE=false` to skip the lookups. (#98)
- The NOTICE normalizes license aliases to SPDX ids, shows component copyright when present, and appends the SPDX standard full text of each used license from a bundled set (21 common licenses, offline). (#99)
- The security report surfaces CVSS, EPSS (exploit probability) and CISA KEV (known-exploited) signals, sorting findings KEV first, then by severity, then by EPSS. Set `SECURITY_ENRICH=false` for offline runs. (#100)
- Redesigned the post-scan artifact download experience with per-format chips and a bulk ZIP download. (#102)

### Changed

- Synced the user documentation, in-app help, and screenshots with the new features. (#101, #103)

### Fixed

- Removed the redundant maven pre-resolve step in build-prep that printed a spurious NoPluginFoundForPrefix error on every Java source scan, with no effect on the resulting SBOM. (#97)

## [v1.1.1] - 2026-06-09

### Added

- Desktop startup screen is now bilingual: it follows the system locale (Korean on Korean systems, English elsewhere) and falls back to English, matching the web UI. The `SBOM_LANG` environment variable forces a language (`SBOM_LANG=en` or `ko`).

### Changed

- The main `README.md` is unified to English, with English UI screenshots. The Korean documentation table and Korean guides are kept for Korean users; the Korean screenshots stay with the Korean docs.

## [v1.1.0] - 2026-06-02

### Added

- Electron desktop app (`electron/`) that wraps the web UI with no console window: it checks Docker, pulls the scanner image, runs the `MODE=UI` container, and opens the UI on double-click.
- Desktop installers (`SBOM-Generator-*.exe` / `.dmg`) are built in CI and attached to tagged GitHub Releases, so non-developers can download them directly. Unsigned for now, so Windows SmartScreen prompts to confirm.
- License-manager quickstart (`docs/notice-quickstart.md`) and a setup-check helper (`scripts/check-setup.bat` / `scripts/check-setup.sh`) that reports Docker, image, and port status in Korean.
- Windows verification assets: an automated smoke test (`tests/windows-smoke.ps1`) and a manual e2e checklist (`tests/windows-e2e-checklist.md`).
- Desktop-app packaging study (`docs/internal/desktop-app-study.md`).
- Screenshots and a flow diagram across the user guides.
- Firmware analysis (FIRMWARE mode): unpack a firmware image and produce an SBOM and risk report.
- Supplier SBOM validation and analysis (ANALYZE mode) for SBOMs you receive from third parties.
- End-to-end support for five input forms (source folder, GitHub URL, ZIP archive, Docker image, binary/RootFS) with a risk report emitted in every mode.
- Local web UI: launch a scan, stream live logs, and download results from the browser.
- Cosign signing of generated artifacts via `--sign`, with the key and password passed into the container at runtime.
- Multi-architecture Docker images, with architecture detected at runtime for Trivy and cosign.
- Governance and community-health documents: `CODE_OF_CONDUCT.md` and `SECURITY.md`.
- Korean documentation style guide, enforced by a doc-style check.

### Changed

- `scripts/sbom-ui.bat`: results go to a dedicated `%USERPROFILE%\sbom-output` folder, the scanner image is pre-pulled on first run with progress shown, and messages are in Korean.
- README routes first-time Windows users to the easiest path up front, and the license-manager quickstart leads with the desktop app and lists expected install and download times.
- Renamed the product to SBOM Generator; the post-process image is co-published as `ghcr.io/sktelecom/sbom-generator` (the legacy `sbom-scanner` name keeps working).
- Windows-friendly onboarding: a download-and-double-click web UI flow, plus consistent Windows guidance across the supplier docs.
- The Windows release archive now bundles both launchers and the host-mounted `build-prep.sh`, so it runs without the full repo.
- Reworked the scanner into a two-stage architecture (generate, then assess risk).
- Documentation refreshed to match the current product, including the web UI flow and the two core roles.

### Fixed

- Standard squashfs images now extract correctly during firmware unpacking.
- Detection of `.csproj`-only and `.gradle`-only projects (multi-glob matching bug).
- Generated artifacts are written as the host user so the Examples CI no longer fails on root-owned files.

## [v1.0.0] - 2026-02-19

### Added

- Initial public release of SBOM Tools.
- CycloneDX SBOM generation from source code for Java (Maven/Gradle), Python, Node.js, Ruby, PHP, Rust, Go, .NET, and C/C++.
- Open-source notice (고지문) and a Trivy-based security report alongside each SBOM.
- Docker image distribution via `ghcr.io/sktelecom/sbom-scanner`.
- GitHub Actions workflows for CI (ShellCheck, hadolint, integration and example tests), image publishing, and releases.

### Security

- No publicly known vulnerabilities have been reported or fixed in this project to date.

[Unreleased]: https://github.com/sktelecom/bomlens/compare/v1.11.6...HEAD
[v1.11.6]: https://github.com/sktelecom/bomlens/releases/tag/v1.11.6
[v1.11.5]: https://github.com/sktelecom/bomlens/releases/tag/v1.11.5
[v1.11.4]: https://github.com/sktelecom/bomlens/releases/tag/v1.11.4
[v1.11.3]: https://github.com/sktelecom/bomlens/releases/tag/v1.11.3
[v1.11.2]: https://github.com/sktelecom/bomlens/releases/tag/v1.11.2
[v1.11.1]: https://github.com/sktelecom/bomlens/releases/tag/v1.11.1
[v1.11.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.11.0
[v1.10.5]: https://github.com/sktelecom/bomlens/releases/tag/v1.10.5
[v1.10.4]: https://github.com/sktelecom/bomlens/releases/tag/v1.10.4
[v1.10.3]: https://github.com/sktelecom/bomlens/releases/tag/v1.10.3
[v1.10.2]: https://github.com/sktelecom/bomlens/releases/tag/v1.10.2
[v1.10.1]: https://github.com/sktelecom/bomlens/releases/tag/v1.10.1
[v1.10.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.10.0
[v1.9.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.9.0
[v1.8.3]: https://github.com/sktelecom/bomlens/releases/tag/v1.8.3
[v1.8.2]: https://github.com/sktelecom/bomlens/releases/tag/v1.8.2
[v1.8.1]: https://github.com/sktelecom/bomlens/releases/tag/v1.8.1
[v1.8.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.8.0
[v1.7.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.7.0
[v1.6.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.6.0
[v1.5.5]: https://github.com/sktelecom/bomlens/releases/tag/v1.5.5
[v1.5.4]: https://github.com/sktelecom/bomlens/releases/tag/v1.5.4
[v1.5.3]: https://github.com/sktelecom/bomlens/releases/tag/v1.5.3
[v1.5.2]: https://github.com/sktelecom/bomlens/releases/tag/v1.5.2
[v1.5.1]: https://github.com/sktelecom/bomlens/releases/tag/v1.5.1
[v1.5.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.5.0
[v1.4.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.4.0
[v1.3.1]: https://github.com/sktelecom/bomlens/releases/tag/v1.3.1
[v1.3.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.3.0
[v1.2.2]: https://github.com/sktelecom/bomlens/releases/tag/v1.2.2
[v1.2.1]: https://github.com/sktelecom/bomlens/releases/tag/v1.2.1
[v1.2.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.2.0
[v1.1.1]: https://github.com/sktelecom/bomlens/releases/tag/v1.1.1
[v1.1.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.1.0
[v1.0.0]: https://github.com/sktelecom/bomlens/releases/tag/v1.0.0
