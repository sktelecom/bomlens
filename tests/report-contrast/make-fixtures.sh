#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# make-fixtures.sh - regenerate the demo-scale inputs of
# tests/test-report-contrast.sh in tests/fixtures/report-contrast/. The output is
# committed; run this only to change the data, then commit the result.
#
#   sbom.json   a 72-component CycloneDX 1.6 SBOM with every licence class, a
#               licence that needs review, components with no version or no
#               package purl, and a missing required field (conformance fails)
#   risk-bom.json  the same components as the pipeline's normalized _bom.json would
#               carry them: licence-conflict, malicious-package, presence-only and
#               model-assessment properties the risk report reads
#   trivy.json  a canned Trivy result: 360 findings over all five severities, ten
#               kernel advisories and a few advisories that name no CVE
#   epss.json   canned EPSS answer for those CVEs (FIRST.org response shape)
#   kev.json    canned CISA KEV answer (a subset of those CVEs)
#
# Fully deterministic: no clock, no network, no randomness.
set -e

OUT="$(cd "$(dirname "$0")/../fixtures/report-contrast" && pwd)"
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 2; }

# Software SBOM ---------------------------------------------------------------
jq -n '
  def lic: ["MIT","Apache-2.0","BSD-3-Clause","MIT","ISC","MPL-2.0","LGPL-2.1-only",
            "GPL-3.0-only","AGPL-3.0-only","Apache-2.0","BSD-2-Clause","GPL-2.0-only",
            "EPL-2.0","LicenseRef-vendor-eula","MIT","Apache-2.0"];
  def eco: ["npm","maven","pypi","golang"];
  def comp($i):
    (eco[$i % 4]) as $e |
    ("lib-\($i)") as $n |
    ("\(1 + ($i % 5)).\($i % 11).\($i % 7)") as $v |
    { type:"library", "bom-ref":"c\($i)", name:$n, version:$v,
      purl:"pkg:\($e)/\($n)@\($v)", licenses:[{license:{id:lic[$i % 16]}}] };
  { bomFormat:"CycloneDX", specVersion:"1.6", version:1,
    metadata:{ timestamp:"2026-01-01T00:00:00Z",
      tools:{components:[{type:"application",name:"cdxgen",version:"12.0.0"}]},
      component:{type:"application",name:"contrast-sample",version:"1.0.0","bom-ref":"root",
                 licenses:[{license:{id:"Apache-2.0"}}]} },
    components:
      (([range(0;60)] | map(comp(.)))
      + [ { type:"library","bom-ref":"x1",name:"weights-lib",version:"1.0",
            purl:"pkg:npm/weights-lib@1.0",licenses:[{license:{name:"Llama 2 Community License"}}] },
          { type:"library","bom-ref":"x2",name:"openrail-lib",version:"2.1",
            purl:"pkg:pypi/openrail-lib@2.1",licenses:[{license:{name:"OpenRAIL-M"}}] },
          { type:"library","bom-ref":"x3",name:"noncommercial-lib",version:"0.3",
            purl:"pkg:npm/noncommercial-lib@0.3",licenses:[{license:{id:"CC-BY-NC-4.0"}}] },
          { type:"library","bom-ref":"x4",name:"mystery",version:"0.1",purl:"pkg:npm/mystery@0.1" },
          { type:"library","bom-ref":"x5",name:"readline-lib",version:"8.1",
            purl:"pkg:generic/readline-lib@8.1",licenses:[{license:{id:"GPL-3.0-only"}}] },
          { type:"library","bom-ref":"x6",name:"unversioned-lib",purl:"pkg:npm/unversioned-lib" },
          { type:"library","bom-ref":"x7",name:"vendored-blob",version:"3.4" },
          { type:"library","bom-ref":"x8",name:"busybox-applet",version:"1.36.1",
            purl:"pkg:generic/busybox-applet@1.36.1",licenses:[{license:{id:"GPL-2.0-only"}}] },
          { type:"library","bom-ref":"x9",name:"proprietary-agent",version:"7.0",
            purl:"pkg:generic/proprietary-agent@7.0",licenses:[{license:{id:"LicenseRef-vendor-eula"}}] },
          { type:"library","bom-ref":"x10",name:"copyleft-net",version:"4.2",
            purl:"pkg:npm/copyleft-net@4.2",licenses:[{license:{id:"AGPL-3.0-only"}}] },
          { type:"library","bom-ref":"x11",name:"tiny-util",version:"0.0.1",
            purl:"pkg:npm/tiny-util@0.0.1",licenses:[{license:{id:"MIT"}}] },
          { type:"library","bom-ref":"x12",name:"dual-lib",version:"1.1",
            purl:"pkg:maven/dual-lib@1.1",licenses:[{expression:"MIT OR Apache-2.0"}] } ]),
    dependencies:[ {ref:"root", dependsOn:([range(0;60)] | map("c\(.)"))},
                   {ref:"c1", dependsOn:["c2","c3"]}, {ref:"c2", dependsOn:["c4"]} ] }
' > "$OUT/sbom.json"

# Normalized BOM as the risk report reads it ---------------------------------
jq '
  def prop($n; $v): {name:$n, value:$v};
  .components |= map(
      if   .["bom-ref"] == "c7"  then . + {properties:[prop("bomlens:licenseConflict";"incompatible")]}
      elif .["bom-ref"] == "c8"  then . + {properties:[prop("bomlens:licenseConflict";"incompatible")]}
      elif .["bom-ref"] == "c3"  then . + {properties:[prop("bomlens:licenseConflict";"conditional")]}
      elif .["bom-ref"] == "c6"  then . + {properties:[prop("bomlens:licenseConflict";"unknown")]}
      elif .["bom-ref"] == "x7"  then . + {properties:[prop("bomlens:evidenceGrade";"presence-only")]}
      elif .["bom-ref"] == "x11" then . + {properties:[prop("bomlens:malicious";"true"),
                                            prop("bomlens:malicious:id";"MAL-2026-0001"),
                                            prop("bomlens:malicious:source";"OSV malicious-packages snapshot")]}
      else . end)
  | .components += [
      { type:"machine-learning-model","bom-ref":"m1",name:"sample-model",version:"1.0",
        licenses:[{license:{name:"OpenRAIL-M"}}],
        properties:[prop("bomlens:assessment:overall";"conditional")] },
      { type:"machine-learning-model","bom-ref":"m2",name:"sample-model-small",version:"1.0",
        licenses:[{license:{id:"Apache-2.0"}}],
        properties:[prop("bomlens:assessment:overall";"ok")] },
      { type:"machine-learning-model","bom-ref":"m3",name:"sample-model-gated",version:"1.0",
        licenses:[{license:{name:"Llama 2 Community License"}}],
        properties:[prop("bomlens:assessment:overall";"caution")] },
      { type:"machine-learning-model","bom-ref":"m4",name:"sample-model-unknown",version:"1.0",
        properties:[prop("bomlens:assessment:overall";"review")] } ]
' "$OUT/sbom.json" > "$OUT/risk-bom.json"

# Trivy result, EPSS and KEV answers -----------------------------------------
jq -n '
  def sev($i): ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"][
      if   $i % 20 < 2  then 0
      elif $i % 20 < 7  then 1
      elif $i % 20 < 14 then 2
      elif $i % 20 < 18 then 3
      else 4 end];
  def vuln($i):
    (($i % 60)) as $c |
    ["npm","maven","pypi","golang"][$c % 4] as $e |
    { VulnerabilityID:"CVE-2024-\(1000 + $i)",
      PkgName:"lib-\($c)",
      InstalledVersion:"\(1 + ($c % 5)).\($c % 11).\($c % 7)",
      FixedVersion:(if $i % 3 == 0 then "" else "\(2 + ($c % 5)).0.0" end),
      Severity:sev($i),
      Title:"Sample finding \($i): a flaw in a component of the sample project",
      PkgIdentifier:{PURL:"pkg:\($e)/lib-\($c)@\(1 + ($c % 5)).\($c % 11).\($c % 7)"},
      CVSS:{nvd:{V3Score:((($i * 37) % 100) / 10)}},
      PrimaryURL:"https://example.invalid/\($i)" };
  def adv($i):
    { VulnerabilityID:"DLA-\(3000 + $i)-1", PkgName:"lib-\($i)", InstalledVersion:"1.0.0",
      FixedVersion:"1.0.1", Severity:"HIGH", Title:"Distribution advisory \($i)",
      PkgIdentifier:{PURL:"pkg:npm/lib-\($i)@1.0.0"} };
  def kern($i):
    { VulnerabilityID:"CVE-2023-\(5000 + $i)", PkgName:"linux-kernel", InstalledVersion:"5.10.\($i)",
      FixedVersion:"5.10.\($i + 9)", Severity:["HIGH","MEDIUM","LOW"][$i % 3], Title:"Kernel flaw \($i)",
      PkgIdentifier:{PURL:"pkg:generic/linux-kernel@5.10.\($i)"} };
  { SchemaVersion:2, ArtifactName:"sbom.json", ArtifactType:"cyclonedx",
    Results:[ { Target:"sample", Class:"lang-pkgs", Type:"npm",
                Vulnerabilities:(([range(0;360)] | map(vuln(.)))
                                 + ([range(0;4)] | map(adv(.)))
                                 + ([range(0;10)] | map(kern(.)))) } ] }
' > "$OUT/trivy.json"

jq -n '{ data: ([range(0;360)] | map({cve:"CVE-2024-\(1000 + .)",
          epss:("0." + (((. * 7919) % 9000) + 1000 | tostring)), percentile:"0.5", date:"2026-01-01"})) }' \
    > "$OUT/epss.json"
jq -n '{ title:"CISA Catalog of Known Exploited Vulnerabilities",
         vulnerabilities: ([range(0;360) | select(. % 9 == 0)] | map({cveID:"CVE-2024-\(1000 + .)"})) }' \
    > "$OUT/kev.json"

echo "wrote: $(ls "$OUT" | tr '\n' ' ')"
