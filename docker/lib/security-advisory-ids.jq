# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# security-advisory-ids.jq - keep advisory numbers out of the vulnerability list.
#
# Input and output: a Trivy JSON report (_security.json). Trivy reports some
# findings under the number of the advisory that announced the fix rather than
# a vulnerability id: a Debian LTS advisory (DLA-4792-1), a Node.js security
# working group entry (NSWG-ECO-516), a Red Hat or Ubuntu notice. Such a number
# names a publication, not one vulnerability, so it does not belong in a list of
# CVEs, its counts or its EPSS/KEV lookup.
#
# A finding whose VulnerabilityID is not a vulnerability id is handled in one
# of two ways:
#   - Trivy names a CVE for it (in VendorIDs, PrimaryURL or References): it is
#     reported under that CVE, one finding per CVE, and the advisory number is
#     kept in VendorIDs, the field Trivy itself uses for a CVE's advisory
#     numbers. A CVE already reported for the same package takes the advisory
#     number into its own VendorIDs instead of being repeated.
#   - Trivy names no CVE: it moves to the top-level Advisories list, with the
#     Target it came from. It is not counted in the vulnerability totals, the
#     severity counts or the --fail-on gate, and the reports list it apart.
#
# Vulnerability ids: CVE, plus the vulnerability databases whose records each
# describe one vulnerability that has no CVE (yet): GHSA, GO, PYSEC, RUSTSEC,
# and Debian's TEMP placeholder. Idempotent: a second pass finds nothing to do.

def sa_is_vuln_id: test("^(CVE|GHSA|GO|PYSEC|RUSTSEC|TEMP)-");

def sa_pkg_key: (((.PkgIdentifier // {}).PURL // .PkgName) // "");

# CVE ids Trivy gives for this finding, first occurrence first.
def sa_related_cves:
  [ ((.VendorIDs // [])[]?), (.PrimaryURL // ""), ((.References // [])[]?)
    | strings | match("CVE-[0-9]{4}-[0-9]{4,}"; "g").string ]
  | reduce .[] as $c ([]; if index([$c]) then . else . + [$c] end);

def sa_add_vendor_id($id):
  .VendorIDs = (((.VendorIDs // []) + [$id]) | reduce .[] as $v ([]; if index([$v]) then . else . + [$v] end));

(.Advisories // []) as $prior
| reduce range(0; (.Results // []) | length) as $i (
    {doc: ., adv: []};
    .doc.Results[$i] as $r
    | (($r.Vulnerabilities // []) | map(select(.VulnerabilityID // "" | sa_is_vuln_id))) as $kept
    | (($r.Vulnerabilities // []) | map(select(.VulnerabilityID // "" | sa_is_vuln_id | not))) as $others
    | if ($others | length) == 0 then .
      else
        (reduce $others[] as $o ({vulns: $kept, adv: []};
            ($o.VulnerabilityID // "") as $orig
            | ($o | sa_related_cves) as $cves
            | if ($cves | length) == 0 then
                .adv += [$o + {Target: ($r.Target // "")}]
              else
                reduce $cves[] as $cve (.;
                  ($o | sa_pkg_key) as $k
                  | (.vulns | map((.VulnerabilityID == $cve) and (sa_pkg_key == $k)) | index(true)) as $at
                  | if $at != null then .vulns[$at] |= sa_add_vendor_id($orig)
                    else .vulns += [$o | .VulnerabilityID = $cve
                          | .VendorIDs = ((.VendorIDs // []) | map(select(test("^CVE-") | not)))
                          | sa_add_vendor_id($orig)]
                    end)
              end)) as $out
        | .doc.Results[$i].Vulnerabilities = $out.vulns
        | .adv += $out.adv
      end)
| if (.adv | length) > 0 or ($prior | length) > 0
  then .doc + {Advisories: ($prior + .adv)}
  else .doc end
