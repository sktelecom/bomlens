#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# generate-notice.sh — build an open-source attribution NOTICE from a CycloneDX SBOM.
#
# Usage: generate-notice.sh <sbom.json> <out_prefix> <project_name>
#   produces  <out_prefix>_NOTICE.txt  and  <out_prefix>_NOTICE.html
#
# License data source: components[].licenses[] of the SBOM (CycloneDX).
#   - License ids/names/expressions are normalized to SPDX ids (common aliases),
#     so "Apache License, version 2.0" and "Apache-2.0" group together.
#   - component.copyright is shown per component when present (cdxgen leaves it
#     empty; scancode --deep-license or other sources can fill it).
#   - The SPDX standard full text for each used license is appended from the
#     bundled ./licenses/<spdx-id>.txt set (offline; no network at notice time).
set -e

SBOM="$1"
OUT_PREFIX="$2"
PROJECT="${3:-project}"

if [ -z "$SBOM" ] || [ ! -f "$SBOM" ]; then
    echo "[notice] SBOM file not found: $SBOM" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LICENSE_DIR="$SCRIPT_DIR/licenses"   # bundled SPDX full texts (<spdx-id>.txt)

TXT="${OUT_PREFIX}_NOTICE.txt"
HTML="${OUT_PREFIX}_NOTICE.html"

# Normalize a license id/name/expression to an SPDX id for common aliases.
# A genuine compound expression ("X OR Y") is left untouched; LGPL/GPL "or later"
# is matched before the compound check so it is not mistaken for a compound.
NORMALIZE_DEF='
def normalize($s):
  ($s | ascii_downcase | gsub("[ ,._/-]+"; " ") | sub("^ +";"") | sub(" +$";"")) as $n |
  if   ($n | test("(lesser|library) general public.*2 1.*later")) then "LGPL-2.1-or-later"
  elif ($n | test("(lesser|library) general public.*2 1")) then "LGPL-2.1-only"
  elif ($n | test("(lesser|library) general public.*3.*later")) then "LGPL-3.0-or-later"
  elif ($n | test("(lesser|library) general public.*3")) then "LGPL-3.0-only"
  elif ($n | test("general public.*2.*later")) then "GPL-2.0-or-later"
  elif ($n | test("general public.*2 0|general public.*v2")) then "GPL-2.0-only"
  elif ($n | test("general public.*3.*later")) then "GPL-3.0-or-later"
  elif ($n | test("general public.*3")) then "GPL-3.0-only"
  elif ($n | test(" or | and ")) then $s
  elif ($n | test("apache.*2")) then "Apache-2.0"
  elif ($n | test("mit license") or $n == "mit") then "MIT"
  elif ($n | test("eclipse distribution") or ($n|test("^edl "))) then "BSD-3-Clause"
  elif ($n | test("eclipse public.*2")) then "EPL-2.0"
  elif ($n | test("eclipse public.*1")) then "EPL-1.0"
  elif ($n | test("bsd.*3")) then "BSD-3-Clause"
  elif ($n | test("bsd.*2")) then "BSD-2-Clause"
  else $s end;
'

# Build { license, components:[ {comp, copyright} ] } grouped by normalized id.
LICENSE_MAP=$(jq -r "$NORMALIZE_DEF"'
  [ .components[]?
    | { comp: ((.name // "unknown") + (if .version then "@" + .version else "" end)),
        copyright: (.copyright // null),
        lic: (
          ( [ .licenses[]?
              | (.license.id // .license.name // .expression)
            ] | map(select(. != null)) | map(normalize(.)) )
          | if length == 0 then ["NOASSERTION"] else . end
        )
      }
    | . as $c | $c.lic[] | { key: ., comp: $c.comp, copyright: $c.copyright }
  ]
  | group_by(.key)
  | map({ license: .[0].key,
          components: ( [ .[] | { comp, copyright } ] | unique | sort_by(.comp) ) })
  | sort_by(.license)
' "$SBOM")

TOTAL_COMP=$(jq '[.components[]?] | length' "$SBOM")
TOTAL_LIC=$(echo "$LICENSE_MAP" | jq 'length')
GEN_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Used licenses that have a bundled SPDX full text.
LICENSES_WITH_TEXT=""
for lic in $(echo "$LICENSE_MAP" | jq -r '.[].license'); do
    [ -f "$LICENSE_DIR/$lic.txt" ] && LICENSES_WITH_TEXT="$LICENSES_WITH_TEXT $lic"
done

# ---------- TEXT ----------
{
    echo "Third-party Open Source Licenses for ${PROJECT}"
    echo "Generated: ${GEN_AT}"
    echo "Total components: ${TOTAL_COMP} · Distinct licenses: ${TOTAL_LIC}"
    echo ""
    echo "This product includes the following open source software."
    echo "================================================================================"
    # license -> components, with copyright shown when present.
    echo "$LICENSE_MAP" | jq -r '.[] |
        "\nLicense: \(.license)\nComponents (\(.components | length)):",
        (.components[] | "  - \(.comp)" + (if .copyright then "  (© \(.copyright))" else "" end))'
    echo ""
    if [ -n "$LICENSES_WITH_TEXT" ]; then
        echo "================================================================================"
        echo "License texts (SPDX standard)"
        echo "================================================================================"
        for lic in $LICENSES_WITH_TEXT; do
            echo ""
            echo "----------------------------- $lic -----------------------------"
            cat "$LICENSE_DIR/$lic.txt"
        done
    fi
    echo ""
    echo "================================================================================"
} > "$TXT"

# ---------- HTML (all dynamic fields escaped to prevent XSS from package metadata) ----------
{
    cat <<HTMLHEAD
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<title>Open Source Notice — ${PROJECT}</title>
<style>
 body{font-family:system-ui,Arial,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#1a1a1a;}
 h1{border-bottom:2px solid #ddd;padding-bottom:.4rem;}
 h2{font-size:1.05rem;color:#0b5;}
 .meta{color:#666;font-size:.9rem;}
 .lic{margin:1.4rem 0;padding:1rem;border:1px solid #e3e3e3;border-radius:6px;background:#fafafa;}
 .lic h2{margin:.2rem 0;}
 ul{margin:.4rem 0 0 1rem;} li{font-family:ui-monospace,monospace;font-size:.85rem;}
 .cr{color:#666;}
 .texts{margin-top:2rem;border-top:2px solid #ddd;padding-top:1rem;}
 .texts pre{background:#f6f6f6;border:1px solid #e3e3e3;border-radius:6px;padding:1rem;
   overflow:auto;font-size:.78rem;line-height:1.4;white-space:pre-wrap;}
</style>
</head>
<body>
<h1>Third-party Open Source Notice</h1>
<p class="meta">Project: ${PROJECT} &middot; Generated: ${GEN_AT} &middot; Components: ${TOTAL_COMP} &middot; Licenses: ${TOTAL_LIC}</p>
HTMLHEAD

    # jq @html escapes license names, component identifiers, and copyright.
    echo "$LICENSE_MAP" | jq -r '.[] |
        "<div class=\"lic\"><h2>" + (.license | @html) + "</h2>" +
        "<p>" + (.components | length | tostring) + " component(s)</p><ul>" +
        (.components | map("<li>" + (.comp | @html)
            + (if .copyright then " <span class=\"cr\">(© " + (.copyright | @html) + ")</span>" else "" end)
            + "</li>") | join("")) +
        "</ul></div>"'

    # Bundled SPDX full texts (HTML-escaped, preformatted).
    if [ -n "$LICENSES_WITH_TEXT" ]; then
        echo '<div class="texts"><h2>License texts (SPDX standard)</h2>'
        for lic in $LICENSES_WITH_TEXT; do
            esc=$(sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' "$LICENSE_DIR/$lic.txt")
            printf '<h3>%s</h3><pre>%s</pre>\n' "$lic" "$esc"
        done
        echo '</div>'
    fi

    echo "</body></html>"
} > "$HTML"

echo "[notice] generated: $TXT, $HTML (${TOTAL_LIC} licenses, ${TOTAL_COMP} components)"
