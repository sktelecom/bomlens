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
# Optional 1st-party source license detection (scancode) is layered in by the
# entrypoint when --deep-license is set; this script consumes whatever is in the SBOM.
set -e

SBOM="$1"
OUT_PREFIX="$2"
PROJECT="${3:-project}"

if [ -z "$SBOM" ] || [ ! -f "$SBOM" ]; then
    echo "[notice] SBOM file not found: $SBOM" >&2
    exit 1
fi

TXT="${OUT_PREFIX}_NOTICE.txt"
HTML="${OUT_PREFIX}_NOTICE.html"

# license_id -> "name@version" lines, grouped. Unknown license => "NOASSERTION".
# jq builds a map { license: [ "name@version", ... ] }.
LICENSE_MAP=$(jq -r '
  [ .components[]?
    | { comp: ((.name // "unknown") + (if .version then "@" + .version else "" end)),
        lic: (
          ( [ .licenses[]?
              | (.license.id // .license.name // .expression)
            ] | map(select(. != null)) )
          | if length == 0 then ["NOASSERTION"] else . end
        )
      }
    | . as $c | $c.lic[] | { key: ., comp: $c.comp }
  ]
  | group_by(.key)
  | map({ license: .[0].key, components: (map(.comp) | unique | sort) })
  | sort_by(.license)
' "$SBOM")

TOTAL_COMP=$(jq '[.components[]?] | length' "$SBOM")
TOTAL_LIC=$(echo "$LICENSE_MAP" | jq 'length')
GEN_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# ---------- TEXT ----------
{
    echo "Third-party Open Source Licenses for ${PROJECT}"
    echo "Generated: ${GEN_AT}"
    echo "Total components: ${TOTAL_COMP} · Distinct licenses: ${TOTAL_LIC}"
    echo ""
    echo "This product includes the following open source software."
    echo "================================================================================"
    echo "$LICENSE_MAP" | jq -r '.[] |
        "\nLicense: \(.license)\nComponents (\(.components | length)):\n" +
        (.components | map("  - " + .) | join("\n"))'
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
 .meta{color:#666;font-size:.9rem;}
 .lic{margin:1.4rem 0;padding:1rem;border:1px solid #e3e3e3;border-radius:6px;background:#fafafa;}
 .lic h2{margin:.2rem 0;font-size:1.05rem;color:#0b5;}
 ul{margin:.4rem 0 0 1rem;} li{font-family:ui-monospace,monospace;font-size:.85rem;}
</style>
</head>
<body>
<h1>Third-party Open Source Notice</h1>
<p class="meta">Project: ${PROJECT} &middot; Generated: ${GEN_AT} &middot; Components: ${TOTAL_COMP} &middot; Licenses: ${TOTAL_LIC}</p>
HTMLHEAD

    # jq @html escapes license names and component identifiers.
    echo "$LICENSE_MAP" | jq -r '.[] |
        "<div class=\"lic\"><h2>" + (.license | @html) + "</h2>" +
        "<p>" + (.components | length | tostring) + " component(s)</p><ul>" +
        (.components | map("<li>" + (. | @html) + "</li>") | join("")) +
        "</ul></div>"'

    echo "</body></html>"
} > "$HTML"

echo "[notice] generated: $TXT, $HTML (${TOTAL_LIC} licenses, ${TOTAL_COMP} components)"
