#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# generate-notice.sh — build an open-source attribution NOTICE from a CycloneDX SBOM.
#
# Usage: generate-notice.sh <sbom.json> <out_prefix> <project_name>
#   produces  <out_prefix>_NOTICE.txt  and  <out_prefix>_NOTICE.html
#   and, when a PDF renderer is in the image, <out_prefix>_NOTICE.pdf
#
# License data source: components[].licenses[] of the SBOM (CycloneDX).
#   - License ids/names/expressions are normalized to SPDX ids (common aliases),
#     so "Apache License, version 2.0" and "Apache-2.0" group together.
#   - Per component we also show:
#       * Source / download location — from externalReferences (vcs / distribution
#         / website), else inferred from the purl's package registry, else the raw
#         purl. This satisfies a copyleft notice's "where to get the source" duty.
#       * Copyright / attribution — component.copyright when present (cdxgen leaves
#         it empty; scancode --deep-license or other sources fill it). When absent,
#         an honest minimal attribution (name + license + source) is shown rather
#         than a blank.
#   - The SPDX standard full text for each used license is appended from the
#     bundled ./licenses/<spdx-id>.txt set (offline; no network at notice time).
#   - When a PDF renderer (weasyprint) is present, the HTML is rendered to a PDF.
#     The renderer is opt-in (--build-arg SBOM_PDF=true): its native deps
#     (pango/cairo/gdk-pixbuf) are heavy, so the base image stays lean. If the
#     renderer is absent the PDF step is skipped with a log line; TXT/HTML are
#     always produced.
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
# The normalize() definition is shared with normalize-sbom.sh via spdx-normalize.jq
# so the NOTICE and the bom.json the web UI reads group licenses identically.
NORMALIZE_DEF="$(cat "$SCRIPT_DIR/spdx-normalize.jq")"
# AI-relevant restrictive-license classifier (behavioral-use / non-commercial),
# shared with normalize-sbom.sh. Drives the "license review" section below.
LICENSE_FLAGS_DEF="$(cat "$SCRIPT_DIR/license-flags.jq")"

# purl_src($purl): infer a human-usable package-registry/download URL from a purl
# for the registry types we can map safely. Returns null when the type is unknown
# (the caller then falls back to the raw purl string). Only well-known, stable URL
# shapes are mapped — anything uncertain is left to the raw purl so we never emit a
# wrong "source location".
# shellcheck disable=SC2016  # this is a jq program; $purl etc. are jq variables.
PURL_SRC_DEF='
def purl_src($purl):
  ($purl // "") as $p
  | if ($p | startswith("pkg:")) | not then null
    else
      # pkg:<type>/<namespace>/<name>@<version>?<qual>#<sub>  (namespace optional)
      ($p | ltrimstr("pkg:") | split("#")[0] | split("?")[0]) as $body
      | ($body | split("@")) as $nv
      | ($nv[1] // "") as $ver
      | ($nv[0] | split("/")) as $seg
      | ($seg[0] | ascii_downcase) as $type
      | ($seg[-1]) as $name
      | (($seg[1:-1]) | join("/")) as $ns
      | if   $type == "maven" and ($ver != "")
        then "https://repo1.maven.org/maven2/" + (($ns | gsub("\\."; "/")) ) + "/" + $name + "/" + $ver + "/"
        elif $type == "npm" and ($ver != "")
        then "https://www.npmjs.com/package/" + ($seg[1:] | join("/")) + "/v/" + $ver
        elif $type == "npm"
        then "https://www.npmjs.com/package/" + ($seg[1:] | join("/"))
        elif $type == "pypi" and ($ver != "")
        then "https://pypi.org/project/" + $name + "/" + $ver + "/"
        elif $type == "pypi"
        then "https://pypi.org/project/" + $name + "/"
        elif $type == "gem" and ($ver != "")
        then "https://rubygems.org/gems/" + $name + "/versions/" + $ver
        elif $type == "gem"
        then "https://rubygems.org/gems/" + $name
        elif $type == "cargo" and ($ver != "")
        then "https://crates.io/crates/" + $name + "/" + $ver
        elif $type == "cargo"
        then "https://crates.io/crates/" + $name
        elif $type == "nuget" and ($ver != "")
        then "https://www.nuget.org/packages/" + $name + "/" + $ver
        elif $type == "nuget"
        then "https://www.nuget.org/packages/" + $name
        elif $type == "golang" and ($ver != "")
        then "https://pkg.go.dev/" + ($seg[1:] | join("/")) + "@" + $ver
        elif $type == "golang"
        then "https://pkg.go.dev/" + ($seg[1:] | join("/"))
        elif $type == "composer" and ($ver != "")
        then "https://packagist.org/packages/" + ($ns | ascii_downcase) + "/" + $name + "#" + $ver
        elif $type == "composer"
        then "https://packagist.org/packages/" + ($ns | ascii_downcase) + "/" + $name
        elif $type == "huggingface"
        then "https://huggingface.co/" + ($seg[1:] | join("/"))
        else null end
    end;'

# src($comp): preferred source/download location for a component object.
# Order: externalReferences vcs > distribution > website, else inferred from purl,
# else the raw purl string, else null. The notice never leaves source blank when a
# purl is present.
# shellcheck disable=SC2016  # jq program; $c / $refs are jq variables.
SRC_DEF="$PURL_SRC_DEF"'
def src($c):
  ([ $c.externalReferences[]? | select(.url != null and .url != "") ]) as $refs
  | ( [ $refs[] | select((.type // "") == "vcs") | .url ][0]
      // [ $refs[] | select((.type // "") == "distribution") | .url ][0]
      // [ $refs[] | select((.type // "") == "website") | .url ][0]
      // purl_src($c.purl)
      // ($c.purl // null) );'

# Build groups keyed by normalized license id. Each component carries comp (name@ver),
# copyright (attribution) and src (source/download location).
#
# A training dataset reaches the notice as a CycloneDX "data" component and its
# license genuinely belongs here — CC-BY-SA and friends carry attribution and
# share-alike duties on redistribution just as a code license does. It is tagged
# so a reader can tell data from code: the obligations attach to different things
# (the corpus, not the binary), and the rest of this file is written for software.
LICENSE_MAP=$(jq -r "$NORMALIZE_DEF$SRC_DEF"'
  [ .components[]?
    | . as $c
    | { comp: (($c.name // "unknown") + (if $c.version then "@" + $c.version else "" end)
               + (if ($c.type // "") == "data" then " [dataset]" else "" end)),
        copyright: ($c.copyright // null),
        src: (src($c)),
        lic: (
          ( [ $c.licenses[]?
              | (.license.id // .license.name // .expression)
            ] | map(select(. != null)) | map(normalize(.)) )
          | if length == 0 then ["NOASSERTION"] else . end
        )
      }
    | . as $x | $x.lic[] | { key: ., comp: $x.comp, copyright: $x.copyright, src: $x.src }
  ]
  | group_by(.key)
  | map({ license: .[0].key,
          components: ( [ .[] | { comp, copyright, src } ] | unique | sort_by(.comp) ) })
  | sort_by(.license)
' "$SBOM")

TOTAL_COMP=$(jq '[.components[]?] | length' "$SBOM")
TOTAL_LIC=$(echo "$LICENSE_MAP" | jq 'length')
GEN_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Licenses needing human review (AI behavioral-use / non-commercial). Empty for a
# normal software scan; populated when a model/dataset carries e.g. a Llama/RAIL
# or CC-BY-NC license. The tool surfaces the class; a human judges applicability.
REVIEW=$(echo "$LICENSE_MAP" | jq -c "$LICENSE_FLAGS_DEF"'
  [ .[] | (license_flag(.license)) as $f | select($f != "")
    | { license: .license, flag: $f, components: [ .components[].comp ] } ]')
REVIEW_N=$(echo "$REVIEW" | jq 'length')

# Used licenses that have a bundled SPDX full text. Read one license per line
# (IFS=newline) so a compound expression like "Apache-2.0 OR BSD-2-Clause" is
# matched whole — it has no bundled .txt, so it is skipped — instead of being
# word-split into "Apache-2.0"/"BSD-2-Clause" and appending those texts a second
# time. group_by already made the licenses unique, so each text appears once.
LICENSES_WITH_TEXT=$(echo "$LICENSE_MAP" | jq -r '.[].license' | while IFS= read -r lic; do
    [ -f "$LICENSE_DIR/$lic.txt" ] && printf '%s\n' "$lic"
    :  # keep the loop's exit status 0 (set -e) when the last license has no text
done)

# ---------- TEXT ----------
{
    echo "Third-party Open Source Licenses for ${PROJECT}"
    echo "Generated: ${GEN_AT}"
    echo "Total components: ${TOTAL_COMP} · Distinct licenses: ${TOTAL_LIC}"
    echo ""
    echo "This product includes the following open source software."
    echo "Each component lists its source/download location and copyright/attribution."
    echo "================================================================================"
    # license -> components, each with source location and copyright/attribution.
    # Attribution falls back to an honest "not captured" line (never blank) so the
    # notice always names the holder source even when component.copyright is empty.
    echo "$LICENSE_MAP" | jq -r '.[] |
        "\nLicense: \(.license)\nComponents (\(.components | length)):",
        (.components[] |
            "  - \(.comp)",
            (if .src then "      Source: \(.src)" else empty end),
            (if .copyright
                then "      Copyright: \(.copyright)"
                else "      Copyright: holders not captured in SBOM — see source" + (if .src then " (\(.src))" else "" end)
             end))'
    echo ""
    if [ "$REVIEW_N" -gt 0 ]; then
        echo "================================================================================"
        echo "License review needed — AI / restrictive terms (human review required)"
        echo "================================================================================"
        echo "behavioral-use = use-based restrictions (RAIL/Llama/Gemma 등); non-commercial = 상업적 사용 제한."
        echo "$REVIEW" | jq -r '.[] |
            "\n[\(.flag)] \(.license)  (\(.components|length) component(s)):",
            (.components[] | "  - \(.)")'
        echo ""
    fi
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
 :root{
  --bg:#fafafa;--surface:#ffffff;--text:#18181b;--muted:#6c6c75;--border:#e5e5ea;
  --brand:#EA002C;--brand-2:#F47725;--th-bg:#f4f4f5;--row-hover:#fafafa;
  --radius:.375rem;--radius-card:.5rem;
  --shadow:0 1px 2px rgb(0 0 0/.04),0 2px 8px -2px rgb(0 0 0/.08);
  --font:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Apple SD Gothic Neo","Malgun Gothic",sans-serif;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
 }
 @media (prefers-color-scheme:dark){:root{
  --bg:#0a0a0c;--surface:#18181b;--text:#fafafa;--muted:#a1a1aa;--border:#27272a;
  --th-bg:#1f1f23;--row-hover:#202024;
  --shadow:0 1px 2px rgb(0 0 0/.3),0 2px 8px -2px rgb(0 0 0/.5);
 }}
 *{box-sizing:border-box;}
 body{font-family:var(--font);background:var(--bg);color:var(--text);
  max-width:1040px;margin:0 auto;padding:2.5rem 1.5rem 4rem;line-height:1.55;
  -webkit-font-smoothing:antialiased;}
 a{color:var(--brand);}
 .report-header{display:flex;align-items:flex-end;justify-content:space-between;
  gap:1rem;flex-wrap:wrap;padding-bottom:.85rem;border-bottom:1px solid var(--border);
  margin-bottom:1.5rem;}
 .wordmark{display:flex;align-items:center;gap:.5rem;font-size:1.15rem;font-weight:800;
  letter-spacing:-.02em;color:var(--brand);}
 .wordmark .tag{font-size:.62rem;font-weight:700;letter-spacing:.1em;color:var(--muted);
  border:1px solid var(--border);border-radius:999px;padding:.15rem .5rem;background:var(--surface);}
 .report-kind{font-size:.78rem;font-weight:600;color:var(--muted);
  text-transform:uppercase;letter-spacing:.07em;}
 h1{font-size:1.55rem;font-weight:700;letter-spacing:-.01em;margin:.2rem 0 .35rem;}
 h2{font-size:1.15rem;font-weight:600;letter-spacing:-.01em;margin:2.1rem 0 .8rem;}
 h3{font-size:.95rem;font-weight:600;margin:1.3rem 0 .4rem;}
 .meta{color:var(--muted);font-size:.875rem;margin:.15rem 0 0;}
 .review{background:rgba(202,138,4,.1);border-left:3px solid #ca8a04;
  border-radius:var(--radius);padding:.9rem 1.1rem;margin:1.2rem 0;}
 .review h2{color:#ca8a04;margin:.1rem 0 .3rem;font-size:1.05rem;font-weight:600;}
 .review .meta{margin:.2rem 0 .4rem;}
 .review ul{list-style:none;padding:0;margin:.5rem 0 0;}
 .review li{font-family:var(--mono);font-size:.82rem;margin:.3rem 0;}
 .lic{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius-card);box-shadow:var(--shadow);
  padding:1rem 1.15rem;margin:1rem 0;}
 .lic h2{margin:0;font-size:1.05rem;font-weight:700;color:var(--brand);}
 .lic .count{display:block;color:var(--muted);font-size:.8rem;margin:.15rem 0 .5rem;}
 .lic ul{list-style:none;padding:0;margin:0;}
 .lic li{font-family:var(--mono);font-size:.82rem;padding:.45rem 0;
  border-top:1px solid var(--border);margin:0;}
 .lic li:first-child{border-top:none;}
 .src{display:block;color:var(--muted);font-size:.78rem;margin-top:.25rem;}
 .src a{color:var(--brand);text-decoration:none;word-break:break-all;}
 .attr{display:block;color:var(--muted);font-size:.78rem;margin-top:.1rem;}
 .attr.none{font-style:italic;opacity:.75;}
 .texts{margin-top:2.5rem;border-top:1px solid var(--border);padding-top:1.25rem;}
 .texts pre{background:var(--th-bg);border:1px solid var(--border);
  border-radius:var(--radius);padding:1rem;overflow:auto;font-size:.76rem;
  line-height:1.45;white-space:pre-wrap;}
</style>
</head>
<body>
<header class="report-header">
 <div class="wordmark">BomLens<span class="tag">SBOM</span></div>
 <div class="report-kind">Open Source Notice</div>
</header>
<h1>Third-party Open Source Notice</h1>
<p class="meta">Project: ${PROJECT} &middot; Generated: ${GEN_AT} &middot; Components: ${TOTAL_COMP} &middot; Licenses: ${TOTAL_LIC}</p>
HTMLHEAD

    # License review banner (AI behavioral-use / non-commercial). Escaped via @html.
    if [ "$REVIEW_N" -gt 0 ]; then
        echo '<div class="review"><h2>License review needed — AI / restrictive terms</h2>'
        echo '<p class="meta">behavioral-use = use-based restrictions (RAIL/Llama/Gemma 등); non-commercial = restricted commercial use. Human review required.</p><ul>'
        echo "$REVIEW" | jq -r '.[] |
            "<li><b>[" + (.flag|@html) + "]</b> " + (.license|@html) + " — "
            + (.components | map(@html) | join(", ")) + "</li>"'
        echo "</ul></div>"
    fi

    # jq @html escapes license names, component identifiers, source URLs and
    # copyright. An http(s) source is rendered as a link; a raw purl as plain text.
    # Attribution always renders: component.copyright, or an honest "not captured".
    echo "$LICENSE_MAP" | jq -r '
        def srchtml($s):
          if $s == null then ""
          elif ($s | test("^https?://"))
          then "<span class=\"src\">Source: <a href=\"" + ($s|@html) + "\" target=\"_blank\" rel=\"noopener noreferrer\">" + ($s|@html) + "</a></span>"
          else "<span class=\"src\">Source: " + ($s|@html) + "</span>" end;
        def attrhtml($c):
          if $c.copyright
          then "<span class=\"attr\">Copyright: " + ($c.copyright|@html) + "</span>"
          else "<span class=\"attr none\">Copyright: holders not captured in SBOM — see source</span>" end;
        .[] |
        "<div class=\"lic\"><h2>" + (.license | @html) + "</h2>" +
        "<p class=\"count\">" + (.components | length | tostring) + " component(s)</p><ul>" +
        (.components | map("<li>" + (.comp | @html)
            + srchtml(.src)
            + attrhtml(.)
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

# ---------- PDF (opt-in renderer; graceful skip when absent) ----------
# weasyprint renders the HTML to a print-ready PDF. It is bundled only when the
# image was built with --build-arg SBOM_PDF=true (heavy pango/cairo/gdk-pixbuf
# native deps). When the renderer is missing we log and skip — TXT/HTML still
# stand — so a default-image scan is never broken by the absence of the tool.
PDF="${OUT_PREFIX}_NOTICE.pdf"
if command -v weasyprint >/dev/null 2>&1; then
    if weasyprint "$HTML" "$PDF" >/dev/null 2>&1; then
        echo "[notice] generated PDF: $PDF"
    else
        echo "[notice] weasyprint present but PDF render failed; keeping TXT/HTML only." >&2
        rm -f "$PDF"
    fi
else
    echo "[notice] PDF skipped: no PDF renderer in image (rebuild with --build-arg SBOM_PDF=true for weasyprint)."
fi

echo "[notice] generated: $TXT, $HTML (${TOTAL_LIC} licenses, ${TOTAL_COMP} components)"
