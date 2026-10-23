#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
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
#         For pypi, a distribution externalReference is not used: it names one
#         resolved wheel/sdist file (cdxgen fills it from the PyPI JSON API), and a
#         wheel's filename encodes a platform/ABI tag that need not match what this
#         scan actually installed. The pypi.org project-page URL is version-scoped
#         rather than file-scoped, so it can't point at the wrong platform's file.
#       * Copyright / attribution — component.copyright when present (cdxgen leaves
#         it empty; build-prep.sh fills npm and Python components from the
#         installed license files, and scancode --deep-license or other sources
#         can fill others). When absent,
#         the line is omitted rather than guessed.
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
# Shared look of the HTML reports (design tokens, print rules, time format).
if [ ! -f "$SCRIPT_DIR/report-common.sh" ]; then
    echo "[notice] report-common.sh not found next to $0; the image is incomplete. Fix: rebuild the scanner image." >&2
    exit 1
fi
# shellcheck source=report-common.sh
. "$SCRIPT_DIR/report-common.sh"

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
#
# pypi is the one exception to "distribution wins": that externalReference is a
# single resolved wheel/sdist URL, and a wheel's filename bakes in a platform/ABI
# tag (e.g. "-cp311-cp311-manylinux...whl" or "-macosx_..."). Nothing upstream of
# this script confirms that tag matches what was actually installed for this scan,
# so a pypi component skips straight to the version-scoped pypi.org project page
# instead — always correct, even if less specific.
# shellcheck disable=SC2016  # jq program; $c / $refs / $ptype are jq variables.
SRC_DEF="$PURL_SRC_DEF"'
def purl_type($purl):
  ($purl // "") as $p
  | if ($p | startswith("pkg:")) | not then null
    else ($p | ltrimstr("pkg:") | split("/")[0] | split("@")[0] | ascii_downcase) end;
def src($c):
  (purl_type($c.purl)) as $ptype
  | ([ $c.externalReferences[]? | select(.url != null and .url != "") ]) as $refs
  | ( [ $refs[] | select((.type // "") == "vcs") | .url ][0]
      // (if $ptype == "pypi" then null
          else [ $refs[] | select((.type // "") == "distribution") | .url ][0] end)
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
# Two kinds of entry are folded into one line per licence rather than listed
# individually, because listing them item by item tells a reader nothing they can
# act on.
#
# Linux kernel modules. A firmware that ships lib/modules can carry hundreds of
# them — a MikroTik RouterOS image has 304 — and each was arriving as three lines
# whose source read `pkg:generic/nls_utf8`, a purl syft builds from the module
# name that leads nowhere. The obligation is discharged by the kernel they were
# built from, which is listed here in its own right, so the notice says how many
# there are and which kernel they belong to.
#
# Catalogued files. A firmware scan records the files it walked as CycloneDX
# `type: file` components, which is a legitimate inventory but not something a
# licence notice can speak to: a path is not a project, so there is no name to
# attribute and no source to point at. Measured across the corpus, 4,649 such
# entries carry no licence, no purl and no external reference between them, so
# every one of them landed under NOASSERTION with no source or attribution line
# beneath it. One access point image alone contributed 423.
#
# Everything folded here remains in the SBOM under its own name. What changes is
# a document written for a person to act on.
#
# The supplier's own components are left out. A source scan's declaration file
# marks each component it adds with bomlens:origin; one marked first-party is
# the supplier's own work, which no third-party notice is owed for. It stays in
# the SBOM and in the licence and risk reports.
FIRST_PARTY_DEF='def first_party: any(.properties[]?; .name == "bomlens:origin" and .value == "first-party");'
LICENSE_MAP=$(jq -r "$NORMALIZE_DEF$SRC_DEF$FIRST_PARTY_DEF"'
  def kmod_of($c):
    if any($c.properties[]?;
           .name == "syft:package:type" and .value == "linux-kernel-module")
    then ( [ $c.properties[]? | select(.name == "syft:metadata:kernelVersion") | .value ][0]
           // "unknown version" )
    else null end;
  def is_file($c): ($c.type // "") == "file";
  # A dataset scan describes one published item and has no components[]: the
  # item sits in the document root. Its terms are exactly what a notice exists
  # to carry (CC-BY asks for attribution like any other licence), so the root is
  # folded in when the collectors marked it as one they fetched. Every other
  # root is the scanned project itself and stays out.
  def collected_root:
    [ .metadata.component // empty ]
    | map(select((.type // "") == "data"
                 and ((.properties // []) | any(.name == "bomlens:dataset:collectedBy"))));
  [ collected_root[], (.components[]? | select(first_party | not))
    | . as $c
    | { comp: (($c.name // "unknown") + (if $c.version then "@" + $c.version else "" end)
               + (if ($c.type // "") == "data" then " [dataset]" else "" end)),
        copyright: ($c.copyright // null),
        src: (src($c)),
        kmod: (kmod_of($c)),
        isfile: (is_file($c)),
        lic: (
          ( [ $c.licenses[]?
              | (.license.id // .license.name // .expression)
            ] | map(select(. != null)) | map(normalize(.)) )
          | if length == 0 then ["NOASSERTION"] else . end
        )
      }
    | . as $x | $x.lic[] | { key: ., comp: $x.comp, copyright: $x.copyright,
                             src: $x.src, kmod: $x.kmod, isfile: $x.isfile }
  ]
  | group_by(.key)
  | map({ license: .[0].key,
          # The header counts components, not lines. Folding 191 modules or 423
          # file entries into one line must not make them read as one.
          count: ( ( [ .[] | select(.kmod == null and (.isfile | not))
                           | { comp, copyright, src } ] | unique | length )
                   + ( [ .[] | select(.kmod != null) ] | length )
                   + ( [ .[] | select(.kmod == null and .isfile) ] | length ) ),
          components: (
            ( [ .[] | select(.kmod == null and (.isfile | not))
                    | { comp, copyright, src } ] | unique )
            + ( [ .[] | select(.kmod != null) ]
                | group_by(.kmod)
                | map({ comp: ("Linux kernel modules (" + (length | tostring)
                               + "), part of linux_kernel@" + .[0].kmod),
                        copyright: null,
                        src: null }) )
            # A kernel module is also the more specific description, so it wins
            # when a component is both; the file branch takes what is left.
            + ( [ .[] | select(.kmod == null and .isfile) ]
                | if length == 0 then []
                  else [ { comp: ("Catalogued files (" + (length | tostring)
                                  + ") — paths recorded by the scan, listed in the SBOM, not components"),
                           copyright: null,
                           src: null } ] end )
            | sort_by(.comp) ) })
  | sort_by(.license)
' "$SBOM")

TOTAL_COMP=$(jq "$FIRST_PARTY_DEF"'[ ([.metadata.component // empty]
                   | map(select((.type // "") == "data"
                                and ((.properties // []) | any(.name == "bomlens:dataset:collectedBy")))))[],
                   (.components[]? | select(first_party | not)) ] | length' "$SBOM")
TOTAL_LIC=$(echo "$LICENSE_MAP" | jq 'length')
GEN_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Some upstream metadata names a license without saying which one it is: PyPI's
# trove classifier "BSD License" covers the 2-, 3- and 4-clause variants, and
# python-dateutil declares the bare string "Dual License". Those arrive here as
# the license name, because neither the scanner nor cdxgen will guess a clause
# count, and a name is not an obligation a reader can act on. Rather than drop or
# rewrite them, say so where the group is printed, so the reader knows this one
# entry still needs the component's own license file to settle.
#
# The test is structural: an SPDX id carries no spaces, and an SPDX expression is
# ids joined by OR / AND / WITH. Anything else is prose. NOASSERTION is excluded
# — it already says, in its own vocabulary, that nothing was declared.
SPDX_SHAPE_DEF='
def is_spdx_shaped($s):
  ($s == "NOASSERTION")
  or ($s | test("^[A-Za-z0-9.+()-]+$"))
  or ($s | test("^\\(?[A-Za-z0-9.+-]+\\)?( (OR|AND|WITH) \\(?[A-Za-z0-9.+-]+\\)?)+$"));
def unverified_note($s):
  if is_spdx_shaped($s) then ""
  else "  [unverified name — not an SPDX identifier; confirm against the component'"'"'s license file]" end;
'

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
    # The Copyright line is printed only when component.copyright was captured;
    # when it wasn't, the line is omitted rather than guessed or filled with a
    # placeholder — Source above still points a reader at the holder.
    echo "$LICENSE_MAP" | jq -r "$SPDX_SHAPE_DEF"'.[] |
        "\nLicense: \(.license)\(unverified_note(.license))\nComponents (\(.count // (.components | length))):",
        (.components[] |
            "  - \(.comp)",
            (if .src then "      Source: \(.src)" else empty end),
            (if .copyright then "      Copyright: \(.copyright)" else empty end))'
    echo ""
    if [ "$REVIEW_N" -gt 0 ]; then
        echo "================================================================================"
        echo "License review needed — AI / restrictive terms (human review required)"
        echo "================================================================================"
        echo "behavioral-use = use-based restrictions (RAIL/Llama/Gemma, etc.); non-commercial = restricted commercial use."
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
esc() { printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }
PROJECT_ESC="$(esc "$PROJECT")"
{
    cat <<HTMLHEAD
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<title>Open Source Notice — ${PROJECT_ESC}</title>
HTMLHEAD
    report_style
    cat <<HTMLHEAD2
</head>
<body>
<header class="report-header">
 <div class="wordmark">BomLens<span class="tag">SBOM</span></div>
 <div class="report-kind">Open Source Notice</div>
</header>
<h1>Third-party Open Source Notice</h1>
<p class="meta">Project: ${PROJECT_ESC} &middot; Generated: $(report_time_html "$GEN_AT") &middot; Components: ${TOTAL_COMP} &middot; Licenses: ${TOTAL_LIC}</p>
HTMLHEAD2

    # License review banner (AI behavioral-use / non-commercial). Escaped via @html.
    if [ "$REVIEW_N" -gt 0 ]; then
        echo '<div class="review"><h2>License review needed — AI / restrictive terms</h2>'
        echo '<p class="meta">behavioral-use = use-based restrictions (RAIL/Llama/Gemma, etc.); non-commercial = restricted commercial use. Human review required.</p><ul>'
        echo "$REVIEW" | jq -r '.[] |
            "<li><b>[" + (.flag|@html) + "]</b> " + (.license|@html) + " — "
            + (.components | map(@html) | join(", ")) + "</li>"'
        echo "</ul></div>"
    fi

    # jq @html escapes license names, component identifiers, source URLs and
    # copyright. An http(s) source is rendered as a link; a raw purl as plain text.
    # The Copyright line renders only when component.copyright was captured; when
    # it wasn't, attrhtml prints nothing rather than a placeholder.
    echo "$LICENSE_MAP" | jq -r "$SPDX_SHAPE_DEF"'
        def srchtml($s):
          if $s == null then ""
          elif ($s | test("^https?://"))
          then "<span class=\"src\">Source: <a href=\"" + ($s|@html) + "\" target=\"_blank\" rel=\"noopener noreferrer\">" + ($s|@html) + "</a></span>"
          else "<span class=\"src\">Source: " + ($s|@html) + "</span>" end;
        def attrhtml($c):
          if $c.copyright
          then "<span class=\"attr\">Copyright: " + ($c.copyright|@html) + "</span>"
          else "" end;
        .[] |
        "<div class=\"lic\"><h2>" + (.license | @html) + "</h2>" +
        (if is_spdx_shaped(.license) then ""
         else "<p class=\"unverified\">unverified name — not an SPDX identifier; confirm against the component'"'"'s license file</p>" end) +
        "<p class=\"count\">" + ((.count // (.components | length)) | tostring) + " component(s)</p><ul>" +
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
