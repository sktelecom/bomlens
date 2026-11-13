#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# report-common.sh - shared look of the four single-file HTML reports (risk,
# security, NOTICE, conformance). Sourced, never executed.
#
#   report_style          print one <style> element: the design tokens of the web
#                         UI, the shared report CSS and the print rules
#   report_time_html ISO  print a <time datetime="ISO"> element that reads
#                         "2026-10-14 18:04 UTC"
#   report_topbar, report_h1, report_desc
#                         the page head: top bar with the report kind, the
#                         "Project version" title and the description line
#   report_version, report_type_label, report_component_count
#                         the values the page head shows
#   report_jq_defs        jq helpers for table cells (severity label, package
#                         name, fixed versions)
#
# The colour and font-size variables come from bomlens-tokens.css, which is
# generated from the web UI's index.css (npm run tokens:build in
# docker/web/frontend), so a report and the app can never drift apart. The file
# is inlined at generation time because a report is one file under a strict CSP
# (default-src 'none'): no external stylesheet, no web font, system fonts only.
#
# The tokens file is looked up in, in order:
#   $BOMLENS_TOKENS_CSS                  (explicit override, used by tests)
#   <this directory>/bomlens-tokens.css  (the image: Dockerfile copies it next to the scripts)
#   <this directory>/../shared/...       (a repository checkout)
# When none is usable the report is still produced, with a built-in copy of the
# palette it needs, and a warning is printed. A missing file never yields a
# report with no colours at all.

REPORT_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_TOKENS_WARNED=false

# Print the path of a usable tokens file, or nothing. "Usable" means it carries
# the role colours the report text depends on.
report_tokens_path() {
    local c
    for c in "${BOMLENS_TOKENS_CSS:-}" \
             "$REPORT_LIB_DIR/bomlens-tokens.css" \
             "$REPORT_LIB_DIR/../shared/bomlens-tokens.css"; do
        if [ -n "$c" ] && [ -s "$c" ] && grep -q -- '--role-danger-fg:' "$c" 2>/dev/null; then
            printf '%s' "$c"
            return 0
        fi
    done
    return 0
}

# Print the token variables. Light is the default; the app's .dark block becomes
# a prefers-color-scheme rule limited to screens, so a printout is always light.
report_tokens_css() {
    local f
    f="$(report_tokens_path)"
    if [ -n "$f" ]; then
        awk '
            /^\/\*/ { next }
            /^[[:space:]]*$/ { next }
            /^\.dark[[:space:]]*\{/ { print "@media screen and (prefers-color-scheme: dark) {"; print ":root {"; dark = 1; next }
            dark && /^\}/ { print "}"; print "}"; dark = 0; next }
            { print }
        ' "$f"
        return 0
    fi
    if [ "$REPORT_TOKENS_WARNED" != "true" ]; then
        REPORT_TOKENS_WARNED=true
        echo "[report] WARN: bomlens-tokens.css not found (looked next to $REPORT_LIB_DIR and in ../shared); the report embeds its built-in fallback palette." >&2
        echo "[report]       Fix: rebuild the image (the Dockerfile copies docker/shared/bomlens-tokens.css), or run 'npm run tokens:build' in docker/web/frontend." >&2
    fi
    # Built-in fallback: the subset of the tokens the report CSS uses, with the
    # same values. tests/test-postprocess.sh checks it against the tokens file.
    cat <<'FALLBACK'
/* bomlens-report: built-in fallback palette (tokens file not found) */
:root{
  --background:0 0% 98%;--foreground:240 6% 10%;--card:0 0% 100%;--muted:240 5% 96%;
  --muted-foreground:240 4% 44%;--border:240 5% 91%;--brand:224.3 76.3% 48%;
  --brand-strong:224.3 76.3% 48%;--role-danger-fg:185 28 28;--role-danger-muted:251 229 229;
  --role-danger-emphasis:220 38 38;--role-danger-border:239 157 157;--role-severe-fg:154 52 18;
  --role-severe-muted:252 235 226;--role-severe-emphasis:234 88 12;--role-severe-border:246 180 146;
  --role-attention-fg:133 77 14;--role-attention-muted:247 240 225;
  --role-attention-emphasis:190 129 3;--role-attention-border:231 202 142;--role-info-fg:29 78 216;
  --role-info-muted:229 236 253;--role-info-emphasis:37 99 235;--role-info-border:157 185 246;
  --role-success-fg:6 95 70;--role-success-muted:226 243 238;--role-success-emphasis:10 155 110;
  --role-success-border:147 224 198;--role-neutral-fg:63 63 70;--role-neutral-muted:238 238 239;
  --role-neutral-emphasis:113 113 122;--role-neutral-border:191 191 195;
  --cat-permissive-fg:12 100 91;--cat-permissive-muted:227 240 239;
  --cat-permissive-emphasis:24 134 123;--cat-permissive-border:151 201 196;--cat-weak-fg:31 45 111;
  --cat-weak-muted:232 235 247;--cat-weak-emphasis:66 87 189;--cat-weak-border:170 179 225;
  --cat-strong-fg:82 40 103;--cat-strong-muted:241 234 244;--cat-strong-emphasis:137 78 166;
  --cat-strong-border:202 175 215;--cat-network-fg:107 36 74;--cat-network-muted:244 233 239;
  --cat-network-emphasis:167 68 121;--cat-network-border:215 171 195;--cat-review-fg:80 60 43;
  --cat-review-muted:240 237 234;--cat-review-emphasis:131 106 84;--cat-review-border:199 188 178;
  --font-size-display:1.875rem;--font-size-title:1.25rem;--font-size-heading:1.125rem;
  --font-size-body:1rem;--font-size-body-sm:0.875rem;--font-size-label:0.75rem;
  --font-size-caption:0.6875rem;--font-size-mono:0.75rem;
}
@media screen and (prefers-color-scheme: dark){:root{
  --background:240 6% 7%;--foreground:0 0% 98%;--card:240 4% 12%;--muted:240 4% 16%;
  --muted-foreground:240 5% 65%;--border:240 4% 24%;--brand:224.3 76.3% 48%;
  --brand-strong:213.1 93.9% 67.8%;--role-danger-fg:252 165 165;--role-danger-muted:60 38 41;
  --role-danger-emphasis:248 113 113;--role-danger-border:125 64 66;--role-severe-fg:253 186 116;
  --role-severe-muted:60 44 32;--role-severe-emphasis:251 146 60;--role-severe-border:126 79 42;
  --role-attention-fg:232 200 110;--role-attention-muted:53 47 34;
  --role-attention-emphasis:205 170 70;--role-attention-border:105 90 46;--role-info-fg:147 197 253;
  --role-info-muted:36 47 63;--role-info-emphasis:96 165 250;--role-info-border:56 87 127;
  --role-success-fg:110 231 183;--role-success-muted:28 54 47;--role-success-emphasis:52 211 153;
  --role-success-border:37 108 84;--role-neutral-fg:212 212 216;--role-neutral-muted:46 46 50;
  --role-neutral-emphasis:161 161 170;--role-neutral-border:86 86 91;
  --cat-permissive-fg:134 234 224;--cat-permissive-muted:27 50 51;
  --cat-permissive-emphasis:40 189 174;--cat-permissive-border:31 98 93;--cat-weak-fg:194 201 240;
  --cat-weak-muted:43 45 59;--cat-weak-emphasis:124 139 218;--cat-weak-border:71 77 114;
  --cat-strong-fg:223 198 235;--cat-strong-muted:52 44 58;--cat-strong-emphasis:183 134 208;
  --cat-strong-border:97 75 110;--cat-network-fg:237 196 218;--cat-network-muted:57 43 52;
  --cat-network-emphasis:213 129 174;--cat-network-border:111 73 94;--cat-review-fg:230 216 204;
  --cat-review-muted:54 50 48;--cat-review-emphasis:196 169 146;--cat-review-border:103 91 82;
}}
FALLBACK
}

# The shared report CSS. Text uses only the -fg / foreground tokens; the muted,
# emphasis and border shades are for backgrounds and borders. The brand colour
# is for links only, never a data colour; red is for Critical, errors and
# failures only.
#
# Building blocks (the same ones the web UI uses):
#   .topbar        logo, "BomLens", the report kind
#   .page-head     h1 "Project version", .desc lines (items joined by a dot)
#   .box           1px border, 6px corners: .box-head (title + .counter) and
#                  rows (a table in .table-scroll, a .rows list, or .box-body)
#   .banner        one notice block (warn / danger / info), no side stripe
#   .lbl           a label: a shape marker and a word, never colour alone
#   .counter       a count
# A table wider than the page scrolls inside its box, never the page.
report_common_css() {
    cat <<'CSS'
:root{
  color-scheme:light dark;
  --bg:hsl(var(--card));--surface:hsl(var(--card));--text:hsl(var(--foreground));
  --text-muted:hsl(var(--muted-foreground));--line:hsl(var(--border));--th-bg:hsl(var(--muted));
  --link:hsl(var(--brand-strong));
  --radius:6px;
  --font:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Apple SD Gothic Neo","Malgun Gothic",sans-serif;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
}
*{box-sizing:border-box;}
html{-webkit-text-size-adjust:100%;}
body{font-family:var(--font);font-size:var(--font-size-body-sm);background:var(--bg);color:var(--text);
  max-width:1280px;margin:0 auto;padding:0 32px 48px;line-height:1.5;
  -webkit-font-smoothing:antialiased;overflow-wrap:break-word;}
a{color:var(--link);text-decoration:underline;text-underline-offset:.2em;}
/* Top bar and page header */
.topbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:12px 0;
  border-bottom:1px solid var(--line);margin-bottom:24px;}
.topbar .brand{display:inline-flex;align-items:center;gap:8px;font-weight:600;color:var(--text);}
.topbar .brand svg{width:20px;height:20px;flex:none;display:block;}
.topbar .sep{color:var(--text-muted);}
.report-kind{color:var(--text);font-weight:400;margin:0;}
.page-head{margin:0 0 24px;}
h1{font-size:var(--font-size-title);font-weight:600;line-height:1.3;margin:0 0 4px;}
h1 .ver{font-weight:400;color:var(--text-muted);}
h1 a{color:inherit;text-decoration-thickness:1px;}
.subtitle{color:var(--text);margin:0 0 4px;}
.desc{color:var(--text-muted);font-size:var(--font-size-label);margin:2px 0 0;}
.desc>span+span::before{content:"\00B7";padding:0 6px;color:var(--text-muted);}
.meta{color:var(--text-muted);font-size:var(--font-size-label);margin:4px 0 0;}
time{white-space:nowrap;}
/* Sections */
h2{font-size:1rem;font-weight:600;line-height:1.4;margin:32px 0 8px;padding-bottom:8px;
  border-bottom:1px solid var(--line);}
h3{font-size:var(--font-size-body-sm);font-weight:600;margin:16px 0 8px;}
p{margin:8px 0;}
.lead{margin:8px 0 12px;}
/* Box: one border, a head row (title + count) and rows. No box inside a box. */
.box{border:1px solid var(--line);border-radius:var(--radius);background:var(--surface);
  margin:12px 0 24px;overflow:hidden;}
.box-head{display:flex;align-items:baseline;gap:8px;flex-wrap:wrap;padding:8px 16px;
  background:var(--th-bg);border-bottom:1px solid var(--line);}
.box-head h2,.box-head h3,.box-head .box-title{font-size:var(--font-size-body-sm);font-weight:600;
  margin:0;padding:0;border:0;}
.box-head .meta{margin:0;flex-basis:100%;}
.box-body{padding:12px 16px;}
.box-body>:first-child{margin-top:0;}.box-body>:last-child{margin-bottom:0;}
.rows{list-style:none;margin:0;padding:0;}
.rows>li{padding:8px 16px;border-top:1px solid var(--line);margin:0;}
.rows>li:first-child{border-top:0;}
.rows.mono>li,.mono li{font-family:var(--mono);font-size:var(--font-size-mono);}
/* Counter and labels */
.counter{display:inline-block;min-width:20px;padding:0 6px;border-radius:2em;text-align:center;
  background:rgb(var(--role-neutral-muted));color:var(--text);font-size:var(--font-size-label);
  font-weight:500;line-height:18px;font-variant-numeric:tabular-nums;}
.summary{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:8px 0 12px;}
.lbl{display:inline-flex;align-items:center;gap:4px;padding:0 7px;border:1px solid rgb(var(--role-neutral-border));
  border-radius:2em;color:rgb(var(--role-neutral-fg));background:transparent;font-size:var(--font-size-label);
  font-weight:500;line-height:18px;white-space:nowrap;}
.lbl .count{font-weight:600;font-variant-numeric:tabular-nums;color:var(--text);}
.lbl .mk{font-size:.75em;line-height:1;}
.summary .lbl{font-size:var(--font-size-body-sm);line-height:22px;padding:0 10px;}
.lbl-danger,.sev-CRITICAL .lbl,.lbl.sev-CRITICAL,.s-fail .lbl{color:rgb(var(--role-danger-fg));border-color:rgb(var(--role-danger-emphasis));}
.lbl-severe,.lbl.sev-HIGH{color:rgb(var(--role-severe-fg));border-color:rgb(var(--role-severe-emphasis));}
.lbl-attention,.lbl.sev-MEDIUM,.s-warn .lbl{color:rgb(var(--role-attention-fg));border-color:rgb(var(--role-attention-emphasis));}
.lbl-success,.s-pass .lbl{color:rgb(var(--role-success-fg));border-color:rgb(var(--role-success-emphasis));}
.lbl-info,.s-review .lbl{color:rgb(var(--role-info-fg));border-color:rgb(var(--role-info-emphasis));}
.lbl.sev-LOW,.lbl.sev-UNKNOWN,.s-na .lbl{color:rgb(var(--role-neutral-fg));border-color:rgb(var(--role-neutral-border));}
.lbl-cat-network{color:rgb(var(--cat-network-fg));border-color:rgb(var(--cat-network-emphasis));}
.lbl-cat-strong{color:rgb(var(--cat-strong-fg));border-color:rgb(var(--cat-strong-emphasis));}
.lbl-cat-weak{color:rgb(var(--cat-weak-fg));border-color:rgb(var(--cat-weak-emphasis));}
.lbl-cat-permissive{color:rgb(var(--cat-permissive-fg));border-color:rgb(var(--cat-permissive-emphasis));}
.lbl-cat-review{color:rgb(var(--cat-review-fg));border-color:rgb(var(--cat-review-emphasis));}
.kevbadge{display:inline-block;padding:0 7px;border:1px solid rgb(var(--role-danger-emphasis));border-radius:2em;
  color:rgb(var(--role-danger-fg));font-size:var(--font-size-label);font-weight:600;line-height:18px;white-space:nowrap;}
/* Banner: one notice block. Tinted fill and a full 1px border. */
.banner,.note{border:1px solid rgb(var(--role-attention-border));background:rgb(var(--role-attention-muted));
  border-radius:var(--radius);padding:12px 16px;margin:12px 0 16px;}
.banner>:first-child{margin-top:0;}.banner>:last-child{margin-bottom:0;}
.banner p{margin:6px 0;}
.banner ul{margin:6px 0 0;padding-left:20px;}
.banner li{margin:2px 0;}
.banner b{color:var(--text);}
.banner-title,.banner h2.banner-title{font-size:var(--font-size-body-sm);font-weight:600;margin:0 0 4px;padding:0;border:0;}
.banner-danger{border-color:rgb(var(--role-danger-border));background:rgb(var(--role-danger-muted));}
.banner-info{border-color:var(--line);background:var(--th-bg);}
.banner code{overflow-wrap:anywhere;}
/* Definition rows: a label, then what it means (the risk report's deadlines). */
.deadlines{margin:0;}
.deadlines>div{display:flex;align-items:center;gap:12px;padding:8px 16px;border-top:1px solid var(--line);}
.deadlines>div:first-child{border-top:0;}
.deadlines dt{min-width:7em;margin:0;}
.deadlines dd{margin:0;}
.box>.deadlines+.legend{border-bottom:0;border-top:1px solid var(--line);}
/* Legend under a table head: what a column or a mark means. */
.legend{margin:0;padding:8px 16px;border-bottom:1px solid var(--line);color:var(--text-muted);
  font-size:var(--font-size-label);display:flex;flex-wrap:wrap;gap:4px 20px;}
.legend span b{color:var(--text);font-weight:600;}
.box>.legend:last-child{border-bottom:0;border-top:1px solid var(--line);}
/* Tables */
.table-scroll{overflow-x:auto;}
.table-scroll::-webkit-scrollbar{height:10px;}
.table-scroll::-webkit-scrollbar-thumb{background:rgb(var(--role-neutral-border));border-radius:6px;border:2px solid var(--surface);}
.table-scroll::-webkit-scrollbar-track{background:var(--th-bg);}
table{border-collapse:collapse;width:100%;font-size:var(--font-size-body-sm);}
th{background:var(--th-bg);text-align:left;font-size:var(--font-size-label);font-weight:600;
  color:var(--text-muted);padding:6px 10px;border-bottom:1px solid var(--line);white-space:nowrap;vertical-align:bottom;}
td{padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top;}
tbody tr:last-child td{border-bottom:none;}
tbody tr:hover td{background:var(--th-bg);}
th.num,td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap;}
td.num:first-child{color:var(--text-muted);}
/* Short columns take their content width; the column marked grow takes the rest. */
th.num,td.num,td.sev,td.id,td.ver,td.req,td.s-pass,td.s-fail,td.s-warn,td.s-review,td.s-na{width:1%;}
td.id{white-space:nowrap;font-variant-numeric:tabular-nums;}
td.sev,td[class^="sev-"]{white-space:nowrap;}
td.ver{white-space:nowrap;}
td.fix{min-width:11em;}
td.fix .v{white-space:nowrap;}
td.grow{min-width:14em;}
td.wrap,td.purl{overflow-wrap:anywhere;}
td.purl{font-family:var(--mono);font-size:var(--font-size-mono);min-width:14em;}
td.total{font-weight:600;}
abbr[title]{text-decoration:underline dotted;text-underline-offset:.2em;cursor:help;}
.pkg .pn{font-weight:600;white-space:nowrap;}
.pkg .pg{color:var(--text-muted);white-space:nowrap;}
.pkg .pv{white-space:nowrap;font-variant-numeric:tabular-nums;}

code{font-family:var(--mono);font-size:var(--font-size-mono);}
pre{background:var(--th-bg);border:1px solid var(--line);border-radius:var(--radius);
  padding:8px 12px;overflow-x:auto;margin:8px 0;}
pre code{white-space:pre;}
ol,ul{margin:8px 0 0;padding-left:20px;}
li{margin:4px 0;}
.mono{list-style:none;padding-left:0;}
/* NOTICE */
.rows .src{display:block;color:var(--text-muted);font-family:var(--font);font-size:var(--font-size-label);margin-top:2px;}
.src a{word-break:break-all;}
.rows .attr{display:block;color:var(--text-muted);font-family:var(--font);font-size:var(--font-size-label);margin-top:2px;}
.unverified{color:rgb(var(--role-attention-fg));font-size:var(--font-size-label);margin:0;flex-basis:100%;}
.texts .box pre{border:0;border-radius:0;margin:0;background:transparent;padding:12px 16px;
  font-size:var(--font-size-mono);line-height:1.45;white-space:pre-wrap;overflow-wrap:anywhere;}
/* Conformance */
.s-pass,.s-fail,.s-warn,.s-review,.s-na{white-space:nowrap;}
td.req{white-space:nowrap;}
details.fix{margin:6px 0 0;}
details.fix summary{cursor:pointer;color:var(--link);font-size:var(--font-size-label);font-weight:600;}
details.fix pre{margin:6px 0 2px;}
details.fix pre code{white-space:pre-wrap;overflow-wrap:anywhere;}
details.fix .meta{font-size:var(--font-size-label);}
@media screen and (max-width:767px){body{padding:0 16px 32px;}}
/* Print: always light (the dark tokens apply to screens only), A4, no page
   background, table headers repeat on every page, rows and boxes do not split,
   and an external link shows its address because paper cannot be clicked. */
@page{size:A4;margin:16mm 14mm;}
@media print{
  body{max-width:none;margin:0;padding:0;background:#fff;font-size:10pt;line-height:1.45;}
  .topbar{padding-top:0;}
  .table-scroll{overflow:visible;}
  .box{overflow:visible;break-inside:auto;}
  table{font-size:8.5pt;}
  th,td{padding:3px 6px;}
  th{white-space:normal;}
  td.grow,td.fix,td.purl{min-width:0;}
  table .meta{font-size:8pt;}
  pre,pre code{white-space:pre-wrap;overflow-wrap:anywhere;}
  .box-head,th{background:transparent;}
  thead{display:table-header-group;}
  tfoot{display:table-footer-group;}
  tr,.banner,.note,li,.box-head{break-inside:avoid;page-break-inside:avoid;}
  h1,h2,h3,.box-head{break-after:avoid;page-break-after:avoid;}
  tbody tr:hover td{background:transparent;}
  a[href^="http"]::after{content:" (" attr(href) ")";font-size:var(--font-size-label);word-break:break-all;}
  .src a::after,h1 a::after{content:none;}
  details.fix summary{color:var(--text);}
}
CSS
}

# ---------------------------------------------------------------------------
# Page head helpers. REPORT_LANG (en|ko) picks the wording; Korean strings come
# from i18n/report-strings.ko.json next to this file (keys report.*), English is
# built in. Every helper prints HTML; values from the SBOM are escaped here.
# ---------------------------------------------------------------------------
report_esc() { printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g'; }

# report_str KEY [ARG]: one page-head string in REPORT_LANG.
report_str() {
    local key="$1" arg="${2:-}" cat="$REPORT_LIB_DIR/i18n/report-strings.ko.json" f=""
    if [ "${REPORT_LANG:-en}" = "ko" ] && [ -f "$cat" ]; then
        f="$(jq -r --arg k "report.$key" '.[$k] // empty' "$cat" 2>/dev/null)"
    fi
    if [ -z "$f" ]; then
        case "$key" in
            type_source) f="Source" ;;
            type_image) f="Container image" ;;
            type_binary) f="Binary" ;;
            type_rootfs) f="Root filesystem" ;;
            type_firmware) f="Firmware" ;;
            type_aibom) f="AI model" ;;
            type_dataset) f="Dataset" ;;
            type_analyze) f="Received SBOM" ;;
            type_yocto) f="Yocto build" ;;
            type_merge) f="Merged SBOM" ;;
            type_os) f="Operating system" ;;
            type_application) f="Application" ;;
            findings) f="Findings" ;;
            components) if [ "$arg" = "1" ]; then f="%s component"; else f="%s components"; fi ;;
            *) f="$key" ;;
        esac
    fi
    # shellcheck disable=SC2059  # the format is a trusted built-in or catalog string
    printf -- "$f" "$arg"
}

# report_version PROJECT OUT_PREFIX [SBOM]: the version half of the
# "{project}_{version}" prefix, else the SBOM root component's version.
report_version() {
    local project="$1" prefix="$2" bom="${3:-}" base v=""
    base="$(basename -- "$prefix")"
    case "$base" in
        "${project}_"?*) v="${base#"${project}_"}" ;;
    esac
    if [ -z "$v" ] && [ -n "$bom" ] && [ -f "$bom" ]; then
        v="$(jq -r '.metadata.component.version // empty | tostring' "$bom" 2>/dev/null | head -n 1)"
    fi
    printf '%s' "$v"
}

# report_type_label MODE [SBOM]: what was scanned, from the scan mode, else the
# SBOM's bomlens:scanMode, else the root component type. Prints nothing when
# none of them says.
report_type_label() {
    local mode="${1:-}" bom="${2:-}" key="" rtype=""
    if [ -z "$mode" ] && [ -n "$bom" ] && [ -f "$bom" ]; then
        mode="$(jq -r '[.metadata.properties[]? | select(.name? == "bomlens:scanMode") | .value][0] // ""' "$bom" 2>/dev/null)"
    fi
    case "$mode" in
        SOURCE) key=source ;; IMAGE) key=image ;; BINARY) key=binary ;; ROOTFS) key=rootfs ;;
        FIRMWARE) key=firmware ;; AIBOM) key=aibom ;; ANALYZE) key=analyze ;; YOCTO) key=yocto ;;
        MERGE) key=merge ;;
    esac
    if [ -z "$key" ] && [ -n "$bom" ] && [ -f "$bom" ]; then
        rtype="$(jq -r '.metadata.component.type // ""' "$bom" 2>/dev/null)"
        case "$rtype" in
            container) key=image ;; firmware) key=firmware ;; machine-learning-model) key=aibom ;;
            data) key=dataset ;; operating-system) key=os ;;
            application|library|framework) key=application ;;
        esac
    fi
    [ -n "$key" ] && report_str "type_$key"
    return 0
}

# report_component_count SBOM: the number of top-level components, or nothing.
report_component_count() {
    [ -n "${1:-}" ] && [ -f "$1" ] || return 0
    jq -r 'if (.components | type) == "array" then (.components | length) else empty end' "$1" 2>/dev/null || true
}

# The logo mark, drawn inline (a report is one file under a CSP that blocks
# images). Same drawing and colours as docker/web/frontend/public/logo.svg.
report_logo_svg() {
    printf '%s' '<svg viewBox="0 0 48 48" aria-hidden="true" focusable="false"><defs><linearGradient id="bl-mark" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#EA002C"/><stop offset="1" stop-color="#F47725"/></linearGradient></defs><rect width="48" height="48" rx="11" fill="url(#bl-mark)"/><g transform="translate(12 12)" fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="14.31" y1="8" x2="20.05" y2="17.94"/><line x1="9.69" y1="8" x2="21.17" y2="8"/><line x1="7.38" y1="12" x2="13.12" y2="2.06"/><line x1="9.69" y1="16" x2="3.95" y2="6.06"/><line x1="14.31" y1="16" x2="2.83" y2="16"/><line x1="16.62" y1="12" x2="10.88" y2="21.94"/></g></svg>'
}

# report_topbar KIND: the bar above the page head (logo, BomLens, report kind).
report_topbar() {
    printf '<header class="topbar"><span class="brand">%sBomLens</span><span class="sep" aria-hidden="true">/</span><p class="report-kind">%s</p></header>\n' \
        "$(report_logo_svg)" "$1"
}

# report_h1 NAME_HTML VERSION: "Project version", the version in the muted weight.
report_h1() {
    if [ -n "$2" ]; then
        printf '<h1>%s <span class="ver">%s</span></h1>\n' "$1" "$(report_esc "$2")"
    else
        printf '<h1>%s</h1>\n' "$1"
    fi
}

# report_desc ITEM_HTML...: one description line, empty items left out.
report_desc() {
    local item out=""
    for item in "$@"; do
        [ -n "$item" ] && out="${out}<span>${item}</span>"
    done
    [ -n "$out" ] && printf '<p class="desc">%s</p>\n' "$out"
    return 0
}

# jq definitions shared by the report tables:
#   sevlbl    a severity as a label: shape marker and word ("CRITICAL" in, ◆ Critical out)
#   pkgcoord  a package name; "group:artifact" shows the artifact first and the
#             group muted after " / ", the full name kept in title
#   pkgcoordv(v)  the same with the installed version after the name
#   fixlist   "a, b, c" with each version kept on one line
report_jq_defs() {
    cat <<'JQ'
def sevword: ({"CRITICAL":"Critical","HIGH":"High","MEDIUM":"Medium","LOW":"Low","UNKNOWN":"Unknown"}[.] // .);
def sevmark: ({"CRITICAL":"◆","HIGH":"▲","MEDIUM":"●","LOW":"■"}[.] // "–");
def sevlbl: ((. // "UNKNOWN") | tostring) as $s
  | "<span class=\"lbl sev-" + ($s|@html) + "\"><span class=\"mk\" aria-hidden=\"true\">" + ($s|sevmark) + "</span>" + ($s|sevword|@html) + "</span>";
def pkgcoordv($v): ((. // "") | tostring) as $p | ($p | rindex(":")) as $i
  | (if ($v // "") == "" then "" else " <span class=\"pv\">" + ($v|tostring|@html) + "</span>" end) as $ver
  | if $i == null or $i == 0 or $i == (($p|length) - 1)
    then "<span class=\"pkg\"><span class=\"pn\">" + ($p|@html) + "</span>" + $ver + "</span>"
    else "<span class=\"pkg\" title=\"" + ($p|@html) + "\"><span class=\"pn\">" + ($p[$i+1:]|@html)
         + "</span>" + $ver + " <span class=\"pg\">/ " + ($p[0:$i]|@html) + "</span></span>" end;
def pkgcoord: pkgcoordv("");
def fixlist: ((. // "") | tostring) | if . == "" then "" else (split(", ") | map("<span class=\"v\">" + (.|@html) + "</span>") | join(", ")) end;
JQ
}


# The <style> element of a report.
report_style() {
    echo "<style>"
    report_tokens_css
    report_common_css
    echo "</style>"
}

# <time> element for a generated-at stamp. The machine value stays in datetime=;
# the visible text drops the seconds and names the zone. Anything that is not the
# "YYYY-MM-DDTHH:MM:SSZ" form the generators produce is printed as it is.
report_time_html() {
    local iso="$1" d t
    case "$iso" in
        [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z)
            d="${iso%%T*}"; t="${iso#*T}"; t="${t%:*}"
            printf '<time datetime="%s">%s %s UTC</time>' "$iso" "$d" "$t" ;;
        *)
            printf '%s' "$iso" ;;
    esac
}
