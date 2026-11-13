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
  --cat-permissive-fg:63 63 70;--cat-permissive-muted:238 238 239;
  --cat-permissive-emphasis:113 113 122;--cat-permissive-border:191 191 195;--cat-weak-fg:74 80 20;
  --cat-weak-muted:240 242 226;--cat-weak-emphasis:112 121 28;--cat-weak-border:196 202 146;
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
  --cat-permissive-fg:212 212 216;--cat-permissive-muted:46 46 50;
  --cat-permissive-emphasis:161 161 170;--cat-permissive-border:86 86 91;--cat-weak-fg:208 214 140;
  --cat-weak-muted:47 49 33;--cat-weak-emphasis:168 178 72;--cat-weak-border:92 97 50;
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
#   .topbar        logo, "BomLens", then the project and version
#   .page-head     h1 with the report name, one .desc line (items joined by a dot)
#   .box           1px border, 6px corners: .box-head (title + .counter) and
#                  rows (a table in .table-scroll, a .rows list, or .box-body)
#   .banner        one notice block (warn / danger), 1px border all round
#   .lbl           a label: a word, a shape marker for severity; .zero is neutral
#   .counter       a count
# A table wider than its box scrolls inside the box, never the page; cells wrap
# so that from 960px up, and on A4, no table is wider than its box.
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
/* Top bar and page head */
.topbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:12px 0;
  border-bottom:1px solid var(--line);margin-bottom:24px;}
.topbar .brand{display:inline-flex;align-items:center;gap:8px;font-weight:600;color:var(--text);}
.topbar .brand svg{width:20px;height:20px;flex:none;display:block;}
.topbar .sep{color:var(--text-muted);}
.topbar .proj{font-weight:600;}
.topbar .proj a{color:inherit;text-decoration-thickness:1px;}
.topbar .ver,.desc .ver{font-weight:400;color:var(--text-muted);}
.page-head{margin:0 0 24px;}
h1{font-size:var(--font-size-title);font-weight:600;line-height:1.3;margin:0 0 4px;}
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
/* Box: one border, a head row (title + count) and rows. No box inside a box. */
.box{border:1px solid var(--line);border-radius:var(--radius);background:var(--surface);
  margin:12px 0 24px;overflow:hidden;}
.box-head{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:8px 16px;
  background:var(--th-bg);border-bottom:1px solid var(--line);}
.box-head h2,.box-head h3,.box-head .box-title{font-size:var(--font-size-body-sm);font-weight:600;
  margin:0;padding:0;border:0;}
.box-head .meta{margin:0;flex-basis:100%;}
.box-head .end{margin-left:auto;display:flex;gap:6px;flex-wrap:wrap;}
.box-body{padding:12px 16px;}
.box-body>:first-child{margin-top:0;}.box-body>:last-child{margin-bottom:0;}
.rows{list-style:none;margin:0;padding:0;}
.rows>li{padding:8px 16px;border-top:1px solid var(--line);margin:0;}
.rows>li:first-child{border-top:0;}
.rows.mono>li,.mono li{font-family:var(--mono);font-size:var(--font-size-mono);overflow-wrap:anywhere;}
.rows.toc>li{display:flex;gap:8px;align-items:center;padding:4px 16px;}
.rows.toc .counter{margin-left:auto;}
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
.lbl-danger,.lbl.sev-CRITICAL,.s-fail .lbl{color:rgb(var(--role-danger-fg));border-color:rgb(var(--role-danger-emphasis));}
.lbl-severe,.lbl.sev-HIGH{color:rgb(var(--role-severe-fg));border-color:rgb(var(--role-severe-emphasis));}
.lbl-attention,.lbl.sev-MEDIUM,.s-warn .lbl{color:rgb(var(--role-attention-fg));border-color:rgb(var(--role-attention-emphasis));}
.lbl-success,.s-pass .lbl{color:rgb(var(--role-success-fg));border-color:rgb(var(--role-success-emphasis));}
.lbl.sev-LOW,.lbl.sev-UNKNOWN,.s-na .lbl,.s-review .lbl{color:rgb(var(--role-neutral-fg));border-color:rgb(var(--role-neutral-border));}
.lbl-cat-network{color:rgb(var(--cat-network-fg));border-color:rgb(var(--cat-network-emphasis));}
.lbl-cat-strong{color:rgb(var(--cat-strong-fg));border-color:rgb(var(--cat-strong-emphasis));}
.lbl-cat-weak{color:rgb(var(--cat-weak-fg));border-color:rgb(var(--cat-weak-emphasis));}
.lbl-cat-permissive{color:rgb(var(--cat-permissive-fg));border-color:rgb(var(--cat-permissive-emphasis));}
.lbl-cat-review{color:rgb(var(--cat-review-fg));border-color:rgb(var(--cat-review-emphasis));}
.lbl.zero{color:rgb(var(--role-neutral-fg));border-color:rgb(var(--role-neutral-border));}
.kevbadge{display:inline-block;padding:0 7px;border:1px solid rgb(var(--role-danger-emphasis));border-radius:2em;
  color:rgb(var(--role-danger-fg));font-size:var(--font-size-label);font-weight:600;line-height:18px;white-space:nowrap;}
/* Banner: one notice block. Tinted fill and a full 1px border. */
.banner{border:1px solid rgb(var(--role-attention-border));background:rgb(var(--role-attention-muted));
  border-radius:var(--radius);padding:12px 16px;margin:12px 0 16px;}
.banner>:first-child{margin-top:0;}.banner>:last-child{margin-bottom:0;}
.banner p{margin:6px 0;}
.banner ul{margin:6px 0 0;padding-left:20px;}
.banner li{margin:2px 0;}
.banner b{color:var(--text);}
.banner-title,.banner h2.banner-title{font-size:var(--font-size-body-sm);font-weight:600;margin:0 0 4px;padding:0;border:0;}
.banner-danger{border-color:rgb(var(--role-danger-border));background:rgb(var(--role-danger-muted));}
.banner code{overflow-wrap:anywhere;}
/* Definition rows: a label, then what it means (the risk report's deadlines). */
.deadlines{margin:0;}
.deadlines>div{display:flex;align-items:center;gap:12px;padding:8px 16px;border-top:1px solid var(--line);}
.deadlines>div:first-child{border-top:0;}
.deadlines dt{min-width:7em;margin:0;}
.deadlines dd{margin:0;}
/* Legend under a table head, or a closing line of a box. */
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
td{padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere;}
tbody:last-child tr:last-child td{border-bottom:none;}
tbody tr:hover td{background:var(--th-bg);}
th.num,td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap;}
td.num:first-child{color:var(--text-muted);}
/* Short columns take their content width; the column marked grow takes the rest. */
th.num,td.num,td.sev,td.id,td.req,td.dl,td.st{width:1%;}
td.id{white-space:nowrap;font-variant-numeric:tabular-nums;overflow-wrap:normal;}
td.sev,td.st,td.dl{white-space:nowrap;}
td.req{white-space:nowrap;}
td.ver{font-variant-numeric:tabular-nums;}
td.fix{max-width:16ch;min-width:9ch;}
td.grow{width:auto;}
@media screen{td.pkgc{min-width:20ch;}}
td.purl{font-family:var(--mono);font-size:var(--font-size-mono);}
td.total{font-weight:600;}
.nofix{color:var(--text-muted);}
/* Each part of a package stays whole while it fits the cell, and wraps
   anywhere only when one part alone is wider than the cell. */
.pkg .pg,.pkg .pn,.pkg .pv{display:inline-block;max-width:100%;}
.pkg .pn{font-weight:600;}
.pkg .pg,.pkg .psep{color:var(--text-muted);}
.pkg .pv{font-variant-numeric:tabular-nums;}
tr.grp th{background:var(--surface);color:var(--text);font-size:var(--font-size-body-sm);
  padding:10px 10px 6px;border-top:1px solid var(--line);}
tr.grp th .counter{margin-left:6px;}
tbody.met td{padding-top:3px;padding-bottom:3px;}
code{font-family:var(--mono);font-size:var(--font-size-mono);}
pre{background:var(--th-bg);border:1px solid var(--line);border-radius:var(--radius);
  padding:8px 12px;overflow-x:auto;margin:8px 0;}
pre code{white-space:pre;}
ol,ul{margin:8px 0 0;padding-left:20px;}
li{margin:4px 0;}
.mono{list-style:none;padding-left:0;}
.print-only{display:none;}
/* One evidence item per line; a long one ends in an ellipsis, its text in title. */
.ev{display:block;max-width:36ch;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
/* NOTICE */
.rows .src{display:block;color:var(--text-muted);font-family:var(--font);font-size:var(--font-size-label);margin-top:2px;}
.src a{word-break:break-all;}
.rows .attr{display:block;color:var(--text-muted);font-family:var(--font);font-size:var(--font-size-label);margin-top:2px;}
.unverified{color:rgb(var(--role-attention-fg));font-size:var(--font-size-label);margin:0;flex-basis:100%;}
.texts .box pre{border:0;border-radius:0;margin:0;background:transparent;padding:12px 16px;
  font-size:var(--font-size-mono);line-height:1.45;white-space:pre-wrap;overflow-wrap:anywhere;}
/* Conformance */
details.fix,details.more{margin:6px 0 0;}
details.fix summary,details.more summary{cursor:pointer;color:var(--link);font-size:var(--font-size-label);font-weight:600;}
details.fix pre{margin:6px 0 2px;}
details.fix pre code{white-space:pre-wrap;overflow-wrap:anywhere;}
details.fix .meta{font-size:var(--font-size-label);}
@media screen and (max-width:767px){body{padding:0 16px 32px;}}
/* Print: always light (the dark tokens apply to screens only), A4, no page
   background, table headers repeat on every page, rows do not split, a table
   box draws only its row lines (a box border would break at the page edge),
   every cell may wrap, the text of a collapsed details is printed, and an
   external link shows its address because paper cannot be clicked. */
@page{size:A4;margin:16mm 14mm;}
@media print{
  body{max-width:none;margin:0;padding:0;background:#fff;font-size:10pt;line-height:1.45;}
  .topbar{padding-top:0;}
  .table-scroll{overflow:visible;}
  .box{overflow:visible;break-inside:auto;border:0;border-radius:0;}
  .box-head{padding:6px 0;border-bottom:1px solid var(--line);}
  .rows>li,.legend,.deadlines>div{padding-left:0;padding-right:0;}
  table{font-size:8.5pt;}
  th,td{padding:3px 4px;}
  /* Long values wrap; a label, an id, a number and a time stay on one line. */
  th,td{white-space:normal;}
  td.grow{min-width:0;}
  td.fix{max-width:none;}
  .pkg .pg{overflow-wrap:anywhere;}
  .ev{max-width:none;white-space:normal;overflow:visible;overflow-wrap:anywhere;}
  table .meta{font-size:8pt;}
  pre,pre code{white-space:pre-wrap;overflow-wrap:anywhere;}
  .box-head,th,tr.grp th{background:transparent;}
  thead{display:table-header-group;}
  tfoot{display:table-footer-group;}
  tr,.banner,li,.box-head{break-inside:avoid;page-break-inside:avoid;}
  h1,h2,h3,.box-head{break-after:avoid;page-break-after:avoid;}
  tbody tr:hover td{background:transparent;}
  a[href^="http"]::after{content:" (" attr(href) ")";font-size:var(--font-size-label);word-break:break-all;}
  .src a::after,.topbar a::after,.rows.toc a::after{content:none;}
  details.fix,details.more{display:none;}
  .print-only{display:block;}
}
CSS
}

# ---------------------------------------------------------------------------
# Page head helpers. REPORT_LANG (en|ko) picks the wording; Korean strings come
# from i18n/report-strings.ko.json next to this file (keys report.*), English is
# built in. Every helper prints HTML; values from the SBOM are escaped here.
# ---------------------------------------------------------------------------
report_esc() { printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g'; }

# report_num N: a count with thousands separators (60118 -> 60,118); anything
# that is not a plain number is printed as it is.
report_num() {
    case "$1" in
        ''|*[!0-9]*) printf '%s' "$1" ;;
        *) printf '%s' "$1" | sed -E -e ':a' -e 's/^([0-9]+)([0-9]{3})/\1,\2/' -e 'ta' ;;
    esac
}

# report_str KEY [ARG]: one shared string in REPORT_LANG.
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
            no_fix) f="No fix yet" ;;
            and_more) f="and %s more" ;;
            components) if [ "$arg" = "1" ]; then f="%s component"; else f="%s components"; fi ;;
            *) f="$key" ;;
        esac
    fi
    # shellcheck disable=SC2059  # the format is a trusted built-in or catalog string
    printf -- "$f" "$arg"
}

# report_bom_facts SBOM: read, in one jq pass, what the page head shows:
#   RB_VERSION   root component version (a string or a number, else empty)
#   RB_MODE      bomlens:scanMode of the SBOM, if any
#   RB_ROOTTYPE  root component type
#   RB_NCOMP     number of top-level components (empty when there is no array)
RB_VERSION=""; RB_MODE=""; RB_ROOTTYPE=""; RB_NCOMP=""
report_bom_facts() {
    RB_VERSION=""; RB_MODE=""; RB_ROOTTYPE=""; RB_NCOMP=""
    [ -n "${1:-}" ] && [ -f "$1" ] || return 0
    local out
    # shellcheck disable=SC2016
    out="$(jq -r 'def s: if type == "string" or type == "number" then tostring else "" end
                         | gsub("[\u001f\r\n\t]"; " ");
        [ (.metadata.component.version // "" | s),
          ([.metadata.properties[]? | select(.name? == "bomlens:scanMode") | .value | s][0] // ""),
          (.metadata.component.type // "" | s),
          (if (.components | type) == "array" then (.components | length | tostring) else "" end)
        ] | join("\u001f")' "$1" 2>/dev/null)" || return 0
    # shellcheck disable=SC2034  # RB_* are read by the report scripts
    IFS=$'\x1f' read -r RB_VERSION RB_MODE RB_ROOTTYPE RB_NCOMP <<EOF
$out
EOF
}

# report_version PROJECT OUT_PREFIX: the version half of the "{project}_{version}"
# prefix, else RB_VERSION (call report_bom_facts first).
report_version() {
    local project="$1" base v=""
    base="$(basename -- "$2")"
    case "$base" in
        "${project}_"?*) v="${base#"${project}_"}" ;;
    esac
    [ -n "$v" ] || v="$RB_VERSION"
    printf '%s' "$v"
}

# report_type_label MODE: what was scanned, from the scan mode (the caller's
# SCAN_MODE, or MODE from the container environment), else the SBOM's
# bomlens:scanMode, else the root component type (call report_bom_facts first).
report_type_label() {
    local mode="${1:-}" key=""
    case "$mode" in
        SOURCE|IMAGE|BINARY|ROOTFS|FIRMWARE|AIBOM|ANALYZE|YOCTO|MERGE) ;;
        *) mode="$RB_MODE" ;;
    esac
    case "$mode" in
        SOURCE) key=source ;; IMAGE) key=image ;; BINARY) key=binary ;; ROOTFS) key=rootfs ;;
        FIRMWARE) key=firmware ;; AIBOM) key=aibom ;; ANALYZE) key=analyze ;; YOCTO) key=yocto ;;
        MERGE) key=merge ;;
    esac
    if [ -z "$key" ]; then
        case "$RB_ROOTTYPE" in
            container) key=image ;; firmware) key=firmware ;; machine-learning-model) key=aibom ;;
            data) key=dataset ;; operating-system) key=os ;;
            application|library|framework) key=application ;;
        esac
    fi
    [ -n "$key" ] && report_str "type_$key"
    return 0
}

# The logo mark, drawn inline (a report is one file under a CSP that blocks
# images). Same drawing and colours as docker/web/frontend/public/logo.svg.
report_logo_svg() {
    printf '%s' '<svg viewBox="0 0 48 48" aria-hidden="true" focusable="false"><defs><linearGradient id="bl-mark" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#EA002C"/><stop offset="1" stop-color="#F47725"/></linearGradient></defs><rect width="48" height="48" rx="11" fill="url(#bl-mark)"/><g transform="translate(12 12)" fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="14.31" y1="8" x2="20.05" y2="17.94"/><line x1="9.69" y1="8" x2="21.17" y2="8"/><line x1="7.38" y1="12" x2="13.12" y2="2.06"/><line x1="9.69" y1="16" x2="3.95" y2="6.06"/><line x1="14.31" y1="16" x2="2.83" y2="16"/><line x1="16.62" y1="12" x2="10.88" y2="21.94"/></g></svg>'
}

# report_project_html NAME_HTML VERSION: "Project version", the version muted.
report_project_html() {
    if [ -n "$2" ]; then
        printf '%s <span class="ver">%s</span>' "$1" "$(report_esc "$2")"
    else
        printf '%s' "$1"
    fi
}

# report_page_head TITLE PROJECT_HTML VERSION SUBTITLE_HTML DESC_ITEM...: the top
# bar ("BomLens / project version"), the h1 with the report name, an optional
# subtitle and one description line (project version, then the items given).
report_page_head() {
    local title="$1" proj="$2" ver="$3" sub="$4"
    shift 4
    printf '<header class="topbar"><span class="brand">%sBomLens</span><span class="sep" aria-hidden="true">/</span><span class="proj">%s</span></header>\n' \
        "$(report_logo_svg)" "$(report_project_html "$proj" "$ver")"
    echo '<div class="page-head">'
    printf '<h1>%s</h1>\n' "$title"
    [ -n "$sub" ] && printf '%s\n' "$sub"
    report_desc "$(report_project_html "$(printf '%s' "$proj" | sed 's/<[^>]*>//g')" "$ver")" "$@"
    echo '</div>'
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

# report_lbl CLASS COUNT TEXT_HTML [MARK]: a summary label. A zero count is drawn
# neutral, whatever its class.
report_lbl() {
    local cls="$1" n="$2" text="$3" mark="${4:-}" z=""
    [ "$n" = "0" ] && z=" zero"
    [ -n "$mark" ] && mark="<span class=\"mk\" aria-hidden=\"true\">${mark}</span>"
    printf '<span class="lbl%s%s">%s%s <span class="count">%s</span></span>' \
        "${cls:+ $cls}" "$z" "$mark" "$text" "$(report_num "$n")"
}

# report_sev_labels C H M L U: the five severity labels, each with its count.
report_sev_labels() {
    report_lbl "sev-CRITICAL" "$1" "Critical" "&#9670;"; echo
    report_lbl "sev-HIGH" "$2" "High" "&#9650;"; echo
    report_lbl "sev-MEDIUM" "$3" "Medium" "&#9679;"; echo
    report_lbl "sev-LOW" "$4" "Low" "&#9632;"; echo
    report_lbl "sev-UNKNOWN" "$5" "Unknown" "&#8211;"; echo
}

# Box ids: each table names its box head (aria-labelledby).
REPORT_BOX_N=0
# shellcheck disable=SC2034  # REPORT_BOX_ID is read by the report scripts
report_next_id() { REPORT_BOX_N=$((REPORT_BOX_N + 1)); REPORT_BOX_ID="box-${REPORT_BOX_N}"; }

# jq definitions shared by the report tables:
#   num            a count with thousands separators
#   sevlbl         a severity as a label: shape marker and word ("CRITICAL" in, ◆ Critical out)
#   pkgcoordp(v; purl)
#                  a package as the web UI draws it: for a Maven purl the
#                  "group:artifact" name is shown as "group / artifact", the group
#                  muted; then the installed version. The full name is in title.
#                  Split by characters, so a non-ASCII name stays whole.
#   fixlist(none)  "a, b, c", or the muted word for no fixed version
#   cut(n)         text shortened to n characters with an ellipsis, the full
#                  text in title; it may break after "/", "." and "-"
#   wbr(chars)     break opportunities after the given characters
report_jq_defs() {
    cat <<'JQ'
def num: tostring as $s | if ($s|test("^[0-9]{4,}$")) then ([$s|explode|reverse|_nwise(3)|reverse|implode]|reverse|join(",")) else $s end;
def sevword: ({"CRITICAL":"Critical","HIGH":"High","MEDIUM":"Medium","LOW":"Low","UNKNOWN":"Unknown"}[.] // .);
def sevmark: ({"CRITICAL":"◆","HIGH":"▲","MEDIUM":"●","LOW":"■"}[.] // "–");
def sevlbl: ((. // "UNKNOWN") | tostring) as $s
  | "<span class=\"lbl sev-" + ($s|@html) + "\"><span class=\"mk\" aria-hidden=\"true\">" + ($s|sevmark) + "</span>" + ($s|sevword|@html) + "</span>";
def strv: if type == "string" or type == "number" then tostring else "" end;
# wbr(chars): a line-break opportunity after each of the given characters, put
# into text that is already HTML-escaped (the characters are never part of an
# entity), so a long name breaks there before it breaks anywhere.
def wbr($re): gsub("(?<c>" + $re + ")"; "\(.c)<wbr>");
def pkgcoordp($v; $purl): ((. // "") | strv) as $p
  | ((($purl // "") | strv | startswith("pkg:maven/")) and ($p | test(":."))) as $maven
  | (if $maven then ($p | split(":")) else [$p] end) as $parts
  | (if $maven and ($parts[-1] != "") and (($parts[0:-1] | join(":")) != "")
     then {g: ($parts[0:-1] | join(":")), n: $parts[-1]} else {g: "", n: $p} end) as $c
  | (($v // "") | strv) as $vv
  | "<span class=\"pkg\" title=\"" + ($p|@html) + "\">"
    + (if $c.g != "" then "<span class=\"pg\">" + ($c.g|@html|wbr("[.]")) + "</span><span class=\"psep\"> / </span>" else "" end)
    + "<span class=\"pn\">" + ($c.n|@html) + "</span>"
    + (if $vv != "" then " <span class=\"pv\">" + ($vv|@html) + "</span>" else "" end) + "</span>";
def fixlist($none): ((. // "") | strv) | if . == "" then "<span class=\"nofix\">" + ($none|@html) + "</span>"
  else (split(", ") | map("<span class=\"v\">" + (.|@html) + "</span>") | join(", ")) end;
def cut($n): ((. // "") | strv) as $t
  | if ($t | length) > $n then "<span title=\"" + ($t|@html) + "\">" + ($t[0:$n]|@html|wbr("[/.-]")) + "…</span>" else ($t|@html|wbr("[/.-]")) end;
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
