#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Review what a source-code match scan found: a queue page, a pending list, and the decisions applied.

Usage:
  snippet-review.py page  <scan-raw.json> [--lang en|ko] [--root <source dir>] [--origin <release sources dir>] [--decisions file.json] > review.html
  snippet-review.py queue <scan-raw.json> [--decisions file.json]
  snippet-review.py apply <components.json> <scan-raw.json> <decisions.json> > components.json

<scan-raw.json> is the raw result of a match scan: an object keyed by file path whose values are lists of
matches ({"id": "file" | "snippet" | "none", "matched": "87%", "lines": "10-52", "oss_lines": "100-142",
"purl": [...], "component": "...", "version": "...", "licenses": [{"name": "..."}], "file_hash": "...", ...}).

With --root the page shows the user's own matched lines. With --origin, a folder holding the release sources
the knowledge base was built from (tarballs named <component>-<version>*), it shows the original lines next to
them. A scan against a public service sends only hashes, so there the original is just the address and the
line numbers the service returned.

Matches are grouped by the component they came from, so one decision covers every file of the group.
Each group lands in one of three tiers:

  auto       every file is a whole-file match from one source with a known license
  decide     a partial copy (11 lines or more and 40% or more of the file), files that several sources
             claim, a license nobody found, or versions that disagree
  reference  small partial matches (10 lines or fewer, or under 40%); shown, never asked for

Decisions (a JSON list): {"component": <purl or name>, "decision": "add" | "ours" | "coincidence" |
"declared" | "version", "reason": "...", "reviewer": "...", "version": "...", "declared_as": "...",
"files": [{"hash": "...", "lines": "..."}]}. `ours` needs a reason (where the code comes from), `version`
needs a version and `declared` the name it is declared under. When `files` is given, the decision holds only
while the group still matches exactly those file contents and regions; anything else goes back to the
queue. `apply` drops what was decided to be ours, a coincidence or already declared, corrects versions, and
marks every component still waiting for a decision with bomlens:review=pending, so an unreviewed match is
never silently left out of the SBOM.
"""
import argparse
import collections
import json
import os
import re
import sys
import tarfile

MIN_LINES = 11
MIN_PERCENT = 40.0
MAX_TEXT_CHARS = 400_000   # one file's text in the page
MAX_PAGE_TEXT = 8_000_000  # all file text in the page
MAX_TREE = 5000            # paths in one tree
DECISIONS = ("add", "ours", "coincidence", "declared", "version")

STRINGS = {
    "en": {
        "title": "Source match review", "progress": "To decide: {todo} of {need} left", "auto": "Confirmed by evidence ({n})",
        "ref": "For information ({n})", "need": "Needs a decision", "decided": "Decided", "empty": "The scan found no matches.",
        "add": "Third-party code, add to the SBOM", "ours": "Our own code", "coincidence": "Coincidence", "later": "Later",
        "declared": "Already declared under another name", "version": "Correct the version", "undo": "Undo", "export": "Download decisions",
        "reason": "Reason", "reviewer": "Reviewer", "source_ref": "Where the original code is (repository address or commit)",
        "declared_as": "Name it is declared under", "newver": "Version in use", "save": "Save", "cancel": "Cancel",
        "why_partial": "Part of a file was copied from this source.", "why_split": "Several sources claim the same file.",
        "why_license": "No license was found for this source.", "why_versions": "The files match different versions: {v}",
        "why_ok": "Whole files match one source with a known license.", "why_ref": "Small matches, listed for information only.",
        "source": "Source", "versions": "Versions", "licenses": "Licenses", "files": "Files", "best": "Best match", "unknown": "unknown",
        "excerpt": "Your file", "original": "Original file", "tree_ours": "Your source tree (matched files in bold)", "tree_origin": "Source tree of the original", "region": "Matched region", "prev_region": "Previous region", "next_region": "Next region", "prev_file": "Previous file", "next_file": "Next file", "no_ours": "Give --root to show your own file.", "no_original": "The original is not available offline; use the source address.", "original_lines": "Original lines:", "lines": "lines", "keys": "Keys: 1 add, 2 our own code, 3 coincidence, 4 later, 5 declared elsewhere, 6 correct version, j/k move group, n/p region, [/] file, u undo",
        "left": "{n} still undecided: the download lists only what you decided.",
        "need_reason": "A reason is required.", "need_name": "A name is required.", "need_version": "A version is required.",
        "decision_add": "Added", "decision_ours": "Our own code", "decision_coincidence": "Coincidence", "decision_declared": "Declared elsewhere", "decision_version": "Version corrected",
        "add_reason": "Checked in the review page: the code is third-party",
    },
    "ko": {
        "title": "소스 일치 검토", "progress": "판정 필요 {need}건 중 {todo}건 남음", "auto": "근거로 확정됨 ({n}건)",
        "ref": "참고 표시 ({n}건)", "need": "판정 필요", "decided": "판정함", "empty": "스캔에서 일치한 항목이 없습니다.",
        "add": "외부 코드를 가져옴, SBOM에 추가", "ours": "원본은 우리 쪽", "coincidence": "우연한 일치", "later": "나중에",
        "declared": "이미 선언됨(이름이 다름)", "version": "버전 정정", "undo": "되돌리기", "export": "판정 파일 내려받기",
        "reason": "사유", "reviewer": "검토자", "source_ref": "원본이 있는 곳(저장소 주소나 커밋)",
        "declared_as": "선언된 이름", "newver": "사용 중인 버전", "save": "저장", "cancel": "취소",
        "why_partial": "이 출처의 파일 일부를 가져온 것으로 보입니다.", "why_split": "같은 파일을 여러 출처가 가리킵니다.",
        "why_license": "이 출처의 라이선스를 찾지 못했습니다.", "why_versions": "파일마다 맞는 버전이 다릅니다: {v}",
        "why_ok": "파일 전체가 라이선스가 확인된 한 출처와 일치합니다.", "why_ref": "작은 일치이며 참고로만 보여 줍니다.",
        "source": "출처", "versions": "버전", "licenses": "라이선스", "files": "파일", "best": "가장 높은 일치", "unknown": "알 수 없음",
        "excerpt": "우리 파일", "original": "원본 파일", "tree_ours": "우리 소스 트리(일치한 파일은 굵게)", "tree_origin": "원본의 소스 트리", "region": "일치 구간", "prev_region": "이전 구간", "next_region": "다음 구간", "prev_file": "이전 파일", "next_file": "다음 파일", "no_ours": "우리 파일을 보려면 --root를 지정하세요.", "no_original": "원본은 오프라인으로 볼 수 없습니다. 출처 주소를 확인하세요.", "original_lines": "원본 줄:", "lines": "줄", "keys": "단축키: 1 추가, 2 원본은 우리 쪽, 3 우연한 일치, 4 나중에, 5 다른 이름으로 선언됨, 6 버전 정정, j/k 묶음 이동, n/p 구간, [/] 파일, u 되돌리기",
        "left": "아직 {n}건을 판정하지 않았습니다. 내려받는 파일에는 판정한 것만 들어갑니다.",
        "need_reason": "사유가 필요합니다.", "need_name": "이름이 필요합니다.", "need_version": "버전이 필요합니다.",
        "decision_add": "추가", "decision_ours": "원본은 우리 쪽", "decision_coincidence": "우연한 일치", "decision_declared": "다른 이름으로 선언됨", "decision_version": "버전 정정",
        "add_reason": "검토 화면에서 외부 코드임을 확인함",
    },
}


def percent(value):
    try:
        return float(str(value).rstrip("%"))
    except ValueError:
        return 0.0


def line_count(lines, whole):
    """Number of lines a match covers; a whole-file match (`all`) counts as the file."""
    if lines in ("all", "", None):
        return whole
    total = 0
    for part in str(lines).split(","):
        a, _, b = part.partition("-")
        try:
            total += (int(b) if b else int(a)) - int(a) + 1
        except ValueError:
            pass
    return total


def group_key(m):
    purl = (m.get("purl") or [None])[0]
    return purl or m.get("component") or ""


def groups_of(raw, root=None, origin=None, budget=None):
    """Group the matches of a raw scan by source component and judge each group."""
    by = collections.OrderedDict()
    claimed = collections.defaultdict(set)   # path -> sources that claim it
    for path in sorted(raw):
        for m in raw[path] if isinstance(raw[path], list) else []:
            if not isinstance(m, dict) or m.get("id") not in ("file", "snippet"):
                continue
            key = group_key(m)
            if not key:
                continue
            claimed[path].add(key)
            g = by.setdefault(key, {"key": key, "name": m.get("component") or key, "purl": (m.get("purl") or [""])[0],
                                    "versions": collections.Counter(), "licenses": set(), "files": [], "urls": set()})
            if m.get("version"):
                g["versions"][m["version"]] += 1
            g["licenses"].update(l.get("name") for l in m.get("licenses") or [] if isinstance(l, dict) and l.get("name"))
            if m.get("url"):
                g["urls"].add(m["url"])
            g["files"].append({"path": path, "id": m["id"], "matched": percent(m.get("matched")), "lines": m.get("lines") or "all",
                               "oss_lines": m.get("oss_lines") or "", "hash": m.get("file_hash") or "", "version": m.get("version") or "",
                               "origin_file": m.get("file") or "", "component": m.get("component") or "", "origin_tree": ""})
    out = []
    for g in by.values():
        files = g["files"]
        partial = [f for f in files if f["id"] == "snippet" and (line_count(f["lines"], 0) >= MIN_LINES and f["matched"] >= MIN_PERCENT)]
        small = [f for f in files if f["id"] == "snippet" and f not in partial]
        reasons = []
        if partial:
            reasons.append("partial")
        if any(len(claimed[f["path"]]) > 1 for f in files):
            reasons.append("split")
        if not g["licenses"] and any(f["id"] == "file" for f in files):
            reasons.append("license")
        if len(g["versions"]) > 1:
            reasons.append("versions")
        tier = "decide" if reasons else ("auto" if all(f["id"] == "file" for f in files) else "reference")
        item = {"key": g["key"], "name": g["name"], "purl": g["purl"], "versions": dict(g["versions"].most_common()),
                "licenses": sorted(g["licenses"]), "urls": sorted(g["urls"])[:3], "tier": tier, "reasons": reasons,
                "best": max((f["matched"] for f in files), default=0), "files": files, "small": len(small)}
        budget = budget or Budget(MAX_PAGE_TEXT)
        if root:
            item["ours"] = ours_view(root, files, budget)
        if origin:
            item["origin"] = origin_view(origin, files, budget)
        out.append(item)
    out.sort(key=lambda i: ({"decide": 0, "auto": 1, "reference": 2}[i["tier"]], -len(i["files"]), i["name"].lower()))
    return out


class Budget:
    """Caps how much file text one page carries, so a large scan still yields a page that opens."""
    def __init__(self, total):
        self.left = total

    def take(self, text):
        if self.left <= 0:
            return None
        text = text[:MAX_TEXT_CHARS]
        self.left -= len(text)
        return text


def ours_view(root, files, budget):
    """The scanned source tree (paths) and the full text of each matched file, for the page's left side."""
    base = os.path.realpath(root)
    matched = [f["path"] for f in files]
    tree, seen = list(dict.fromkeys(matched)), set(matched)
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for fn in sorted(filenames):
            rel = os.path.relpath(os.path.join(dirpath, fn), base)
            if rel not in seen and len(tree) < MAX_TREE:
                tree.append(rel); seen.add(rel)
        if len(tree) >= MAX_TREE:
            break
    texts = {}
    for f in files:
        p = os.path.realpath(os.path.join(base, f["path"]))
        if not p.startswith(base + os.sep) or not os.path.isfile(p):   # a path outside the tree is never read
            continue
        try:
            with open(p, "r", errors="replace") as fh:
                t = budget.take(fh.read())
        except OSError:
            continue
        if t is not None:
            texts[f["path"]] = t
    return {"tree": sorted(tree), "texts": texts}


def origin_view(folder, files, budget):
    """The release trees and the full text of each matched original file, read from the sources the base was built from."""
    base = os.path.realpath(folder)
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return {"trees": {}, "texts": {}}
    trees, texts = {}, {}
    wanted = collections.defaultdict(dict)       # tarball name -> {origin path: our path}
    for f in files:
        if not (f["origin_file"] and f["component"] and f["version"]):
            continue
        prefix = f"{f['component']}-{f['version']}".lower()
        name = next((n for n in names if n.lower().startswith(prefix) and re.search(r"\.(tar(\.\w+)?|tgz)$", n)), None)
        if name:
            wanted[name][f["origin_file"]] = f["path"]
            f["origin_tree"] = re.sub(r"\.(tar(\.\w+)?|tgz)$", "", name)
    for name, need in wanted.items():
        key = re.sub(r"\.(tar(\.\w+)?|tgz)$", "", name)
        try:
            with tarfile.open(os.path.join(base, name)) as tf:
                paths = []
                for m in tf:
                    parts = m.name.split("/", 1)
                    if not m.isfile() or len(parts) < 2:
                        continue
                    paths.append(parts[1])
                    if parts[1] in need:
                        t = budget.take(tf.extractfile(m).read().decode("utf8", "replace"))
                        if t is not None:
                            texts[f"{key}:{parts[1]}"] = t
                trees[key] = sorted(paths)[:MAX_TREE]
        except (tarfile.TarError, OSError):
            pass
    return {"trees": trees, "texts": texts}


def covers(decision, group):
    """True when a decision still holds for the group as it is now."""
    if decision.get("component") != group["key"]:
        return False
    pinned = decision.get("files")
    if not pinned:
        return True
    now = sorted((f["hash"], str(f["lines"])) for f in group["files"])
    then = sorted((str(p.get("hash", "")), str(p.get("lines", ""))) for p in pinned if isinstance(p, dict))
    return now == then


def valid(d):
    if not isinstance(d, dict) or d.get("decision") not in DECISIONS or not d.get("component"):
        return False
    need = {"ours": "reason", "version": "version", "declared": "declared_as"}.get(d["decision"])
    return not need or bool(str(d.get(need, "")).strip())


def load_decisions(path):
    if not path or not os.path.isfile(path):
        return []
    try:
        raw = json.load(open(path))
    except (OSError, ValueError) as exc:
        print(f"[snippet-review] WARN: cannot read {path} ({exc}); ignoring it", file=sys.stderr)
        return []
    good = []
    for d in raw if isinstance(raw, list) else []:
        if valid(d):
            good.append(d)
        else:
            print(f"[snippet-review] WARN: skipping a malformed or incomplete decision: {str(d)[:80]}", file=sys.stderr)
    return good


def verdict_of(group, decisions):
    found = None
    for d in decisions:
        if covers(d, group):
            found = d
    return found


PAGE = r"""<!DOCTYPE html>
<html lang="__LANG__">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root { --bg:#fff; --panel:#f6f7f9; --line:#d9dce1; --text:#1d2127; --muted:#5a6270; --accent:#ea002c; --ok:#0b6b3a; --warn:#8a5300; --focus:#1a5fd0; }
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) { --bg:#14171c; --panel:#1c2027; --line:#2e343d; --text:#e8eaee; --muted:#9aa3b0; --accent:#ff5a72; --ok:#5fd394; --warn:#f0b35a; --focus:#7aa7ff; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:15px/1.5 system-ui,-apple-system,"Segoe UI","Noto Sans KR",sans-serif; }
header { padding:20px 24px 12px; border-bottom:1px solid var(--line); display:flex; gap:16px; align-items:baseline; flex-wrap:wrap; }
h1 { font-size:20px; margin:0; font-weight:650; } #progress { margin-left:auto; font-weight:600; }
main { display:grid; grid-template-columns:minmax(220px,300px) minmax(0,1fr); min-height:calc(100vh - 140px); }
nav { border-right:1px solid var(--line); padding:12px 8px; overflow:auto; }
nav h2 { font-size:12px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); margin:14px 10px 6px; font-weight:600; }
nav button { all:unset; display:block; width:calc(100% - 8px); margin:2px 4px; padding:8px 10px; border-radius:8px; cursor:pointer; box-sizing:border-box; }
nav button:hover { background:var(--panel); } nav button[aria-current="true"] { background:var(--panel); outline:2px solid var(--line); }
nav button:focus-visible, .actions button:focus-visible, #export:focus-visible, input:focus-visible, textarea:focus-visible, summary:focus-visible { outline:3px solid var(--focus); outline-offset:1px; }
nav .n { font-weight:600; } nav .s { display:block; font-size:13px; color:var(--muted); }
.tag { display:inline-block; font-size:12px; padding:1px 7px; border-radius:999px; border:1px solid var(--line); margin-left:6px; color:var(--muted); }
.tag.done { color:var(--ok); border-color:var(--ok); } .tag.pending { color:var(--warn); border-color:var(--warn); }
section#detail { padding:20px 24px 60px; min-width:0; } section#detail h2 { margin:0 0 4px; font-size:22px; }
.why { max-width:100%; margin:6px 0 18px; padding:10px 14px; background:var(--panel); border-radius:10px; }
dl { display:grid; grid-template-columns:max-content 1fr; gap:6px 18px; margin:0 0 16px; } dt { color:var(--muted); } dd { margin:0; overflow-wrap:anywhere; }
code, .mono, pre { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:13px; }
table { border-collapse:collapse; width:100%; margin:6px 0 16px; } th, td { text-align:left; padding:5px 8px; border-bottom:1px solid var(--line); } th { color:var(--muted); font-weight:600; font-size:13px; }
div.pair { display:grid; grid-template-columns:minmax(0,1fr) minmax(0,1fr); gap:12px; } .pane { min-width:0; } .cap { color:var(--muted); font-size:13px; margin:4px 0; } .pad { padding:10px; }
.cmp { margin:8px 0 14px; } .trees { display:grid; grid-template-columns:minmax(0,1fr) minmax(0,1fr); gap:12px; margin-bottom:10px; } .trees > div { min-width:0; }
ul.tree, ul.tree ul { list-style:none; margin:0; padding-left:16px; } ul.tree { padding-left:0; max-height:200px; overflow:auto; border:1px solid var(--line); border-radius:8px; padding:6px 8px; }
ul.tree summary { cursor:pointer; color:var(--muted); } ul.tree button.leaf { all:unset; cursor:pointer; padding:1px 6px; border-radius:6px; font:13px ui-monospace,Menlo,monospace; color:var(--muted); } ul.tree button.leaf.hit { color:var(--text); font-weight:600; }
ul.tree button.leaf.sel { background:var(--panel); outline:2px solid var(--accent); } ul.tree button.leaf:disabled { cursor:default; } ul.tree button.leaf:focus-visible { outline:3px solid var(--focus); }
.bar { display:flex; flex-wrap:wrap; gap:10px; align-items:center; justify-content:space-between; margin:6px 0; } .navs button { font:inherit; padding:4px 10px; margin-left:6px; border-radius:8px; border:1px solid var(--line); background:var(--bg); color:var(--text); cursor:pointer; }
.navs kbd { font:12px ui-monospace,Menlo,monospace; border:1px solid var(--line); border-radius:4px; padding:0 5px; margin-right:5px; background:var(--panel); }
.code { height:420px; overflow:auto; border:1px solid var(--line); border-radius:8px; background:var(--panel); font:13px/19px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; } .code:focus-visible { outline:3px solid var(--focus); }
.ln { display:flex; min-height:19px; white-space:pre; } .ln .no { flex:0 0 52px; text-align:right; padding-right:10px; color:var(--muted); user-select:none; } .ln.hit { background:rgba(234,0,44,.13); } .ln.hit .no { color:var(--accent); font-weight:700; }
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) .ln.hit { background:rgba(255,90,114,.18); } }
pre { background:var(--panel); border-radius:8px; padding:10px 12px; overflow:auto; max-height:320px; white-space:pre; margin:6px 0; }
.actions { display:flex; flex-wrap:wrap; gap:10px; margin:20px 0 8px; }
.actions button, #export, .form button { font:inherit; padding:9px 16px; border-radius:10px; border:1px solid var(--line); background:var(--bg); color:var(--text); cursor:pointer; }
.actions button.primary, #export { background:var(--accent); border-color:var(--accent); color:#fff; font-weight:600; }
.actions kbd { font:12px ui-monospace,Menlo,monospace; border:1px solid var(--line); border-radius:4px; padding:0 5px; margin-right:6px; background:var(--panel); color:var(--text); }
.actions button.primary kbd { background:transparent; color:#fff; border-color:#ffffff88; }
.form { margin:12px 0; padding:14px; border:1px solid var(--line); border-radius:12px; } .form label { display:block; margin:8px 0 3px; color:var(--muted); font-size:13px; }
.form input, .form textarea { width:100%; font:inherit; padding:8px 10px; border-radius:8px; border:1px solid var(--line); background:var(--bg); color:var(--text); }
.form .err { color:var(--accent); min-height:1.3em; font-size:13px; } .keys { color:var(--muted); font-size:13px; margin-top:24px; }
footer { position:sticky; bottom:0; padding:12px 24px; background:var(--bg); border-top:1px solid var(--line); display:flex; gap:16px; align-items:center; }
#left { color:var(--muted); font-size:13px; } details.fold summary { cursor:pointer; padding:6px 10px; color:var(--muted); }
@media (max-width:760px) { main { grid-template-columns:1fr; } nav { border-right:0; border-bottom:1px solid var(--line); max-height:40vh; } }
</style>
</head>
<body>
<header><h1>__TITLE__</h1><span id="progress" role="status" aria-live="polite"></span></header>
<main><nav id="queue" aria-label="queue"></nav><section id="detail" tabindex="-1"></section></main>
<footer><button id="export" type="button"></button><span id="left"></span></footer>
<script id="data" type="application/json">__DATA__</script>
<script>
(function () {
  var D = JSON.parse(document.getElementById('data').textContent), T = D.t, items = D.items, key = 'bomlens-snippet-review';
  var decisions = {}, history = [], cur = 0, form = null;
  try { decisions = JSON.parse(localStorage.getItem(key) || '{}'); } catch (e) { decisions = {}; }
  items.forEach(function (i, n) { if (!decisions[n] && D.preset && D.preset[n]) decisions[n] = D.preset[n]; });
  function save() { try { localStorage.setItem(key, JSON.stringify(decisions)); } catch (e) {} }
  function el(tag, attrs, kids) { var n = document.createElement(tag); for (var k in (attrs || {})) { if (k === 'text') n.textContent = attrs[k]; else n.setAttribute(k, attrs[k]); } (kids || []).forEach(function (c) { n.appendChild(c); }); return n; }
  function fmt(s, o) { return s.replace(/\{(\w+)\}/g, function (_, k) { return o[k]; }); }
  function need(i) { return i.tier === 'decide'; }
  function verText(i) { var v = Object.keys(i.versions); return v.length ? (v.length > 1 ? v[0] + ' +' + (v.length - 1) : v[0]) : ''; }
  function why(i) {
    if (i.tier === 'reference') return T.why_ref;
    var out = [];
    if (i.reasons.indexOf('partial') >= 0) out.push(T.why_partial);
    if (i.reasons.indexOf('split') >= 0) out.push(T.why_split);
    if (i.reasons.indexOf('license') >= 0) out.push(T.why_license);
    if (i.reasons.indexOf('versions') >= 0) out.push(fmt(T.why_versions, { v: Object.keys(i.versions).join(', ') }));
    return out.length ? out.join(' ') : T.why_ok;
  }
  function todo() { return items.filter(function (i, n) { return need(i) && !decisions[n]; }).length; }
  function render() {
    var q = document.getElementById('queue'); q.textContent = '';
    document.getElementById('progress').textContent = fmt(T.progress, { need: items.filter(need).length, todo: todo() });
    var left = items.filter(function (i, n) { return need(i) && !decisions[n]; }).length;
    document.getElementById('left').textContent = left ? fmt(T.left, { n: left }) : '';
    q.appendChild(el('h2', { text: T.need }));
    var autoD = el('details', { 'class': 'fold' }); autoD.appendChild(el('summary', { text: fmt(T.auto, { n: items.filter(function (i) { return i.tier === 'auto'; }).length }) }));
    var refD = el('details', { 'class': 'fold' }); refD.appendChild(el('summary', { text: fmt(T.ref, { n: items.filter(function (i) { return i.tier === 'reference'; }).length }) }));
    items.forEach(function (i, n) {
      var done = decisions[n];
      var b = el('button', { type: 'button', 'data-n': n }, [el('span', { 'class': 'n', text: i.name + ' ' + verText(i) })]);
      b.firstChild.appendChild(el('span', { 'class': 'tag ' + (done ? 'done' : (need(i) ? 'pending' : '')), text: done ? T['decision_' + done.decision] : (need(i) ? T.need : '') }));
      b.appendChild(el('span', { 'class': 's', text: i.files.length + ' ' + T.files.toLowerCase() + ', ' + Math.round(i.best) + '%' }));
      if (n === cur) b.setAttribute('aria-current', 'true');
      b.addEventListener('click', function () { cur = n; sel = 0; region = 0; form = null; render(); });
      (need(i) ? q : (i.tier === 'auto' ? autoD : refD)).appendChild(b);
    });
    q.appendChild(autoD); q.appendChild(refD);
    renderDetail();
  }
  function row(dl, k, v) { if (v === '' || v == null) return; dl.appendChild(el('dt', { text: k })); var dd = el('dd'); dd.appendChild(typeof v === 'string' ? document.createTextNode(v) : v); dl.appendChild(dd); }
  var sel = 0, region = 0;
  function regions(spec, total) {
    if (!spec || spec === 'all') return [[1, total]];
    var out = [];
    String(spec).split(',').forEach(function (part) { var m = part.split('-'), a = parseInt(m[0], 10), b = parseInt(m[1] || m[0], 10); if (a > 0 && b >= a) out.push([a, b]); });
    return out.length ? out : [[1, total]];
  }
  function inRegions(n, rs) { for (var k = 0; k < rs.length; k++) if (n >= rs[k][0] && n <= rs[k][1]) return true; return false; }
  function buildTree(paths, mark, picked, onPick) {
    var root = {}; paths.forEach(function (p) { var node = root; p.split('/').forEach(function (seg, k, arr) { node = (node[seg] = node[seg] || (k === arr.length - 1 ? { __f: p } : {})); }); });
    function hasMark(node) { if (node.__f) return !!mark[node.__f]; return Object.keys(node).some(function (k) { return hasMark(node[k]); }); }
    function make(node, name) {
      if (node.__f) {
        var f = node.__f, b = el('button', { type: 'button', 'class': 'leaf' + (mark[f] ? ' hit' : '') + (f === picked ? ' sel' : ''), text: name + (mark[f] ? '  ' + mark[f] : '') });
        if (mark[f]) b.addEventListener('click', function () { onPick(f); }); else b.disabled = true; return el('li', {}, [b]);
      }
      var det = el('details'); if (hasMark(node)) det.setAttribute('open', '');
      det.appendChild(el('summary', { text: name + '/' })); var ul = el('ul');
      Object.keys(node).sort(function (x, y) { var dx = !node[x].__f, dy = !node[y].__f; return dx === dy ? (x < y ? -1 : 1) : (dx ? -1 : 1); }).forEach(function (k) { ul.appendChild(make(node[k], k)); });
      det.appendChild(ul); return el('li', {}, [det]);
    }
    var top = el('ul', { 'class': 'tree' });
    Object.keys(root).sort(function (x, y) { var dx = !root[x].__f, dy = !root[y].__f; return dx === dy ? (x < y ? -1 : 1) : (dx ? -1 : 1); }).forEach(function (k) { top.appendChild(make(root[k], k)); });
    return top;
  }
  function codePane(title, text, rs, id, missing) {
    var wrap = el('div', { 'class': 'pane' }); wrap.appendChild(el('div', { 'class': 'cap', text: title }));
    var box = el('div', { 'class': 'code', id: id, tabindex: '0', role: 'region', 'aria-label': title });
    if (text == null) { box.appendChild(el('p', { 'class': 'cap pad', text: missing })); wrap.appendChild(box); return wrap; }
    var lines = text.split('\n'), frag = document.createDocumentFragment();
    lines.slice(0, 20000).forEach(function (t, k) {
      var hit = inRegions(k + 1, rs);
      frag.appendChild(el('div', { 'class': 'ln' + (hit ? ' hit' : ''), 'data-n': k + 1 }, [el('span', { 'class': 'no', text: String(k + 1) }), el('span', { 'class': 'tx', text: t === '' ? ' ' : t })]));
    });
    box.appendChild(frag); wrap.appendChild(box); return wrap;
  }
  function scrollTo(id, line) { var b = document.getElementById(id); if (b) b.scrollTop = Math.max(0, (line - 1) * 19 - 60); }
  function compare(i) {
    var box = el('div', { 'class': 'cmp' });
    if (sel >= i.files.length) sel = 0;
    var f = i.files[sel], ours = i.ours || {}, ot = ours.texts || {}, org = i.origin || {}, ottexts = org.texts || {};
    var mine = {}, theirs = {};
    i.files.forEach(function (x) { mine[x.path] = Math.round(x.matched) + '%'; if (x.origin_file) theirs[x.origin_file] = Math.round(x.matched) + '%'; });
    var trees = el('div', { 'class': 'trees' });
    var left = el('div'), right = el('div');
    left.appendChild(el('div', { 'class': 'cap', text: T.tree_ours }));
    left.appendChild(buildTree(ours.tree || i.files.map(function (x) { return x.path; }), mine, f.path, function (p) { sel = i.files.findIndex(function (x) { return x.path === p; }); region = 0; renderDetail(); }));
    right.appendChild(el('div', { 'class': 'cap', text: T.tree_origin + (f.origin_tree ? ' (' + f.origin_tree + ')' : '') }));
    var otree = (org.trees || {})[f.origin_tree];
    if (otree) {
      var m2 = {}; i.files.forEach(function (x) { if (x.origin_tree === f.origin_tree && x.origin_file) m2[x.origin_file] = Math.round(x.matched) + '%'; });
      right.appendChild(buildTree(otree, m2, f.origin_file, function (p) { var k = i.files.findIndex(function (x) { return x.origin_tree === f.origin_tree && x.origin_file === p; }); if (k >= 0) { sel = k; region = 0; renderDetail(); } }));
    } else right.appendChild(el('p', { 'class': 'cap', text: T.no_original + (f.origin_file ? ' ' + f.origin_file : '') }));
    trees.appendChild(left); trees.appendChild(right); box.appendChild(trees);
    var myText = ot[f.path], theirText = ottexts[f.origin_tree + ':' + f.origin_file];
    var total = myText == null ? 1 : myText.split('\n').length, otot = theirText == null ? 1 : theirText.split('\n').length;
    var mr = regions(f.lines, total), orr = regions(f.oss_lines, otot);
    if (region >= mr.length) region = 0;
    var bar = el('div', { 'class': 'bar' });
    bar.appendChild(el('span', { 'class': 'mono', text: f.path + '  ' + Math.round(f.matched) + '%  ' + T.lines + ' ' + f.lines + (f.oss_lines ? ' → ' + f.oss_lines : '') }));
    function nav(label, key, delta) { var b = el('button', { type: 'button' }, [el('kbd', { text: key }), document.createTextNode(label)]); b.addEventListener('click', function () { move(i, delta); }); return b; }
    var nb = el('span', { 'class': 'navs' }); nb.appendChild(el('span', { text: T.region + ' ' + (region + 1) + '/' + mr.length + '  ' }));
    nb.appendChild(nav(T.prev_region, 'p', -1)); nb.appendChild(nav(T.next_region, 'n', 1));
    var pf = el('button', { type: 'button' }, [el('kbd', { text: '[' }), document.createTextNode(T.prev_file)]); pf.addEventListener('click', function () { moveFile(i, -1); });
    var nf = el('button', { type: 'button' }, [el('kbd', { text: ']' }), document.createTextNode(T.next_file)]); nf.addEventListener('click', function () { moveFile(i, 1); });
    nb.appendChild(pf); nb.appendChild(nf); bar.appendChild(nb); box.appendChild(bar);
    var pair = el('div', { 'class': 'pair' });
    pair.appendChild(codePane(T.excerpt + ': ' + f.path, myText == null ? null : myText, mr, 'code-mine', T.no_ours));
    pair.appendChild(codePane(T.original + (f.origin_file ? ': ' + f.origin_file : ''), theirText == null ? null : theirText, orr, 'code-orig', T.no_original));
    box.appendChild(pair);
    setTimeout(function () { scrollTo('code-mine', mr[region][0]); scrollTo('code-orig', (orr[region] || orr[0])[0]); }, 0);
    box._rs = { mr: mr, orr: orr }; cmpState = box._rs;
    return box;
  }
  var cmpState = null;
  function move(i, delta) { if (!cmpState) return; var n = cmpState.mr.length; region = (region + delta + n) % n; scrollTo('code-mine', cmpState.mr[region][0]); scrollTo('code-orig', (cmpState.orr[region] || cmpState.orr[0])[0]); renderBar(i); }
  function renderBar(i) { renderDetail(); }
  function moveFile(i, delta) { sel = (sel + delta + i.files.length) % i.files.length; region = 0; renderDetail(); }
  function renderDetail() {
    var d = document.getElementById('detail'); d.textContent = '';
    if (!items.length) { d.appendChild(el('p', { text: T.empty })); return; }
    var i = items[cur], dec = decisions[cur];
    d.appendChild(el('h2', { text: i.name })); d.appendChild(el('div', { 'class': 'why', text: why(i) }));
    var dl = el('dl');
    row(dl, T.source, i.purl || i.name); row(dl, T.versions, Object.keys(i.versions).map(function (v) { return v + ' (' + i.versions[v] + ')'; }).join(', '));
    row(dl, T.licenses, i.licenses.length ? i.licenses.join(', ') : T.unknown); row(dl, T.best, Math.round(i.best) + '%');
    if (i.urls.length) row(dl, 'URL', el('span', { 'class': 'mono', text: i.urls.join('  ') }));
    if (dec) row(dl, T['decision_' + dec.decision], (dec.reason || '') + (dec.version ? ' (' + dec.version + ')' : '') + (dec.declared_as ? ' (' + dec.declared_as + ')' : ''));
    d.appendChild(dl);
    var tb = el('table'), hd = el('tr'); [T.files, '%', T.lines].forEach(function (h) { hd.appendChild(el('th', { text: h })); }); tb.appendChild(hd);
    i.files.slice(0, 200).forEach(function (f) { var r = el('tr'); [f.path, Math.round(f.matched) + '%', f.lines].forEach(function (c, k) { r.appendChild(el('td', { 'class': k === 0 ? 'mono' : '', text: String(c) })); }); tb.appendChild(r); });
    d.appendChild(tb);
    d.appendChild(compare(i));
    var act = el('div', { 'class': 'actions' });
    [['add', 1, true], ['ours', 2], ['coincidence', 3], ['later', 4], ['declared', 5], ['version', 6]].forEach(function (a) {
      var b = el('button', { type: 'button', 'class': a[2] ? 'primary' : '' }, [el('kbd', { text: String(a[1]) }), document.createTextNode(T[a[0]])]);
      b.addEventListener('click', function () { act_(a[0]); }); act.appendChild(b);
    });
    var u = el('button', { type: 'button' }, [el('kbd', { text: 'u' }), document.createTextNode(T.undo)]); u.addEventListener('click', undo); act.appendChild(u);
    d.appendChild(act);
    if (form) d.appendChild(renderForm());
    d.appendChild(el('p', { 'class': 'keys', text: T.keys }));
  }
  function renderForm() {
    var f = el('div', { 'class': 'form', role: 'group', 'aria-label': T[form] });
    if (form === 'declared') { f.appendChild(el('label', { 'for': 'f-name', text: T.declared_as })); f.appendChild(el('input', { id: 'f-name', type: 'text', autocomplete: 'off' })); }
    if (form === 'version') { f.appendChild(el('label', { 'for': 'f-ver', text: T.newver })); f.appendChild(el('input', { id: 'f-ver', type: 'text', autocomplete: 'off' })); }
    f.appendChild(el('label', { 'for': 'f-reason', text: form === 'ours' ? T.source_ref : T.reason })); f.appendChild(el('textarea', { id: 'f-reason', rows: '2' }));
    f.appendChild(el('label', { 'for': 'f-who', text: T.reviewer })); var who = el('input', { id: 'f-who', type: 'text', autocomplete: 'name' });
    try { who.value = localStorage.getItem(key + ':reviewer') || ''; } catch (e) {}
    f.appendChild(who); f.appendChild(el('div', { 'class': 'err', id: 'f-err', 'aria-live': 'assertive' }));
    var ok = el('button', { type: 'button', text: T.save }); ok.addEventListener('click', commit);
    var no = el('button', { type: 'button', text: T.cancel }); no.addEventListener('click', function () { form = null; renderDetail(); });
    f.appendChild(ok); f.appendChild(document.createTextNode(' ')); f.appendChild(no);
    setTimeout(function () { var x = document.getElementById(form === 'declared' ? 'f-name' : (form === 'version' ? 'f-ver' : 'f-reason')); if (x) x.focus(); }, 0);
    return f;
  }
  function record(n, dec) { history.push({ n: n, prev: decisions[n] || null }); decisions[n] = dec; save(); }
  function next() { for (var k = 1; k <= items.length; k++) { var m = (cur + k) % items.length; if (need(items[m]) && !decisions[m]) { cur = m; return; } } }
  function pinned(i) { return i.files.map(function (f) { return { hash: f.hash, lines: String(f.lines) }; }); }
  function who() { try { return localStorage.getItem(key + ':reviewer') || ''; } catch (e) { return ''; } }
  function make(i, kind, reason, extra) { var d = { component: i.key, decision: kind, reason: reason, reviewer: who(), files: pinned(i) }; for (var k in (extra || {})) if (extra[k]) d[k] = extra[k]; return d; }
  function commit() {
    var i = items[cur], reason = document.getElementById('f-reason').value.trim(), w = document.getElementById('f-who').value.trim(), err = document.getElementById('f-err');
    var nm = form === 'declared' ? document.getElementById('f-name').value.trim() : '', ver = form === 'version' ? document.getElementById('f-ver').value.trim() : '';
    if ((form === 'ours' || (form === 'coincidence' && i.files.length >= 5)) && !reason) { err.textContent = T.need_reason; return; }
    if (form === 'declared' && !nm) { err.textContent = T.need_name; return; }
    if (form === 'version' && !ver) { err.textContent = T.need_version; return; }
    try { localStorage.setItem(key + ':reviewer', w); } catch (e) {}
    record(cur, make(i, form, reason, { declared_as: nm, version: ver })); form = null; next(); render();
  }
  function act_(a) {
    if (!items.length) return;
    var i = items[cur];
    if (a === 'add') { record(cur, make(i, 'add', T.add_reason)); next(); render(); }
    else if (a === 'later') { form = null; next(); render(); }
    else { form = a; renderDetail(); }
  }
  function undo() { var h = history.pop(); if (!h) return; if (h.prev) decisions[h.n] = h.prev; else delete decisions[h.n]; save(); cur = h.n; form = null; render(); }
  function exportFile() {
    var out = Object.keys(decisions).map(function (n) { return decisions[n]; });
    var blob = new Blob([JSON.stringify(out, null, 2) + '\n'], { type: 'application/json' });
    var a = el('a', { href: URL.createObjectURL(blob), download: 'snippet-decisions.json' }); document.body.appendChild(a); a.click(); a.remove();
  }
  document.getElementById('export').textContent = T.export; document.getElementById('export').addEventListener('click', exportFile);
  document.addEventListener('keydown', function (e) {
    var tag = (e.target.tagName || '').toLowerCase();
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && form) { commit(); return; }
    if (e.key === 'Escape' && form) { form = null; renderDetail(); return; }
    if (tag === 'input' || tag === 'textarea' || e.ctrlKey || e.metaKey || e.altKey || !items.length) return;
    var k = e.key;
    if (k === 'j' || k === 'ArrowDown') { cur = (cur + 1) % items.length; sel = 0; region = 0; form = null; render(); e.preventDefault(); }
    else if (k === 'k' || k === 'ArrowUp') { cur = (cur - 1 + items.length) % items.length; sel = 0; region = 0; form = null; render(); e.preventDefault(); }
    else if (k === 'n') { move(items[cur], 1); } else if (k === 'p') { move(items[cur], -1); } else if (k === ']') { moveFile(items[cur], 1); } else if (k === '[') { moveFile(items[cur], -1); }
    else if (k === '1') act_('add'); else if (k === '2') { act_('ours'); e.preventDefault(); } else if (k === '3') { act_('coincidence'); e.preventDefault(); }
    else if (k === '4') act_('later'); else if (k === '5') { act_('declared'); e.preventDefault(); } else if (k === '6') { act_('version'); e.preventDefault(); }
    else if (k === 'u') undo();
  });
  render();
})();
</script>
</body>
</html>
"""


def read_raw(path):
    try:
        raw = json.load(open(path))
    except (OSError, ValueError) as exc:
        print(f"[snippet-review] cannot read {path}: {exc}", file=sys.stderr)
        return None
    return raw if isinstance(raw, dict) else None


def cmd_page(args):
    raw = read_raw(args.raw)
    if raw is None:
        return 1
    items = groups_of(raw, args.root, args.origin, Budget(MAX_PAGE_TEXT))
    done = load_decisions(args.decisions)
    t = STRINGS[args.lang]
    # '</' is escaped so the data can never close the script element it sits in.
    data = json.dumps({"t": t, "items": items, "preset": [verdict_of(i, done) for i in items]}, ensure_ascii=False).replace("</", "<\\/")
    sys.stdout.write(PAGE.replace("__LANG__", args.lang).replace("__TITLE__", t["title"]).replace("__DATA__", data))
    print(f"[snippet-review] {len(items)} group(s), {sum(1 for i in items if i['tier'] == 'decide')} to decide.", file=sys.stderr)
    return 0


def cmd_queue(args):
    raw = read_raw(args.raw)
    if raw is None:
        return 1
    done = load_decisions(args.decisions)
    pending = [i for i in groups_of(raw) if i["tier"] == "decide" and not verdict_of(i, done)]
    for i in pending:
        print(f"{i['key']}\t{len(i['files'])} file(s)\t{','.join(i['reasons'])}")
    print(f"[snippet-review] {len(pending)} group(s) waiting for a decision.", file=sys.stderr)
    return 0


def cmd_apply(args):
    try:
        comps = json.load(open(args.components))
    except (OSError, ValueError) as exc:
        print(f"[snippet-review] cannot read {args.components}: {exc}", file=sys.stderr)
        return 1
    raw = read_raw(args.raw)
    groups = {g["key"]: g for g in groups_of(raw)} if raw else {}
    done = load_decisions(args.decisions)
    kept, dropped, pending = [], 0, 0
    for c in comps if isinstance(comps, list) else []:
        props = {p.get("name"): p.get("value") for p in c.get("properties") or []}
        key = props.get("bomlens:scanoss:purl") or c.get("purl") or c.get("name")
        g = groups.get(key) or groups.get(c.get("name")) or {"key": key, "files": [], "tier": "auto"}
        d = verdict_of(g, done)
        if d and d["decision"] in ("ours", "coincidence", "declared"):
            dropped += 1
            print(f"[snippet-review] {c.get('name')}: left out ({d['decision']}): {d.get('reason') or d.get('declared_as', '')}", file=sys.stderr)
            continue
        c = dict(c)
        c["properties"] = list(c.get("properties") or [])
        if d:
            if d["decision"] == "version":
                c["version"] = str(d["version"]).strip()
                c["properties"].append({"name": "bomlens:versionBasis", "value": "review"})
            c["properties"].append({"name": "bomlens:review", "value": f"{d['decision']}: {d.get('reason', '')}".strip()})
        elif g["tier"] == "decide":
            pending += 1
            c["properties"].append({"name": "bomlens:review", "value": "pending"})
        kept.append(c)
    print(json.dumps(kept, ensure_ascii=False))
    print(f"[snippet-review] {len(kept)} component(s) kept, {dropped} left out by review, {pending} waiting for a decision.", file=sys.stderr)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("page"); p.add_argument("raw"); p.add_argument("--lang", choices=sorted(STRINGS), default="en")
    p.add_argument("--root"); p.add_argument("--origin"); p.add_argument("--decisions"); p.set_defaults(fn=cmd_page)
    q = sub.add_parser("queue"); q.add_argument("raw"); q.add_argument("--decisions"); q.set_defaults(fn=cmd_queue)
    a = sub.add_parser("apply"); a.add_argument("components"); a.add_argument("raw"); a.add_argument("decisions"); a.set_defaults(fn=cmd_apply)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
