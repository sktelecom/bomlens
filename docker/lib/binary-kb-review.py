#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Write a self-contained review page for what a binary knowledge base found.

Usage: binary-kb-review.py <Project>_<Version>_bom.json [--lang en|ko] [--decisions file.json] > review.html

The page lists every component the knowledge base identified (bomlens:identifiedBy = binary-kb) as a
queue. The ones a person has to decide come first: no single version fits, the version may be newer than
the base knows, or only constant tables matched. The rest are listed as confirmed by evidence, folded
away but never hidden. For each one the page shows the evidence a person can check against the file (the
matched strings, the score, the files and their hash) and takes a decision from the keyboard:

  1 confirm   2 exclude   3 correct the version   4 later      j/k or arrows move      u undo

`exclude` and a version correction ask for a reason. The decisions are downloaded as a JSON list that
`scan-sbom.sh --kb-decisions` reads; an entry carries the hash of the evidence file, so a file that
changed goes back to review. The page needs no server and loads nothing from the network. Decisions
are also kept in the browser's local storage while the page is open, so a closed tab loses nothing.
"""
import argparse
import json
import sys

STRINGS = {
    "en": {
        "title": "Binary knowledge base review", "progress": "To decide: {todo} of {need} left", "auto": "Confirmed by evidence ({n})",
        "need": "Needs a decision", "decided": "Decided", "later": "Later", "empty": "Nothing was identified by the knowledge base.",
        "confirm": "Confirm", "exclude": "Exclude", "version": "Correct version", "skip": "Later", "undo": "Undo", "export": "Download decisions",
        "reason": "Reason", "reviewer": "Reviewer", "newver": "Version shipped", "save": "Save", "cancel": "Cancel",
        "why_range": "No single release fits. Candidates: {c}", "why_newer": "The newest release the base has. The shipped version may be newer.",
        "why_tables": "Found by constant tables only, no version.", "why_ok": "One release fits the strings found.",
        "evidence": "Evidence", "files": "Found in", "strings": "Longest matched strings", "score": "Score", "unique": "Strings only this component has",
        "tables": "Constant tables", "release": "Knowledge base release", "sha": "Evidence file SHA-256", "keys": "Keys: 1 confirm, 2 exclude, 3 correct version, 4 later, j/k move, u undo",
        "left": "{n} still undecided: the download lists only what you decided.", "version_label": "Version", "none": "none",
        "confirm_reason": "Evidence checked in the review page", "need_reason": "A reason is required.", "need_version": "A version is required.",
        "decision_confirm": "Confirmed", "decision_exclude": "Excluded", "decision_version": "Version corrected",
    },
    "ko": {
        "title": "바이너리 지식 베이스 검토", "progress": "판정 필요 {need}건 중 {todo}건 남음", "auto": "근거로 확정됨 ({n}건)",
        "need": "판정 필요", "decided": "판정함", "later": "나중에", "empty": "지식 베이스가 식별한 컴포넌트가 없습니다.",
        "confirm": "맞음", "exclude": "아님(제외)", "version": "버전 정정", "skip": "나중에", "undo": "되돌리기", "export": "판정 파일 내려받기",
        "reason": "사유", "reviewer": "검토자", "newver": "실제 버전", "save": "저장", "cancel": "취소",
        "why_range": "맞는 릴리스가 하나로 정해지지 않습니다. 후보: {c}", "why_newer": "베이스가 가진 가장 새 릴리스입니다. 실제 버전은 더 새것일 수 있습니다.",
        "why_tables": "상수 테이블로만 찾았고 버전이 없습니다.", "why_ok": "찾은 문자열에 맞는 릴리스가 하나입니다.",
        "evidence": "근거", "files": "찾은 위치", "strings": "맞은 문자열(긴 순)", "score": "점수", "unique": "이 컴포넌트에만 있는 문자열",
        "tables": "상수 테이블", "release": "지식 베이스 릴리스", "sha": "근거 파일 SHA-256", "keys": "단축키: 1 맞음, 2 제외, 3 버전 정정, 4 나중에, j/k 이동, u 되돌리기",
        "left": "아직 {n}건을 판정하지 않았습니다. 내려받는 파일에는 판정한 것만 들어갑니다.", "version_label": "버전", "none": "없음",
        "confirm_reason": "검토 화면에서 근거를 확인함", "need_reason": "사유가 필요합니다.", "need_version": "버전이 필요합니다.",
        "decision_confirm": "맞음", "decision_exclude": "제외", "decision_version": "버전 정정",
    },
}


def items_of(bom):
    out = []
    for c in bom.get("components") or []:
        props = {p.get("name"): p.get("value") for p in c.get("properties") or []}
        if props.get("bomlens:identifiedBy") != "binary-kb" and "bomlens:kbRelease" not in props:
            continue
        try:
            sample = json.loads(props.get("bomlens:kbEvidenceStrings", "[]"))
        except ValueError:
            sample = []
        cands = [x for x in props.get("bomlens:versionCandidates", "").split(",") if x]
        reasons = []
        if not c.get("version") and cands:
            reasons.append("range")
        if props.get("bomlens:versionMayBeNewer") == "true":
            reasons.append("newer")
        if not c.get("version") and not cands:
            reasons.append("tables")
        out.append({
            "name": c.get("name", ""), "version": c.get("version", ""), "candidates": cands, "reasons": reasons,
            "score": props.get("bomlens:kbScore", ""), "unique": props.get("bomlens:kbUniqueStrings", ""),
            "tables": props.get("bomlens:kbTables", ""), "release": props.get("bomlens:kbRelease", ""),
            "files": [o.get("location", "") for o in (c.get("evidence") or {}).get("occurrences") or []],
            "sha": props.get("bomlens:kbEvidenceSha256", ""), "strings": sample,
            "reviewed": props.get("bomlens:review", ""),
        })
    out.sort(key=lambda i: (not i["reasons"], i["name"].lower()))
    return out


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
h1 { font-size:20px; margin:0; font-weight:650; }
#project { color:var(--muted); }
#progress { margin-left:auto; font-weight:600; }
main { display:grid; grid-template-columns:minmax(240px,320px) 1fr; min-height:calc(100vh - 140px); }
nav { border-right:1px solid var(--line); padding:12px 8px; overflow:auto; }
nav h2 { font-size:12px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); margin:14px 10px 6px; font-weight:600; }
nav button { all:unset; display:block; width:calc(100% - 8px); margin:2px 4px; padding:8px 10px; border-radius:8px; cursor:pointer; box-sizing:border-box; }
nav button:hover { background:var(--panel); }
nav button[aria-current="true"] { background:var(--panel); outline:2px solid var(--line); }
nav button:focus-visible, .actions button:focus-visible, #export:focus-visible, input:focus-visible, textarea:focus-visible, summary:focus-visible { outline:3px solid var(--focus); outline-offset:1px; }
nav .n { font-weight:600; } nav .s { display:block; font-size:13px; color:var(--muted); }
.tag { display:inline-block; font-size:12px; padding:1px 7px; border-radius:999px; border:1px solid var(--line); margin-left:6px; color:var(--muted); }
.tag.done { color:var(--ok); border-color:var(--ok); } .tag.pending { color:var(--warn); border-color:var(--warn); }
section#detail { padding:20px 28px 60px; max-width:900px; }
section#detail h2 { margin:0 0 4px; font-size:22px; }
.why { margin:6px 0 18px; padding:10px 14px; background:var(--panel); border-radius:10px; }
dl { display:grid; grid-template-columns:max-content 1fr; gap:6px 18px; margin:0 0 16px; }
dt { color:var(--muted); } dd { margin:0; overflow-wrap:anywhere; }
code, .mono { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:13px; }
ul.strings { list-style:none; padding:0; margin:6px 0 16px; } ul.strings li { padding:4px 8px; background:var(--panel); border-radius:6px; margin:3px 0; overflow-wrap:anywhere; }
.actions { display:flex; flex-wrap:wrap; gap:10px; margin:20px 0 8px; }
.actions button, #export, .form button { font:inherit; padding:9px 16px; border-radius:10px; border:1px solid var(--line); background:var(--bg); color:var(--text); cursor:pointer; }
.actions button.primary, #export { background:var(--accent); border-color:var(--accent); color:#fff; font-weight:600; }
.actions kbd { font:12px ui-monospace,Menlo,monospace; border:1px solid var(--line); border-radius:4px; padding:0 5px; margin-right:6px; background:var(--panel); color:var(--text); }
.actions button.primary kbd { background:transparent; color:#fff; border-color:#ffffff88; }
.form { margin:12px 0; padding:14px; border:1px solid var(--line); border-radius:12px; } .form label { display:block; margin:8px 0 3px; color:var(--muted); font-size:13px; }
.form input, .form textarea { width:100%; font:inherit; padding:8px 10px; border-radius:8px; border:1px solid var(--line); background:var(--bg); color:var(--text); }
.form .err { color:var(--accent); min-height:1.3em; font-size:13px; }
.keys { color:var(--muted); font-size:13px; margin-top:24px; }
footer { position:sticky; bottom:0; padding:12px 24px; background:var(--bg); border-top:1px solid var(--line); display:flex; gap:16px; align-items:center; }
#left { color:var(--muted); font-size:13px; }
details.auto summary { cursor:pointer; padding:6px 10px; color:var(--muted); }
@media (max-width:760px) { main { grid-template-columns:1fr; } nav { border-right:0; border-bottom:1px solid var(--line); max-height:40vh; } }
</style>
</head>
<body>
<header><h1>__TITLE__</h1><span id="project"></span><span id="progress" role="status" aria-live="polite"></span></header>
<main><nav id="queue" aria-label="queue"></nav><section id="detail" tabindex="-1"></section></main>
<footer><button id="export" type="button"></button><span id="left"></span></footer>
<script id="data" type="application/json">__DATA__</script>
<script>
(function () {
  var D = JSON.parse(document.getElementById('data').textContent), T = D.t, items = D.items, key = 'bomlens-kb-review:' + D.project;
  var decisions = {}, history = [], cur = 0, form = null;
  try { decisions = JSON.parse(localStorage.getItem(key) || '{}'); } catch (e) { decisions = {}; }
  function save() { try { localStorage.setItem(key, JSON.stringify(decisions)); } catch (e) {} }
  function el(tag, attrs, kids) { var n = document.createElement(tag); for (var k in (attrs || {})) { if (k === 'text') n.textContent = attrs[k]; else n.setAttribute(k, attrs[k]); } (kids || []).forEach(function (c) { n.appendChild(c); }); return n; }
  function fmt(s, o) { return s.replace(/\{(\w+)\}/g, function (_, k) { return o[k]; }); }
  function need(i) { return i.reasons.length > 0; }
  function whyText(i) {
    var out = [];
    if (i.reasons.indexOf('range') >= 0) out.push(fmt(T.why_range, { c: i.candidates.join(', ') }));
    if (i.reasons.indexOf('newer') >= 0) out.push(T.why_newer);
    if (i.reasons.indexOf('tables') >= 0) out.push(T.why_tables);
    return out.length ? out.join(' ') : T.why_ok;
  }
  function verText(i) { return i.version || (i.candidates.length ? i.candidates[0] + '..' + i.candidates[i.candidates.length - 1] : T.none); }
  function order() { return items.map(function (_, n) { return n; }); }
  function todo() { return items.filter(function (i, n) { return need(i) && !decisions[n] && !i.reviewed; }).length; }
  function render() {
    var q = document.getElementById('queue'); q.textContent = '';
    var needN = items.filter(need).length;
    document.getElementById('progress').textContent = fmt(T.progress, { need: needN, todo: todo() });
    document.getElementById('project').textContent = D.project;
    var left = items.filter(function (i, n) { return !decisions[n]; }).length;
    document.getElementById('left').textContent = left ? fmt(T.left, { n: left }) : '';
    var sec1 = el('h2', { text: T.need }); q.appendChild(sec1);
    var det = el('details', { 'class': 'auto' }); det.appendChild(el('summary', { text: fmt(T.auto, { n: items.filter(function (i) { return !need(i); }).length }) }));
    items.forEach(function (i, n) {
      var done = decisions[n] || i.reviewed;
      var b = el('button', { type: 'button', 'data-n': n }, [el('span', { 'class': 'n', text: i.name + ' ' + verText(i) })]);
      var sub = el('span', { 'class': 'tag ' + (done ? 'done' : (need(i) ? 'pending' : '')), text: done ? (decisions[n] ? T['decision_' + decisions[n].decision] : i.reviewed.split(':')[0]) : (need(i) ? T.need : T.why_ok.split('.')[0]) });
      b.firstChild.appendChild(sub);
      if (n === cur) b.setAttribute('aria-current', 'true');
      b.addEventListener('click', function () { cur = n; form = null; render(); });
      (need(i) ? q : det).appendChild(b);
    });
    q.appendChild(det);
    renderDetail();
  }
  function row(dl, k, v) { if (v === '' || v == null) return; dl.appendChild(el('dt', { text: k })); var dd = el('dd'); dd.appendChild(typeof v === 'string' ? document.createTextNode(v) : v); dl.appendChild(dd); }
  function renderDetail() {
    var d = document.getElementById('detail'); d.textContent = '';
    if (!items.length) { d.appendChild(el('p', { text: T.empty })); return; }
    var i = items[cur], dec = decisions[cur];
    d.appendChild(el('h2', { text: i.name }));
    d.appendChild(el('div', { 'class': 'why', text: whyText(i) }));
    var dl = el('dl');
    row(dl, T.version_label, verText(i)); row(dl, T.score, i.score); row(dl, T.unique, i.unique); row(dl, T.tables, i.tables); row(dl, T.release, i.release);
    row(dl, T.sha, i.sha ? el('span', { 'class': 'mono', text: i.sha }) : '');
    if (dec) row(dl, T['decision_' + dec.decision], dec.reason + (dec.version ? ' (' + dec.version + ')' : ''));
    else if (i.reviewed) row(dl, T.decided, i.reviewed);
    d.appendChild(dl);
    if (i.files.length) { d.appendChild(el('h3', { text: T.files })); var ul = el('ul', { 'class': 'strings' }); i.files.forEach(function (f) { ul.appendChild(el('li', { 'class': 'mono', text: f })); }); d.appendChild(ul); }
    if (i.strings.length) { d.appendChild(el('h3', { text: T.strings })); var us = el('ul', { 'class': 'strings' }); i.strings.forEach(function (s) { us.appendChild(el('li', { 'class': 'mono', text: s })); }); d.appendChild(us); }
    var act = el('div', { 'class': 'actions' });
    [['confirm', 1, true], ['exclude', 2], ['version', 3], ['skip', 4]].forEach(function (a) {
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
    if (form === 'version') { f.appendChild(el('label', { 'for': 'f-ver', text: T.newver })); f.appendChild(el('input', { id: 'f-ver', type: 'text', autocomplete: 'off' })); }
    f.appendChild(el('label', { 'for': 'f-reason', text: T.reason })); f.appendChild(el('textarea', { id: 'f-reason', rows: '2' }));
    f.appendChild(el('label', { 'for': 'f-who', text: T.reviewer })); var who = el('input', { id: 'f-who', type: 'text', autocomplete: 'name' });
    try { who.value = localStorage.getItem('bomlens-kb-review:reviewer') || ''; } catch (e) {}
    f.appendChild(who); var err = el('div', { 'class': 'err', id: 'f-err', 'aria-live': 'assertive' }); f.appendChild(err);
    var ok = el('button', { type: 'button', text: T.save }); ok.addEventListener('click', commit);
    var no = el('button', { type: 'button', text: T.cancel }); no.addEventListener('click', function () { form = null; renderDetail(); });
    f.appendChild(ok); f.appendChild(document.createTextNode(' ')); f.appendChild(no);
    setTimeout(function () { var x = document.getElementById(form === 'version' ? 'f-ver' : 'f-reason'); if (x) x.focus(); }, 0);
    return f;
  }
  function record(n, dec) { history.push({ n: n, prev: decisions[n] || null }); decisions[n] = dec; save(); }
  function next() { for (var k = 1; k <= items.length; k++) { var m = (cur + k) % items.length; if (!decisions[m] && !items[m].reviewed) { cur = m; return; } } }
  function commit() {
    var i = items[cur], reason = document.getElementById('f-reason').value.trim(), who = document.getElementById('f-who').value.trim(), err = document.getElementById('f-err');
    var ver = form === 'version' ? document.getElementById('f-ver').value.trim() : '';
    if (!reason) { err.textContent = T.need_reason; return; }
    if (form === 'version' && !ver) { err.textContent = T.need_version; return; }
    try { localStorage.setItem('bomlens-kb-review:reviewer', who); } catch (e) {}
    var dec = { component: i.name, decision: form, reason: reason, reviewer: who }; if (ver) dec.version = ver; if (i.sha) dec.evidence_sha256 = i.sha;
    record(cur, dec); form = null; next(); render();
  }
  function act_(a) {
    if (!items.length) return;
    var i = items[cur];
    if (a === 'confirm') { var dec = { component: i.name, decision: 'confirm', reason: T.confirm_reason, reviewer: (function () { try { return localStorage.getItem('bomlens-kb-review:reviewer') || ''; } catch (e) { return ''; } })() }; if (i.sha) dec.evidence_sha256 = i.sha; record(cur, dec); next(); render(); }
    else if (a === 'exclude' || a === 'version') { form = a; renderDetail(); }
    else { form = null; next(); render(); }
  }
  function undo() { var h = history.pop(); if (!h) return; if (h.prev) decisions[h.n] = h.prev; else delete decisions[h.n]; save(); cur = h.n; form = null; render(); }
  function exportFile() {
    var out = Object.keys(decisions).map(function (n) { return decisions[n]; });
    var blob = new Blob([JSON.stringify(out, null, 2) + '\n'], { type: 'application/json' });
    var a = el('a', { href: URL.createObjectURL(blob), download: 'kb-decisions.json' }); document.body.appendChild(a); a.click(); a.remove();
  }
  document.getElementById('export').textContent = T.export;
  document.getElementById('export').addEventListener('click', exportFile);
  document.addEventListener('keydown', function (e) {
    var tag = (e.target.tagName || '').toLowerCase();
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && form) { commit(); return; }
    if (e.key === 'Escape' && form) { form = null; renderDetail(); return; }
    if (tag === 'input' || tag === 'textarea' || e.ctrlKey || e.metaKey || e.altKey || !items.length) return;
    var k = e.key;
    if (k === 'j' || k === 'ArrowDown') { cur = (cur + 1) % items.length; form = null; render(); e.preventDefault(); }
    else if (k === 'k' || k === 'ArrowUp') { cur = (cur - 1 + items.length) % items.length; form = null; render(); e.preventDefault(); }
    else if (k === '1') act_('confirm'); else if (k === '2') { act_('exclude'); e.preventDefault(); } else if (k === '3') { act_('version'); e.preventDefault(); } else if (k === '4') act_('skip');
    else if (k === 'u') undo();
  });
  render();
})();
</script>
</body>
</html>
"""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("bom"); ap.add_argument("--lang", choices=sorted(STRINGS), default="en")
    ap.add_argument("--decisions", help="a decisions file from an earlier review; its entries start as decided")
    args = ap.parse_args(argv)
    try:
        bom = json.load(open(args.bom))
    except (OSError, ValueError) as exc:
        print(f"[binary-kb-review] cannot read {args.bom}: {exc}", file=sys.stderr)
        return 1
    items = items_of(bom)
    meta = (bom.get("metadata") or {}).get("component") or {}
    project = f"{meta.get('name', '')} {meta.get('version', '')}".strip()
    t = STRINGS[args.lang]
    # '</' is escaped so the data can never close the script element it sits in.
    data = json.dumps({"t": t, "items": items, "project": project}, ensure_ascii=False).replace("</", "<\\/")
    sys.stdout.write(PAGE.replace("__LANG__", args.lang).replace("__TITLE__", t["title"]).replace("__DATA__", data))
    print(f"[binary-kb-review] {len(items)} component(s), {sum(1 for i in items if i['reasons'])} to decide.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
