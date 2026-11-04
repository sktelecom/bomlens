#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Review what a source-code match scan found: a queue page, a pending list, and the decisions applied.

Usage:
  snippet-review.py page  <scan-raw.json> [--lang en|ko] [--root <source dir>] [--origin <release sources dir>] [--decisions file.json] > review.html
  snippet-review.py queue <scan-raw.json> [--decisions file.json]
  snippet-review.py apply <components.json> <scan-raw.json> <decisions.json> [--root <source dir>] > components.json

<scan-raw.json> is the raw result of a match scan: an object keyed by file path whose values are lists of
matches ({"id": "file" | "snippet" | "none", "matched": "87%", "lines": "10-52", "oss_lines": "100-142",
"purl": [...], "component": "...", "version": "...", "licenses": [{"name": "..."}], "file_hash": "...", ...}).

With --root the page shows the user's own matched lines. With --origin, a folder holding the release sources
the knowledge base was built from (tarballs named <component>-<version>*), it shows the original lines next to
them. A scan against a public service sends only hashes, so there the original is just the address and the
line numbers the service returned.

Matches are grouped by the component they came from, so one decision covers every file of the group.
Each group lands in one of three tiers:

  auto       every file is a whole-file match from one source with a known license that carries no
             copyleft obligation
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
import hashlib
import json
import os
import re
import sys
import tarfile

MIN_LINES = 11       # a partial copy shorter than this is shown for information only
MIN_PERCENT = 40.0   # ... unless it covers this share of the file
BIG_LINES = 50       # ... or is this long, however large the file: a long copy inside a big file still counts
MAX_TEXT_CHARS = 400_000   # one file's text in the page
MAX_PAGE_TEXT = 8_000_000  # all file text in the page
MAX_TREE = 5000            # paths in one tree
DECISIONS = ("add", "ours", "coincidence", "declared", "version", "origin")
CLASS_RANK = {"unknown": 0, "permissive": 1, "weak": 2, "strong": 3}

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
        "why_copyleft": "The license of this source carries a copyleft obligation. The scan names one best match per file and may point to a copy of the code in another project: confirm the source is the one the code was taken from.", "why_ok": "Whole files match one source with a known license.", "why_ref": "Small matches, listed for information only.",
        "source": "Source", "versions": "Versions", "licenses": "Licenses", "files": "Files", "best": "Best match", "unknown": "unknown",
        "excerpt": "Your file", "original": "Original file", "tree_ours": "Your source tree (matched files in bold)", "tree_origin": "Source tree of the original", "region": "Matched region", "prev_region": "Previous region", "next_region": "Next region", "prev_file": "Previous file", "next_file": "Next file", "no_ours": "Give --root to show your own file.", "no_original": "The original is not available offline; use the source address.", "original_lines": "Original lines:", "lines": "lines", "keys": "Keys: 1 add, 2 our own code, 3 coincidence, 4 later, 5 declared elsewhere, 6 correct version, j/k move group, n/p region, [/] file, u undo",
        "left": "{n} still undecided: the download lists only what you decided.",
        "need_reason": "A reason is required.", "need_name": "A name is required.", "need_version": "A version is required.",
        "decision_add": "Added", "decision_ours": "Our own code", "decision_coincidence": "Coincidence", "decision_declared": "Declared elsewhere", "decision_version": "Version corrected",
        "add_reason": "Checked in the review page: the code is third-party",
        "why_contest": "Several sources match the same lines of this file. Pick the one the code was taken from.", "why_differs": "The candidates carry different license obligations: the choice changes what you must do, so give the reason.", "contest_tag": "[same code]", "keys_contest": "Keys: 1-9 pick the source the code was taken from, o our own code, x coincidence, l later, n/p region, [/] candidate, j/k move, u undo", "candidates": "Candidates", "origin_is": "Taken from", "origin_reason": "Why this source (for example the header, the version, or where the supplier says it came from)", "decision_origin": "Origin chosen",
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
        "why_copyleft": "이 출처의 라이선스는 복제 의무(copyleft)를 담고 있습니다. 스캔은 파일마다 가장 가까운 일치 하나만 알려 주므로 같은 코드를 담은 다른 프로젝트를 가리킬 수 있습니다. 코드를 가져온 출처가 맞는지 확인하세요.", "why_ok": "파일 전체가 라이선스가 확인된 한 출처와 일치합니다.", "why_ref": "작은 일치이며 참고로만 보여 줍니다.",
        "source": "출처", "versions": "버전", "licenses": "라이선스", "files": "파일", "best": "가장 높은 일치", "unknown": "알 수 없음",
        "excerpt": "우리 파일", "original": "원본 파일", "tree_ours": "우리 소스 트리(일치한 파일은 굵게)", "tree_origin": "원본의 소스 트리", "region": "일치 구간", "prev_region": "이전 구간", "next_region": "다음 구간", "prev_file": "이전 파일", "next_file": "다음 파일", "no_ours": "우리 파일을 보려면 --root를 지정하세요.", "no_original": "원본은 오프라인으로 볼 수 없습니다. 출처 주소를 확인하세요.", "original_lines": "원본 줄:", "lines": "줄", "keys": "단축키: 1 추가, 2 원본은 우리 쪽, 3 우연한 일치, 4 나중에, 5 다른 이름으로 선언됨, 6 버전 정정, j/k 묶음 이동, n/p 구간, [/] 파일, u 되돌리기",
        "left": "아직 {n}건을 판정하지 않았습니다. 내려받는 파일에는 판정한 것만 들어갑니다.",
        "need_reason": "사유가 필요합니다.", "need_name": "이름이 필요합니다.", "need_version": "버전이 필요합니다.",
        "decision_add": "추가", "decision_ours": "원본은 우리 쪽", "decision_coincidence": "우연한 일치", "decision_declared": "다른 이름으로 선언됨", "decision_version": "버전 정정",
        "add_reason": "검토 화면에서 외부 코드임을 확인함",
        "why_contest": "같은 줄을 여러 출처가 가리킵니다. 이 코드를 가져온 출처를 고르세요.", "why_differs": "후보의 라이선스 의무가 서로 다릅니다. 무엇을 골랐는지에 따라 지켜야 할 의무가 달라지므로 사유를 적어야 합니다.", "contest_tag": "[같은 코드]", "keys_contest": "단축키: 1~9 코드를 가져온 출처 선택, o 원본은 우리 쪽, x 우연한 일치, l 나중에, n/p 구간, [/] 후보, j/k 이동, u 되돌리기", "candidates": "후보", "origin_is": "가져온 곳:", "origin_reason": "이 출처로 본 이유(예: 파일 머리말, 버전, 공급사가 밝힌 출처)", "decision_origin": "원본 출처 선택",
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


def name_key(m):
    """What identify-vendored.sh groups by: the component name in lower case."""
    purl = (m.get("purl") or [""])[0]
    return (m.get("component") or re.sub(r"^pkg:[^/]+/", "", purl)).lower()


def license_class(names):
    """strong, weak, permissive or unknown for a set of license names; the strictest one wins."""
    best = "unknown"
    for n in names:
        u = str(n).upper()
        if re.search(r"LGPL|MPL|EPL|CDDL|CLASSPATH|GCC-EXCEPTION|LINKING-EXCEPTION", u):
            c = "weak"
        elif re.search(r"GPL|SSPL|EUPL|OSL", u):
            c = "strong"
        elif re.search(r"MIT|BSD|APACHE|ISC|ZLIB|UNLICENSE|CC0|PYTHON|OPENSSL|BOOST|BSL|X11|WTFPL", u):
            c = "permissive"
        else:
            continue
        if CLASS_RANK[c] > CLASS_RANK[best]:
            best = c
    return best


def parse_regions(spec):
    """[(first, last)] of a line spec such as `10-60,100-190`; `all` covers the whole file."""
    if not spec or spec == "all":
        return [(1, 10 ** 9)]
    out = []
    for part in str(spec).split(","):
        a, _, b = part.partition("-")
        try:
            lo, hi = int(a), int(b or a)
        except ValueError:
            continue
        if 0 < lo <= hi:
            out.append((lo, hi))
    return out or [(1, 10 ** 9)]


def overlap(r1, r2):
    return any(a1 <= b2 and a2 <= b1 for a1, b1 in r1 for a2, b2 in r2)


def read_local(root, rel):
    """Bytes of one of the user's files, or None. A path that leaves the tree is never read."""
    base = os.path.realpath(root)
    p = os.path.realpath(os.path.join(base, rel))
    if not p.startswith(base + os.sep) or not os.path.isfile(p):
        return None
    try:
        with open(p, "rb") as fh:
            return fh.read(16_000_000)
    except OSError:
        return None


def local_keys(root, f):
    """Hash of the user's file and of the matched lines, so a decision follows the content, not the path or the scan."""
    data = read_local(root, f["path"]) if root else None
    if data is None:
        base = f.get("source_hash") or f.get("hash") or ""
        return base, f"{base}:{f['lines']}"
    lines = data.decode("utf8", "replace").splitlines()
    region = "\n".join("\n".join(lines[a - 1:b]) for a, b in parse_regions(f["lines"]))
    return hashlib.sha256(data).hexdigest(), hashlib.sha256(region.encode()).hexdigest()


def groups_of(raw, root=None, origin=None, budget=None):
    """Group the matches of a raw scan by source component and judge each group.

    Returns groups and contests. A contest is one file whose matched lines overlap between two or more
    sources: the sources compete for the same code, so a person picks the origin instead of approving each.
    Sources that match different regions of one file are a combination, not a contest.
    """
    budget = budget or Budget(MAX_PAGE_TEXT)
    by = collections.OrderedDict()
    per_path = collections.defaultdict(list)
    for path in sorted(raw):
        for m in raw[path] if isinstance(raw[path], list) else []:
            if not isinstance(m, dict) or m.get("id") not in ("file", "snippet"):
                continue
            nk = name_key(m)
            if not nk:
                continue
            g = by.setdefault(nk, {"name": m.get("component") or nk, "purls": collections.Counter(), "versions": collections.Counter(),
                                   "licenses": set(), "files": [], "urls": set()})
            if m.get("purl"):
                g["purls"][m["purl"][0]] += 1
            if m.get("version"):
                g["versions"][m["version"]] += 1
            lic = [l.get("name") for l in m.get("licenses") or [] if isinstance(l, dict) and l.get("name")]
            g["licenses"].update(lic)
            if m.get("url"):
                g["urls"].add(m["url"])
            f = {"path": path, "id": m["id"], "matched": percent(m.get("matched")), "lines": m.get("lines") or "all",
                 "oss_lines": m.get("oss_lines") or "", "hash": m.get("file_hash") or "", "source_hash": m.get("source_hash") or "",
                 "version": m.get("version") or "", "origin_file": m.get("file") or "", "component": m.get("component") or "",
                 "origin_tree": "", "name_key": nk, "licenses": lic, "class": license_class(lic),
                 "purl": (m.get("purl") or [""])[0]}
            f["file_hash"], f["rkey"] = local_keys(root, f)
            # The scan's own hash of the user's file (source_hash, an MD5) plus the lines: a second key that
            # needs no --root, so a decision made on a page built with --root still matches an apply without it.
            f["akey"] = f"{f['source_hash']}:{f['lines']}" if f["source_hash"] else ""
            g["files"].append(f)
            per_path[path].append(f)

    # contests: files whose matched regions overlap between different sources
    contested = set()
    contests = []
    for path, fs in per_path.items():
        parent = list(range(len(fs)))
        def find(i):
            while parent[i] != i:
                parent[i] = parent[parent[i]]; i = parent[i]
            return i
        for i in range(len(fs)):
            for j in range(i + 1, len(fs)):
                if fs[i]["name_key"] != fs[j]["name_key"] and overlap(parse_regions(fs[i]["lines"]), parse_regions(fs[j]["lines"])):
                    parent[find(i)] = find(j)
        clusters = collections.defaultdict(list)
        for i in range(len(fs)):
            clusters[find(i)].append(fs[i])
        for members in clusters.values():
            if len({m["name_key"] for m in members}) < 2:
                continue
            for m in members:
                contested.add(id(m))
            cid = hashlib.sha256("|".join(sorted({m["rkey"] for m in members})).encode()).hexdigest()[:24]
            classes = sorted({m["class"] for m in members})
            c = {"kind": "contest", "key": "contest:" + cid, "name": path, "purl": "", "versions": {}, "licenses": [], "urls": [],
                 "tier": "decide", "reasons": ["contest"], "best": max(m["matched"] for m in members), "small": 0,
                 "files": sorted(members, key=lambda m: (-m["matched"], m["name_key"])), "classes": classes,
                 "differs": len(classes) > 1}
            if root:
                c["ours"] = ours_view(root, c["files"][:1], budget)
            if origin:
                c["origin"] = origin_view(origin, c["files"], budget)
            contests.append(c)

    out = []
    for nk, g in by.items():
        files = [f for f in g["files"] if id(f) not in contested]
        key = g["purls"].most_common(1)[0][0] if g["purls"] else nk
        small = [f for f in files if f["id"] == "snippet" and line_count(f["lines"], 0) < MIN_LINES]
        big = [f for f in files if f["id"] == "snippet" and (line_count(f["lines"], 0) >= BIG_LINES or
                                                              (line_count(f["lines"], 0) >= MIN_LINES and f["matched"] >= MIN_PERCENT))]
        small_total = sum(line_count(f["lines"], 0) for f in files if f["id"] == "snippet")
        reasons = []
        if big or (files and small_total >= BIG_LINES and any(f["id"] == "snippet" for f in files)):
            reasons.append("partial")
        if not g["licenses"] and any(f["id"] == "file" for f in files):
            reasons.append("license")
        if len(g["versions"]) > 1:
            reasons.append("versions")
        if license_class(g["licenses"]) in ("strong", "weak"):
            reasons.append("copyleft")     # a match that carries a copyleft obligation is never settled without a person
        if not files:
            continue    # every file of this source is in a contest; the contests carry the decision
        tier = "decide" if reasons else ("auto" if all(f["id"] == "file" for f in files) else "reference")
        item = {"kind": "group", "key": key, "name": g["name"], "name_key": nk, "purl": key if key.startswith("pkg:") else "",
                "versions": dict(g["versions"].most_common()), "licenses": sorted(g["licenses"]), "urls": sorted(g["urls"])[:3],
                "tier": tier, "reasons": reasons, "best": max((f["matched"] for f in files), default=0), "files": files, "small": len(small),
                "class": license_class(g["licenses"])}
        if root:
            item["ours"] = ours_view(root, files, budget)
        if origin:
            item["origin"] = origin_view(origin, files, budget)
        out.append(item)
    out.extend(contests)
    out.sort(key=lambda i: ({"decide": 0, "auto": 1, "reference": 2}[i["tier"]], i["kind"] != "contest", -len(i["files"]), i["name"].lower()))
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
        # the name must end right after the version (libfoo-1.2 is not libfoo-1.2.10)
        name = next((n for n in names if re.match(re.escape(prefix) + r"([._-](src|source|orig|dfsg)[\w.+-]*)?\.(tar(\.\w+)?|tgz)$", n.lower())), None)
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


def covers(d, item):
    """True when a decision still holds for the group or contest as it is now."""
    if item.get("kind") == "contest":
        if d.get("contest") != item["key"]:
            return False
        if d["decision"] != "origin":
            return True
        cands = {(c["purl"] or c["name_key"]): c for c in item["files"]}
        choice = d.get("choice")
        if choice not in cands:
            return False                                   # the chosen source is no longer a candidate
        known = {choice} | {o.get("purl") for o in d.get("others") or [] if isinstance(o, dict)}
        for k, c in cands.items():
            if k not in known and c["class"] != cands[choice]["class"]:
                return False                               # a new candidate with a different obligation: ask again
        return True
    if d.get("component") != item["key"]:
        return False
    pinned = d.get("files")
    if not pinned:
        return True
    entries = [p for p in pinned if isinstance(p, dict)]
    if sorted(f["rkey"] for f in item["files"]) == sorted(str(p.get("key", "")) for p in entries):
        return True
    alts = [f["akey"] for f in item["files"]]
    return all(alts) and sorted(alts) == sorted(str(p.get("alt", "")) for p in entries)


def valid(d):
    if not isinstance(d, dict) or d.get("decision") not in DECISIONS:
        return False
    if d["decision"] == "origin":
        return bool(d.get("contest")) and bool(str(d.get("choice", "")).strip()) and bool(str(d.get("reason", "")).strip())
    if d.get("decision") in ("ours", "coincidence") and d.get("contest"):
        return d["decision"] != "ours" or bool(str(d.get("reason", "")).strip())
    if not d.get("component"):
        return False
    need = {"ours": "reason", "version": "version", "declared": "declared_as", "add": "reason"}.get(d["decision"])
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


def verdict_of(item, decisions):
    hits = [d for d in decisions if covers(d, item)]
    if len({(d["decision"], d.get("choice", ""), d.get("version", "")) for d in hits}) > 1:
        print(f"[snippet-review] WARN: {item['key']} has conflicting decisions; the last one is used", file=sys.stderr)
    return hits[-1] if hits else None


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
.cands tr.sel td { background:var(--panel); font-weight:600; } .cands tr { cursor:pointer; } .cands td { overflow-wrap:anywhere; }
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
  var D = JSON.parse(document.getElementById('data').textContent), T = D.t, items = D.items, key = 'bomlens-snippet-review:' + D.id, rkey = 'bomlens-snippet-review:reviewer';
  var decisions = {}, history = [], cur = 0, form = null;
  try { decisions = JSON.parse(localStorage.getItem(key) || '{}'); } catch (e) { decisions = {}; }
  items.forEach(function (i, n) { if (!decisions[n] && D.preset && D.preset[n]) decisions[n] = D.preset[n]; });
  function save() { try { localStorage.setItem(key, JSON.stringify(decisions)); } catch (e) {} }
  function el(tag, attrs, kids) { var n = document.createElement(tag); for (var k in (attrs || {})) { if (k === 'text') n.textContent = attrs[k]; else n.setAttribute(k, attrs[k]); } (kids || []).forEach(function (c) { n.appendChild(c); }); return n; }
  function fmt(s, o) { return s.replace(/\{(\w+)\}/g, function (_, k) { return o[k]; }); }
  function need(i) { return i.tier === 'decide'; }
  function verText(i) { var v = Object.keys(i.versions); return v.length ? (v.length > 1 ? v[0] + ' +' + (v.length - 1) : v[0]) : ''; }
  function why(i) {
    if (i.kind === 'contest') return T.why_contest + (i.differs ? ' ' + T.why_differs : '');
    if (i.tier === 'reference') return T.why_ref;
    var out = [];
    if (i.reasons.indexOf('partial') >= 0) out.push(T.why_partial);
    if (i.reasons.indexOf('split') >= 0) out.push(T.why_split);
    if (i.reasons.indexOf('license') >= 0) out.push(T.why_license);
    if (i.reasons.indexOf('versions') >= 0) out.push(fmt(T.why_versions, { v: Object.keys(i.versions).join(', ') }));
    if (i.reasons.indexOf('copyleft') >= 0) out.push(T.why_copyleft);
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
      var b = el('button', { type: 'button', 'data-n': n }, [el('span', { 'class': 'n', text: (i.kind === 'contest' ? T.contest_tag + ' ' : '') + i.name + ' ' + verText(i) })]);
      b.firstChild.appendChild(el('span', { 'class': 'tag ' + (done ? 'done' : (need(i) ? 'pending' : '')), text: done ? (T['decision_' + done.decision] || done.decision) : (need(i) ? T.need : '') }));
      b.appendChild(el('span', { 'class': 's', text: i.kind === 'contest' ? i.files.length + ' ' + T.candidates.toLowerCase() : i.files.length + ' ' + T.files.toLowerCase() + ', ' + Math.round(i.best) + '%' }));
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
    i.files.forEach(function (x) { mine[x.path] = Math.max(parseInt(mine[x.path] || '0', 10), Math.round(x.matched)) + '%'; if (x.origin_file) theirs[x.origin_file] = Math.round(x.matched) + '%'; });
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
  function candidateTable(i) {
    var tb = el('table', { 'class': 'cands' }), hd = el('tr');
    ['#', T.source, T.versions, T.licenses, '%', T.lines].forEach(function (h) { hd.appendChild(el('th', { text: h })); }); tb.appendChild(hd);
    i.files.forEach(function (c, n) {
      var r = el('tr', n === sel ? { 'class': 'sel', 'aria-current': 'true' } : {});
      [String(n + 1), c.purl || c.component, c.version, (c.licenses.join(', ') || T.unknown) + ' [' + c.class + ']', Math.round(c.matched) + '%', c.lines + (c.oss_lines ? ' → ' + c.oss_lines : '')].forEach(function (x) { r.appendChild(el('td', { text: x })); });
      r.addEventListener('click', function () { sel = n; region = 0; renderDetail(); }); tb.appendChild(r);
    });
    return tb;
  }
  function chooseOrigin(n) { if (n >= items[cur].files.length) return; sel = n; form = 'origin'; renderDetail(); }
  function renderDetail() {
    var d = document.getElementById('detail'); d.textContent = '';
    if (!items.length) { d.appendChild(el('p', { text: T.empty })); return; }
    var i = items[cur], dec = decisions[cur];
    d.appendChild(el('h2', { text: i.name })); d.appendChild(el('div', { 'class': 'why', text: why(i) }));
    if (i.kind !== 'contest') {
    var dl = el('dl');
    row(dl, T.source, i.purl || i.name); row(dl, T.versions, Object.keys(i.versions).map(function (v) { return v + ' (' + i.versions[v] + ')'; }).join(', '));
    row(dl, T.licenses, i.licenses.length ? i.licenses.join(', ') : T.unknown); row(dl, T.best, Math.round(i.best) + '%');
    if (i.urls.length) row(dl, 'URL', el('span', { 'class': 'mono', text: i.urls.join('  ') }));
    if (dec) row(dl, T['decision_' + dec.decision] || dec.decision, (dec.reason || '') + (dec.choice ? ' (' + dec.choice + ')' : '') + (dec.version ? ' (' + dec.version + ')' : '') + (dec.declared_as ? ' (' + dec.declared_as + ')' : ''));
    d.appendChild(dl);
    var tb = el('table'), hd = el('tr'); [T.files, '%', T.lines].forEach(function (h) { hd.appendChild(el('th', { text: h })); }); tb.appendChild(hd);
    i.files.slice(0, 200).forEach(function (f) { var r = el('tr'); [f.path, Math.round(f.matched) + '%', f.lines].forEach(function (c, k) { r.appendChild(el('td', { 'class': k === 0 ? 'mono' : '', text: String(c) })); }); tb.appendChild(r); });
    d.appendChild(tb);
    }
    if (i.kind === 'contest') d.appendChild(candidateTable(i));
    d.appendChild(compare(i));
    var act = el('div', { 'class': 'actions' });
    if (i.kind === 'contest') {
      i.files.slice(0, 9).forEach(function (c, n) {
        var b = el('button', { type: 'button', 'class': n === sel ? 'primary' : '' }, [el('kbd', { text: String(n + 1) }), document.createTextNode(T.origin_is + ' ' + c.component + ' ' + c.version)]);
        b.addEventListener('click', function () { chooseOrigin(n); }); act.appendChild(b);
      });
      [['ours', 'o'], ['coincidence', 'x'], ['later', 'l']].forEach(function (a) {
        var b = el('button', { type: 'button' }, [el('kbd', { text: a[1] }), document.createTextNode(T[a[0]])]); b.addEventListener('click', function () { act_(a[0]); }); act.appendChild(b);
      });
    } else
    [['add', 1, true], ['ours', 2], ['coincidence', 3], ['later', 4], ['declared', 5], ['version', 6]].forEach(function (a) {
      var b = el('button', { type: 'button', 'class': a[2] ? 'primary' : '' }, [el('kbd', { text: String(a[1]) }), document.createTextNode(T[a[0]])]);
      b.addEventListener('click', function () { act_(a[0]); }); act.appendChild(b);
    });
    var u = el('button', { type: 'button' }, [el('kbd', { text: 'u' }), document.createTextNode(T.undo)]); u.addEventListener('click', undo); act.appendChild(u);
    d.appendChild(act);
    if (form) d.appendChild(renderForm());
    d.appendChild(el('p', { 'class': 'keys', text: i.kind === 'contest' ? T.keys_contest : T.keys }));
  }
  function renderForm() {
    var f = el('div', { 'class': 'form', role: 'group', 'aria-label': T[form] });
    if (form === 'declared') { f.appendChild(el('label', { 'for': 'f-name', text: T.declared_as })); f.appendChild(el('input', { id: 'f-name', type: 'text', autocomplete: 'off' })); }
    if (form === 'version') { f.appendChild(el('label', { 'for': 'f-ver', text: T.newver })); f.appendChild(el('input', { id: 'f-ver', type: 'text', autocomplete: 'off' })); }
    f.appendChild(el('label', { 'for': 'f-reason', text: form === 'ours' ? T.source_ref : (form === 'origin' ? T.origin_reason : T.reason) })); f.appendChild(el('textarea', { id: 'f-reason', rows: '2' }));
    f.appendChild(el('label', { 'for': 'f-who', text: T.reviewer })); var who = el('input', { id: 'f-who', type: 'text', autocomplete: 'name' });
    try { who.value = localStorage.getItem(rkey) || ''; } catch (e) {}
    f.appendChild(who); f.appendChild(el('div', { 'class': 'err', id: 'f-err', 'aria-live': 'assertive' }));
    var ok = el('button', { type: 'button', text: T.save }); ok.addEventListener('click', commit);
    var no = el('button', { type: 'button', text: T.cancel }); no.addEventListener('click', function () { form = null; renderDetail(); });
    f.appendChild(ok); f.appendChild(document.createTextNode(' ')); f.appendChild(no);
    setTimeout(function () { var x = document.getElementById(form === 'declared' ? 'f-name' : (form === 'version' ? 'f-ver' : 'f-reason')); if (x) x.focus(); }, 0);
    return f;
  }
  function record(n, dec) { history.push({ n: n, prev: decisions[n] || null }); decisions[n] = dec; save(); }
  function next() { for (var k = 1; k <= items.length; k++) { var m = (cur + k) % items.length; if (need(items[m]) && !decisions[m]) { cur = m; return; } } }
  function pinned(i) { return i.files.map(function (f) { return { key: f.rkey, alt: f.akey }; }); }
  function who() { try { return localStorage.getItem(rkey) || ''; } catch (e) { return ''; } }
  function make(i, kind, reason, extra) { var d = { component: i.key, decision: kind, reason: reason, reviewer: who(), files: pinned(i) }; for (var k in (extra || {})) if (extra[k]) d[k] = extra[k]; return d; }
  function commit() {
    var i = items[cur], reason = document.getElementById('f-reason').value.trim(), w = document.getElementById('f-who').value.trim(), err = document.getElementById('f-err');
    var nm = form === 'declared' ? document.getElementById('f-name').value.trim() : '', ver = form === 'version' ? document.getElementById('f-ver').value.trim() : '';
    if ((form === 'ours' || form === 'origin' || (form === 'coincidence' && i.files.length >= 5 && i.kind !== 'contest')) && !reason) { err.textContent = T.need_reason; return; }
    if (form === 'declared' && !nm) { err.textContent = T.need_name; return; }
    if (form === 'version' && !ver) { err.textContent = T.need_version; return; }
    try { localStorage.setItem(rkey, w); } catch (e) {}
    if (i.kind === 'contest') {
      var d2 = { contest: i.key, decision: form, reason: reason, reviewer: w, files: pinned(i) };
      if (form === 'origin') {
        var win = i.files[sel], classes = { unknown: 0, permissive: 1, weak: 2, strong: 3 };
        d2.choice = win.purl || win.name_key; d2.version = win.version; d2.component = d2.choice;
        d2.others = i.files.filter(function (c, n) { return n !== sel; }).map(function (c) { return { purl: c.purl || c.name_key, version: c.version, license: c.licenses.join(', ') }; });
        if (i.files.some(function (c) { return classes[c['class']] > classes[win['class']]; })) d2.needs_sample = true;
      }
      record(cur, d2); form = null; next(); render(); return;
    }
    record(cur, make(i, form, reason, { declared_as: nm, version: ver })); form = null; next(); render();
  }
  function commitNow() { var i = items[cur], d2 = { contest: i.key, decision: 'coincidence', reason: '', reviewer: who(), files: pinned(i) }; record(cur, d2); form = null; next(); render(); }
  function act_(a) {
    if (!items.length) return;
    var i = items[cur];
    if (a === 'add' && i.kind !== 'contest') { record(cur, make(i, 'add', T.add_reason)); next(); render(); }
    else if (a === 'later') { form = null; next(); render(); }
    else if (a === 'coincidence' && i.kind === 'contest') { form = a; commitNow(); }
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
    else if (items[cur].kind === 'contest' && /^[1-9]$/.test(k)) { chooseOrigin(parseInt(k, 10) - 1); e.preventDefault(); }
    else if (items[cur].kind === 'contest' && k === 'o') { act_('ours'); e.preventDefault(); } else if (items[cur].kind === 'contest' && k === 'x') { act_('coincidence'); } else if (items[cur].kind === 'contest' && k === 'l') { act_('later'); }
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
    ident = hashlib.sha256("|".join(sorted(i["key"] + ":" + ",".join(sorted(f["rkey"] for f in i["files"])) for i in items)).encode()).hexdigest()[:16]
    data = json.dumps({"t": t, "id": ident, "items": items, "preset": [verdict_of(i, done) for i in items]}, ensure_ascii=False).replace("</", "<\\/")
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
        print(f"{i['key']}\t{i['kind']}\t{len(i['files'])} file(s)\t{','.join(i['reasons'])}")
    print(f"[snippet-review] {len(pending)} item(s) waiting for a decision.", file=sys.stderr)
    return 0


def component_of(item, review):
    """A component for a source a person accepted although the scan's own list did not carry it."""
    vers = item.get("versions") or {}
    props = [{"name": "bomlens:layer", "value": "vendored"}, {"name": "bomlens:identifiedBy", "value": "scanoss"},
             {"name": "bomlens:scanoss:files", "value": str(len(item["files"]))},
             {"name": "bomlens:scanoss:match", "value": f"{int(item['best'])}%"},
             {"name": "bomlens:scanoss:purl", "value": item["key"] if item["key"].startswith("pkg:") else ""},
             {"name": "bomlens:evidenceGrade", "value": "reviewed-match"}, {"name": "bomlens:review", "value": review}]
    c = {"type": "library", "name": item["name"], "version": next(iter(vers), ""), "purl": item["purl"] or None,
         "licenses": [{"license": {"name": n}} for n in item.get("licenses") or []],
         "properties": [p for p in props if p["value"]]}
    return {k: v for k, v in c.items() if v not in (None, "", [])}


def cmd_apply(args):
    try:
        comps = json.load(open(args.components))
    except (OSError, ValueError) as exc:
        print(f"[snippet-review] cannot read {args.components}: {exc}", file=sys.stderr)
        return 1
    raw = read_raw(args.raw) or {}
    items = groups_of(raw, args.root)
    groups = {i["name_key"]: i for i in items if i["kind"] == "group"}
    done = load_decisions(args.decisions)
    chosen_names, rejected, support, also, pending_contest = set(), set(), collections.Counter(), collections.defaultdict(list), set()
    for c in (i for i in items if i["kind"] == "contest"):
        v = verdict_of(c, done)
        cands = {(f["purl"] or f["name_key"]): f for f in c["files"]}
        if v is None:
            for f in c["files"]:
                support[f["name_key"]] += 1; pending_contest.add(f["name_key"])
        elif v["decision"] == "origin":
            win = cands[v["choice"]]
            support[win["name_key"]] += 1; chosen_names.add(win["name_key"])
            for k, f in cands.items():
                if f is not win:
                    also[win["name_key"]].append(f"{f['purl'] or f['name_key']}@{f['version']} ({f['class']})")
                    if f["class"] != "unknown" and CLASS_RANK[win["class"]] < CLASS_RANK[f["class"]]:
                        print(f"[snippet-review] {c['name']}: origin {win['name_key']} ({win['class']}) is weaker than candidate {f['name_key']} ({f['class']}); sample it", file=sys.stderr)
        # ours / coincidence: no candidate is supported by this file
    contest_names = {f["name_key"] for c in items if c["kind"] == "contest" for f in c["files"]}
    kept, dropped, pending = [], 0, 0
    seen = set()
    for comp in comps if isinstance(comps, list) else []:
        props = {p.get("name"): p.get("value") for p in comp.get("properties") or []}
        nk = str(comp.get("name", "")).lower()
        g = groups.get(nk)
        seen.add(nk)
        d = verdict_of(g, done) if g else None
        if d and d["decision"] in ("ours", "coincidence", "declared"):
            dropped += 1
            print(f"[snippet-review] {comp.get('name')}: left out ({d['decision']}): {d.get('reason') or d.get('declared_as', '')}", file=sys.stderr)
            continue
        if g:
            own = len(g["files"]) + support[nk]
        elif nk in contest_names:
            own = support[nk]            # every file of this source is in a contest, so only a win keeps it
        else:
            own = 1
        if own == 0:
            dropped += 1
            print(f"[snippet-review] {comp.get('name')}: left out (every file of it went to another source or was ruled out)", file=sys.stderr)
            continue
        comp = dict(comp)
        comp["properties"] = list(comp.get("properties") or [])
        if d:
            if d["decision"] == "version":
                comp["version"] = str(d["version"]).strip()
                comp["properties"].append({"name": "bomlens:versionBasis", "value": "review"})
            comp["properties"].append({"name": "bomlens:review", "value": f"{d['decision']}: {d.get('reason', '')}".strip()})
        elif g and g["tier"] == "decide":
            pending += 1
            comp["properties"].append({"name": "bomlens:review", "value": "pending"})
        if nk in pending_contest:
            comp["properties"].append({"name": "bomlens:contested", "value": "pending"})
            if not any(p["name"] == "bomlens:review" for p in comp["properties"]):
                pending += 1
                comp["properties"].append({"name": "bomlens:review", "value": "pending"})
        for a in also.get(nk, []):
            comp["properties"].append({"name": "bomlens:alsoMatched", "value": a})
        kept.append(comp)
    # accepted sources the scan's own list did not carry: a partial copy, or the origin chosen in a contest
    for nk, g in groups.items():
        d = verdict_of(g, done)
        if nk not in seen and d and d["decision"] == "add":
            kept.append(component_of(g, f"add: {d.get('reason', '')}"))
    for nk in chosen_names - seen:
        f = next(f for c in items if c["kind"] == "contest" for f in c["files"] if f["name_key"] == nk)
        item = groups.get(nk) or {"key": f["purl"] or nk, "name": f["component"] or nk, "purl": f["purl"], "versions": {f["version"]: 1} if f["version"] else {},
                                  "licenses": f["licenses"], "files": [f], "best": f["matched"]}
        comp = component_of(item, "origin: chosen in review")
        comp["properties"].extend({"name": "bomlens:alsoMatched", "value": a} for a in also.get(nk, []))
        kept.append(comp)
    print(json.dumps(kept, ensure_ascii=False))
    print(f"[snippet-review] {len(kept)} component(s) kept, {dropped} left out by review, {pending} waiting for a decision.", file=sys.stderr)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("page"); p.add_argument("raw"); p.add_argument("--lang", choices=sorted(STRINGS), default="en")
    p.add_argument("--root"); p.add_argument("--origin"); p.add_argument("--decisions"); p.set_defaults(fn=cmd_page)
    q = sub.add_parser("queue"); q.add_argument("raw"); q.add_argument("--decisions"); q.set_defaults(fn=cmd_queue)
    a = sub.add_parser("apply"); a.add_argument("components"); a.add_argument("raw"); a.add_argument("decisions"); a.add_argument("--root"); a.set_defaults(fn=cmd_apply)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
