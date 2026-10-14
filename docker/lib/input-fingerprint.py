#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# input-fingerprint.py - the input fingerprint of a source scan's stage 1.
#
# Called by input-fingerprint.sh (make-plan.sh for the execution plan, and
# entrypoint.sh for the result manifest of a POSTPROCESS run). Prints one JSON
# object: algorithm, sha256 (null when the result is not reusable), reusable,
# reasons, components. Documented in the input fingerprint section of
# docs/reference/engine-contract.md.
#
# The rule throughout: when in doubt, not reusable. A reuse that is missed
# costs one stage 1 run; a reuse that should not have happened gives a wrong
# SBOM. So every check below says "reusable" only for a case it can prove.
#
# Stage 1 runs `cdxgen -r` with no type filter, and cdxgen reads far more kinds
# of file than a list here could keep up with (its own config files, archives,
# installed package metadata, minified scripts, build files of many tools). So
# the whole tree is hashed: every file except under .git/, as one "tree"
# component. An identical tree can still give a different stage 1 result when a
# resolver asks the registry again; the checks after that look for those cases,
# on the manifests a scan resolves (the folders source_manifests in
# source-detect.sh skips are skipped here too).
#
# Usage: input-fingerprint.py --src DIR --ecosystem LANG --manifest-re RE
#   [--non-shipped-dirs "a b"] [--image NAME=DIGEST] [--engine-file NAME=PATH]
#   [--engine-sha NAME=HEX] [--setting NAME=VALUE] [--unsupported]
#   [--stage1-missing-reason REASON]

import argparse
import functools
import hashlib
import json
import os
import re
import stat
import sys
import time

ALGORITHM = "bomlens-input-1"

NOT_MANIFEST_RE = re.compile(r"(^|/)(METADATA|PKG-INFO)$")
REQUIREMENTS_RE = re.compile(r"(^|/)([^/]*requirements[^/]*\.txt|requirements/[^/]+\.txt)$", re.I)
JUDGE_PRUNE = {".git", "node_modules", "vendor", ".venv", "site-packages"}

NODE_LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb")
PY_LOCKS = ("poetry.lock", "uv.lock", "Pipfile.lock")


def sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def sha256_text(value):
    return hashlib.sha256(value.encode("utf-8", "surrogateescape")).hexdigest()


# The checks read at most this much of a file. A larger manifest, lock file or
# Go source cannot be judged and makes the value unhashable-input; it is still
# hashed in full, in a stream.
READ_CAP = 4 << 20
OVERSIZED = object()


def read_text(path):
    """The text of a regular file for the checks, opened without blocking and
    re-checked as a regular file, at most READ_CAP bytes. None when it cannot
    be read or is not a regular file, OVERSIZED when it is larger."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        chunks, size = [], 0
        while size <= READ_CAP:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > READ_CAP:
            return OVERSIZED
        return b"".join(chunks).decode("utf-8", "replace")
    except OSError:
        return None
    finally:
        os.close(fd)


def parent_dir(rel):
    return rel.rsplit("/", 1)[0] if "/" in rel else ""


def join(d, name):
    return f"{d}/{name}" if d else name


def ancestors(d):
    """The folders above d, nearest first, ending with the root ("")."""
    out = []
    while d:
        d = parent_dir(d)
        out.append(d)
    return out


def glob_re(pattern):
    """A workspace glob (*, **, ?) as a regular expression over a folder path."""
    pattern = pattern.strip().strip("'\"")
    while pattern.startswith("./"):
        pattern = pattern[2:]
    pattern = pattern.rstrip("/")
    parts = []
    for seg in pattern.split("/"):
        if seg == "**":
            parts.append(None)
            continue
        rx = ""
        for ch in seg:
            rx += "[^/]*" if ch == "*" else "[^/]" if ch == "?" else re.escape(ch)
        parts.append(rx)
    rx = ""
    for i, p in enumerate(parts):
        if p is None:
            rx += "(?:[^/]+/)*" if i < len(parts) - 1 else ".*"
        else:
            rx += p + ("/" if i < len(parts) - 1 else "")
    return re.compile("^" + rx + "$")


def matches(patterns, path):
    """True when path matches a pattern and no later "!" pattern excludes it."""
    hit = False
    for pat in patterns:
        if not isinstance(pat, str) or not pat.strip():
            continue
        if pat.startswith("!"):
            if hit and glob_re(pat[1:]).match(path):
                hit = False
        elif glob_re(pat).match(path):
            hit = True
    return hit


class Budget(Exception):
    """The walk went over BOMLENS_FINGERPRINT_MAX_FILES or the time limit."""


def env_int(name, default):
    try:
        v = int(os.environ.get(name, ""))
        return v if v > 0 else default
    except ValueError:
        return default


def go_ignored(rel):
    """The go tool leaves out testdata, vendor and names starting with . or _."""
    return any(seg == "testdata" or seg == "vendor" or seg[:1] in "._" for seg in rel.split("/"))


class Tree:
    """One walk of the source. Every file except any file or folder named .git
    is hashed into the tree value; the manifests a scan resolves are kept for
    the checks."""

    def __init__(self, src, manifest_re, judge_prune, exclude_dir=""):
        self.src = src
        self.real = os.path.realpath(src)
        self.manifest_re = manifest_re
        self.judge_prune = judge_prune
        self.exclude_dir = exclude_dir
        self.names = set()          # every regular file and file link, relative
        self.hashes = {}            # relative path -> (mode, sha256 or None)
        self.unhashable = []        # paths that could not be hashed
        self.truncated = False      # stopped at the file count or time limit
        self.judged = []            # manifests the general checks look at
        # Resolved from the root whatever a scan leaves out, so judged over
        # the whole tree: Maven reactor modules, Gradle included projects, and
        # Go modules and packages (go itself leaves out testdata, vendor and
        # names starting with . or _).
        self.poms, self.go_mods, self.go_files, self.gradle_files = [], [], [], []
        self.dotnet_props = []
        self.folders = 0
        self.unanalysable = set()   # files over READ_CAP the checks could not read
        self._texts = {}
        self.max_files = env_int("BOMLENS_FINGERPRINT_MAX_FILES", 200000)
        self.deadline = time.monotonic() + env_int("BOMLENS_FINGERPRINT_TIMEOUT", 300)
        try:
            self._walk()
        except Budget:
            self.truncated = True

    def inside(self, target):
        return target == self.real or target.startswith(self.real + os.sep)

    def _hash_regular(self, path):
        """sha256 of a regular file, opened without blocking (a FIFO swapped
        in after the lstat is caught by the fstat). None when unreadable."""
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        except OSError:
            return None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            h = hashlib.sha256()
            while True:
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                h.update(chunk)
                if time.monotonic() > self.deadline:
                    raise Budget()
            return h.hexdigest()
        except OSError:
            return None
        finally:
            os.close(fd)

    def _entry(self, rel):
        """(mode, sha256) of a tree entry: mode is 644 or 755 by the execute
        bit, with an l in front for a link. A link counts only when it leads
        to a regular file inside the source; a FIFO, socket or device is never
        opened. sha256 is None for anything that cannot be hashed."""
        path = os.path.join(self.src, rel)
        try:
            st = os.lstat(path)
        except OSError:
            return "?", None
        prefix = ""
        if stat.S_ISLNK(st.st_mode):
            target = os.path.realpath(path)
            if not self.inside(target):
                return "l", None
            try:
                st = os.stat(target)
            except OSError:
                return "l", None
            path, prefix = target, "l"
        if not stat.S_ISREG(st.st_mode):
            return prefix + "?", None
        mode = "755" if st.st_mode & 0o111 else "644"
        return prefix + mode, self._hash_regular(path)

    def _judge(self, rel):
        return not any(seg in self.judge_prune for seg in rel.split("/")[:-1])

    def _walk(self):
        def onerror(err):
            rel = os.path.relpath(getattr(err, "filename", self.src) or self.src, self.src).replace(os.sep, "/")
            self.unhashable.append("" if rel == "." else rel)

        for dirpath, dirnames, filenames in os.walk(self.src, topdown=True, followlinks=False, onerror=onerror):
            # Folders count toward the limit too, and the time is checked per
            # folder: a tree of empty folders must stop as well.
            self.folders += 1
            if len(self.hashes) + self.folders > self.max_files or time.monotonic() > self.deadline:
                raise Budget()
            reld = os.path.relpath(dirpath, self.src).replace(os.sep, "/")
            reld = "" if reld == "." else reld
            keep = []
            for d in dirnames:
                rel = join(reld, d)
                if d == ".git" or rel == self.exclude_dir:
                    continue
                if os.path.islink(os.path.join(dirpath, d)):
                    # A folder link is not walked, and cdxgen may follow it:
                    # what is behind it cannot be accounted for.
                    self.unhashable.append(rel)
                    continue
                keep.append(d)
            dirnames[:] = keep
            for f in filenames:
                if f == ".git":
                    continue        # a worktree's gitlink, which names an absolute path
                rel = join(reld, f)
                if len(self.hashes) + self.folders >= self.max_files or time.monotonic() > self.deadline:
                    raise Budget()
                mode, sha = self._entry(rel)
                self.hashes[rel] = (mode, sha)
                if sha is None or "\n" in rel or "\t" in rel:
                    self.unhashable.append(rel)
                    continue
                self.names.add(rel)
                if f == "pom.xml":
                    self.poms.append(rel)
                elif f == "go.mod":
                    self.go_mods.append(rel)
                elif f.endswith(".go") and not go_ignored(rel):
                    self.go_files.append(rel)
                elif f.endswith((".gradle", ".gradle.kts")):
                    self.gradle_files.append(rel)
                if not self._judge(rel):
                    continue
                if f.endswith((".props", ".targets")):
                    self.dotnet_props.append(rel)
                if (self.manifest_re.search(rel) and not NOT_MANIFEST_RE.search(rel)) or REQUIREMENTS_RE.search(rel):
                    self.judged.append(rel)

    def tree_component(self):
        """The whole tree as one component: sha256 over
        "path<TAB>mode<TAB>sha256" lines in byte order, and the file count."""
        h = hashlib.sha256()
        for rel in sorted(self.hashes, key=os.fsencode):
            mode, sha = self.hashes[rel]
            h.update(os.fsencode(rel) + b"\t" + mode.encode("ascii") + b"\t" + (sha or "").encode("ascii") + b"\n")
        comp = {"kind": "file", "name": ".", "sha256": None if (self.unhashable or self.truncated) else h.hexdigest(),
                "count": len(self.hashes)}
        if self.truncated:
            comp["truncated"] = True
        return comp

    def text(self, rel):
        """The file's text for the checks, read once. None when it is not a
        hashed file of the tree or is over READ_CAP (then also recorded)."""
        if rel not in self.names:
            return None
        if rel not in self._texts:
            t = read_text(os.path.join(self.src, rel))
            if t is OVERSIZED:
                self.unanalysable.add(rel)
                t = None
            self._texts[rel] = t
        return self._texts[rel]

    def include(self, rel):
        """A file another input names (a requirements include): True when it
        is a hashed file of the tree."""
        norm = os.path.normpath(rel).replace(os.sep, "/")
        if norm.startswith("../") or norm == ".." or os.path.isabs(norm):
            return False
        return norm in self.names


# --- does a manifest declare anything to resolve? ----------------------------
# Only a "no" that is certain counts: anything unreadable or unknown declares.

def declares(tree, rel):
    base = rel.rsplit("/", 1)[-1]
    text = tree.text(rel)
    if text is None:
        return True
    try:
        if base == "package.json":
            d = json.loads(text)
            return any(isinstance(d.get(k), (dict, list)) and len(d.get(k)) > 0
                       for k in ("dependencies", "devDependencies", "optionalDependencies",
                                 "peerDependencies", "bundleDependencies", "bundledDependencies"))
        if base == "composer.json":
            d = json.loads(text)
            return any(k != "php" and not k.startswith("ext-")
                       for sect in ("require", "require-dev") for k in (d.get(sect) or {}))
    except (ValueError, AttributeError, TypeError):
        return True
    if base == "Cargo.toml":
        return any(line.strip().startswith("[") and "dependencies" in line.strip().split("]", 1)[0]
                   for line in text.splitlines())
    if base == "Package.swift":
        return ".package(" in text
    if base.endswith("proj"):
        if "PackageReference" in text:
            return True
        # Directory.Build.props/.targets can add a PackageReference to every project.
        return dotnet_props_add_references(tree)
    if base == "pyproject.toml":
        try:
            import tomllib
            d = tomllib.loads(text)
        except Exception:
            return True
        proj = d.get("project") or {}
        poetry = (d.get("tool") or {}).get("poetry") or {}
        uv = (d.get("tool") or {}).get("uv") or {}
        groups = [g.get("dependencies") or {} for g in (poetry.get("group") or {}).values() if isinstance(g, dict)]
        poetry_deps = [k for t in [poetry.get("dependencies") or {}, poetry.get("dev-dependencies") or {}] + groups
                       for k in t if k.lower() != "python"]
        return bool(proj.get("dependencies") or proj.get("optional-dependencies") or poetry_deps
                    or d.get("dependency-groups") or uv.get("dev-dependencies")
                    or "dependencies" in (proj.get("dynamic") or []))
    if base == "setup.cfg":
        return "install_requires" in text or "extras_require" in text
    return bool(text.strip())


@functools.lru_cache(maxsize=None)
def dotnet_props_add_references(tree):
    return any("PackageReference" in (tree.text(p) or "x") for p in tree.dotnet_props)


# --- requirements files ------------------------------------------------------
# Stage 1 installs requirements files with pip from the registry, and no
# poetry.lock, uv.lock or Pipfile.lock covers that. pip installs exactly what a
# requirements file lists only in hash-checking mode, where every requirement
# (the transitive ones too) must be pinned with == and carry a --hash; pip
# refuses to install anything else. So a requirements file is locked when every
# requirement in it is `name==version` with --hash, and it includes nothing.

REQ_PIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[^\]]*\])?\s*===?\s*[^\s,;*=<>!~]+\s*(;.*)?$")
REQ_INCLUDE = ("-r", "--requirement", "-c", "--constraint")
REQ_HARMLESS = ("-i", "--index-url", "--extra-index-url", "--no-index", "-f", "--find-links",
                "--trusted-host", "--require-hashes", "--prefer-binary", "--only-binary",
                "--no-binary", "--pre", "--use-feature")


def requirement_lines(text):
    joined = re.sub(r"\\\r?\n", " ", text)
    for line in joined.splitlines():
        line = re.sub(r"(^|\s)#.*$", "", line).strip()
        if line:
            yield line


def check_requirements(tree, rel, seen=None):
    """(locked, includes_ok) for a requirements file and what it includes."""
    seen = set() if seen is None else seen
    if rel in seen:
        return True, True
    seen.add(rel)
    text = tree.text(rel)
    if text is None:
        return False, False
    locked, ok = True, True
    base_dir = parent_dir(rel)
    for line in requirement_lines(text):
        if "${" in line:
            locked = False      # pip expands environment variables here
        if line.startswith("-"):
            tok = line.split(None, 1)
            opt, rest = tok[0], (tok[1] if len(tok) > 1 else "")
            target = None
            for inc in REQ_INCLUDE:
                if opt == inc:
                    target = rest.strip()
                elif opt.startswith(inc + "=") and inc.startswith("--"):
                    target = opt.split("=", 1)[1]
                elif inc in ("-r", "-c") and opt.startswith(inc) and len(opt) > 2:
                    target = opt[2:]
            if target is not None:
                locked = False
                inc_rel = join(base_dir, target) if target and not target.startswith("/") else target
                if not target or "://" in target or not tree.include(inc_rel):
                    ok = False
                else:
                    _, sub_ok = check_requirements(tree, os.path.normpath(inc_rel).replace(os.sep, "/"), seen)
                    ok = ok and sub_ok
                continue
            if opt.split("=", 1)[0] in REQ_HARMLESS:
                continue
            locked = False      # -e/--editable and anything else not known to be harmless
            continue
        spec = re.split(r"\s--hash[=\s]", line, maxsplit=1)
        req = spec[0].strip()
        if ("://" in req or " @ " in req or req.startswith((".", "/", "~", "file:"))
                or not REQ_PIN_RE.match(req) or len(spec) < 2):
            locked = False
    return locked, ok


# --- workspaces --------------------------------------------------------------

@functools.lru_cache(maxsize=None)
def node_workspace_patterns(tree, root):
    pats = []
    text = tree.text(join(root, "package.json"))
    if text:
        try:
            ws = json.loads(text).get("workspaces")
            if isinstance(ws, dict):
                ws = ws.get("packages")
            if isinstance(ws, list):
                pats += [p for p in ws if isinstance(p, str)]
        except (ValueError, AttributeError):
            pass
    text = tree.text(join(root, "pnpm-workspace.yaml"))
    if text:
        inpk = False
        for line in text.splitlines():
            if re.match(r"^packages\s*:", line):
                inpk = True
                continue
            if inpk:
                m = re.match(r"^\s+-\s*['\"]?([^'\"#]+?)['\"]?\s*(#.*)?$", line)
                if m:
                    pats.append(m.group(1).strip())
                elif line.strip() and not line.startswith((" ", "\t")):
                    inpk = False
    return tuple(pats)


@functools.lru_cache(maxsize=None)
def cargo_workspace(tree, root):
    text = tree.text(join(root, "Cargo.toml"))
    if not text:
        return (), ()
    try:
        import tomllib
        ws = tomllib.loads(text).get("workspace") or {}
        return tuple(ws.get("members") or []), tuple(ws.get("exclude") or [])
    except Exception:
        return (), ()


NODE_DEP_SECTIONS = ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies")


def npm_lock_in_sync(tree, lock_rel, key, pkg_rel):
    """True when an npm lock file records the package.json at pkg_rel as it is:
    the same dependency specs in its packages[key] entry (lockfile v2 and v3),
    or every dependency name in its dependencies (v1). npm resolves anything
    else again from the registry, and build-prep's production filter runs npm."""
    try:
        lock = json.loads(tree.text(lock_rel) or "")
        pkg = json.loads(tree.text(pkg_rel) or "")
    except ValueError:
        return False
    if not isinstance(lock, dict) or not isinstance(pkg, dict):
        return False
    if isinstance(lock.get("packages"), dict):
        entry = lock["packages"].get(key)
        if not isinstance(entry, dict):
            return False
        return all((pkg.get(sec) or {}) == (entry.get(sec) or {}) for sec in NODE_DEP_SECTIONS)
    names = set((lock.get("dependencies") or {}).keys())
    return all(n in names for sec in NODE_DEP_SECTIONS for n in (pkg.get(sec) or {}))


def node_reasons_for(tree, rel):
    """Reasons for one package.json: no lock, or an npm lock that does not
    match it."""
    d = parent_dir(rel)
    for n in NODE_LOCKS:
        if join(d, n) in tree.names:
            if n in ("package-lock.json", "npm-shrinkwrap.json") and not npm_lock_in_sync(tree, join(d, n), "", rel):
                return {"registry-resolution"}
            return set()
    for a in ancestors(d):
        locks = [n for n in NODE_LOCKS if join(a, n) in tree.names]
        if locks:
            member = d[len(a) + 1:] if a else d
            if matches(node_workspace_patterns(tree, a), member):
                for n in locks:
                    if n in ("package-lock.json", "npm-shrinkwrap.json") and not npm_lock_in_sync(tree, join(a, n), member, rel):
                        return {"registry-resolution"}
                return set()
    return {"no-lockfile"}


def gemfile_in_sync(tree, d):
    """True when Gemfile.lock's DEPENDENCIES names every gem the Gemfile does."""
    gems = set()
    for line in (tree.text(join(d, "Gemfile")) or "").splitlines():
        m = re.match(r"[ \t]*gem[ \t]+['\"]([^'\"]+)['\"]", line)
        if m:
            gems.add(m.group(1))
    locked, inside = set(), False
    for line in (tree.text(join(d, "Gemfile.lock")) or "").splitlines():
        if line.strip() == "DEPENDENCIES":
            inside = True
            continue
        if inside:
            if not line.startswith("  "):
                break
            locked.add(line.split()[0].rstrip("!"))
    return gems <= locked


def swift_url(u):
    u = u.strip().lower().rstrip("/")
    return u[:-4] if u.endswith(".git") else u


def swift_urls(text):
    """The remote package URLs in Package.swift, or None when a .package( is
    not closed. Each .package( is cut at the next ")" found once, so the cost
    stays linear in the file size."""
    urls, pos, close = set(), 0, -1
    while True:
        i = text.find(".package(", pos)
        if i < 0:
            return urls
        if close < i:
            close = text.find(")", i)
            if close < 0:
                return None
        m = re.search(r'url[ \t]*:[ \t]*"([^"]*)"', text[i:close])
        if m:
            urls.add(swift_url(m.group(1)))
        pos = i + 9


def swift_in_sync(tree, d):
    """True when Package.resolved pins every remote package Package.swift names."""
    urls = swift_urls(tree.text(join(d, "Package.swift")) or "")
    if urls is None:
        return False
    try:
        res = json.loads(tree.text(join(d, "Package.resolved")) or "")
    except ValueError:
        return False
    pins = res.get("pins") or (res.get("object") or {}).get("pins") or []
    pinned = {swift_url(p.get("location") or p.get("repositoryURL") or "") for p in pins if isinstance(p, dict)}
    return urls <= pinned


def cargo_locked(tree, d):
    if join(d, "Cargo.lock") in tree.names:
        return True
    for a in ancestors(d):
        if join(a, "Cargo.lock") in tree.names and join(a, "Cargo.toml") in tree.names:
            members, exclude = cargo_workspace(tree, a)
            member = d[len(a) + 1:] if a else d
            if matches(members, member) and not matches(exclude, member):
                return True
    return False


def node_reresolves(tree, settings):
    """True when build-prep's production filter resolves the root package.json
    again with `npm install --package-lock-only`: no package-lock.json at the
    root (npm-shrinkwrap.json is not copied for it), not a workspace root, and
    BOMLENS_NODE_FULL_GRAPH not set."""
    if "package.json" not in tree.names or "package-lock.json" in tree.names:
        return False
    if settings.get("BOMLENS_NODE_FULL_GRAPH", "") in ("1", "true"):
        return False
    if "pnpm-workspace.yaml" in tree.names:
        return False
    try:
        if json.loads(tree.text("package.json") or "{}").get("workspaces"):
            return False
    except (ValueError, AttributeError):
        return True
    return True


# --- Go ----------------------------------------------------------------------
# `go mod tidy` runs in stage 1 and adds, at the newest version, a module for
# any import go.mod does not cover. Imports are read from the .go files of each
# module and compared with its own path and its require list.

# An import path is a double-quoted or a back-quoted (raw) string.
GO_PATH = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"|`([^`]*)`')


def go_paths(segment):
    return [a or b for a, b in GO_PATH.findall(segment)]


def go_imports(text):
    """The import paths of a .go file, read line by line (linear in its size):
    `import "x"`, `import name "x"` and `import ( ... )` blocks."""
    paths, block = [], False
    for line in text.splitlines():
        s = line.split("//", 1)[0].strip()
        if block:
            if ")" in s:
                paths += go_paths(s.split(")", 1)[0])
                block = False
            else:
                paths += go_paths(s)
            continue
        if not s.startswith("import") or s[6:7] not in ("", " ", "\t", "("):
            continue
        rest = s[6:].strip()
        if rest.startswith("("):
            rest = rest[1:]
            if ")" in rest:
                paths += go_paths(rest.split(")", 1)[0])
            else:
                paths += go_paths(rest)
                block = True
        else:
            paths += go_paths(rest)
    return paths


def go_module(text):
    """The module path and the required module paths of a go.mod."""
    mod, reqs, block = "", set(), False
    for line in text.splitlines():
        s = line.split("//", 1)[0].strip()
        if block:
            if s.startswith(")"):
                block = False
            elif len(s.split()) >= 2:
                reqs.add(s.split()[0])
            continue
        f = s.split()
        if not f:
            continue
        if f[0] == "module" and len(f) > 1:
            mod = f[1].strip('"')
        elif f[0] == "require" or f[0].startswith("require("):
            rest = s[len("require"):].strip()
            if rest.startswith("("):
                rest = rest[1:].strip()
                if rest and not rest.startswith(")") and len(rest.split()) >= 2:
                    reqs.add(rest.split()[0])
                block = ")" not in rest
            elif len(rest.split()) >= 2:
                reqs.add(rest.split()[0])
    return mod, reqs


def go_covered(path, own, reqs):
    if "." not in path.split("/", 1)[0]:
        return True                     # the standard library, or the module itself without a dot
    for m in [own] + sorted(reqs, key=len, reverse=True):
        if m and (path == m or path.startswith(m + "/")):
            rest = path[len(m) + 1:].split("/", 1)[0] if path != m else ""
            # example.com/x/v2 is another module than example.com/x.
            if re.fullmatch(r"v[0-9]+", rest) and m != own:
                return False
            return True
    return False


def go_reasons(tree):
    reasons = set()
    mods = {}
    for rel in tree.go_mods:
        text = tree.text(rel)
        if text is None:
            reasons.add("unhashable-input")
            continue
        mods[parent_dir(rel)] = go_module(text)
    for d, (own, reqs) in mods.items():
        if reqs and join(d, "go.sum") not in tree.names:
            reasons.add("no-lockfile")
    for rel in tree.go_files:
        d = parent_dir(rel)
        home = next((a for a in [d] + ancestors(d) if a in mods), None)
        if home is None:
            continue
        paths = go_imports(tree.text(rel) or "")
        own, reqs = mods[home]
        if any(not go_covered(p, own, reqs) for p in paths):
            reasons.add("registry-resolution")
            break
    return reasons


# --- Gradle ------------------------------------------------------------------
# A gradle.lockfile pins a project's dependencies only when locking is turned
# on (dependencyLocking { lockAllConfigurations() }, or a configuration's
# resolutionStrategy.activateDependencyLocking()). Without it Gradle resolves
# dynamic versions afresh and ignores the file.

GRADLE_LOCKING = re.compile(r"lockAllConfigurations|activateDependencyLocking")


def strip_comments(text):
    """Groovy and Kotlin comments out, so a commented-out locking line does not
    count. A // inside a string is cut too, which can only hide a locking line.
    One pass with str.find, linear in the size."""
    out, i, n = [], 0, len(text)
    while i < n:
        j = text.find("/", i)
        if j < 0 or j + 1 >= n:
            out.append(text[i:])
            break
        if text[j + 1] == "/":
            out.append(text[i:j])
            k = text.find("\n", j)
            i = n if k < 0 else k
        elif text[j + 1] == "*":
            out.append(text[i:j] + " ")
            k = text.find("*/", j + 2)
            i = n if k < 0 else k + 2
        else:
            out.append(text[i:j + 1])
            i = j + 1
    return "".join(out)


SHARED_RE = re.compile(r"\b(?:subprojects|allprojects)[ \t\r\n]*\{")
BRACE_RE = re.compile(r"[{}]")


def shared_blocks(text):
    """The bodies of the subprojects {} and allprojects {} blocks. A block
    inside one already read is not read again, so this stays linear."""
    out, last_end = [], -1
    for m in SHARED_RE.finditer(text):
        if m.start() < last_end:
            continue
        depth, end = 1, len(text)
        for b in BRACE_RE.finditer(text, m.end()):
            depth += 1 if b.group() == "{" else -1
            if depth == 0:
                end = b.start()
                break
        out.append(text[m.end():end])
        last_end = end
    return out


LOCK_ENTRY_RE = re.compile(r"[^#\s=:]+:[^\s=:]+:[^\s=]+=")


def gradle_reasons(tree):
    reasons = set()
    texts = {rel: strip_comments(tree.text(rel) or "") for rel in tree.gradle_files}
    roots = {parent_dir(rel) for rel in texts if rel.rsplit("/", 1)[-1].startswith("settings.gradle")}

    def root_of(d):
        return next((a for a in [d] + ancestors(d) if a in roots), d)

    def root_text(root):
        return texts.get(join(root, "build.gradle"), "") + texts.get(join(root, "build.gradle.kts"), "")

    def has_entries(d):
        # A lock file with only "empty=" lines locks nothing.
        return any(LOCK_ENTRY_RE.match(line) for line in (tree.text(join(d, "gradle.lockfile")) or "").splitlines())

    def locked(d, own_text):
        if join(d, "gradle.lockfile") not in tree.names or not has_entries(d):
            return False
        if GRADLE_LOCKING.search(own_text):
            return True
        # Locking at the top of the root build file locks the root project
        # only; for the others it has to sit in subprojects {} or allprojects {}.
        root = root_of(d)
        return root != d and any(GRADLE_LOCKING.search(b) for b in shared_blocks(root_text(root)))

    project_dirs = set()
    for rel, text in texts.items():
        base = rel.rsplit("/", 1)[-1]
        if base in ("build.gradle", "build.gradle.kts"):
            d = parent_dir(rel)
            project_dirs.add(d)
            if text.strip() and not locked(d, text):
                reasons.add("no-lockfile")
    # Projects settings.gradle includes with no build file of their own get
    # their dependencies from the root's subprojects {} or allprojects {}.
    for root in roots:
        blocks = shared_blocks(root_text(root))
        if not any("dependencies" in b for b in blocks):
            continue
        stext = texts.get(join(root, "settings.gradle"), "") + texts.get(join(root, "settings.gradle.kts"), "")
        for line in stext.splitlines():
            m = re.match(r"[ \t]*include\b[ \t]*\(?(.*)", line)
            if not m:
                continue
            for path in re.findall(r"['\"]([^'\"]+)['\"]", m.group(1)):
                d = join(root, path.strip(":").replace(":", "/"))
                if d not in project_dirs and not locked(d, ""):
                    reasons.add("no-lockfile")
    return reasons


# --- .NET --------------------------------------------------------------------

# A Version="..." or VersionOverride="..." attribute anywhere (ToolsVersion and
# the like do not match), and a <Version> element.
DOTNET_VERSION = re.compile(r'\bVersion(?:Override)?[ \t]*=[ \t]*"([^"]*)"')
DOTNET_VERSION_ELEM = re.compile(r"<Version>([^<]*)</Version>")


def dotnet_floating(v):
    v = v.strip()
    return not v or "*" in v or v[:1] in "[(" or "," in v or "$(" in v


def dotnet_reasons(tree):
    reasons = set()
    projects = [rel for rel in tree.judged if re.search(r"\.(cs|fs|vb)proj$", rel)]
    slns = [rel for rel in tree.names if rel.endswith((".sln", ".slnx"))]
    for rel in projects + tree.dotnet_props:
        text = tree.text(rel)
        if text is None:
            reasons.add("unhashable-input")
            continue
        if any(dotnet_floating(v) for v in DOTNET_VERSION.findall(text) + DOTNET_VERSION_ELEM.findall(text)):
            reasons.add("unpinned-versions")
    if not (projects or slns):
        return reasons
    any_lock = any(n.rsplit("/", 1)[-1] in ("packages.lock.json", "paket.lock") or n.endswith("obj/project.assets.json")
                   for n in tree.names)
    if not any_lock:
        reasons.add("no-lockfile")      # dotnet restore asks the registry
    for rel in projects:
        d = parent_dir(rel)
        own = join(d, "packages.lock.json") in tree.names or join(d, "obj/project.assets.json") in tree.names
        paket = any(join(a, "paket.lock") in tree.names for a in [d] + ancestors(d))
        if declares(tree, rel) and not (own or paket):
            reasons.add("no-lockfile")
    return reasons


# --- Maven -------------------------------------------------------------------
# Maven has no lock file, so nothing pins the transitive graph: a range in a
# dependency's own pom is resolved against the registry on each run and cannot
# be seen from here. A tree with a pom.xml is therefore never reusable.

POM_VALUE = re.compile(r">([^<>]*)<")


def maven_reasons(tree):
    """Any pom.xml makes the tree registry-resolution. unpinned-versions is
    added when an element of the tree's own poms holds a version range, a
    -SNAPSHOT, LATEST or RELEASE as written; properties are not expanded, so
    the cost stays linear in the size of the poms."""
    if not tree.poms:
        return set()
    reasons = {"registry-resolution"}
    for rel in tree.poms:
        for v in POM_VALUE.findall(tree.text(rel) or ""):
            v = v.strip()
            if (v[:1] in "[(" and "," in v) or v.endswith("-SNAPSHOT") or v in ("LATEST", "RELEASE"):
                reasons.add("unpinned-versions")
                return reasons
    return reasons


# --- the reasons -------------------------------------------------------------

def reasons_for(tree, ecosystem, settings):
    reasons = set()
    if ecosystem in ("unknown", "cpp") or any(n.rsplit("/", 1)[-1] == "package.mo" for n in tree.names):
        reasons.add("unsupported-ecosystem")
    if ecosystem == "swift" and not any(n in tree.names for n in ("Package.swift", "Podfile", "Podfile.lock")):
        reasons.add("unsupported-ecosystem")      # an Xcode project only
    if tree.unhashable or tree.truncated:
        reasons.add("unhashable-input")
    if node_reresolves(tree, settings):
        reasons.add("registry-resolution")
    reasons |= go_reasons(tree) | gradle_reasons(tree) | dotnet_reasons(tree) | maven_reasons(tree)
    for rel in tree.judged:
        base = rel.rsplit("/", 1)[-1]
        d = parent_dir(rel)
        tree.text(rel)      # records a file over READ_CAP

        def own(*locks):
            return any(join(d, n) in tree.names for n in locks)

        if base in ("conanfile.txt", "conanfile.py", "vcpkg.json"):
            reasons.add("unsupported-ecosystem")
        elif REQUIREMENTS_RE.search(rel):
            locked, ok = check_requirements(tree, rel)
            if not ok:
                reasons.add("unhashable-input")
            if not locked and any(requirement_lines(tree.text(rel) or "x")):
                reasons.add("no-lockfile")
        elif base == "package.json":
            if declares(tree, rel):
                reasons |= node_reasons_for(tree, rel)
        elif base in ("pyproject.toml", "setup.py", "setup.cfg", "Pipfile"):
            if declares(tree, rel) and not own(*PY_LOCKS):
                reasons.add("no-lockfile")
        elif base == "Cargo.toml":
            if declares(tree, rel) and not cargo_locked(tree, d):
                reasons.add("no-lockfile")
        elif base == "Gemfile" or base.endswith(".gemspec"):
            if declares(tree, rel) and not own("Gemfile.lock"):
                reasons.add("no-lockfile")
            elif base == "Gemfile" and not gemfile_in_sync(tree, d):
                reasons.add("registry-resolution")
        elif base == "composer.json":
            if declares(tree, rel) and not own("composer.lock"):
                reasons.add("no-lockfile")
        elif base == "Package.swift":
            if declares(tree, rel) and not own("Package.resolved"):
                reasons.add("no-lockfile")
            elif declares(tree, rel) and not swift_in_sync(tree, d):
                reasons.add("registry-resolution")
        elif base == "Podfile":
            if declares(tree, rel) and not own("Podfile.lock"):
                reasons.add("no-lockfile")
    return reasons


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--ecosystem", required=True)
    ap.add_argument("--manifest-re", required=True)
    ap.add_argument("--non-shipped-dirs", default="")
    ap.add_argument("--image", action="append", default=[])
    ap.add_argument("--engine-file", action="append", default=[])
    ap.add_argument("--engine-sha", action="append", default=[])
    ap.add_argument("--setting", action="append", default=[])
    ap.add_argument("--unsupported", action="store_true")
    ap.add_argument("--stage1-missing-reason", default="plan-unsupported")
    ap.add_argument("--exclude-dir", default="")
    a = ap.parse_args()

    # The run's own output folder inside the source (the CLI's default; "."
    # for an output written into the source root itself). It is left out of
    # the walk, since it holds this run's results, but stage 1 ran before it
    # was cleaned and may have read an earlier run's files there: what it read
    # cannot be known, so the value is not reusable. The folder is listed as a
    # file component with sha256 null. Only a plain relative path counts.
    output_inside = bool(a.exclude_dir)
    exclude = os.path.normpath(a.exclude_dir).replace(os.sep, "/") if a.exclude_dir else ""
    if exclude in (".", "") or exclude.startswith("../") or exclude == ".." or os.path.isabs(exclude):
        exclude = ""
    settings = dict(item.split("=", 1) for item in a.setting)
    tree = Tree(a.src, re.compile(a.manifest_re), JUDGE_PRUNE | set(a.non_shipped_dirs.split()), exclude)
    if exclude:
        tree.unhashable.append(exclude)
    reasons = reasons_for(tree, a.ecosystem, settings)
    if tree.unanalysable:
        reasons.add("unhashable-input")     # a manifest or Go source over READ_CAP
    if output_inside:
        reasons.add("unhashable-input")

    # One component for the whole tree; a path that could not be hashed is
    # also listed on its own, so a reader can see which.
    comps = [tree.tree_component()]
    comps += [{"kind": "file", "name": rel, "sha256": None} for rel in sorted(set(tree.unhashable), key=os.fsencode)]
    for item in a.engine_file:
        name, path = item.split("=", 1)
        comps.append({"kind": "engine", "name": name, "sha256": sha256_file(path) if path else None})
    for item in a.engine_sha:
        name, value = item.split("=", 1)
        comps.append({"kind": "engine", "name": name,
                      "sha256": value if re.fullmatch(r"[0-9a-f]{64}", value) else None})
    for item in a.image:
        name, digest = item.split("=", 1)
        hexd = digest[7:] if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) else None
        comps.append({"kind": "image", "name": name, "sha256": hexd})
        if name == "stage1" and hexd is None:
            reasons.add(a.stage1_missing_reason)
    comps.append({"kind": "setting", "name": "detected_ecosystem", "sha256": sha256_text(a.ecosystem)})
    for name, value in settings.items():
        comps.append({"kind": "setting", "name": name, "sha256": sha256_text(value)})
    comps.sort(key=lambda c: (c["kind"], os.fsencode(c["name"])))

    # A component that could not be hashed leaves the value blind to it. The
    # BomLens image digest is the caller's to give and may be absent; the files
    # it would cover are hashed as engine components.
    if any(c["sha256"] is None and c["kind"] != "image" for c in comps):
        reasons.add("unhashable-input")
    if a.unsupported:
        reasons.add("plan-unsupported")

    canon = json.dumps({"algorithm": ALGORITHM, "components": comps}, separators=(",", ":"), ensure_ascii=True)
    reusable = not reasons
    out = {
        "algorithm": ALGORITHM,
        "sha256": hashlib.sha256(canon.encode("ascii")).hexdigest() if reusable else None,
        "reusable": reusable,
        "reasons": sorted(reasons),
        "components": comps,
    }
    sys.stdout.write(json.dumps(out, separators=(",", ":"), ensure_ascii=True) + "\n")


if __name__ == "__main__":
    main()
