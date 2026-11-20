#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Read the Python packages a project's own virtual environment holds.

Usage:
  read-python-venv.py find  <source_dir>
  read-python-venv.py read  <source_dir> <venv_dir> <output.json>
  read-python-venv.py merge <bom.json> <venv.json> <venv_dir> <reason>

A project that resolves from a company package index cannot be resolved in
the scan container (no credentials, a proxy that inspects TLS). The
developer's own build has already installed what it needs, in .venv/ or
venv/ next to the code, and each installed package keeps its metadata in a
*.dist-info folder: the name, the version, the licence fields and the
packages it requires (Requires-Dist). build-prep.sh uses this script when the
package index does not answer or `pip install` failed; otherwise the normal
resolution runs as it always has.

find   prints the environment folder (relative to the source) on the first
       line and its site-packages folders (absolute) on the next ones. Exit 1
       when there is none.
read   writes a CycloneDX document with the installed packages that the
       project's declared dependencies reach through Requires-Dist, and the
       dependency graph between them. A tool installed into the environment
       that nothing declared reaches (pytest, pip itself) is left out. Prints
       one tab-separated line: kept, installed, how versions were compared
       (pip-packaging, packaging or fallback), unsure detail. Exit 2 when no
       declared dependency could be read, 3 when none of them is installed.
merge  adds that document's components and graph to the SBOM cdxgen wrote and
       records the environment on it (bomlens:python-environment*).

Nothing in the environment is run or written: its python executable may be a
macOS or Windows one that cannot run here, and the folder belongs to the
user. Only text files are read, each one capped, and a path that leads out of
the scanned tree is not followed.

Environment markers (`; python_version < "3.11"`) are evaluated by this
script, with three-valued logic: the Python version comes from pyvenv.cfg,
the platform from the wheel tags of the installed packages (WHEEL files) and
the folder layout. A comparison whose variable is not known makes that part
unknown, and a requirement whose marker stays unknown is kept, counted as
unsure. Version comparisons use pip's vendored `packaging` when it can be
imported (also a standalone `packaging`), else a numeric comparison.
"""
import json
import os
import re
import sys
from datetime import datetime, timezone
from email.parser import HeaderParser
from urllib.parse import quote

CDX_SPEC_VERSION = "1.7" if os.environ.get("CYCLONEDX_SPEC_VERSION") == "1.7" else "1.6"

MAX_META_BYTES = 4 * 1024 * 1024     # a METADATA file, its long description included
MAX_MANIFEST_BYTES = 1024 * 1024     # a requirements file or pyproject.toml
MAX_DISTS = 20000
MAX_DEPTH = 6                        # folders below the source for manifests
DEFAULT_CANDIDATES = (".venv", "venv")
ALWAYS_PRUNE = {".git", "node_modules", ".tox", ".nox", "__pycache__", "site-packages", ".hg", ".svn"}

try:
    from pip._vendor.packaging.specifiers import InvalidSpecifier, Specifier
    from pip._vendor.packaging.version import InvalidVersion, Version
    VERSION_ENGINE = "pip-packaging"
except Exception:  # pragma: no cover - depends on the image
    try:
        from packaging.specifiers import InvalidSpecifier, Specifier
        from packaging.version import InvalidVersion, Version
        VERSION_ENGINE = "packaging"
    except Exception:
        Specifier = Version = None
        InvalidSpecifier = InvalidVersion = ValueError
        VERSION_ENGINE = "fallback"


def canon(name):
    """PEP 503 normalised name, as pkg:pypi purls are written."""
    return re.sub(r"[-_.]+", "-", (name or "").strip()).lower()


def inside(path, root):
    try:
        real = os.path.realpath(path)
    except OSError:
        return False
    return real == root or real.startswith(root + os.sep)


def read_capped(path, cap):
    try:
        with open(path, "rb") as fh:
            data = fh.read(cap + 1)
    except OSError:
        return None
    if len(data) > cap:
        return None
    return data.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------
# The environment
# --------------------------------------------------------------------------

def read_cfg(venv):
    cfg = {}
    text = read_capped(os.path.join(venv, "pyvenv.cfg"), 64 * 1024)
    if text is None:
        return None
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            cfg[k.strip().lower()] = v.strip()
    return cfg


def has_metadata(site):
    try:
        names = os.listdir(site)
    except OSError:
        return False
    return any(n.endswith((".dist-info", ".egg-info")) for n in names)


def site_dirs(venv, root, cfg):
    """site-packages folders of a venv: lib/pythonX.Y (Linux, macOS), lib64,
    lib/pypyX.Y, Lib (Windows). Only folders that hold package metadata."""
    want = ""
    m = re.match(r"(\d+)\.(\d+)", (cfg or {}).get("version_info") or (cfg or {}).get("version") or "")
    if m:
        want = f"{m.group(1)}.{m.group(2)}"
    posix = []
    for lib in ("lib", "lib64"):
        base = os.path.join(venv, lib)
        try:
            entries = sorted(os.listdir(base))
        except OSError:
            continue
        for e in entries:
            if re.fullmatch(r"(python|pypy)\d+\.\d+t?", e):
                posix.append((e, os.path.join(base, e, "site-packages")))
    if want and any(e.endswith(want) or e.endswith(want + "t") for e, _ in posix):
        posix = [(e, p) for e, p in posix if e.endswith(want) or e.endswith(want + "t")]
    out, seen = [], set()
    for _e, p in posix + [("", os.path.join(venv, "Lib", "site-packages"))]:
        if not os.path.isdir(p) or not inside(p, root) or not has_metadata(p):
            continue
        real = os.path.realpath(p)
        if real in seen:
            continue
        seen.add(real)
        out.append(p)
    return out


def find_venv(src):
    """(relative folder, site dirs, cfg) of the environment, or None."""
    root = os.path.realpath(src)
    cands = list(DEFAULT_CANDIDATES)
    try:
        others = sorted(e for e in os.listdir(src) if e not in DEFAULT_CANDIDATES
                        and os.path.isfile(os.path.join(src, e, "pyvenv.cfg")))
    except OSError:
        others = []
    if len(others) == 1:
        cands.append(others[0])
    for c in cands:
        venv = os.path.join(src, c)
        if not os.path.isdir(venv) or not inside(venv, root):
            continue
        cfg = read_cfg(venv)
        if cfg is None:
            continue
        sites = site_dirs(venv, root, cfg)
        if sites:
            return c, sites, cfg
    return None


# --------------------------------------------------------------------------
# Marker environment
# --------------------------------------------------------------------------

PLATFORM_OF_TAG = (
    (re.compile(r"^macosx_"), "darwin"),
    (re.compile(r"^(many|musl)?linux"), "linux"),
    (re.compile(r"^win"), "win32"),
)


def tag_machine(plat):
    p = plat.lower()
    if p.startswith("win"):
        return {"win_amd64": "AMD64", "win32": "x86", "win_arm64": "ARM64"}.get(p)
    for m in ("x86_64", "aarch64", "arm64", "i686", "ppc64le", "s390x", "armv7l"):
        if p.endswith("_" + m):
            return m
    return None


def marker_env(sites, cfg, dists_dirs):
    """The marker variables this environment fixes, and nothing else."""
    env = {}
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", (cfg.get("version_info") or cfg.get("version") or ""))
    if not m:
        for s in sites:
            mm = re.search(r"(?:python|pypy)(\d+)\.(\d+)", s)
            if mm:
                m = mm
                break
    if m:
        env["python_version"] = f"{m.group(1)}.{m.group(2)}"
        if m.lastindex and m.lastindex >= 3 and m.group(3) is not None:
            env["python_full_version"] = f"{m.group(1)}.{m.group(2)}.{m.group(3)}"
    impl = (cfg.get("implementation") or "").lower()
    if not impl:
        impl = "pypy" if any("pypy" in s.lower() for s in sites) else "cpython"
    if impl in ("cpython", "pypy"):
        env["implementation_name"] = impl
        env["platform_python_implementation"] = "CPython" if impl == "cpython" else "PyPy"
        if impl == "cpython" and "python_full_version" in env:
            env["implementation_version"] = env["python_full_version"]

    windows = any(os.path.basename(os.path.dirname(s)) == "Lib" for s in sites)
    platforms, machines = set(), set()
    for d in dists_dirs:
        text = read_capped(os.path.join(d, "WHEEL"), 64 * 1024)
        if not text:
            continue
        for line in text.splitlines():
            if not line.lower().startswith("tag:"):
                continue
            parts = line.split(":", 1)[1].strip().split("-")
            if len(parts) < 3:
                continue
            for plat in parts[-1].split("."):
                if plat == "any":
                    continue
                for rx, name in PLATFORM_OF_TAG:
                    if rx.match(plat):
                        platforms.add(name)
                        break
                mach = tag_machine(plat)
                if mach:
                    machines.add(mach)
    if windows:
        platforms.add("win32")
    if not platforms:
        # No platform wheel installed: the interpreter's folder, only where it
        # says. /usr/bin and /usr/local are used on both Linux and macOS.
        home = (cfg.get("home") or "")
        if re.search(r"^/Users/|Python\.framework|/opt/homebrew|^/Library/|macos", home):
            platforms.add("darwin")
        elif re.search(r"^/home/|linux", home):
            platforms.add("linux")
        elif re.search(r"^[A-Za-z]:[\\/]", home):
            platforms.add("win32")
    if len(platforms) == 1:
        plat = platforms.pop()
        env["sys_platform"] = plat
        env["platform_system"] = {"darwin": "Darwin", "linux": "Linux", "win32": "Windows"}[plat]
        env["os_name"] = "nt" if plat == "win32" else "posix"
    if len(machines) == 1:
        env["platform_machine"] = machines.pop()
    return env


# --------------------------------------------------------------------------
# Markers: a small PEP 508 marker evaluator with three-valued logic
# --------------------------------------------------------------------------

TOKEN_RE = re.compile(r"""\s*(?:
    (?P<lp>\() | (?P<rp>\)) |
    (?P<op>===|==|!=|<=|>=|~=|<|>|not\s+in\b|in\b) |
    (?P<bool>and\b|or\b) |
    (?P<str>'[^']*'|"[^"]*") |
    (?P<var>[A-Za-z_][A-Za-z0-9_.]*)
)""", re.X)
VERSION_VARS = {"python_version", "python_full_version", "implementation_version"}
ALIASES = {"os.name": "os_name", "sys.platform": "sys_platform", "platform.version": "platform_version",
           "platform.machine": "platform_machine", "platform.python_implementation": "platform_python_implementation",
           "python_implementation": "platform_python_implementation"}
FLIP = {"<": ">", ">": "<", "<=": ">=", ">=": "<=", "==": "==", "!=": "!="}


class MarkerError(Exception):
    pass


def tokenize(text):
    pos, out = 0, []
    text = text.strip()
    while pos < len(text):
        m = TOKEN_RE.match(text, pos)
        if not m or m.end() == pos:
            raise MarkerError(text)
        kind = m.lastgroup
        val = m.group(kind)
        if kind == "op":
            val = re.sub(r"\s+", " ", val)
        out.append((kind, val))
        pos = m.end()
        while pos < len(text) and text[pos].isspace():
            pos += 1
    return out


def num_tuple(v):
    m = re.fullmatch(r"(\d+(?:\.\d+)*)", v.strip())
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def version_compare(lhs, op, rhs):
    """lhs op rhs for versions: True, False or None (cannot tell)."""
    if Specifier is not None:
        try:
            return Specifier(op + rhs).contains(lhs, prereleases=True)
        except (InvalidSpecifier, InvalidVersion, TypeError, ValueError):
            pass
    a, b = num_tuple(lhs), num_tuple(rhs)
    if a is None or b is None:
        if op == "==":
            return lhs == rhs
        if op == "!=":
            return lhs != rhs
        return None
    if op == "~=":
        if len(b) < 2:
            return None
        return a >= b and a[:len(b) - 1] == b[:len(b) - 1]
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return {"<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b, "==": a == b, "!=": a != b}.get(op)


def compare(lhs, op, rhs, env):
    def value(tok):
        kind, v = tok
        if kind == "str":
            return v[1:-1], None
        name = ALIASES.get(v, v)
        return env.get(name), name
    lv, lname = value(lhs)
    rv, rname = value(rhs)
    if lv is None or rv is None:
        return None
    if lname == "extra" or rname == "extra":
        lv, rv = canon(lv), canon(rv)
    if op == "in":
        return lv in rv
    if op == "not in":
        return lv not in rv
    if op == "===":
        return lv == rv
    vname = lname or rname
    if vname in VERSION_VARS or op in ("<", ">", "<=", ">=", "~="):
        if lname:
            return version_compare(lv, op, rv)
        if op in FLIP:
            return version_compare(rv, FLIP[op], lv)
        return None
    if op == "==":
        return lv == rv
    if op == "!=":
        return lv != rv
    return None


def k_and(a, b):
    if a is False or b is False:
        return False
    if a is None or b is None:
        return None
    return True


def k_or(a, b):
    if a is True or b is True:
        return True
    if a is None or b is None:
        return None
    return False


def eval_marker(text, env):
    """True, False, or None when it depends on something not known here.
    A marker that cannot be parsed is None as well."""
    if not text or not text.strip():
        return True
    try:
        toks = tokenize(text)
    except MarkerError:
        return None
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else (None, None)

    def take():
        t = peek()
        pos[0] += 1
        return t

    def atom():
        kind, _v = peek()
        if kind == "lp":
            take()
            r = expr()
            if take()[0] != "rp":
                raise MarkerError(text)
            return r
        lhs = take()
        op = take()
        rhs = take()
        if lhs[0] not in ("var", "str") or op[0] != "op" or rhs[0] not in ("var", "str"):
            raise MarkerError(text)
        return compare(lhs, op[1], rhs, env)

    def and_expr():
        r = atom()
        while peek() == ("bool", "and"):
            take()
            r = k_and(r, atom())
        return r

    def expr():
        r = and_expr()
        while peek() == ("bool", "or"):
            take()
            r = k_or(r, and_expr())
        return r

    try:
        result = expr()
        if pos[0] != len(toks):
            return None
        return result
    except (MarkerError, IndexError):
        return None


# --------------------------------------------------------------------------
# Requirements
# --------------------------------------------------------------------------

REQ_RE = re.compile(r"^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[([^\]]*)\])?\s*(.*)$")


def parse_req(line):
    """(canon name, extras, spec, marker) of a PEP 508 requirement, or None."""
    m = REQ_RE.match(line or "")
    if not m:
        return None
    rest = m.group(3) or ""
    marker = ""
    if ";" in rest:
        rest, marker = rest.split(";", 1)
    if rest.strip().startswith("@"):
        rest = ""
    extras = {canon(e) for e in (m.group(2) or "").split(",") if e.strip()}
    return canon(m.group(1)), extras, rest.strip().strip("()").strip(), marker.strip()


def exact_pin(spec):
    m = re.fullmatch(r"===?\s*([0-9][^,\s*]*)", spec or "")
    return m.group(1) if m else None


def requirement_files(src, prune):
    out = []
    root_depth = src.rstrip(os.sep).count(os.sep)
    for cur, dirs, files in os.walk(src):
        depth = cur.count(os.sep) - root_depth
        keep = []
        for d in sorted(dirs):
            full = os.path.join(cur, d)
            if d in ALWAYS_PRUNE or d in prune or os.path.isfile(os.path.join(full, "pyvenv.cfg")):
                continue
            if os.path.islink(full):
                continue
            keep.append(d)
        dirs[:] = keep if depth < MAX_DEPTH else []
        base = os.path.basename(cur)
        for f in sorted(files):
            if (re.fullmatch(r"[^/]*requirements[^/]*\.txt", f, re.I)
                    or (base == "requirements" and f.endswith(".txt"))):
                out.append(("requirements", os.path.join(cur, f)))
            elif f == "pyproject.toml":
                out.append(("pyproject", os.path.join(cur, f)))
            elif f == "setup.cfg":
                out.append(("setupcfg", os.path.join(cur, f)))
    return out


def read_requirements(path, root, seen=None):
    """PEP 508 lines of a requirements file, following -r includes in the tree."""
    seen = seen if seen is not None else set()
    real = os.path.realpath(path)
    if real in seen or not inside(path, root):
        return []
    seen.add(real)
    text = read_capped(path, MAX_MANIFEST_BYTES)
    if text is None:
        return []
    text = re.sub(r"\\\r?\n", " ", text)
    out = []
    for raw in text.splitlines():
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()
        if not line:
            continue
        m = re.match(r"^(-r|--requirement)(?:\s+|=)(\S+)", line)
        if m:
            out += read_requirements(os.path.join(os.path.dirname(path), m.group(2)), root, seen)
            continue
        if line.startswith("-"):
            continue                                   # -c, -e, --index-url, --hash, ...
        if re.match(r"^[a-z][a-z0-9+.-]*://", line, re.I) or line.startswith((".", "/")) \
                or re.search(r"\.(whl|zip|tar\.gz|tgz)$", line.split(";")[0].strip(), re.I):
            continue                                   # a path or URL, no name
        line = re.sub(r"\s--hash[= ]\S+", "", line)
        out.append(line)
    return out


def poetry_dep(name, spec):
    """A Poetry dependency table entry as a PEP 508 line, or None for optional."""
    marker = ""
    extras = ""
    if isinstance(spec, dict):
        if spec.get("optional"):
            return None
        if isinstance(spec.get("markers"), str):
            marker = spec["markers"]
        if isinstance(spec.get("platform"), str):
            plat = f'sys_platform == "{spec["platform"]}"'
            marker = f"({marker}) and {plat}" if marker else plat
        if isinstance(spec.get("extras"), list):
            extras = "[" + ",".join(str(e) for e in spec["extras"]) + "]"
    elif isinstance(spec, list):
        # Several constraints for different markers: keep the name, which
        # every one of them installs on some platform.
        return name
    return name + extras + (f"; {marker}" if marker else "")


def read_pyproject(path, include_dev):
    """(project name, PEP 508 lines, readable)."""
    try:
        import tomllib
    except ImportError:
        return None, [], False
    text = read_capped(path, MAX_MANIFEST_BYTES)
    if text is None:
        return None, [], False
    try:
        data = tomllib.loads(text)
    except Exception:
        return None, [], False
    lines, name = [], None
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    if isinstance(project.get("name"), str):
        name = project["name"]
    for d in project.get("dependencies") or []:
        if isinstance(d, str):
            lines.append(d)
    tool = data.get("tool") if isinstance(data.get("tool"), dict) else {}
    poetry = tool.get("poetry") if isinstance(tool.get("poetry"), dict) else {}
    if not name and isinstance(poetry.get("name"), str):
        name = poetry["name"]
    tables = [poetry.get("dependencies")]
    if include_dev:
        tables.append(poetry.get("dev-dependencies"))
        groups = poetry.get("group") if isinstance(poetry.get("group"), dict) else {}
        tables += [g.get("dependencies") for g in groups.values() if isinstance(g, dict)]
        dg = data.get("dependency-groups") if isinstance(data.get("dependency-groups"), dict) else {}
        for items in dg.values():
            lines += [d for d in (items or []) if isinstance(d, str)]
        uv = tool.get("uv") if isinstance(tool.get("uv"), dict) else {}
        lines += [d for d in (uv.get("dev-dependencies") or []) if isinstance(d, str)]
    for table in tables:
        if not isinstance(table, dict):
            continue
        for dep, spec in table.items():
            if str(dep).lower() == "python":
                continue
            line = poetry_dep(str(dep), spec)
            if line:
                lines.append(line)
    return name, lines, True


def read_setup_cfg(path):
    import configparser
    text = read_capped(path, MAX_MANIFEST_BYTES)
    if text is None:
        return None, []
    cp = configparser.RawConfigParser(strict=False)
    try:
        cp.read_string(text)
    except configparser.Error:
        return None, []
    name = cp.get("metadata", "name", fallback=None)
    reqs = cp.get("options", "install_requires", fallback="") or ""
    return name, [r.strip() for r in reqs.splitlines() if r.strip() and not r.strip().startswith("#")]


# --------------------------------------------------------------------------
# Installed distributions
# --------------------------------------------------------------------------

def egg_requires(text):
    """requires.txt of an .egg-info, as PEP 508 lines."""
    out, marker = [], ""
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.fullmatch(r"\[([^\]]*)\]", line)
        if m:
            sect = m.group(1)
            extra, _, cond = sect.partition(":")
            parts = []
            if extra.strip():
                parts.append(f'extra == "{extra.strip()}"')
            if cond.strip():
                parts.append(f"({cond.strip()})")
            marker = " and ".join(parts)
            continue
        out.append(line + (f"; {marker}" if marker else ""))
    return out


def read_dists(sites, root):
    dists, dirs, dupes = {}, [], set()
    parser = HeaderParser()
    for site in sites:
        try:
            entries = sorted(os.listdir(site))
        except OSError:
            continue
        for e in entries:
            if len(dists) >= MAX_DISTS:
                break
            d = os.path.join(site, e)
            if e.endswith(".dist-info"):
                meta_path, req_path = os.path.join(d, "METADATA"), None
            elif e.endswith(".egg-info"):
                if os.path.isdir(d):
                    meta_path, req_path = os.path.join(d, "PKG-INFO"), os.path.join(d, "requires.txt")
                else:
                    meta_path, req_path = d, None
            else:
                continue
            if not inside(meta_path, root):
                continue
            text = read_capped(meta_path, MAX_META_BYTES)
            if text is None:
                continue
            # The headers end at the first blank line; the long description
            # after it is not needed.
            head = re.split(r"\r?\n\r?\n", text, maxsplit=1)[0]
            try:
                msg = parser.parsestr(head + "\n")
            except Exception:
                continue
            name, version = msg.get("Name"), msg.get("Version")
            if not name or not version:
                continue
            requires = [str(r) for r in (msg.get_all("Requires-Dist") or [])]
            if req_path and inside(req_path, root):
                requires += egg_requires(read_capped(req_path, MAX_MANIFEST_BYTES))
            key = canon(name)
            info = {
                "name": key, "version": str(version).strip(), "requires": requires,
                "meta": meta_path,
                "expression": msg.get("License-Expression"),
                "license": msg.get("License"),
                "classifiers": [str(c) for c in (msg.get_all("Classifier") or [])],
                "summary": msg.get("Summary"),
                "home": msg.get("Home-page"),
                "urls": [str(u) for u in (msg.get_all("Project-URL") or [])],
            }
            if os.path.isdir(d):
                dirs.append(d)
            if key in dists:
                dupes.add(key)
                if newer(info["version"], dists[key]["version"]):
                    dists[key] = info
                continue
            dists[key] = info
    return dists, dirs, dupes


def newer(a, b):
    if Version is not None:
        try:
            return Version(a) > Version(b)
        except (InvalidVersion, TypeError, ValueError):
            pass
    ta, tb = num_tuple(a), num_tuple(b)
    return bool(ta and tb and ta > tb)


def licenses_of(info):
    expr = (info.get("expression") or "").strip()
    if expr:
        if re.search(r"\s(AND|OR|WITH)\s", expr):
            return [{"expression": expr}]
        return [{"license": {"name": expr}}]
    lic = (info.get("license") or "").strip()
    if lic and "\n" not in lic and len(lic) <= 100 and lic.upper() not in ("UNKNOWN", "NONE"):
        return [{"license": {"name": lic}}]
    names = []
    for c in info.get("classifiers") or []:
        parts = [p.strip() for p in c.split("::")]
        if len(parts) >= 2 and parts[0] == "License" and parts[-1] not in ("OSI Approved", "Other/Proprietary License"):
            if parts[-1] not in names:
                names.append(parts[-1])
    return [{"license": {"name": n}} for n in names]


def url_ok(u):
    return isinstance(u, str) and re.fullmatch(r"https?://[^\s\"<>]+", u.strip() or "") is not None


def external_refs(info):
    refs, seen = [], set()

    def add(kind, url):
        url = url.strip()
        if url_ok(url) and (kind, url) not in seen:
            seen.add((kind, url))
            refs.append({"type": kind, "url": url})
    if info.get("home"):
        add("website", info["home"])
    for entry in info.get("urls") or []:
        label, _, url = entry.partition(",")
        lab = label.strip().lower()
        if lab in ("homepage", "home", "home-page"):
            add("website", url)
        elif lab in ("source", "source code", "repository", "code", "github"):
            add("vcs", url)
        elif lab in ("issues", "bug tracker", "tracker", "issue tracker"):
            add("issue-tracker", url)
        elif lab in ("documentation", "docs"):
            add("documentation", url)
    return refs


# --------------------------------------------------------------------------
# read
# --------------------------------------------------------------------------

def outcome(results):
    """Fold the values a marker gave for each active extra."""
    if any(r is True for r in results):
        return True
    if any(r is None for r in results):
        return None
    return False


def cmd_read(src, venv_rel, out_path):
    root = os.path.realpath(src)
    found = find_venv(src)
    if not found or found[0] != venv_rel:
        print("no installed environment", file=sys.stderr)
        return 1
    _rel, sites, cfg = found
    dists, dist_dirs, dupes = read_dists(sites, root)
    env = marker_env(sites, cfg, dist_dirs)
    include_dev = os.environ.get("BOMLENS_INCLUDE_DEV_DEPENDENCIES") in ("1", "true")
    prune = set((os.environ.get("BOMLENS_NON_SHIPPED_DIRS") or "").split())

    declared, project_names, unreadable = [], set(), []
    for kind, path in requirement_files(src, prune):
        rel = os.path.relpath(path, src).replace(os.sep, "/")
        if kind == "requirements":
            declared += [(rel, line) for line in read_requirements(path, root)]
        elif kind == "pyproject":
            name, lines, ok = read_pyproject(path, include_dev)
            if not ok:
                unreadable.append(rel)
            if name:
                project_names.add(canon(name))
            declared += [(rel, line) for line in lines]
        else:
            name, lines = read_setup_cfg(path)
            if name:
                project_names.add(canon(name))
            declared += [(rel, line) for line in lines]

    direct = []
    for rel, line in declared:
        parsed = parse_req(line)
        if parsed and parsed[0] not in project_names:
            direct.append(parsed)
    if not direct:
        why = "no declared dependency could be read"
        if unreadable:
            why += " (" + ", ".join(unreadable[:3]) + " not readable here)"
        print(why, file=sys.stderr)
        return 2

    unsure_edges, missing, mismatch = set(), set(), []
    active = {}
    edges = {}
    root_edges = set()
    queue = []

    def activate(name, extras):
        before = active.get(name)
        now = (before or set()) | extras
        if before is None or now != before:
            active[name] = now
            queue.append(name)

    for name, extras, spec, marker in direct:
        r = eval_marker(marker, dict(env, extra=""))
        if r is False:
            continue
        if name not in dists:
            missing.add(name)
            continue
        if r is None:
            unsure_edges.add(("", name))
        pin = exact_pin(spec)
        if pin and pin != dists[name]["version"] and not (Version is not None and same_version(pin, dists[name]["version"])):
            mismatch.append(f"{name} ({dists[name]['version']}, declared {pin})")
        root_edges.add(name)
        activate(name, extras)

    while queue:
        name = queue.pop(0)
        info = dists[name]
        extras = [""] + sorted(active.get(name) or ())
        for line in info["requires"]:
            parsed = parse_req(line)
            if not parsed:
                continue
            child, child_extras, _spec, marker = parsed
            if child == name or child in project_names:
                continue
            r = outcome([eval_marker(marker, dict(env, extra=x)) for x in extras])
            if r is False:
                continue
            if child not in dists:
                if r is True:
                    missing.add(child)
                continue
            if r is None:
                unsure_edges.add((name, child))
            edges.setdefault(name, set()).add(child)
            activate(child, child_extras)

    kept = sorted(active)
    if not kept:
        print("none of the declared dependencies is installed in " + venv_rel, file=sys.stderr)
        return 3

    purl = {n: f"pkg:pypi/{n}@{quote(dists[n]['version'], safe='.!-_~')}" for n in kept}
    components = []
    for n in kept:
        info = dists[n]
        c = {"type": "library", "name": n, "version": info["version"], "purl": purl[n], "bom-ref": purl[n]}
        if info.get("summary") and "\n" not in info["summary"]:
            c["description"] = info["summary"].strip()[:500]
        lic = licenses_of(info)
        if lic:
            c["licenses"] = lic
        refs = external_refs(info)
        if refs:
            c["externalReferences"] = refs
        c["properties"] = [{"name": "SrcFile", "value": os.path.relpath(info["meta"], src).replace(os.sep, "/")}]
        components.append(c)
    dependencies = [{"ref": "bomlens-python-environment-root", "dependsOn": sorted(purl[n] for n in root_edges)}]
    for n in kept:
        dependencies.append({"ref": purl[n], "dependsOn": sorted(purl[c] for c in edges.get(n, ()) if c in purl)})

    unsure = []
    if unsure_edges:
        unsure.append(f"{len(unsure_edges)} dependency marker(s) could not be evaluated")
    if missing:
        unsure.append("declared but not installed: " + ", ".join(sorted(missing)[:5]) + (" (+%d more)" % (len(missing) - 5) if len(missing) > 5 else ""))
    if mismatch:
        unsure.append("installed version differs from the declared pin: " + ", ".join(mismatch[:3]) + (" (+%d more)" % (len(mismatch) - 3) if len(mismatch) > 3 else ""))
    if dupes:
        unsure.append("more than one installed version of " + ", ".join(sorted(dupes)[:3]))
    if (cfg.get("include-system-site-packages") or "").lower() == "true":
        unsure.append("the environment also uses the system site-packages, which are not here")
    unsure_text = "; ".join(unsure)[:300]

    doc = {
        "bomFormat": "CycloneDX", "specVersion": CDX_SPEC_VERSION, "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "properties": [{"name": "bomlens:python-environment-unsure", "value": unsure_text}] if unsure_text else [],
        },
        "components": components,
        "dependencies": dependencies,
    }
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
    os.replace(tmp, out_path)
    print(f"{len(kept)}\t{len(dists)}\t{VERSION_ENGINE}\t{unsure_text}")
    return 0


def same_version(a, b):
    try:
        return Version(a) == Version(b)
    except (InvalidVersion, TypeError, ValueError):
        return False


# --------------------------------------------------------------------------
# merge
# --------------------------------------------------------------------------

def cmd_merge(bom_path, venv_path, venv_rel, reason):
    with open(bom_path, encoding="utf-8") as fh:
        bom = json.load(fh)
    with open(venv_path, encoding="utf-8") as fh:
        venv = json.load(fh)
    if not isinstance(bom, dict):
        return 1
    bom.setdefault("metadata", {})
    root = (bom["metadata"].get("component") or {}).get("bom-ref")
    if not root and not bom["metadata"].get("component"):
        # cdxgen with its python cataloger left out finds no project in a
        # Python-only tree and writes no root. One is made the way cdxgen
        # names it (pkg:pypi/<name>@<version>), so the declared dependencies
        # hang from it; stamp-metadata.sh sets the name and version later.
        name = canon(os.environ.get("PROJECT_NAME") or "") or "app"
        version = (os.environ.get("PROJECT_VERSION") or "latest").strip() or "latest"
        root = f"pkg:pypi/{quote(name, safe='.-_~')}@{quote(version, safe='.!-_~')}"
        if any(c.get("bom-ref") == root for c in (venv.get("components") or []) + (bom.get("components") or [])
               if isinstance(c, dict)):
            root = "bomlens-project-root"
        bom["metadata"]["component"] = {"type": "application", "name": name, "version": version, "bom-ref": root}
    have = set()

    def walk(items):
        for c in items or []:
            if isinstance(c, dict):
                if c.get("bom-ref"):
                    have.add(c["bom-ref"])
                walk(c.get("components"))
    if not isinstance(bom.get("components"), list):
        bom["components"] = []
    walk(bom["components"])
    added = 0
    for c in venv.get("components") or []:
        if c.get("bom-ref") in have:
            continue
        bom["components"].append(c)
        have.add(c["bom-ref"])
        added += 1
    if not isinstance(bom.get("dependencies"), list):
        bom["dependencies"] = []
    by_ref = {d.get("ref"): d for d in bom["dependencies"] if isinstance(d, dict)}
    for d in venv.get("dependencies") or []:
        ref = d.get("ref")
        if ref == "bomlens-python-environment-root":
            if not root:
                continue
            ref = root
        on = [x for x in d.get("dependsOn") or [] if x in have]
        cur = by_ref.get(ref)
        if cur is None:
            cur = {"ref": ref, "dependsOn": []}
            bom["dependencies"].append(cur)
            by_ref[ref] = cur
        cur["dependsOn"] = sorted(set(cur.get("dependsOn") or []) | set(on))
    names = ("bomlens:python-environment", "bomlens:python-environment-reason",
             "bomlens:python-environment-unsure")
    props = [p for p in bom["metadata"].get("properties") or [] if p.get("name") not in names]
    props.append({"name": "bomlens:python-environment", "value": venv_rel})
    props.append({"name": "bomlens:python-environment-reason", "value": reason})
    for p in (venv.get("metadata") or {}).get("properties") or []:
        if p.get("name") in names:
            props.append(p)
    bom["metadata"]["properties"] = props
    tmp = bom_path + ".venv.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(bom, fh, indent=2)
    os.replace(tmp, bom_path)
    print(added)
    return 0


def main(argv):
    if len(argv) >= 2 and argv[0] == "find":
        found = find_venv(argv[1])
        if not found:
            return 1
        print(found[0])
        for s in found[1]:
            print(os.path.abspath(s))
        return 0
    if len(argv) >= 4 and argv[0] == "read":
        return cmd_read(argv[1], argv[2], argv[3])
    if len(argv) >= 5 and argv[0] == "merge":
        return cmd_merge(argv[1], argv[2], argv[3], argv[4])
    print(__doc__.split("\n\n")[1], file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
