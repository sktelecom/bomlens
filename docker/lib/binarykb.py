#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Binary knowledge base: find open-source components in binaries from what their releases leave behind.

Two kinds of evidence, both read out of the release sources rather than out of a package manager:

  strings    The printable parts of every C string literal in a release. A binary that carries
             many literals only one component has is that component. A literal shared between
             components counts for less (length / 5^(owners - 1)) and goes to the owner that
             already scores highest, so a library copied into several programs is credited to the
             package it came from. The same literals say which releases contain them, which gives
             the version as a set of candidates.
  tables     Large read-only data objects (CRC, Huffman and cipher tables). They survive static
             linking and function-level garbage collection when the strings do not. Tables that
             also occur in a background file are dropped, and each table is stored in both byte
             orders so a signature built on one architecture is found on the other.

A component is reported when its strings score at least `score` with at least `unique` strings
only it has, or when at least `table_count` distinct tables totalling `table_bytes` bytes are found.

Usage:
  binarykb.py build --kb kb.csv [--bg DIR]... [--ref refs.csv] [--ref-bg files.txt]
                    [--kernel-only NAME]... --release ID --out kb.sqlite3
      kb.csv     lines `component,version,tarball[,url[,purl]]`. Every release of a component belongs
                 here; a version missing from the list is reported as the nearest release that is there.
                 `url` is where the tarball was published, `purl` the package URL of the component
                 without a version (`pkg:generic/busybox`); both are optional and kept in the base.
      DIR        tarballs of packages that are not reported. Their strings only lower the weight
                 of strings they share with a reported component.
      refs.csv   lines `component,path` of unstripped ELF files; each large read-only object with a
                 symbol becomes a table signature.
      files.txt  one path per line; a table found in one of these files is not a signature.
      --kernel-only NAME   report NAME only for kernel images and modules.
      --rule-score N, --rule-unique N, --rule-table-count N, --rule-table-bytes N
                 the detection thresholds stored in the base (defaults 300, 10, 4, 4096). The right values
                 depend on the base: measure false positives on binaries that hold none of its components
                 and raise the score until they stop.
  binarykb.py info kb.sqlite3

The database is SQLite, opened read-only, and holds no code and no text from the sources: a literal is
kept as the first 8 bytes of its SHA-256 and its length, and a table as one 16-byte window, its length
and its SHA-256. The tarball each release was read from is recorded by its SHA-256 (and URL when given).
"""
import argparse
import collections
import hashlib
import json
import os
import re
import sqlite3
import sys
import tarfile

SCHEMA = 2
READABLE_SCHEMAS = (1, 2)   # schema 1 keeps literals and tables as text and bytes
STRING_KEY_BYTES = 8
MIN_LEN = 6
SRC_EXT = ('.c', '.h', '.cc', '.cpp', '.cxx', '.hh', '.hpp')
TABLE_MIN_SIZE, TABLE_KEY = 256, 16
DEFAULT_RULE = {'score': 300, 'unique': 10, 'table_count': 4, 'table_bytes': 4096}
KERNEL_FILE = re.compile(r'(\.ko(\.[a-z0-9]+)?$|^(vmlinu|zImage|bzImage|uImage|Image)[^/]*$)')

TOKEN = re.compile(rb'//[^\n]*|/\*.*?\*/|\'(?:[^\'\\\n]|\\.){1,4}\'|("(?:[^"\\\n]|\\.)*"(?:\s*"(?:[^"\\\n]|\\.)*")*)', re.S)
LITERAL = re.compile(rb'"((?:[^"\\\n]|\\.)*)"')
ESCAPE = re.compile(rb'\\(x[0-9a-fA-F]{1,2}|[0-7]{1,3}|.)', re.S)
SIMPLE = {b'n': b'\n', b't': b'\t', b'r': b'\r', b'a': b'\a', b'b': b'\b', b'f': b'\f', b'v': b'\v'}
PRINTABLE_RUN = re.compile(rb'[\x20-\x7e\t]{%d,}' % MIN_LEN)


# --------------------------------------------------------------------------- ELF

MAX_SECTIONS = 4096   # real images stay far below this; a header claiming more is crafted or damaged

def elf_header(data):
    """(is64, byte order) of an ELF file, or None."""
    if data[:4] != b'\x7fELF' or len(data) < 64 or data[4] not in (1, 2) or data[5] not in (1, 2):
        return None
    return data[4] == 2, 'little' if data[5] == 1 else 'big'


def elf_sections(data):
    """[(name, type, addr, offset, size, link, entsize)] of an ELF file of either class and byte order, or None."""
    h = elf_header(data)
    if h is None:
        return None
    is64, order = h
    i = lambda off, n: int.from_bytes(data[off:off + n], order)
    shoff, shentsize, shnum, shstrndx = (i(0x28, 8), i(0x3a, 2), i(0x3c, 2), i(0x3e, 2)) if is64 \
        else (i(0x20, 4), i(0x2e, 2), i(0x30, 2), i(0x32, 2))
    if shentsize < (64 if is64 else 40) or shnum > MAX_SECTIONS:
        return None
    if not shoff or shstrndx >= shnum or shoff + shnum * shentsize > len(data):
        return None
    secs = []
    for k in range(shnum):
        b = shoff + k * shentsize
        if is64:
            secs.append((i(b, 4), i(b + 4, 4), i(b + 0x10, 8), i(b + 0x18, 8), i(b + 0x20, 8), i(b + 0x28, 4), i(b + 0x38, 8)))
        else:
            secs.append((i(b, 4), i(b + 4, 4), i(b + 0x0c, 4), i(b + 0x10, 4), i(b + 0x14, 4), i(b + 0x18, 4), i(b + 0x24, 4)))
    names = secs[shstrndx][3]

    def name_at(o):
        e = data.find(b'\0', names + o)
        return data[names + o:e if e >= 0 else names + o]
    return [(name_at(s[0]),) + s[1:] for s in secs]


def string_bytes(data):
    """The bytes strings are read from: .rodata*, .data and .modinfo of an ELF file, else the whole file."""
    try:
        secs = elf_sections(data)
    except (ValueError, IndexError):
        secs = None
    if secs is None:
        return data, False
    spans = sorted((off, min(off + size, len(data))) for name, typ, _, off, size, _, _ in secs
                   if typ != 8 and off < len(data) and (name.startswith(b'.rodata') or name in (b'.data', b'.modinfo')))   # 8 = NOBITS
    parts, end = [], 0
    for a, b in spans:   # sections that overlap are read once, so the result never exceeds the file
        a = max(a, end)
        if b > a:
            parts.append(data[a:b]); end = b
    return b'\0'.join(parts), True


def rodata_objects(path):
    """(symbol name, bytes) of every large read-only data object of an ELF file that has a .symtab."""
    data = open(path, 'rb').read()
    h = elf_header(data)
    try:
        secs = elf_sections(data) if h else None
    except (ValueError, IndexError):
        secs = None
    if secs is None:
        return []
    is64, order = h
    i = lambda off, n: int.from_bytes(data[off:off + n], order)
    rodata = {k for k, s in enumerate(secs) if s[0].startswith(b'.rodata') and s[1] != 8}
    out = []
    for _, typ, _, off, size, link, ent in secs:
        if typ != 2:   # SHT_SYMTAB
            continue
        stroff = secs[link][3]
        for e in range(off, off + size, ent or (24 if is64 else 16)):
            if is64:
                nm, info, shndx, value, ssize = i(e, 4), data[e + 4], i(e + 6, 2), i(e + 8, 8), i(e + 16, 8)
            else:
                nm, value, ssize, info, shndx = i(e, 4), i(e + 4, 4), i(e + 8, 4), data[e + 12], i(e + 14, 2)
            if info & 0xf != 1 or shndx not in rodata or ssize < TABLE_MIN_SIZE:   # 1 = STT_OBJECT
                continue
            s = secs[shndx]
            blob = data[s[3] + value - s[2]:s[3] + value - s[2] + ssize]
            if len(blob) == ssize and len(set(blob)) >= 16:
                end = data.find(b'\0', stroff + nm)
                out.append((data[stroff + nm:end].decode('latin-1'), blob))
    return out


def byte_order_variants(blob):
    """The table as stored on a little-endian target and, with the element bytes reversed, on a big-endian one.

    The element size of a table is not known from its symbol, so the 2, 4 and 8 byte reversals are all kept.
    A table of single bytes has one form.
    """
    out = [blob]
    for n in (2, 4, 8):
        if len(blob) % n == 0:
            v = b''.join(blob[j:j + n][::-1] for j in range(0, len(blob), n))
            if v not in out:
                out.append(v)
    return out


# --------------------------------------------------------------------------- sources

def _unescape(m):
    e = m.group(1)
    if e in SIMPLE:
        return SIMPLE[e]
    if e[:1] == b'x' and len(e) > 1:
        return bytes([int(e[1:], 16)])
    if e[:1] in b'01234567':
        return bytes([int(e, 8) & 0xff])
    return e


# A literal that is only an upper-case constant name (X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT, CKR_SESSION_COUNT)
# says nothing about which package it came from: the package that defines the constant writes it through a
# macro, so it never appears as a literal in that package's own source, while every other package that
# prints the name does carry it. Such names would be credited to whichever release spells them out.
CONSTANT_NAME = re.compile(rb'^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+){2,}$')


def source_strings(tarball):
    """Printable runs of every C string literal (adjacent literals joined, as the compiler does)."""
    out = set()
    with tarfile.open(tarball) as tf:
        for m in tf:
            if not m.isfile() or not m.name.endswith(SRC_EXT):
                continue
            data = tf.extractfile(m).read()
            for t in TOKEN.finditer(data):
                if t.group(1) is None:
                    continue
                text = b''.join(ESCAPE.sub(_unescape, x) for x in LITERAL.findall(t.group(1)))
                out.update(r for r in PRINTABLE_RUN.findall(text) if not CONSTANT_NAME.match(r))
    return out


def version_key(v):
    """Release order of a version string: digit runs compare as numbers, so 2.28.10 follows 2.28.9."""
    return [(0, int(t), '') if t.isdigit() else (1, 0, t) for t in re.findall(r'\d+|[A-Za-z]+', v)]


# --------------------------------------------------------------------------- tables

def string_key(s):
    """The key a literal is stored under: the first 8 bytes of its SHA-256."""
    return hashlib.sha256(s).digest()[:STRING_KEY_BYTES]


def table_entry(blob, k, c, name):
    """(length, SHA-256, window offset, component, name): what a table signature is matched by."""
    return len(blob), hashlib.sha256(blob).digest(), k, c, name


def table_key(blob):
    """Offset of the first 16-byte window with at least 8 distinct values, so runs of zeros do not flood the index."""
    return next((k for k in range(len(blob) - TABLE_KEY + 1) if len(set(blob[k:k + TABLE_KEY])) >= 8), None)


def tables_in(index, data):
    """{table name: component id} for every signature table whose bytes occur in data."""
    found, get, sha = {}, index.get, hashlib.sha256
    for p in range(len(data) - TABLE_KEY + 1):
        cand = get(data[p:p + TABLE_KEY])
        if cand:
            for n, digest, k, c, name in cand:
                if name not in found and p >= k and p - k + n <= len(data) and sha(data[p - k:p - k + n]).digest() == digest:
                    found[name] = c
    return found


# --------------------------------------------------------------------------- database

SCHEMA_SQL = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE comp (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, kind TEXT NOT NULL, purl TEXT);
CREATE TABLE ver (comp INTEGER NOT NULL, idx INTEGER NOT NULL, version TEXT NOT NULL, PRIMARY KEY (comp, idx));
CREATE TABLE src (comp INTEGER NOT NULL, version TEXT NOT NULL, sha256 TEXT NOT NULL, url TEXT NOT NULL, PRIMARY KEY (comp, version, sha256)) WITHOUT ROWID;
CREATE TABLE str (h BLOB PRIMARY KEY, n INTEGER NOT NULL, owners TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE strv (h BLOB NOT NULL, comp INTEGER NOT NULL, mask INTEGER NOT NULL, PRIMARY KEY (h, comp)) WITHOUT ROWID;
CREATE TABLE tbl (id INTEGER PRIMARY KEY, comp INTEGER NOT NULL, name TEXT NOT NULL, koff INTEGER NOT NULL, key BLOB NOT NULL, size INTEGER NOT NULL, sha256 BLOB NOT NULL);
CREATE INDEX tbl_key ON tbl (key);
"""


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def mask_value(mask):
    """A version bitmask as SQLite stores it: an integer while it fits in 63 bits, big-endian bytes beyond
    that (a component with more than 63 releases). Readers accept both, so older bases read unchanged."""
    return mask if mask < 1 << 63 else mask.to_bytes((mask.bit_length() + 7) // 8, 'big')


def build(args):
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    if os.path.exists(args.out):
        os.remove(args.out)
    rows = []
    for n, line in enumerate(open(args.kb), 1):
        if not line.strip() or line.startswith('#'):
            continue
        f = line.strip().split(',')
        if not 3 <= len(f) <= 5 or not all(f[:3]):
            sys.exit(f'{args.kb}:{n}: expected component,version,tarball[,url[,purl]]')
        rows.append((f + ['', ''])[:5])
    rows.sort(key=lambda r: (r[0], version_key(r[1])))
    purls, sources = {}, []
    for comp, _, _, _, purl in rows:
        if not purl:
            continue
        if not purl.startswith('pkg:') or '@' in purl:
            sys.exit(f'{args.kb}: purl of {comp} must be a package URL without a version: {purl}')
        if purls.setdefault(comp, purl) != purl:
            sys.exit(f'{args.kb}: {comp} has two purls: {purls[comp]} and {purl}')
    names, kinds, owners = {}, {}, collections.defaultdict(set)
    versions = collections.defaultdict(list)
    vmask = collections.defaultdict(dict)          # comp -> {string: version bitmask}

    def comp_id(name, kind):
        if name not in names:
            names[name] = len(names) + 1; kinds[name] = kind
        return names[name]

    for comp, ver, tb, url, _ in rows:
        cid = comp_id(comp, 'kb')
        sources.append((cid, ver, file_sha256(tb), url))
        bit = 1 << len(versions[comp])
        versions[comp].append(ver)
        strings = source_strings(tb)
        for s in strings:
            owners[s].add(cid)
            vmask[comp][s] = vmask[comp].get(s, 0) | bit
        print(f'{comp} {ver}: {len(strings)} strings', file=sys.stderr)
    for d in args.bg or []:
        for tb in sorted(os.path.join(d, f) for f in os.listdir(d)):
            base = re.split(r'-\d', os.path.basename(tb), maxsplit=1)[0]
            if base in versions:
                # A component's own release in the background would make every one of its strings shared,
                # so it could never score unique strings and would never be reported.
                print(f'background {os.path.basename(tb)} skipped: {base} is a component', file=sys.stderr)
                continue
            name = 'bg:' + base
            cid = comp_id(name, 'bg')
            sources.append((cid, '', file_sha256(tb), ''))
            strings = source_strings(tb)
            for s in strings:
                owners[s].add(cid)
            print(f'{name}: {len(strings)} strings', file=sys.stderr)

    # Table signatures from unstripped reference builds.
    tcomp, tname = collections.defaultdict(set), {}
    for line in (open(args.ref) if args.ref else []):
        if not line.strip():
            continue
        comp, path = line.rstrip('\n').split(',', 1)
        objs = rodata_objects(path)
        if not objs:
            print(f'no tables (stripped or not an ELF file): {path}', file=sys.stderr)
        for name, blob in objs:
            tcomp[blob].add(comp_id(comp, 'kb')); tname.setdefault(blob, f'{comp}:{os.path.basename(path)}:{name}')
    index, per = collections.defaultdict(list), collections.Counter()
    for blob, cs in tcomp.items():
        if len(cs) != 1:
            continue   # a table two components carry says nothing about either
        c = next(iter(cs))
        for v in byte_order_variants(blob):
            k = table_key(v)
            if k is not None:
                index[v[k:k + TABLE_KEY]].append(table_entry(v, k, c, tname[blob]))
        per[c] += 1
    dropped = collections.Counter()
    for path in (l.strip() for l in open(args.ref_bg)) if args.ref_bg else []:
        if not path:
            continue
        for name, c in tables_in(index, open(path, 'rb').read()).items():
            for key in list(index):
                index[key] = [e for e in index[key] if e[4] != name]
                if not index[key]:
                    del index[key]
            dropped[c] += 1
            print(f'background {os.path.basename(path)}: {name}', file=sys.stderr)

    con = sqlite3.connect(args.out)
    con.executescript(SCHEMA_SQL)
    rule = dict(DEFAULT_RULE)
    for k in rule:
        if getattr(args, 'rule_' + k, None) is not None:
            rule[k] = getattr(args, 'rule_' + k)
    meta = {'schema': SCHEMA, 'release': args.release, 'rule': rule, 'kernel_only': sorted(args.kernel_only or [])}
    con.executemany('INSERT INTO meta VALUES (?,?)', [(k, json.dumps(v)) for k, v in meta.items()])
    con.executemany('INSERT INTO comp VALUES (?,?,?,?)', [(i, n, kinds[n], purls.get(n)) for n, i in sorted(names.items(), key=lambda x: x[1])])
    con.executemany('INSERT OR IGNORE INTO src VALUES (?,?,?,?)', sorted(sources))
    con.executemany('INSERT INTO ver VALUES (?,?,?)', [(names[c], j, v) for c in sorted(versions) for j, v in enumerate(versions[c])])
    # Rows go in sorted, so the same inputs give the same file bytes whatever the hash seed or the machine.
    # Two literals whose keys collide would share one row and credit each other's owners; neither is kept.
    keys, clash = {}, set()
    for s in owners:
        h = string_key(s)
        if h in keys:
            clash.add(h)
        keys[h] = s
    for h in clash:
        print(f'string key collision, dropped: {h.hex()}', file=sys.stderr)
    keyed = sorted((h, s) for h, s in keys.items() if h not in clash)
    con.executemany('INSERT INTO str VALUES (?,?,?)', ((h, len(s), ','.join(str(i) for i in sorted(owners[s]))) for h, s in keyed))
    key_of = {s: h for h, s in keyed}
    con.executemany('INSERT INTO strv VALUES (?,?,?)', ((h, names[c], mask_value(m)) for c in sorted(vmask)
                                                        for h, m in sorted((key_of[s], m) for s, m in vmask[c].items() if s in key_of)))
    rows_t = sorted((key, k, c, name, n, digest) for key, ents in index.items() for n, digest, k, c, name in ents)
    for i, (key, k, c, name, n, digest) in enumerate(rows_t, 1):
        con.execute('INSERT INTO tbl VALUES (?,?,?,?,?,?,?)', (i, c, name, k, key, n, digest))
    con.commit(); con.close()
    print(f'db: {len(owners)} distinct strings, {sum(1 for _ in per)} components with table signatures '
          f'({sum(per.values())} tables, {sum(dropped.values())} dropped as background)', file=sys.stderr)


# --------------------------------------------------------------------------- reading

class KnowledgeBase:
    """A built database, opened read-only."""

    def __init__(self, path):
        self.path = path
        self.con = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
        self.meta = {k: json.loads(v) for k, v in self.con.execute('SELECT key, value FROM meta')}
        self.schema = self.meta.get('schema')
        if self.schema not in READABLE_SCHEMAS:
            raise ValueError(f'unsupported knowledge base schema {self.schema!r} (this reader knows {", ".join(map(str, READABLE_SCHEMAS))})')
        hashed = self.schema >= 2
        self._key = string_key if hashed else bytes
        self._col = 'h' if hashed else 's'
        self.rule = dict(DEFAULT_RULE, **self.meta.get('rule', {}))
        self.release = self.meta.get('release', '')
        self.kernel_only = set(self.meta.get('kernel_only', []))
        self.comps = {i: (n, k) for i, n, k in self.con.execute('SELECT id, name, kind FROM comp')}
        self.purls = dict(self.con.execute('SELECT name, purl FROM comp WHERE purl IS NOT NULL')) if hashed else {}
        self.versions = collections.defaultdict(list)
        for c, _, v in self.con.execute('SELECT comp, idx, version FROM ver ORDER BY comp, idx'):
            self.versions[c].append(v)
        self.index = collections.defaultdict(list)
        self.table_size = {}
        if hashed:
            for c, name, k, key, n, digest in self.con.execute('SELECT comp, name, koff, key, size, sha256 FROM tbl'):
                self.index[bytes(key)].append((n, bytes(digest), k, c, name)); self.table_size[name] = n
        else:
            for c, name, k, key, data in self.con.execute('SELECT comp, name, koff, key, data FROM tbl'):
                self.index[bytes(key)].append(table_entry(bytes(data), k, c, name)); self.table_size[name] = len(data)
        self._owners = {}

    def owners_of(self, strings):
        """{string: tuple of component ids} for the strings the database knows."""
        need = [s for s in strings if s not in self._owners]
        hashed = self.schema >= 2
        for i in range(0, len(need), 500):
            chunk = need[i:i + 500]
            by_key = {self._key(s): s for s in chunk}
            cols = 'h, n, owners' if hashed else 's, 0, owners'
            for k, n, o in self.con.execute(f'SELECT {cols} FROM str WHERE {self._col} IN ({",".join("?" * len(by_key))})', list(by_key)):
                s = by_key[bytes(k)]
                if not hashed or n == len(s):
                    self._owners[s] = tuple(int(x) for x in o.split(','))
            for s in chunk:
                self._owners.setdefault(s, ())
        return {s: self._owners[s] for s in strings if self._owners[s]}

    def _masks(self, comp, strings):
        out = {}
        for i in range(0, len(strings), 500):
            by_key = {self._key(s): s for s in strings[i:i + 500]}
            for k, m in self.con.execute(f'SELECT {self._col}, mask FROM strv WHERE comp = ? AND {self._col} IN ({",".join("?" * len(by_key))})',
                                         [comp] + list(by_key)):
                out[by_key[bytes(k)]] = int.from_bytes(m, 'big') if isinstance(m, bytes) else m
        return out

    def identify(self, strings):
        """{component name: {score, unique, versions, n, best, latest}} for the reported components found in the strings."""
        owners = self.owners_of(strings)
        score = collections.Counter(); unique = collections.Counter(); assigned = collections.defaultdict(list); shared = []
        for s, o in owners.items():
            if len(o) == 1:
                score[o[0]] += len(s); unique[o[0]] += 1; assigned[o[0]].append(s)
            else:
                shared.append((s, o))
        for s, o in sorted(shared, key=lambda x: (len(x[1]), -len(x[0]), x[0])):
            p = max(o, key=lambda q: (score[q], -q))
            score[p] += len(s) / 5 ** (len(o) - 1); assigned[p].append(s)
        result = {}
        for p in score:
            name, kind = self.comps[p]
            if kind != 'kb':
                continue
            vers = self.versions[p]
            counts = [0] * len(vers)
            for s, m in self._masks(p, assigned[p]).items():
                for b in range(len(counts)):
                    if m >> b & 1:
                        counts[b] += 1
            best = max(counts) if counts else 0
            cands = [vers[b] for b in range(len(vers)) if counts[b] == best] if best else []
            result[name] = {'score': round(score[p], 1), 'unique': unique[p], 'versions': cands, 'n': len(assigned[p]), 'best': best,
                            # the candidates reach the newest release the database has: the shipped one may be newer
                            'latest': any(self._newest_of_series(vers, c) for c in cands),
                            # the longest strings that matched, as evidence a person can check against the file
                            'sample': [t[:80] for t in (x.decode('latin-1').strip() for x in sorted(assigned[p], key=lambda x: (-len(x), x))[:12]) if t][:8]}
        return result

    @staticmethod
    def _newest_of_series(vers, cand):
        """True when no later release of the same series (every number but the last: 1.2.x) is in the database.
        A version newer than the database comes back as the last release of its own series, so the single newest
        release of the whole database is not enough to tell: 1.2.13 would read as 1.2.12 while 1.3.0 exists."""
        def series(v):   # every number but the last: 1.2.12 -> (1, 2), 1.2 -> (1,)
            nums = tuple(t[1] for t in version_key(v) if t[0] == 0)
            return nums[:max(1, len(nums) - 1)]
        i = vers.index(cand)
        return not any(series(v) == series(cand) for v in vers[i + 1:])

    def table_hits(self, data):
        """{component name: [distinct tables found, their total bytes]}."""
        hits = collections.defaultdict(lambda: [0, 0])
        for name, c in tables_in(self.index, data).items():
            n = self.comps[c][0]
            hits[n][0] += 1; hits[n][1] += self.table_size[name]
        return dict(hits)

    def detected(self, hits, tables, path=''):
        """Names of the components reported for one file under the rule stored in the database.
        A kernel image or module reports only kernel-only components: drivers spell many messages and
        counter names through macros, so the sources do not carry them as literals and they cannot be
        put in the background, while a user-space project that shares the driver code (DPDK with the
        Intel and Broadcom drivers) has them as literals and would be credited with the kernel module."""
        r = self.rule
        kernel_file = bool(KERNEL_FILE.search(os.path.basename(path)))
        out = {n for n, h in hits.items() if h['unique'] >= r['unique'] and h['score'] >= r['score']}
        out.update(n for n, (cnt, size) in tables.items() if cnt >= r['table_count'] and size >= r['table_bytes'])
        return {n for n in out if (n in self.kernel_only) == kernel_file}

    def scan_bytes(self, data, path=''):
        """(hits, tables) for the bytes of one file."""
        body, _ = string_bytes(data)
        hits = self.identify(set(PRINTABLE_RUN.findall(body)))
        tables = self.table_hits(body) if self.index else {}
        return hits, tables


def content_hash(con):
    """SHA-256 of the rows of every table in key order. Two builds from the same inputs agree on it even when
    the SQLite library that wrote them differs, which changes the file bytes but not the content."""
    h = hashlib.sha256()
    schema = json.loads(con.execute("SELECT value FROM meta WHERE key = 'schema'").fetchone()[0])
    tables = (('meta', 'key'), ('comp', 'id'), ('ver', 'comp, idx'), ('str', 's'), ('strv', 's, comp'), ('tbl', 'id')) if schema < 2 else \
        (('meta', 'key'), ('comp', 'id'), ('ver', 'comp, idx'), ('src', 'comp, version, sha256'), ('str', 'h'), ('strv', 'h, comp'), ('tbl', 'id'))
    for table, order in tables:
        h.update(table.encode())
        for row in con.execute(f'SELECT * FROM {table} ORDER BY {order}'):
            h.update(repr(row).encode())
    return h.hexdigest()


def info(args):
    kb = KnowledgeBase(args.db)
    print(json.dumps({'release': kb.release, 'content_sha256': content_hash(kb.con), 'rule': kb.rule, 'kernel_only': sorted(kb.kernel_only),
                      'components': {kb.comps[c][0]: {'versions': len(v), 'first': v[0], 'last': v[-1]} for c, v in kb.versions.items()},
                      'background': sum(1 for n, k in kb.comps.values() if k == 'bg'), 'table_signatures': len(kb.table_size),
                      'schema': kb.schema, 'purls': kb.purls,
                      'sources': kb.con.execute('SELECT count(*) FROM src').fetchone()[0] if kb.schema >= 2 else 0},
                     indent=2, ensure_ascii=False))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    b = sub.add_parser('build'); b.add_argument('--kb', required=True); b.add_argument('--bg', action='append')
    b.add_argument('--ref'); b.add_argument('--ref-bg'); b.add_argument('--kernel-only', action='append')
    b.add_argument('--release', required=True); b.add_argument('--out', required=True)
    for k, v in DEFAULT_RULE.items():
        b.add_argument('--rule-' + k.replace('_', '-'), dest='rule_' + k, type=int, help=f'detection threshold stored in the base (default {v})')
    i = sub.add_parser('info'); i.add_argument('db')
    args = ap.parse_args(argv)
    {'build': build, 'info': info}[args.cmd](args)
    return 0


if __name__ == '__main__':
    sys.exit(main())
