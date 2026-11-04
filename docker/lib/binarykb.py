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
      kb.csv     lines `component,version,tarball`. Every release of a component belongs here;
                 a version missing from the list is reported as the nearest release that is there.
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

The database is SQLite, opened read-only, and holds no code.
"""
import argparse
import collections
import json
import os
import re
import sqlite3
import sys
import tarfile

SCHEMA = 1
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
    parts = [data[off:off + size] for name, typ, _, off, size, _, _ in secs
             if typ != 8 and (name.startswith(b'.rodata') or name in (b'.data', b'.modinfo'))]   # 8 = NOBITS
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

def table_key(blob):
    """Offset of the first 16-byte window with at least 8 distinct values, so runs of zeros do not flood the index."""
    return next((k for k in range(len(blob) - TABLE_KEY + 1) if len(set(blob[k:k + TABLE_KEY])) >= 8), None)


def tables_in(index, data):
    """{table name: component id} for every signature table whose bytes occur in data."""
    found, get = {}, index.get
    for p in range(len(data) - TABLE_KEY + 1):
        cand = get(data[p:p + TABLE_KEY])
        if cand:
            for blob, k, c, name in cand:
                if name not in found and p >= k and data[p - k:p - k + len(blob)] == blob:
                    found[name] = c
    return found


# --------------------------------------------------------------------------- database

SCHEMA_SQL = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE comp (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, kind TEXT NOT NULL);
CREATE TABLE ver (comp INTEGER NOT NULL, idx INTEGER NOT NULL, version TEXT NOT NULL, PRIMARY KEY (comp, idx));
CREATE TABLE str (s BLOB PRIMARY KEY, owners TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE strv (s BLOB NOT NULL, comp INTEGER NOT NULL, mask INTEGER NOT NULL, PRIMARY KEY (s, comp)) WITHOUT ROWID;
CREATE TABLE tbl (id INTEGER PRIMARY KEY, comp INTEGER NOT NULL, name TEXT NOT NULL, koff INTEGER NOT NULL, key BLOB NOT NULL, data BLOB NOT NULL);
CREATE INDEX tbl_key ON tbl (key);
"""


def build(args):
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    if os.path.exists(args.out):
        os.remove(args.out)
    rows = sorted((tuple(l.strip().split(',', 2)) for l in open(args.kb) if l.strip() and not l.startswith('#')),
                  key=lambda r: (r[0], version_key(r[1])))
    names, kinds, owners = {}, {}, collections.defaultdict(set)
    versions = collections.defaultdict(list)
    vmask = collections.defaultdict(dict)          # comp -> {string: version bitmask}

    def comp_id(name, kind):
        if name not in names:
            names[name] = len(names) + 1; kinds[name] = kind
        return names[name]

    for comp, ver, tb in rows:
        cid = comp_id(comp, 'kb')
        bit = 1 << len(versions[comp])
        versions[comp].append(ver)
        strings = source_strings(tb)
        for s in strings:
            owners[s].add(cid)
            vmask[comp][s] = vmask[comp].get(s, 0) | bit
        print(f'{comp} {ver}: {len(strings)} strings', file=sys.stderr)
    for d in args.bg or []:
        for tb in sorted(os.path.join(d, f) for f in os.listdir(d)):
            name = 'bg:' + re.split(r'-\d', os.path.basename(tb), maxsplit=1)[0]
            cid = comp_id(name, 'bg')
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
                index[v[k:k + TABLE_KEY]].append((v, k, c, tname[blob]))
        per[c] += 1
    dropped = collections.Counter()
    for path in (l.strip() for l in open(args.ref_bg)) if args.ref_bg else []:
        if not path:
            continue
        for name, c in tables_in(index, open(path, 'rb').read()).items():
            for key in list(index):
                index[key] = [e for e in index[key] if e[3] != name]
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
    con.executemany('INSERT INTO comp VALUES (?,?,?)', [(i, n, kinds[n]) for n, i in sorted(names.items(), key=lambda x: x[1])])
    con.executemany('INSERT INTO ver VALUES (?,?,?)', [(names[c], j, v) for c in sorted(versions) for j, v in enumerate(versions[c])])
    # Rows go in sorted, so the same inputs give the same file bytes whatever the hash seed or the machine.
    con.executemany('INSERT INTO str VALUES (?,?)', ((s, ','.join(str(i) for i in sorted(owners[s]))) for s in sorted(owners)))
    con.executemany('INSERT INTO strv VALUES (?,?,?)', ((s, names[c], vmask[c][s]) for c in sorted(vmask) for s in sorted(vmask[c])))
    rows_t = sorted((key, k, c, name, data) for key, ents in index.items() for data, k, c, name in ents)
    for n, (key, k, c, name, data) in enumerate(rows_t, 1):
        con.execute('INSERT INTO tbl VALUES (?,?,?,?,?,?)', (n, c, name, k, key, data))
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
        if self.meta.get('schema') != SCHEMA:
            raise ValueError(f'unsupported knowledge base schema {self.meta.get("schema")!r} (this reader knows {SCHEMA})')
        self.rule = dict(DEFAULT_RULE, **self.meta.get('rule', {}))
        self.release = self.meta.get('release', '')
        self.kernel_only = set(self.meta.get('kernel_only', []))
        self.comps = {i: (n, k) for i, n, k in self.con.execute('SELECT id, name, kind FROM comp')}
        self.versions = collections.defaultdict(list)
        for c, _, v in self.con.execute('SELECT comp, idx, version FROM ver ORDER BY comp, idx'):
            self.versions[c].append(v)
        self.index = collections.defaultdict(list)
        self.table_size = {}
        for c, name, k, key, data in self.con.execute('SELECT comp, name, koff, key, data FROM tbl'):
            self.index[bytes(key)].append((bytes(data), k, c, name)); self.table_size[name] = len(data)
        self._owners = {}

    def owners_of(self, strings):
        """{string: tuple of component ids} for the strings the database knows."""
        need = [s for s in strings if s not in self._owners]
        for i in range(0, len(need), 500):
            chunk = need[i:i + 500]
            for s, o in self.con.execute(f'SELECT s, owners FROM str WHERE s IN ({",".join("?" * len(chunk))})', chunk):
                self._owners[bytes(s)] = tuple(int(x) for x in o.split(','))
            for s in chunk:
                self._owners.setdefault(s, ())
        return {s: self._owners[s] for s in strings if self._owners[s]}

    def _masks(self, comp, strings):
        out = {}
        for i in range(0, len(strings), 500):
            chunk = strings[i:i + 500]
            for s, m in self.con.execute(f'SELECT s, mask FROM strv WHERE comp = ? AND s IN ({",".join("?" * len(chunk))})', [comp] + chunk):
                out[bytes(s)] = m
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
                            'latest': bool(cands) and vers[-1] in cands,
                            # the longest strings that matched, as evidence a person can check against the file
                            'sample': [t[:80] for t in (x.decode('latin-1').strip() for x in sorted(assigned[p], key=lambda x: (-len(x), x))[:12]) if t][:8]}
        return result

    def table_hits(self, data):
        """{component name: [distinct tables found, their total bytes]}."""
        hits = collections.defaultdict(lambda: [0, 0])
        for name, c in tables_in(self.index, data).items():
            n = self.comps[c][0]
            hits[n][0] += 1; hits[n][1] += self.table_size[name]
        return dict(hits)

    def detected(self, hits, tables, path=''):
        """Names of the components reported for one file under the rule stored in the database."""
        r = self.rule
        out = {n for n, h in hits.items() if h['unique'] >= r['unique'] and h['score'] >= r['score']
               and (n not in self.kernel_only or KERNEL_FILE.search(os.path.basename(path)))}
        out.update(n for n, (cnt, size) in tables.items() if cnt >= r['table_count'] and size >= r['table_bytes'])
        return out

    def scan_bytes(self, data, path=''):
        """(hits, tables) for the bytes of one file."""
        body, _ = string_bytes(data)
        hits = self.identify(set(PRINTABLE_RUN.findall(body)))
        tables = self.table_hits(body) if self.index else {}
        return hits, tables


def content_hash(con):
    """SHA-256 of the rows of every table in key order. Two builds from the same inputs agree on it even when
    the SQLite library that wrote them differs, which changes the file bytes but not the content."""
    import hashlib
    h = hashlib.sha256()
    for table, order in (('meta', 'key'), ('comp', 'id'), ('ver', 'comp, idx'), ('str', 's'), ('strv', 's, comp'), ('tbl', 'id')):
        h.update(table.encode())
        for row in con.execute(f'SELECT * FROM {table} ORDER BY {order}'):
            h.update(repr(row).encode())
    return h.hexdigest()


def info(args):
    kb = KnowledgeBase(args.db)
    print(json.dumps({'release': kb.release, 'content_sha256': content_hash(kb.con), 'rule': kb.rule, 'kernel_only': sorted(kb.kernel_only),
                      'components': {kb.comps[c][0]: {'versions': len(v), 'first': v[0], 'last': v[-1]} for c, v in kb.versions.items()},
                      'background': sum(1 for n, k in kb.comps.values() if k == 'bg'), 'table_signatures': len(kb.table_size)},
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
