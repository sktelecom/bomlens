# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0

# spdx-normalize.jq — map a license id/name/expression to an SPDX id for common
# aliases. Single source of truth shared by generate-notice.sh (NOTICE grouping)
# and normalize-sbom.sh (bom.json component licenses), so the attribution NOTICE
# and the web UI surfaces (license filter, distribution card, dependency tree)
# agree on the same canonical id.
#
# A genuine compound expression ("X OR Y") is left untouched; LGPL/GPL "or later"
# is matched before the compound check so it is not mistaken for a compound. An
# unrecognized string is returned unchanged, so a valid-but-wrong SPDX id from the
# upstream tool (e.g. cdxgen FETCH_LICENSE marking a package 0BSD) is preserved
# rather than silently rewritten to a guess.
def normalize($s):
  ($s | ascii_downcase | gsub("[ ,._/-]+"; " ") | sub("^ +";"") | sub(" +$";"")) as $n |
  if   ($n | test("(lesser|library) general public.*2 1.*later")) then "LGPL-2.1-or-later"
  elif ($n | test("(lesser|library) general public.*2 1")) then "LGPL-2.1-only"
  elif ($n | test("(lesser|library) general public.*3.*later")) then "LGPL-3.0-or-later"
  elif ($n | test("(lesser|library) general public.*3")) then "LGPL-3.0-only"
  elif ($n | test("general public.*2.*later")) then "GPL-2.0-or-later"
  elif ($n | test("general public.*2 0|general public.*v2")) then "GPL-2.0-only"
  elif ($n | test("general public.*3.*later")) then "GPL-3.0-or-later"
  elif ($n | test("general public.*3")) then "GPL-3.0-only"
  elif ($n | test(" or | and ")) then $s
  # Creative Commons. Datasets and documentation carry these where code carries
  # Apache/MIT, and HuggingFace spells them lowercase ("cc-by-sa-4.0"), which
  # would otherwise split from an upstream "CC-BY-SA-4.0" into two buckets in the
  # NOTICE and the license filter. The match is anchored to the whole string so a
  # jurisdiction port ("cc by 3 0 us") falls through unchanged rather than being
  # rewritten to the unported id.
  elif ($n | test("^cc0 [0-9]+ [0-9]+$")) then "CC0-1.0"
  elif ($n | test("^cc by( nc)?( sa| nd)? [0-9]+ [0-9]+$")) then
    "CC-BY"
    + (if ($n | test(" nc ")) then "-NC" else "" end)
    + (if ($n | test(" sa ")) then "-SA" else "" end)
    + (if ($n | test(" nd ")) then "-ND" else "" end)
    + ($n | capture(" (?<a>[0-9]+) (?<b>[0-9]+)$") | "-" + .a + "." + .b)
  elif ($n | test("apache.*2")) then "Apache-2.0"
  elif ($n | test("mit license") or $n == "mit" or ($n | test("expat"))) then "MIT"
  elif ($n | test("eclipse distribution") or ($n|test("^edl "))) then "BSD-3-Clause"
  elif ($n | test("eclipse public.*2")) then "EPL-2.0"
  elif ($n | test("eclipse public.*1")) then "EPL-1.0"
  elif ($n | test("bsd.*3")) then "BSD-3-Clause"
  elif ($n | test("bsd.*2")) then "BSD-2-Clause"
  else $s end;

# identify_license_text — classify a full license text by its distinctive clause
# wording, for entries where the upstream tool gave up on the name (cdxgen's Go
# resolver emits name:"CUSTOM" + the LICENSE file text when the file deviates
# from its template, e.g. pflag's two-copyright-line BSD-3-Clause). Matches on
# clause phrases, never on the copyright header, so holder count and names do
# not matter. Deliberately small and high-precision: only licenses whose body
# has an unmistakable phrase are listed, the BSD tests reject 4-clause texts
# (advertising clause), and a text matching several templates (e.g. a
# concatenated multi-license file) returns "" rather than a guess.
#
# build-prep.sh carries the same tests plus a step this one deliberately lacks:
# there, a multi-license file is read for the license it LEADS with, because an
# installed distribution also ships trove classifiers to confirm that reading
# against. Here the input is a finished SBOM, where the only other license
# statement is the one already suspected of being wrong, so there is nothing to
# confirm against and the ambiguity stands. The asymmetry is intended; do not
# port the leading-license step into this filter without a second source.
def identify_license_text($t):
  (($t // "") | ascii_downcase | gsub("\\s+"; " ")) as $x |
  [ (if ($x | test("permission is hereby granted, free of charge"))
        and ($x | test("without restriction")) then "MIT" else empty end),
    (if ($x | test("permission to use, copy, modify, and/or distribute this software for any purpose")) then "ISC" else empty end),
    (if ($x | test("apache license")) and ($x | test("version 2\\.0")) then "Apache-2.0" else empty end),
    (if ($x | test("redistributions of source code must retain"))
        and ($x | test("redistributions in binary form must reproduce"))
        and (($x | test("advertising materials")) | not) then
       (if ($x | test("neither the name")) then "BSD-3-Clause" else "BSD-2-Clause" end)
     else empty end)
  ] as $hits |
  if ($hits | length) == 1 then $hits[0] else "" end;
