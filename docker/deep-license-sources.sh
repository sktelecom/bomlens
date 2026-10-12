#!/bin/sh
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# deep-license-sources.sh - run at build time in the deep-license image only.
#
# The deep-license image carries two LGPL components in object form: the 7-Zip
# executable inside the extractcode-7z package (linux/amd64) and the compiled
# intbitset extension. Their source is placed in the image itself, under
# /usr/share/bomlens/sources/, each download checked against a pinned sha256.
# It also checks that the 7-Zip actually installed is the version the bundled
# source is for, so a newer plugin cannot ship beside the wrong source.
#
# 7-Zip: the plugin's binary was built with the Homebrew p7zip 16.02 formula
# (its own INSTALL_RECEIPT.json says so). The bundle holds what that formula's
# revision 2 builds from: the upstream source, the two Debian security patches
# and the AES patch it applies.

set -eu

DEST=/usr/share/bomlens/sources
mkdir -p "$DEST/p7zip-16.02" "$DEST/intbitset-${INTBITSET_VERSION}"

fetch() {
    # fetch <url> <sha256> <output>
    # The upstream hosts are slow to recover at times: retry on any error,
    # for a few minutes, before the build gives up.
    curl -sSfL --retry 8 --retry-delay 20 --retry-all-errors --retry-connrefused -o "$3" "$1"
    echo "$2  $3" | sha256sum -c -
}

fetch "https://downloads.sourceforge.net/project/p7zip/p7zip/16.02/p7zip_16.02_src_all.tar.bz2" \
    5eb20ac0e2944f6cb9c2d51dd6c4518941c185347d4089ea89087ffdd6e2341f \
    "$DEST/p7zip-16.02/p7zip_16.02_src_all.tar.bz2"
fetch "https://snapshot.debian.org/archive/debian/20180601T000000Z/pool/main/p/p7zip/p7zip_16.02%2Bdfsg-6.debian.tar.xz" \
    fab0be1764efdbde1804072f1daa833de4e11ea65f718ad141a592404162643c \
    "$DEST/p7zip-16.02/p7zip_16.02+dfsg-6.debian.tar.xz"
fetch "https://github.com/aonez/Keka/files/2940620/15-Enhanced-encryption-strength.patch.zip" \
    838dd2175c3112dc34193e99b8414d1dc1b2b20b861bdde0df2b32dbf59d1ce4 \
    "$DEST/p7zip-16.02/15-Enhanced-encryption-strength.patch.zip"
cat > "$DEST/p7zip-16.02/README" <<'EOF'
7-Zip (p7zip 16.02), the 7z and 7z.so files in the extractcode-7z package
(site-packages/extractcode_7z/bin/), linux/amd64 only.

Build record: the package's licenses/p7zip/INSTALL_RECEIPT.json names the
Homebrew formula p7zip, stable version 16.02. The files here are what that
formula (revision 2, Homebrew/homebrew-core commit
80dcd3648433f2cd9956871b3b393953ff3d54c2, Formula/p7zip.rb) builds from:

  p7zip_16.02_src_all.tar.bz2              upstream source (sourceforge.net/projects/p7zip)
  p7zip_16.02+dfsg-6.debian.tar.xz         Debian packaging; the formula applies
                                           patches/12-CVE-2016-9296.patch and
                                           patches/13-CVE-2017-17969.patch
  15-Enhanced-encryption-strength.patch.zip  AES patch, applied with -p4

Build on Linux: unpack the source, apply the patches above, then
  cp makefile.linux_any_cpu makefile.machine && make all3

License: GNU LGPL 2.1 or later; the RAR decompression code is under the
GNU LGPL with the unRAR restriction (see DOC/License.txt and
DOC/unRarLicense.txt in the source).
EOF

fetch "https://files.pythonhosted.org/packages/source/i/intbitset/intbitset-${INTBITSET_VERSION}.tar.gz" \
    "${INTBITSET_SDIST_SHA256}" \
    "$DEST/intbitset-${INTBITSET_VERSION}/intbitset-${INTBITSET_VERSION}.tar.gz"

# The 7-Zip that ships must be the one the source above is for. On other
# platforms the plugin carries no 7-Zip at all; a release that starts to would
# need its own source here, so that fails the build too.
sevenzip_dir="$(python3 -c 'import extractcode_7z, os; print(os.path.join(os.path.dirname(extractcode_7z.__file__), "bin"))' 2>/dev/null || true)"
if [ "$(uname -m)" != "x86_64" ]; then
    if [ -n "$sevenzip_dir" ] && ls "$sevenzip_dir"/7z* >/dev/null 2>&1; then
        echo "[build] extractcode-7z ships a 7-Zip binary on $(uname -m); add its source to deep-license-sources.sh" >&2
        exit 1
    fi
else
    bin="$(python3 -c 'import extractcode_7z, os; print(os.path.join(os.path.dirname(extractcode_7z.__file__), "bin", "7z"))')"
    "$bin" | head -n 3 | grep -q ' 16\.02 ' || {
        echo "[build] the installed 7-Zip is not 16.02; update the bundled source in deep-license-sources.sh" >&2
        "$bin" | head -n 3 >&2
        exit 1
    }
fi
# And the intbitset that ships must be the version of the bundled sdist.
python3 -c "import importlib.metadata as m, sys; v = m.version('intbitset'); sys.exit(0 if v == '${INTBITSET_VERSION}' else 'intbitset ' + v + ' installed, source is for ${INTBITSET_VERSION}')"
echo "[build] LGPL component sources placed in $DEST"
