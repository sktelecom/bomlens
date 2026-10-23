# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Builds the two programs sbom-declared.cdx.json names in bomlens:artifact.
# tests/test-declared-components.sh does not run this: it writes files with the
# same names and the first bytes of an ELF and a PE executable instead, so the
# test needs no compiler.

CC ?= cc
WINCC ?= x86_64-w64-mingw32-gcc

all: out/bin/media-daemon out/bin/media-ctl.exe

out/bin/media-daemon: src/media-daemon.c
	mkdir -p out/bin
	$(CC) -o $@ $< -lz

out/bin/media-ctl.exe: src/media-ctl.c
	mkdir -p out/bin
	$(WINCC) -o $@ $<

clean:
	rm -rf out

.PHONY: all clean
