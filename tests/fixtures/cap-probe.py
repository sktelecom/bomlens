#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
"""Check that a pass's cap() reads the environment the way its callers need.

Usage: cap-probe.py <path to a lib script defining cap()>

The caps are forwarded as `-e NAME=` whether or not anyone set one, so an unset
cap arrives as an empty string. This lifts cap() out of the shipping script and
exercises the three cases that matter: empty falls back, zero falls back (a cap
read as zero would examine nothing while looking like it worked), and a real
value is honoured.
"""
import ast
import os
import sys

src = open(sys.argv[1]).read()
fn = next((n for n in ast.parse(src).body
           if isinstance(n, ast.FunctionDef) and n.name == "cap"), None)
if fn is None:
    sys.exit("cap() not found in " + sys.argv[1])
ns = {"os": os}
exec(compile(ast.Module(body=[fn], type_ignores=[]), "<cap>", "exec"), ns)

for raw, want in (("", 20000), ("0", 20000), ("-5", 20000), ("abc", 20000), ("50000", 50000)):
    os.environ["CAP_PROBE"] = raw
    got = ns["cap"]("CAP_PROBE", 20000)
    if got != want:
        sys.exit(f"cap({raw!r}) returned {got}, wanted {want}")
os.environ.pop("CAP_PROBE", None)
