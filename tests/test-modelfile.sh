#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-modelfile.sh — No-Docker checks for identify-model-file.py, the reader
# behind MODE=MODELFILE (an AI model file described from its own header).
#
# The samples are BUILT HERE rather than committed. Two reasons: a weight file
# is large and would bloat the repository, and one of the cases has to be a
# pickle carrying an os.system payload — which belongs in a temp dir for the
# length of the run, not in a public tree. Every sample is a few hundred bytes,
# written by the generator below from the format specs.
#
# Pure python3/jq, so it runs in CI without Docker, an image, or the network.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
READER="$ROOT_DIR/docker/lib/identify-model-file.py"
LIB="$ROOT_DIR/docker/lib"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); }

for tool in python3 jq; do
    command -v "$tool" >/dev/null 2>&1 || { echo "[ERROR] $tool is required"; exit 1; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- build the samples ------------------------------------------------------
python3 - "$WORK" <<'PY'
import json, os, pickle, struct, sys, zipfile

out = sys.argv[1]
p = lambda n: os.path.join(out, n)

def gguf_str(s):
    b = s.encode()
    return struct.pack("<Q", len(b)) + b

def kv_str(k, v):
    return gguf_str(k) + struct.pack("<I", 8) + gguf_str(v)

def kv_arr_str(k, values):
    # A token vocabulary: the array the reader must SEEK past rather than read.
    body = gguf_str(k) + struct.pack("<I", 9) + struct.pack("<IQ", 8, len(values))
    for v in values:
        body += gguf_str(v)
    return body

kvs = [
    kv_str("general.architecture", "llama"),
    # The vocabulary sits BEFORE the keys we want, so a reader that cannot skip
    # an array never reaches the name and the license.
    kv_arr_str("tokenizer.ggml.tokens", ["tok%d" % i for i in range(500)]),
    kv_str("general.name", "TinyTest-1B"),
    kv_str("general.license", "apache-2.0"),
    kv_str("general.organization", "test-org"),
]
with open(p("model.gguf"), "wb") as f:
    f.write(b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 12) + struct.pack("<Q", len(kvs)))
    for k in kvs:
        f.write(k)
    f.write(b"\x00" * 200000)   # stand-in for the weights

header = {
    "__metadata__": {"format": "pt", "license": "mit", "modelspec.title": "st-model"},
    "layer.0.weight": {"dtype": "BF16", "shape": [64, 32], "data_offsets": [0, 4096]},
    "layer.1.weight": {"dtype": "F32", "shape": [32, 8], "data_offsets": [4096, 5120]},
}
hj = json.dumps(header).encode()
with open(p("model.safetensors"), "wb") as f:
    f.write(struct.pack("<Q", len(hj)) + hj + b"\x00" * 5120)

# safetensors bytes under a .gguf name: the magic must win over the extension.
with open(p("mislabelled.gguf"), "wb") as f:
    f.write(struct.pack("<Q", len(hj)) + hj + b"\x00" * 5120)

class Evil:
    def __reduce__(self):
        return (os.system, ("echo pwned",))

with open(p("evil.pkl"), "wb") as f:
    pickle.dump(Evil(), f)
with open(p("benign.pkl"), "wb") as f:
    pickle.dump({"weights": [1, 2, 3]}, f)

# torch.save layout: a zip whose payload is a pickle.
with zipfile.ZipFile(p("model.pt"), "w") as z:
    z.writestr("archive/data.pkl", pickle.dumps({"layer": "w"}))
    z.writestr("archive/data/0", b"\x00" * 512)

# npz: a zip of .npy members.
npy = b"\x93NUMPY\x01\x00" + b"v" * 118 + b"\x00" * 32
with zipfile.ZipFile(p("model.npz"), "w") as z:
    z.writestr("arr_0.npy", npy)

with open(p("random.bin"), "wb") as f:
    f.write(b"\xde\xad\xbe\xef" * 64)

# GGUF chat templates: a known Jinja2 sandbox-escape gadget chain, and a clean
# multi-turn loop with none of the gadget tokens.
risky_template = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
clean_template = "{% for message in messages %}{{ message.content }}{% endfor %}"

def gguf_with_template(name, template):
    kvs = [kv_str("general.architecture", "llama")]
    if template is not None:
        kvs.append(kv_str("tokenizer.chat_template", template))
    with open(p(name), "wb") as f:
        f.write(b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 0) + struct.pack("<Q", len(kvs)))
        for k in kvs:
            f.write(k)

gguf_with_template("template_risk.gguf", risky_template)
gguf_with_template("template_clean.gguf", clean_template)

# Keras HDF5: the model_config JSON attribute is just readable text in the
# file, so a synthetic file only needs the HDF5 magic and that text somewhere
# in it — an HDF5 parser is not required to test a byte scan of one.
def keras_h5(name, layer_class):
    # The bytes an HDF5 root-group attribute named "model_config" holds are
    # just the UTF-8 JSON text below, unwrapped -- exactly what a real Keras
    # .h5 file puts on disk for that attribute.
    config = json.dumps({"class_name": "Sequential",
                          "config": {"layers": [{"class_name": layer_class, "config": {}}]}})
    with open(p(name), "wb") as f:
        f.write(b"\x89HDF\r\n\x1a\n")
        f.write(b"\x00" * 32)
        f.write(config.encode())
        f.write(b"\x00" * 32)

keras_h5("lambda.h5", "Lambda")
keras_h5("dense.h5", "Dense")

# .keras: a zip with config.json (+ metadata.json), matching the Keras 3
# archive layout inspect_zip() looks for. config.json is parsed as plain JSON,
# never executed.
def keras_zip(name, layer_class):
    config = {"class_name": "Sequential",
              "config": {"layers": [{"class_name": "InputLayer", "config": {}},
                                     {"class_name": layer_class, "config": {}}]}}
    with zipfile.ZipFile(p(name), "w") as z:
        z.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))
        z.writestr("config.json", json.dumps(config))
        z.writestr("model.weights.h5", b"\x89HDF\r\n\x1a\n" + b"\x00" * 16)

keras_zip("lambda.keras", "Lambda")
keras_zip("dense.keras", "Dense")

# ONNX: no real protobuf library involved, just the exact byte pattern
# parse_onnx()/find_onnx_external_data_locations() looks for: field1 "location"
# (key) immediately followed by field2 (value), the same order every onnx
# writer that serializes fields in field-number order produces.
def onnx_bytes(location):
    body = b"\x08\x07"  # ir_version varint, satisfies sniff_format's onnx heuristic
    if location is not None:
        loc = location.encode()
        body += b"\x0a\x08location\x12" + bytes([len(loc)]) + loc
    return body

with open(p("escape.onnx"), "wb") as f:
    f.write(onnx_bytes("../../etc/passwd"))
with open(p("safe.onnx"), "wb") as f:
    f.write(onnx_bytes("weights/model.onnx.data"))
with open(p("noext.onnx"), "wb") as f:
    f.write(onnx_bytes(None))
PY

read_one() { python3 "$READER" "$WORK/$1" "$WORK/$1.bom.json" "${2:-1.0}" "scan-$1" 2>"$WORK/$1.err"; }
prop() { jq -r --arg n "$2" '.components[0].properties[] | select(.name==$n) | .value' "$WORK/$1.bom.json"; }

echo "== GGUF: name, license and architecture come out of the header =="
if read_one model.gguf; then
    pass "GGUF file read"
    n=$(jq -r '.components[0].name' "$WORK/model.gguf.bom.json")
    [ "$n" = "TinyTest-1B" ] && pass "name from general.name" || fail "name='$n', expected TinyTest-1B (a token array before it may have stopped the parse)"
    l=$(jq -r '.components[0].licenses[0].license.name // .components[0].licenses[0].license.id // "ABSENT"' "$WORK/model.gguf.bom.json")
    [ "$l" = "apache-2.0" ] && pass "license from general.license" || fail "license='$l', expected apache-2.0"
    [ "$(prop model.gguf bomlens:modelfile:architecture)" = "llama" ] && pass "architecture recorded" || fail "architecture missing"
    [ "$(prop model.gguf bomlens:modelfile:ggufVersion)" = "3" ] && pass "GGUF version recorded" || fail "GGUF version missing"
    [ "$(prop model.gguf bomlens:modelfile:tensors)" = "12" ] && pass "tensor count from the header" || fail "tensor count wrong"
    if jq -e '.components[0].modelCard.modelParameters.architectureFamily == "llama"' "$WORK/model.gguf.bom.json" >/dev/null; then
        pass "architectureFamily lands on the model card"
    else
        fail "architectureFamily missing from the model card"
    fi
else
    fail "GGUF file refused" "$(cat "$WORK/model.gguf.err")"
fi

echo "== a file with no tokenizer.chat_template key carries no template-risk property =="
[ -z "$(prop model.gguf bomlens:modelfile:ggufTemplateRisk)" ] && pass "no chat template -> no ggufTemplateRisk" || fail "ggufTemplateRisk stamped without a template"

echo "== GGUF chat template: a pure string scan for known Jinja2 sandbox-escape gadgets =="
if read_one template_risk.gguf; then
    r=$(prop template_risk.gguf bomlens:modelfile:ggufTemplateRisk)
    [ "$r" = "__class__,__mro__,__subclasses__" ] && pass "gadget tokens found and sorted" || fail "ggufTemplateRisk='$r'"
else
    fail "template_risk.gguf refused" "$(cat "$WORK/template_risk.gguf.err")"
fi
if read_one template_clean.gguf; then
    [ -z "$(prop template_clean.gguf bomlens:modelfile:ggufTemplateRisk)" ] && pass "a plain loop template is not flagged" || fail "clean template wrongly flagged"
else
    fail "template_clean.gguf refused" "$(cat "$WORK/template_clean.gguf.err")"
fi

echo "== safetensors: tensor shapes, dtypes and the optional metadata block =="
if read_one model.safetensors; then
    pass "safetensors file read"
    [ "$(prop model.safetensors bomlens:modelfile:tensors)" = "2" ] && pass "tensor count" || fail "tensor count wrong"
    # 64*32 + 32*8 = 2304
    [ "$(prop model.safetensors bomlens:modelfile:parameters)" = "2304" ] && pass "parameter count summed from shapes" || fail "parameter count wrong"
    [ "$(prop model.safetensors bomlens:modelfile:dtypes)" = "BF16,F32" ] && pass "dtypes collected and sorted" || fail "dtypes wrong"
    n=$(jq -r '.components[0].name' "$WORK/model.safetensors.bom.json")
    [ "$n" = "st-model" ] && pass "name from __metadata__" || fail "name='$n', expected st-model"
else
    fail "safetensors file refused" "$(cat "$WORK/model.safetensors.err")"
fi

echo "== magic bytes beat the extension =="
if read_one mislabelled.gguf; then
    [ "$(prop mislabelled.gguf bomlens:modelfile:format)" = "safetensors" ] && pass "content wins: read as safetensors despite the .gguf name" || fail "format followed the extension"
    [ "$(prop mislabelled.gguf bomlens:modelfile:extensionMismatch)" = "true" ] && pass "mismatch is reported, not silently corrected" || fail "extensionMismatch not stamped"
    [ "$(prop mislabelled.gguf bomlens:modelfile:claimedFormat)" = "gguf" ] && pass "the claimed format is named too" || fail "claimedFormat missing"
else
    fail "mislabelled file refused" "$(cat "$WORK/mislabelled.gguf.err")"
fi

echo "== pickle-format weights are flagged as such (the risk verdict is a later step) =="
for f in evil.pkl benign.pkl; do
    if read_one "$f"; then
        [ "$(prop "$f" bomlens:modelfile:format)" = "pickle" ] && pass "$f: format=pickle" || fail "$f: format wrong"
        [ "$(prop "$f" bomlens:weights:pickleFiles)" = "1" ] && pass "$f: counted as pickle-format weights" || fail "$f: bomlens:weights:pickleFiles missing"
    else
        fail "$f refused" "$(cat "$WORK/$f.err")"
    fi
done

echo "== a torch archive is told apart from an npz =="
if read_one model.pt; then
    [ "$(prop model.pt bomlens:modelfile:format)" = "pytorch-zip" ] && pass "data.pkl inside -> pytorch-zip" || fail "torch archive misread"
    [ "$(prop model.pt bomlens:weights:pickleFiles)" = "1" ] && pass "torch archive counted as pickle-format" || fail "torch archive not flagged as pickle-format"
else
    fail "torch archive refused" "$(cat "$WORK/model.pt.err")"
fi
if read_one model.npz; then
    [ "$(prop model.npz bomlens:modelfile:format)" = "npz" ] && pass ".npy members -> npz" || fail "npz misread"
    [ -z "$(prop model.npz bomlens:weights:pickleFiles)" ] && pass "npz is not counted as pickle-format on its own" || fail "npz wrongly flagged as pickle-format"
else
    fail "npz refused" "$(cat "$WORK/model.npz.err")"
fi

echo "== Keras .h5: a Lambda layer in the model_config attribute text is found by a bounded byte scan =="
if read_one lambda.h5; then
    [ "$(prop lambda.h5 bomlens:modelfile:format)" = "keras-h5" ] && pass "HDF5 magic -> keras-h5" || fail "lambda.h5 misread"
    [ "$(prop lambda.h5 bomlens:weights:marshalledCode)" = "1" ] && pass "Lambda layer flagged as marshalled-code risk" || fail "bomlens:weights:marshalledCode missing"
else
    fail "lambda.h5 refused" "$(cat "$WORK/lambda.h5.err")"
fi
if read_one dense.h5; then
    [ "$(prop dense.h5 bomlens:modelfile:format)" = "keras-h5" ] && pass "a plain Dense layer .h5 still reads as keras-h5" || fail "dense.h5 misread"
    [ -z "$(prop dense.h5 bomlens:weights:marshalledCode)" ] && pass "no Lambda layer -> not flagged" || fail "dense.h5 wrongly flagged"
else
    fail "dense.h5 refused" "$(cat "$WORK/dense.h5.err")"
fi

echo "== Keras .keras: config.json is parsed as JSON only, never executed =="
if read_one lambda.keras; then
    [ "$(prop lambda.keras bomlens:modelfile:format)" = "keras-zip" ] && pass "config.json+metadata.json -> keras-zip" || fail "lambda.keras misread"
    [ "$(prop lambda.keras bomlens:weights:marshalledCode)" = "1" ] && pass "Lambda layer found in config.json" || fail "bomlens:weights:marshalledCode missing"
else
    fail "lambda.keras refused" "$(cat "$WORK/lambda.keras.err")"
fi
if read_one dense.keras; then
    [ "$(prop dense.keras bomlens:modelfile:format)" = "keras-zip" ] && pass "dense.keras reads as keras-zip" || fail "dense.keras misread"
    [ -z "$(prop dense.keras bomlens:weights:marshalledCode)" ] && pass "no Lambda layer -> not flagged" || fail "dense.keras wrongly flagged"
else
    fail "dense.keras refused" "$(cat "$WORK/dense.keras.err")"
fi

echo "== ONNX external_data: a location escaping the model's own directory is flagged =="
if read_one escape.onnx; then
    [ "$(prop escape.onnx bomlens:modelfile:format)" = "onnx" ] && pass "escape.onnx reads as onnx" || fail "escape.onnx misread"
    e=$(prop escape.onnx bomlens:modelfile:onnxExternalDataEscape)
    [ "$e" = "../../etc/passwd" ] && pass "the escaping location is named" || fail "onnxExternalDataEscape='$e'"
else
    fail "escape.onnx refused" "$(cat "$WORK/escape.onnx.err")"
fi
if read_one safe.onnx; then
    [ -z "$(prop safe.onnx bomlens:modelfile:onnxExternalDataEscape)" ] && pass "a safe relative location is not flagged" || fail "safe.onnx wrongly flagged"
else
    fail "safe.onnx refused" "$(cat "$WORK/safe.onnx.err")"
fi
if read_one noext.onnx; then
    [ -z "$(prop noext.onnx bomlens:modelfile:onnxExternalDataEscape)" ] && pass "no external_data reference -> nothing flagged" || fail "noext.onnx wrongly flagged"
else
    fail "noext.onnx refused" "$(cat "$WORK/noext.onnx.err")"
fi

echo "== a file we cannot identify is refused, not described =="
if read_one random.bin; then
    fail "an unidentifiable file produced a model component"
else
    rc=$?
    [ "$rc" = "3" ] && pass "refused with the dedicated exit code (3)" || fail "exit code was $rc, expected 3"
    [ ! -f "$WORK/random.bin.bom.json" ] && pass "no SBOM written for it" || fail "an SBOM was written anyway"
    grep -q "not a recognized model file" "$WORK/random.bin.err" && pass "the message names the problem" || fail "unhelpful error message"
fi

echo "== the document identifies the artifact =="
h=$(jq -r '.components[0].hashes[] | select(.alg=="SHA-256") | .content' "$WORK/model.gguf.bom.json")
real=$(python3 -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$WORK/model.gguf")
[ "$h" = "$real" ] && pass "SHA-256 covers the whole file" || fail "hash mismatch"
purl=$(jq -r '.components[0].purl' "$WORK/model.gguf.bom.json")
case "$purl" in
    pkg:generic/*checksum=sha256:$real) pass "purl is pkg:generic with the checksum qualifier" ;;
    *) fail "purl='$purl'" ;;
esac
if jq -e '(.dependencies | length) == 2 and (.dependencies[0].dependsOn | length) == 1' "$WORK/model.gguf.bom.json" >/dev/null; then
    pass "the dependency graph states the scan covers this model"
else
    fail "dependency edges missing"
fi
[ -n "$(jq -r '.metadata.timestamp // ""' "$WORK/model.gguf.bom.json")" ] && pass "metadata.timestamp is written" || fail "metadata.timestamp missing"

echo "== re-reading the same file yields the same identifiers =="
python3 "$READER" "$WORK/model.gguf" "$WORK/again.json" 1.0 scan-model.gguf 2>/dev/null
a=$(jq -r '.serialNumber + "|" + .components[0]["bom-ref"]' "$WORK/model.gguf.bom.json")
b=$(jq -r '.serialNumber + "|" + .components[0]["bom-ref"]' "$WORK/again.json")
[ "$a" = "$b" ] && pass "serialNumber and bom-ref are derived from the content" || fail "identifiers changed between runs"

echo "== the common post-processing keeps the result intact =="
cp "$WORK/model.gguf.bom.json" "$WORK/norm.json"
bash "$LIB/normalize-sbom.sh" "$WORK/norm.json" >/dev/null 2>&1
[ "$(jq -r '.specVersion' "$WORK/norm.json")" = "1.7" ] && pass "specVersion stays 1.7 through normalize" || fail "specVersion changed"
lic=$(jq -r '.components[0].licenses[0].license.id // "ABSENT"' "$WORK/norm.json")
[ "$lic" = "Apache-2.0" ] && pass "normalize maps apache-2.0 to the SPDX id" || fail "license id='$lic'"
if jq -e '.components[0].modelCard.modelParameters.architectureFamily' "$WORK/norm.json" >/dev/null; then
    pass "the model card survives normalize"
else
    fail "model card lost in normalize"
fi
if AI_RISK_KNOWLEDGE="$LIB/ai-risk-knowledge.json" bash "$LIB/assess-ai-risk.sh" "$WORK/norm.json" >/dev/null 2>&1; then
    v=$(jq -r '.components[0].properties[] | select(.name=="bomlens:assessment:overall") | .value' "$WORK/norm.json")
    [ "$v" = "ok" ] && pass "a permissive licence assesses ok" || fail "assessment='$v', expected ok"
else
    fail "assess-ai-risk.sh failed on a model-file SBOM"
fi
# A file that declares no licence must not read as safe.
cp "$WORK/model.pt.bom.json" "$WORK/nolic.json"
bash "$LIB/normalize-sbom.sh" "$WORK/nolic.json" >/dev/null 2>&1
AI_RISK_KNOWLEDGE="$LIB/ai-risk-knowledge.json" bash "$LIB/assess-ai-risk.sh" "$WORK/nolic.json" >/dev/null 2>&1
v=$(jq -r '.components[0].properties[] | select(.name=="bomlens:assessment:overall") | .value' "$WORK/nolic.json")
[ "$v" = "review" ] && pass "no declared licence assesses review, never ok" || fail "assessment='$v', expected review"

echo "== the risk assessment reads the local pickle scan =="
# Driven through stamped properties rather than the scanner, so this holds even
# where picklescan is not installed. The mapping is the contract between
# scan-model-file-security.py and assess-ai-risk.sh.
stamp_and_assess() {   # $1 = status, $2 = findings (may be empty)
    cp "$WORK/model.pt.bom.json" "$WORK/ls.json"
    jq --arg s "$1" --arg f "$2" '
      .components[0].properties += ([{name:"bomlens:localscan:status", value:$s}]
        + (if $f != "" then [{name:"bomlens:localscan:findings", value:$f}] else [] end))
    ' "$WORK/ls.json" > "$WORK/ls2.json" && mv "$WORK/ls2.json" "$WORK/ls.json"
    bash "$LIB/normalize-sbom.sh" "$WORK/ls.json" >/dev/null 2>&1
    AI_RISK_KNOWLEDGE="$LIB/ai-risk-knowledge.json" bash "$LIB/assess-ai-risk.sh" "$WORK/ls.json" >/dev/null 2>&1
    jq -r '.components[0].properties[] | select(.name=="bomlens:assessment:security") | .value' "$WORK/ls.json"
}
[ "$(stamp_and_assess unsafe 'posix.system')" = "caution" ] && pass "unsafe -> caution" || fail "unsafe did not raise caution"
[ "$(stamp_and_assess suspicious '__main__.Net')" = "review" ] && pass "suspicious -> review (a custom class is common and not an alarm)" || fail "suspicious did not map to review"
[ "$(stamp_and_assess clean '')" = "ok" ] && pass "clean -> ok" || fail "clean did not map to ok"
[ "$(stamp_and_assess not-applicable '')" = "ok" ] && pass "not-applicable -> ok" || fail "not-applicable did not map to ok"
[ "$(stamp_and_assess error '')" = "review" ] && pass "error -> review, never a pass" || fail "an unreadable file did not map to review"
# The finding has to reach the reader, not just the verdict.
stamp_and_assess unsafe 'posix.system' >/dev/null
if jq -e '[.components[0].properties[] | select(.name=="bomlens:assessment:reasons") | .value] | any(test("posix.system"))' "$WORK/ls.json" >/dev/null; then
    pass "the flagged global is named in the reasons"
else
    fail "the finding did not reach the assessment reasons"
fi
# Without the property there is no security axis at all — "not scanned" must not
# read as "safe".
cp "$WORK/model.pt.bom.json" "$WORK/nols.json"
bash "$LIB/normalize-sbom.sh" "$WORK/nols.json" >/dev/null 2>&1
AI_RISK_KNOWLEDGE="$LIB/ai-risk-knowledge.json" bash "$LIB/assess-ai-risk.sh" "$WORK/nols.json" >/dev/null 2>&1
axes=$(jq -r '.components[0].properties[] | select(.name=="bomlens:assessment:axes") | .value' "$WORK/nols.json")
case "$axes" in
    *security*) fail "a security axis appeared with nothing to base it on ($axes)" ;;
    *) pass "no scan recorded -> no security axis" ;;
esac

echo "== the status vocabulary is the same on both sides =="
py_states=$(grep -oE '^#   (clean|suspicious|unsafe|not-applicable|error)' "$LIB/scan-model-file-security.py" \
            | awk '{print $2}' | sort | tr '\n' ' ')
ts_states=$(sed -n '/LOCAL_SCAN_STATUSES/,/\]/p' "$ROOT_DIR/docker/web/frontend/src/lib/models.tsx" \
            | grep -oE '"[a-z-]+"' | tr -d '"' | sort | tr '\n' ' ')
[ "$py_states" = "$ts_states" ] && pass "scanner and web UI agree on the status values" \
    || fail "status vocabulary drifted" "scanner: $py_states / ui: $ts_states"

if python3 -c "import picklescan" 2>/dev/null; then
    echo "== picklescan verdicts on real files =="
    run_scan() { python3 "$ROOT_DIR/docker/lib/scan-model-file-security.py" "$WORK/$1.bom.json" "$WORK/$1" >/dev/null 2>&1; prop "$1" bomlens:localscan:status; }
    [ "$(run_scan evil.pkl)" = "unsafe" ] && pass "an os.system payload reads unsafe" || fail "the malicious pickle was not flagged"
    [ "$(run_scan model.pt)" = "clean" ] && pass "a plain torch archive reads clean" || fail "a benign torch archive was flagged"
    [ "$(run_scan model.gguf)" = "not-applicable" ] && pass "GGUF is not put through a pickle scanner" || fail "GGUF got a pickle verdict"
    [ "$(run_scan model.safetensors)" = "not-applicable" ] && pass "safetensors is not put through a pickle scanner" || fail "safetensors got a pickle verdict"
    if jq -e '[.components[0].properties[] | select(.name=="bomlens:localscan:findings") | .value] | any(test("system"))' "$WORK/evil.pkl.bom.json" >/dev/null; then
        pass "the dangerous global is named on the component"
    else
        fail "no finding recorded for the malicious pickle"
    fi

    echo "== a Keras Lambda finding lands in the same verdict vocabulary, not run through picklescan =="
    [ "$(run_scan lambda.h5)" = "suspicious" ] && pass "a Lambda layer reads suspicious, like a custom pickle global" || fail "lambda.h5 did not read suspicious"
    [ "$(prop lambda.h5 bomlens:localscan:tool)" = "bomlens-modelfile-scan" ] && pass "the tool name does not claim picklescan ran" || fail "localscan:tool wrongly names picklescan"
    [ "$(run_scan dense.h5)" = "clean" ] && pass "no Lambda layer reads clean" || fail "dense.h5 did not read clean"
else
    echo "  SKIP: picklescan not installed (pip install picklescan) — verdict mapping still covered above"
fi

echo ""
echo "=========================================="
echo " model-file reader: $PASS passed, $FAIL failed"
echo "=========================================="
[ "$FAIL" -eq 0 ] || exit 1
