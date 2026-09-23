# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# summarize-unblob-report.jq: totals from `unblob --report` output (a JSON array
# of per-task results). Read by scan-firmware.sh, which stamps them as
# bomlens:firmware:* properties. Only counts and byte totals are kept; the report
# itself is far larger than any SBOM should carry.
# Everything the summary says about "unrecognized" is measured at the top level
# against the input file: bytes not covered by a recognized region. Nested regions
# are counted separately (nested_unknown_chunks) so one sentence never mixes bases.
# extract_failed counts every step that did not complete: an extractor that ran
# and failed, one that timed out, one whose dependency is missing, and a handler
# that raised while processing a region.
def all_reports: [.. | objects | select(has("__typename__"))];
def top_reports: [.[] | select(.task.depth == 0) | .reports[]?];
def failed_types: ["ExtractCommandFailedReport", "ExtractorTimedOut", "ExtractorDependencyNotFoundReport",
                   "CalculateChunkExceptionReport", "CalculateMultiFileExceptionReport", "UnknownError"];
(all_reports) as $r
| (top_reports) as $t
| ([$t[] | select(.__typename__ == "StatReport") | .size] | max // 0) as $input
| ([$t[] | select(.__typename__ == "ChunkReport") | .size] | add // 0) as $known_top
| ([$input - $known_top, 0] | max) as $unk_top_bytes
| ([$r[] | select(.__typename__ == "ChunkReport")]) as $chunks
| {
    input_bytes: $input,
    recognized_chunks: ($chunks | length),
    unknown_chunks: ([$t[] | select(.__typename__ == "UnknownChunkReport")] | length),
    unknown_bytes: $unk_top_bytes,
    unknown_top_percent: (if $input > 0 then ([($unk_top_bytes * 1000 / $input | ceil) / 10, 100] | min) else 0 end),
    nested_unknown_chunks: (([$r[] | select(.__typename__ == "UnknownChunkReport")] | length) - ([$t[] | select(.__typename__ == "UnknownChunkReport")] | length)),
    encrypted_chunks: ([$chunks[] | select(.is_encrypted == true)] | length),
    extract_failed: ([$r[] | select(.__typename__ as $n | failed_types | index($n))] | length),
    extract_failed_formats: ([$chunks[] | select(any(.extraction_reports[]?; .__typename__ as $n | failed_types | index($n))) | .handler_name] | unique),
    missing_extractors: ([$r[] | select(.__typename__ == "ExtractorDependencyNotFoundReport") | .dependencies[]?] | unique)
  }
