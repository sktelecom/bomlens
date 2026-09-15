// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

// Fixture: a `retract (` block directly after a `replace (` block. cdxgen's
// go.mod parser (getGoPkgComponent / parseGoModData, and the parseGoModGraph
// path it also feeds) reads the retracted version as a replacement target
// with no name, then throws building its purl (`Invalid purl: "name" is a
// required field`) instead of skipping or reporting it -- the whole scan
// fails. Confirmed by direct execution: this exact layout crashes.
package main

import "github.com/spf13/cobra"

func main() {
	_ = (&cobra.Command{Use: "fixture"}).Execute()
}
