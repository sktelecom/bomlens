// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

// Fixture: a module whose go.mod requires a newer Go than the cdxgen Go image
// carries, with a transitive dependency (spf13/pflag via cobra) that only a
// successful `go list` resolution reports.
package main

import "github.com/spf13/cobra"

func main() {
	_ = (&cobra.Command{Use: "fixture"}).Execute()
}
