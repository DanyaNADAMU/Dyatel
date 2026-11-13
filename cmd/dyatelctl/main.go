// Command dyatelctl is the CLI consumer of the dyatel-core daemon. It owns
// no state of its own: everything goes through the daemon's /api/v1 HTTP
// API, mirroring the core → CLI → GUI build order (CLI is the first
// consumer that proves the API surface).
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		// Uniform error line on stderr with exit code 1: scripts and the
		// future web panel wrapper only need to check the exit status.
		fmt.Fprintf(os.Stderr, "dyatelctl: %v\n", err)
		os.Exit(1)
	}
}
