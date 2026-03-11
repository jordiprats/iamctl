package cmd

import (
	"fmt"
	"os"
)

func printWarnings(warnings []string, w *os.File) {
	for _, warn := range warnings {
		fmt.Fprintln(w, warn)
	}
	if len(warnings) > 0 {
		fmt.Fprintln(w)
	}
}
