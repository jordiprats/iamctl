package main

import (
	"os"

	"github.com/jordiprats/iam-pb-check/cmd"
)

var version = "dev"

func main() {
	if err := cmd.NewRootCmd(version).Execute(); err != nil {
		os.Exit(1)
	}
}
