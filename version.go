package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// Set by GoReleaser through -ldflags -X. Left as is for local builds.
var (
	version = "dev"
	commit  = ""
	date    = ""
)

// buildVersion returns the release version. `go install …@v0.1.0` doesn't pass
// ldflags, but Go embeds the module version in the binary, so use that instead.
func buildVersion() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return strings.TrimPrefix(bi.Main.Version, "v")
	}
	return version
}

func versionString() string {
	s := fmt.Sprintf("ctq %s (%s, %s/%s)", buildVersion(), runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if commit != "" {
		s += fmt.Sprintf("\ncommit %s, built %s", commit, date)
	}
	return s
}
