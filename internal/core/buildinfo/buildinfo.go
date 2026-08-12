// Package buildinfo holds build metadata injected at link time.
//
// Release builds (GitHub Actions + GoReleaser) populate these variables via
// Go linker flags:
//
//	go build -ldflags "-X .../buildinfo.Version=0.4.0 \
//	                   -X .../buildinfo.Commit=<short git sha> \
//	                   -X .../buildinfo.BuildDate=<ISO-8601 UTC> \
//	                   -X .../buildinfo.Platform=linux/amd64"
//
// Local builds from source (go install / go run) leave them empty; the
// version command then falls back to the in-source ToolVersion constant.
// No version is ever guessed: empty fields are printed as "unknown" so that
// a release build and a local build are distinguishable on sight.
package buildinfo

// Version is injected as "0.4.0" style semver for release binaries.
var Version string

// Commit is the short git commit SHA of the release source.
var Commit string

// BuildDate is the UTC build time in RFC3339.
var BuildDate string

// Platform is the os/arch pair the binary was built for.
var Platform string
