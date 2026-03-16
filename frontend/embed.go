package frontend

import (
	"embed"
	"io/fs"
)

//go:embed all:build
var buildFS embed.FS

// FS returns the frontend build filesystem.
func FS() fs.FS {
	sub, err := fs.Sub(buildFS, "build")
	if err != nil {
		return nil
	}
	entries, err := fs.ReadDir(sub, ".")
	if err != nil || len(entries) == 0 {
		return nil
	}
	return sub
}
