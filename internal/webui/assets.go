package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist returns the built Vite app rooted at its output directory.
func Dist() fs.FS {
	out, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return out
}
