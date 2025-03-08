package audit

import (
	"embed"
	"io/fs"
)

//go:embed policies/*.yaml
var defaultPolicyFiles embed.FS

func GetDefaultPolicyFS() fs.FS {
	return defaultPolicyFiles
}
