package main

import (
	_ "embed"
	"strings"
	"sync"
)

//go:generate go run ./tools/genoui

// oui.txt: MAC prefix (24 bits) → vendor, generated from the Wireshark list.
//
//go:embed oui.txt
var ouiFile string

var ouiDB = sync.OnceValue(func() map[string]string {
	m := make(map[string]string, 60000)
	for _, line := range strings.Split(ouiFile, "\n") {
		if prefix, name, ok := strings.Cut(line, "\t"); ok {
			m[prefix] = name
		}
	}
	return m
})

// Whether the vendor indicates a camera is decided by macEvidence.
func lookupVendor(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	return ouiDB()[strings.ToUpper(mac[:8])]
}
