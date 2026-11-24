// Command genoui downloads the Wireshark vendor list (derived from IEEE) and generates oui.txt.
// Usage: go generate ./...
package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

const source = "https://www.wireshark.org/download/automated/data/manuf"

func main() {
	resp, err := http.Get(source)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("%s: %s", source, resp.Status)
	}

	var b strings.Builder
	n := 0
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), "\t")
		prefix := strings.TrimSpace(fields[0]) // the file pads columns with spaces
		// Only 24-bit blocks ("AA:BB:CC"); the rare /28 and /36 ranges are skipped.
		if len(fields) < 2 || len(prefix) != 8 || strings.HasPrefix(prefix, "#") {
			continue
		}
		name := strings.TrimSpace(fields[len(fields)-1]) // full name; the short one comes first
		if name == "" {
			continue
		}
		fmt.Fprintf(&b, "%s\t%s\n", strings.ToUpper(prefix), name)
		n++
	}
	if err := sc.Err(); err != nil {
		log.Fatal(err)
	}
	// Avoid writing a truncated list if the download is cut short.
	if n < 30000 {
		log.Fatalf("only %d prefixes; incomplete download?", n)
	}
	if err := os.WriteFile("oui.txt.tmp", []byte(b.String()), 0o644); err != nil {
		log.Fatal(err)
	}
	if err := os.Rename("oui.txt.tmp", "oui.txt"); err != nil {
		log.Fatal(err)
	}
	log.Printf("oui.txt: %d prefixes", n)
}
