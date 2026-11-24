// hidden-cam-detector scans the local network for IP cameras, DVRs and NVRs.
// Detection only: it never opens video or attempts a login.
package main

import (
	"embed"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"runtime"
)

//go:embed web
var webFiles embed.FS

// version is set at build time by the release workflow (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	listen := flag.String("listen", "127.0.0.1:8765", "web UI address (use 0.0.0.0:8765 to access it from another device)")
	noBrowser := flag.Bool("no-browser", false, "do not open the browser automatically")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	log.Printf("hidden-cam-detector %s", version)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("could not listen on %s: %v", *listen, err)
	}
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	ip := net.ParseIP(host)
	loopback := ip != nil && ip.IsLoopback()
	if !loopback {
		log.Printf("warning: listening on %s; any device on this network can see the results and trigger scans", ln.Addr())
	}
	if ip == nil || ip.IsUnspecified() {
		host = "127.0.0.1"
	}
	url := "http://" + net.JoinHostPort(host, port)
	log.Printf("UI at %s", url)
	if !*noBrowser {
		openBrowser(url)
	}
	log.Fatal(http.Serve(ln, newServer(NewScanner(sysNet{}), loopback)))
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("open %s in your browser", url)
	}
}
