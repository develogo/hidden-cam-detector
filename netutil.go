package main

import (
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

// defaultSubnet returns the subnet of the default-route interface, capped at /24.
func defaultSubnet() string {
	var routed net.IP
	// "Connecting" UDP sends no packet: it only asks the OS which interface the default route uses.
	if c, err := net.Dial("udp4", "192.0.2.1:9"); err == nil {
		routed = c.LocalAddr().(*net.UDPAddr).IP
		c.Close()
	}
	addrs, _ := net.InterfaceAddrs()
	var fallback *net.IPNet
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.To4() == nil || n.IP.IsLoopback() || n.IP.IsLinkLocalUnicast() {
			continue
		}
		if routed != nil && n.IP.Equal(routed) {
			return clampSubnet(n)
		}
		if fallback == nil && n.IP.IsPrivate() {
			fallback = n
		}
	}
	if fallback != nil {
		return clampSubnet(fallback)
	}
	return ""
}

// clampSubnet shrinks networks larger than /24 to the /24 of the IP itself, so the scan takes seconds.
func clampSubnet(n *net.IPNet) string {
	ones, bits := n.Mask.Size()
	if bits == 128 {
		ones -= 96
	}
	mask := net.CIDRMask(max(ones, 24), 32)
	return (&net.IPNet{IP: n.IP.To4().Mask(mask), Mask: mask}).String()
}

func localIPs() map[string]bool {
	m := map[string]bool{}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			m[n.IP.String()] = true
		}
	}
	return m
}

func readARP() (map[string]string, error) {
	var out []byte
	var err error
	if runtime.GOOS == "linux" {
		out, err = os.ReadFile("/proc/net/arp")
	} else {
		out, err = exec.Command("arp", "-a").Output()
	}
	return parseARP(string(out)), err
}

var (
	ipRe  = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	macRe = regexp.MustCompile(`\b[0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5}\b`)
)

// parseARP handles `arp -a` output (Windows and macOS) and /proc/net/arp (Linux).
func parseARP(text string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		ip, mac := ipRe.FindString(line), macRe.FindString(line)
		if ip == "" || mac == "" {
			continue
		}
		mac = normalizeMAC(mac)
		if mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" || strings.HasPrefix(mac, "01:00:5e") {
			continue
		}
		m[ip] = mac
	}
	return m
}

// normalizeMAC: lowercase, ":" and two digits per byte (macOS drops leading zeros).
func normalizeMAC(mac string) string {
	parts := strings.FieldsFunc(strings.ToLower(mac), func(r rune) bool { return r == ':' || r == '-' })
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ":")
}
