package main

import (
	"crypto/rand"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const discoveryWait = 3 * time.Second

func discover(nw Network, timeout time.Duration, rec func(Finding)) {
	var wg sync.WaitGroup
	for _, f := range []func(Network, time.Duration, func(Finding)){discoverONVIF, discoverSSDP, discoverMDNS} {
		wg.Add(1)
		go func() { defer wg.Done(); f(nw, timeout, rec) }()
	}
	wg.Wait()
}

const wsProbe = `<?xml version="1.0" encoding="UTF-8"?>` +
	`<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dn="http://www.onvif.org/ver10/network/wsdl">` +
	`<e:Header><w:MessageID>uuid:%s</w:MessageID><w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>` +
	`<w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>` +
	`<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>`

var (
	onvifScopeRe = regexp.MustCompile(`onvif://www\.onvif\.org/(name|hardware)/([^\s<]+)`)
	xaddrsRe     = regexp.MustCompile(`XAddrs>([^<]+)<`)
)

func discoverONVIF(nw Network, _ time.Duration, rec func(Finding)) {
	err := nw.Multicast("239.255.255.250:3702", []byte(fmt.Sprintf(wsProbe, newUUID())), discoveryWait, func(ip string, data []byte) {
		msg := string(data)
		if !strings.Contains(msg, "ProbeMatch") {
			return
		}
		// The ONVIF service port (e.g. 2020 on Tapo) is recorded as open so it gets probed later.
		rec(Finding{IP: ip, Port: xaddrPort(msg, ip), Evidence: []Evidence{onvifEvidence(onvifScopes(msg))}})
	})
	if err != nil {
		logf("onvif: %v", err)
	}
}

func onvifScopes(msg string) string {
	var parts []string
	for _, m := range onvifScopeRe.FindAllStringSubmatch(msg, -1) {
		v, err := url.PathUnescape(m[2])
		if err != nil {
			v = m[2]
		}
		parts = append(parts, m[1]+"="+v)
	}
	return strings.Join(parts, " ")
}

// xaddrPort returns the port of the advertised ONVIF address, only if it belongs to the responding device.
func xaddrPort(msg, ip string) int {
	m := xaddrsRe.FindStringSubmatch(msg)
	if m == nil {
		return 0
	}
	for _, a := range strings.Fields(m[1]) {
		u, err := url.Parse(a)
		if err != nil || u.Hostname() != ip {
			continue
		}
		if u.Port() == "" {
			return 80
		}
		p, _ := strconv.Atoi(u.Port())
		return p
	}
	return 0
}

const ssdpSearch = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"

var xmlTagRe = regexp.MustCompile(`(?is)<(manufacturer|modelName)>(.*?)</`)

func discoverSSDP(nw Network, timeout time.Duration, rec func(Finding)) {
	locations := map[string]string{}
	err := nw.Multicast("239.255.255.250:1900", []byte(ssdpSearch), discoveryWait, func(ip string, data []byte) {
		msg := string(data)
		if evs := keywordEvidence("ssdp", msg, ""); evs != nil {
			rec(Finding{IP: ip, Evidence: evs})
		}
		if loc := headerValue(msg, "Location"); loc != "" {
			locations[ip] = loc
		}
	})
	if err != nil {
		logf("ssdp: %v", err)
	}

	var wg sync.WaitGroup
	for ip, loc := range locations {
		// Only follow descriptions hosted on the device that answered.
		if u, err := url.Parse(loc); err != nil || u.Scheme != "http" || u.Hostname() != ip {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			body, _, err := nw.HTTPGet(loc, probeBudget(timeout))
			if err != nil {
				return
			}
			var info []string
			for _, m := range xmlTagRe.FindAllStringSubmatch(body, 2) {
				info = append(info, strings.TrimSpace(m[2]))
			}
			ctx := ""
			if len(info) > 0 {
				ctx = " (" + strings.Join(info, " ") + ")"
			}
			if evs := keywordEvidence("upnp", body, ctx); evs != nil {
				rec(Finding{IP: ip, Evidence: evs})
			}
		}()
	}
	wg.Wait()
}

// mDNS services advertised by cameras. The query leaves from a port other than 5353, so
// per RFC 6762 (legacy unicast) the answer comes straight back to our socket.
var mdnsServices = []string{"_rtsp._tcp.local", "_axis-video._tcp.local"}

func discoverMDNS(nw Network, _ time.Duration, rec func(Finding)) {
	var wg sync.WaitGroup
	for _, svc := range mdnsServices {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := nw.Multicast("224.0.0.251:5353", dnsQuery(svc), discoveryWait, func(ip string, _ []byte) {
				rec(Finding{IP: ip, Evidence: []Evidence{mdnsEvidence(svc)}})
			})
			if err != nil {
				logf("mdns %s: %v", svc, err)
			}
		}()
	}
	wg.Wait()
}

func dnsQuery(name string) []byte {
	b := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0} // id, flags, 1 question
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0, 0, 12, 0, 1) // end of name, type PTR, class IN
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
