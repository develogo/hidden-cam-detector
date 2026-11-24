package main

import (
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var logf = log.Printf

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// probeBudget: total time for one probe (connect + reply), proportional to the user's timeout.
func probeBudget(timeout time.Duration) time.Duration { return 4 * timeout }

// probeRTSP sends only OPTIONS: confirms a video server without opening a stream.
func probeRTSP(nw Network, ip string, port int, timeout time.Duration) []Evidence {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	c, err := nw.Dial(addr, timeout)
	if err != nil {
		return nil
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(probeBudget(timeout)))
	fmt.Fprintf(c, "OPTIONS rtsp://%s/ RTSP/1.0\r\nCSeq: 1\r\n\r\n", addr)
	buf := make([]byte, 2048)
	n, _ := c.Read(buf)
	resp := string(buf[:n])
	return rtspEvidence(port, strings.HasPrefix(resp, "RTSP/"), headerValue(resp, "Server"))
}

func probeHTTP(nw Network, ip string, port int, timeout time.Duration) []Evidence {
	body, hdr, err := nw.HTTPGet("http://"+net.JoinHostPort(ip, strconv.Itoa(port))+"/", probeBudget(timeout))
	if err != nil {
		return nil
	}
	title := htmlTitle(body)
	ctx := ""
	if title != "" {
		ctx = fmt.Sprintf(" (title: %q)", title)
	}
	text := strings.Join([]string{hdr.Get("Server"), hdr.Get("WWW-Authenticate"), title, body}, "\n")
	return keywordEvidence(fmt.Sprintf("http:%d", port), text, ctx)
}

func htmlTitle(body string) string {
	m := titleRe.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	t := strings.Join(strings.Fields(m[1]), " ")
	if r := []rune(t); len(r) > 80 {
		t = string(r[:80]) + "…"
	}
	return t
}

func headerValue(raw, name string) string {
	for _, line := range strings.Split(raw, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
