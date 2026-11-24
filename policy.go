package main

// Evidence policy: the only place that decides each signal's weight, which probe runs
// on each port and how signals become a verdict. Probes and discovery only observe.

import (
	"fmt"
	"regexp"
	"strings"
)

type Weight string

const (
	Strong Weight = "strong"
	Weak   Weight = "weak"
)

type Evidence struct {
	Source string `json:"source"`
	Detail string `json:"detail"`
	Weight Weight `json:"weight"`
}

var defaultPorts = []int{80, 554, 1935, 8000, 8080, 8899, 34567, 37777}

type probeKind int

const (
	kindNone probeKind = iota // binary protocol: the open port says it all
	kindHTTP
	kindRTSP
)

type portRule struct {
	probe probeKind
	ev    *Evidence // signal from the open port, before any probe
}

var portRules = map[int]portRule{
	554:   {kindRTSP, nil},
	8554:  {kindRTSP, nil},
	10554: {kindRTSP, nil},
	37777: {kindNone, &Evidence{"port", "37777 open (Dahua protocol)", Strong}},
	34567: {kindNone, &Evidence{"port", "34567 open (XMeye protocol, generic DVRs)", Strong}},
	8000:  {kindNone, &Evidence{"port", "8000 open (Hikvision SDK)", Strong}},
	8899:  {kindHTTP, &Evidence{"port", "8899 open (ONVIF on cheap cameras)", Weak}},
	1935:  {kindNone, &Evidence{"port", "1935 open (RTMP streaming)", Weak}},
}

// probeFor: a port without a rule (e.g. user extra, port from ONVIF) tries HTTP.
func probeFor(port int) probeKind {
	if r, ok := portRules[port]; ok {
		return r.probe
	}
	return kindHTTP
}

func portEvidence(port int) []Evidence {
	if r, ok := portRules[port]; ok && r.ev != nil {
		return []Evidence{*r.ev}
	}
	return nil
}

func rtspEvidence(port int, isRTSP bool, server string) []Evidence {
	if !isRTSP {
		return []Evidence{{"rtsp", fmt.Sprintf("port %d open, but no RTSP response", port), Weak}}
	}
	evs := []Evidence{{"rtsp", fmt.Sprintf("RTSP (video) server responding on port %d", port), Strong}}
	return append(evs, keywordEvidence("rtsp", server, "")...)
}

func onvifEvidence(info string) Evidence {
	detail := "responds as an ONVIF camera (WS-Discovery)"
	if info != "" {
		detail += ": " + info
	}
	return Evidence{"onvif", detail, Strong}
}

func mdnsEvidence(svc string) Evidence {
	return Evidence{"mdns", "advertises video service " + svc, Strong}
}

// Vendors whose MAC alone is a camera signal. Ezviz and Imou use Hikvision and Dahua blocks;
// Espressif is the Wi-Fi chip in many cheap unbranded cameras. Intelbras, Tuya, Tapo and Xiaomi are
// left out because the same prefixes show up in routers, bulbs and phones (the name is still shown).
var cameraVendorRe = regexp.MustCompile(`(?i)hikvision|dahua|axis communications|uniview|reolink|wyze|amcrest|samsung techwin|hanwha (vision|techwin)|vivotek|reecam|espressif`)

func macEvidence(vendor string) []Evidence {
	if vendor == "" || !cameraVendorRe.MatchString(vendor) {
		return nil
	}
	return []Evidence{{"mac", "camera vendor by MAC: " + vendor, Weak}}
}

var (
	brandRe = regexp.MustCompile(`(?i)\b(hikvision|hikcentral|dahua|uniview|reolink|amcrest|foscam|ezviz|imou|wyze|hanwha|wisenet|vivotek|axis communications|xmeye|netsurveillance)\b`)
	// Generic surveillance terms: on their own they only make a device "possible".
	genericRe = regexp.MustCompile(`(?i)\b(ip ?camera|ipcam|webcam|network camera|network video|dvr|nvr|cctv|surveillance|onvif|nvms|intelbras)\b`)
)

func keywordEvidence(src, text, ctx string) []Evidence {
	if m := brandRe.FindString(text); m != "" {
		return []Evidence{{src, "camera brand: " + strings.ToLower(m) + ctx, Strong}}
	}
	if m := genericRe.FindString(text); m != "" {
		return []Evidence{{src, "surveillance term: " + strings.ToLower(m) + ctx, Weak}}
	}
	return nil
}

// verdicts in display order; the web UI uses these labels and this order.
var verdicts = []struct{ Key, Label string }{
	{"likely", "Likely camera"},
	{"possible", "Possible"},
	{"unlikely", "Unlikely"},
}

var phaseLabels = map[string]string{
	"idle":    "Ready",
	"sweep":   "Scanning ports and discovery",
	"banners": "Reading banners",
	"arp":     "Reading ARP table",
	"done":    "Done",
}

// verdict: any strong signal = likely camera; only weak signals = possible.
func verdict(ev []Evidence) string {
	v := "unlikely"
	for _, e := range ev {
		if e.Weight == Strong {
			return "likely"
		}
		v = "possible"
	}
	return v
}

func verdictRank(v string) int {
	for i, x := range verdicts {
		if x.Key == v {
			return i
		}
	}
	return len(verdicts)
}

func verdictLabel(v string) string {
	return verdicts[min(verdictRank(v), len(verdicts)-1)].Label
}
