package main

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeNet is the in-memory adapter for the Network seam.
type fakeNet struct {
	tcp       map[string]func(server net.Conn) // open addr → server (nil: accept and close)
	http      map[string]string                // URL → body
	multicast map[string][][2]string           // group → replies {ip, payload}
	arp       map[string]string
	local     map[string]bool
}

func (f *fakeNet) Dial(addr string, _ time.Duration) (net.Conn, error) {
	h, ok := f.tcp[addr]
	if !ok {
		return nil, errors.New("connection refused")
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		if h != nil {
			h(server)
		}
	}()
	return client, nil
}

func (f *fakeNet) HTTPGet(url string, _ time.Duration) (string, http.Header, error) {
	if body, ok := f.http[url]; ok {
		return body, http.Header{}, nil
	}
	return "", nil, errors.New("not found")
}

func (f *fakeNet) Multicast(addr string, _ []byte, _ time.Duration, handle func(string, []byte)) error {
	for _, r := range f.multicast[addr] {
		handle(r[0], []byte(r[1]))
	}
	return nil
}

func (f *fakeNet) ARPTable() (map[string]string, error) { return f.arp, nil }
func (f *fakeNet) LocalIPs() map[string]bool            { return f.local }

func rtspServer(c net.Conn) {
	buf := make([]byte, 512)
	if _, err := c.Read(buf); err == nil {
		c.Write([]byte("RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Dahua Rtsp Server\r\n\r\n"))
	}
}

func runScan(t *testing.T, nw Network, subnet string) State {
	t.Helper()
	s := NewScanner(nw)
	changed, cancel := s.subscribe()
	defer cancel()
	if err := s.Start(Options{Subnet: subnet, TimeoutMs: 100}); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(10 * time.Second)
	for {
		if st := s.State(); !st.Status.Running {
			return st
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatal("scan did not finish")
		}
	}
}

func TestScanPipeline(t *testing.T) {
	onvif := `<d:ProbeMatches><d:ProbeMatch><d:Scopes>onvif://www.onvif.org/name/TestCam</d:Scopes>` +
		`<d:XAddrs>http://10.0.0.3:2020/onvif/device_service</d:XAddrs></d:ProbeMatch></d:ProbeMatches>`
	nw := &fakeNet{
		tcp: map[string]func(net.Conn){
			"10.0.0.1:80":    nil, // this machine: must be ignored
			"10.0.0.2:554":   rtspServer,
			"10.0.0.2:80":    nil,
			"10.0.0.5:37777": nil,
		},
		http: map[string]string{
			"http://10.0.0.2:80/":   "<title>HIKVISION</title>",
			"http://10.0.0.3:2020/": "<title>IP Camera</title>", // port known only from discovery
		},
		multicast: map[string][][2]string{
			"239.255.255.250:3702": {{"10.0.0.3", onvif}, {"192.168.9.9", onvif}}, // second: outside the subnet
			"239.255.255.250:1900": {{"10.0.0.1", "HTTP/1.1 200 OK\r\nSERVER: Hikvision\r\n\r\n"}},
		},
		arp: map[string]string{
			"10.0.0.4":    "44:19:b6:00:00:01", // Hikvision
			"10.0.0.6":    "00:00:0c:00:00:01", // Cisco
			"172.16.0.10": "44:19:b6:00:00:02", // outside the subnet
		},
		local: map[string]bool{"10.0.0.1": true},
	}
	st := runScan(t, nw, "10.0.0.0/29")

	got := map[string]Device{}
	for _, d := range st.Devices {
		got[d.IP] = d
	}
	want := map[string]string{"10.0.0.2": "likely", "10.0.0.3": "likely", "10.0.0.5": "likely", "10.0.0.4": "possible", "10.0.0.6": "unlikely"}
	if len(got) != len(want) {
		t.Fatalf("devices: %+v", st.Devices)
	}
	for ip, v := range want {
		if got[ip].Verdict != v {
			t.Errorf("%s: verdict %q, want %q (evidence %+v)", ip, got[ip].Verdict, v, got[ip].Evidence)
		}
	}
	if st.Devices[0].Verdict != "likely" || st.Devices[len(st.Devices)-1].IP != "10.0.0.6" {
		t.Errorf("wrong order: %+v", st.Devices)
	}
	cam := got["10.0.0.3"]
	if len(cam.Ports) != 1 || cam.Ports[0] != 2020 || !hasDetail(cam, "ip camera") {
		t.Errorf("ONVIF port should be probed: %+v", cam)
	}
	if !hasDetail(got["10.0.0.2"], "port 554") || !hasDetail(got["10.0.0.2"], "dahua") {
		t.Errorf("RTSP: %+v", got["10.0.0.2"].Evidence)
	}
	if got["10.0.0.6"].Vendor == "" || got["10.0.0.4"].VerdictLabel != "Possible" {
		t.Errorf("vendor/label: %+v %+v", got["10.0.0.6"], got["10.0.0.4"])
	}
	if st.Status.Phase != "done" || st.Status.Error != "" || st.Summary[0].Count != 3 {
		t.Errorf("status/summary: %+v %+v", st.Status, st.Summary)
	}
}

func hasDetail(d Device, sub string) bool {
	for _, e := range d.Evidence {
		if strings.Contains(e.Detail, sub) {
			return true
		}
	}
	return false
}

func TestServer(t *testing.T) {
	srv := httptest.NewServer(newServer(NewScanner(&fakeNet{}), true))
	defer srv.Close()

	r, _ := http.Post(srv.URL+"/api/scan", "text/plain", strings.NewReader("{}"))
	if r.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain: %d", r.StatusCode)
	}
	req, _ := http.NewRequest("GET", srv.URL+"/api/devices", nil)
	req.Host = "evil.example"
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != http.StatusForbidden || r.Header.Get("Content-Type") != "application/json" {
		t.Errorf("external host: %d %s", r.StatusCode, r.Header.Get("Content-Type"))
	}

	r, err := http.Get(srv.URL + "/api/events")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	sc := bufio.NewScanner(r.Body)
	for sc.Scan() {
		if line := sc.Text(); strings.HasPrefix(line, "data: ") {
			if !strings.Contains(line, `"phaseLabel":"Ready"`) || !strings.Contains(line, `"label":"Likely camera"`) {
				t.Errorf("first state: %s", line)
			}
			return
		}
	}
	t.Fatal("no event received")
}

func TestProbeFor(t *testing.T) {
	for port, want := range map[int]probeKind{554: kindRTSP, 10554: kindRTSP, 37777: kindNone, 8000: kindNone, 80: kindHTTP, 9000: kindHTTP} {
		if got := probeFor(port); got != want {
			t.Errorf("port %d: %v, want %v", port, got, want)
		}
	}
}

func TestParseARP(t *testing.T) {
	text := `
Interface: 192.168.50.3 --- 0x12
  Internet Address      Physical Address      Type
  192.168.50.1          44-19-b6-aa-bb-cc     dynamic
  192.168.50.255        ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
? (10.0.0.7) at 0:9:18:1:2:3 on en0 ifscope [ethernet]
? (10.0.0.8) at (incomplete) on en0 ifscope [ethernet]
IP address       HW type     Flags       HW address            Mask     Device
172.16.0.9       0x1         0x2         ec:71:db:00:11:22     *        wlan0
172.16.0.10      0x1         0x0         00:00:00:00:00:00     *        wlan0
`
	got := parseARP(text)
	want := map[string]string{
		"192.168.50.1": "44:19:b6:aa:bb:cc",
		"10.0.0.7":     "00:09:18:01:02:03",
		"172.16.0.9":   "ec:71:db:00:11:22",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for ip, mac := range want {
		if got[ip] != mac {
			t.Errorf("%s: got %q, want %q", ip, got[ip], mac)
		}
	}
}

func TestVendorEvidence(t *testing.T) {
	cases := []struct {
		mac    string
		vendor bool
		camera bool
	}{
		{"00:09:18:01:02:03", true, true},  // Samsung Techwin
		{"80:85:44:6c:b9:79", true, false}, // Intelbras: name yes, signal no
		{"00:00:0c:12:34:56", true, false}, // Cisco
		{"aa:bb:cc:00:00:00", false, false},
	}
	for _, c := range cases {
		v := lookupVendor(c.mac)
		if (v != "") != c.vendor || (macEvidence(v) != nil) != c.camera {
			t.Errorf("%s: vendor %q, evidence %v", c.mac, v, macEvidence(v))
		}
	}
}

func TestVerdict(t *testing.T) {
	cases := []struct {
		ev   []Evidence
		want string
	}{
		{nil, "unlikely"},
		{[]Evidence{{"mac", "x", Weak}}, "possible"},
		{[]Evidence{{"mac", "x", Weak}, {"onvif", "y", Strong}}, "likely"},
	}
	for _, c := range cases {
		if got := verdict(c.ev); got != c.want {
			t.Errorf("verdict(%v) = %s, want %s", c.ev, got, c.want)
		}
	}
}

func TestKeywordEvidence(t *testing.T) {
	if ev := keywordEvidence("http:80", "Server: App-webs/\n<title>HIKVISION login</title>", ""); len(ev) != 1 || ev[0].Weight != Strong {
		t.Errorf("brand should be a strong signal: %v", ev)
	}
	if ev := keywordEvidence("http:80", "<title>NVR Web</title>", ""); len(ev) != 1 || ev[0].Weight != Weak {
		t.Errorf("generic term should be a weak signal: %v", ev)
	}
	if ev := keywordEvidence("http:80", "<title>Router</title> unanimous adverb", ""); ev != nil {
		t.Errorf("should not match inside words: %v", ev)
	}
}

func TestHostsIn(t *testing.T) {
	for cidr, n := range map[string]int{"192.168.1.0/24": 254, "10.0.0.0/30": 2, "10.0.0.5/32": 1} {
		_, ipnet, _ := net.ParseCIDR(cidr)
		if got := len(hostsIn(ipnet)); got != n {
			t.Errorf("%s: %d hosts, want %d", cidr, got, n)
		}
	}
}

func TestValidate(t *testing.T) {
	bad := []Options{
		{Subnet: "10.0.0.0/8", TimeoutMs: 700},
		{Subnet: "garbage", TimeoutMs: 700},
		{Subnet: "10.0.0.0/24", TimeoutMs: 10},
		{Subnet: "10.0.0.0/24", TimeoutMs: 700, ExtraPorts: []int{70000}},
	}
	for _, o := range bad {
		if _, _, err := o.validate(); err == nil {
			t.Errorf("%+v should be rejected", o)
		}
	}
	_, ports, err := Options{Subnet: "10.0.0.0/24", TimeoutMs: 700, ExtraPorts: []int{80, 9000}}.validate()
	if err != nil || len(ports) != len(defaultPorts)+1 {
		t.Errorf("extra ports: %v %v", ports, err)
	}
}

func TestClampSubnet(t *testing.T) {
	_, n, _ := net.ParseCIDR("172.16.5.9/16")
	n.IP = net.ParseIP("172.16.5.9")
	if got := clampSubnet(n); got != "172.16.5.0/24" {
		t.Errorf("got %s", got)
	}
}
