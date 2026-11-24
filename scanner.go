package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Device struct {
	IP           string     `json:"ip"`
	MAC          string     `json:"mac,omitempty"`
	Vendor       string     `json:"vendor,omitempty"`
	Ports        []int      `json:"ports"`
	Evidence     []Evidence `json:"evidence"`
	Verdict      string     `json:"verdict"` // likely | possible | unlikely
	VerdictLabel string     `json:"verdictLabel"`
}

// Finding is an observed fact about an IP: open port, MAC and/or evidence.
type Finding struct {
	IP       string
	Port     int
	MAC      string
	Vendor   string
	Evidence []Evidence
}

type Options struct {
	Subnet     string `json:"subnet"`
	ExtraPorts []int  `json:"extraPorts"`
	TimeoutMs  int    `json:"timeoutMs"`
}

func (o Options) validate() (*net.IPNet, []int, error) {
	ip, n, err := net.ParseCIDR(strings.TrimSpace(o.Subnet))
	if err != nil || ip.To4() == nil {
		return nil, nil, errors.New("invalid subnet: use IPv4 in the form 192.168.0.0/24")
	}
	if ones, _ := n.Mask.Size(); ones < 20 {
		return nil, nil, errors.New("subnet too large: the maximum is /20 (4096 addresses)")
	}
	if o.TimeoutMs < 100 || o.TimeoutMs > 5000 {
		return nil, nil, errors.New("timeout must be between 100 and 5000 ms")
	}
	if len(o.ExtraPorts) > 32 {
		return nil, nil, errors.New("at most 32 extra ports")
	}
	ports := slices.Clone(defaultPorts)
	for _, p := range o.ExtraPorts {
		if p < 1 || p > 65535 {
			return nil, nil, fmt.Errorf("invalid port: %d", p)
		}
		if !slices.Contains(ports, p) {
			ports = append(ports, p)
		}
	}
	return n, ports, nil
}

// hostsIn lists the usable addresses of the subnet (excluding network and broadcast).
func hostsIn(n *net.IPNet) []string {
	base := binary.BigEndian.Uint32(n.IP.To4())
	ones, bits := n.Mask.Size()
	size := uint32(1) << (bits - ones)
	start, end := uint32(0), size
	if size > 2 {
		start, end = 1, size-1
	}
	var out []string
	for i := start; i < end; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, base+i)
		out = append(out, ip.String())
	}
	return out
}

type Status struct {
	Running    bool   `json:"running"`
	Phase      string `json:"phase"` // idle | sweep | banners | arp | done
	PhaseLabel string `json:"phaseLabel"`
	Subnet     string `json:"subnet,omitempty"`
	Done       int    `json:"done"`
	Total      int    `json:"total"`
	Error      string `json:"error,omitempty"`
}

type Count struct {
	Verdict string `json:"verdict"`
	Label   string `json:"label"`
	Count   int    `json:"count"`
}

// State is the full snapshot shown by the UI and exported as JSON.
type State struct {
	Status  Status   `json:"status"`
	Summary []Count  `json:"summary"`
	Devices []Device `json:"devices"`
}

var errBusy = errors.New("a scan is already running")

// Scanner runs the scan and holds the device registry.
// All data enters through record, which applies filtering and classification in one place.
type Scanner struct {
	net Network

	mu      sync.Mutex
	status  Status
	subnet  *net.IPNet
	local   map[string]bool
	devices map[string]*Device
	subs    map[chan struct{}]struct{}
}

func NewScanner(nw Network) *Scanner {
	return &Scanner{
		net:     nw,
		status:  Status{Phase: "idle"},
		devices: map[string]*Device{},
		subs:    map[chan struct{}]struct{}{},
	}
}

func (s *Scanner) Start(o Options) error {
	n, ports, err := o.validate()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status.Running {
		return errBusy
	}
	s.subnet, s.local = n, s.net.LocalIPs()
	s.devices = map[string]*Device{}
	s.status = Status{Running: true, Phase: "sweep", Subnet: n.String()}
	s.notifyLocked()
	go s.run(n, ports, time.Duration(o.TimeoutMs)*time.Millisecond)
	return nil
}

func (s *Scanner) run(n *net.IPNet, ports []int, timeout time.Duration) {
	defer func() {
		msg := ""
		if r := recover(); r != nil {
			msg = fmt.Sprint("scan aborted: ", r)
			logf("%s", msg)
		}
		s.setStatus(func(st *Status) { st.Running = false; st.Phase = "done"; st.Error = msg })
	}()

	var disc sync.WaitGroup
	disc.Add(1)
	go func() { defer disc.Done(); discover(s.net, timeout, s.record) }()
	s.sweep(n, ports, timeout)
	disc.Wait() // ports advertised by discovery get probed too

	s.setStatus(func(st *Status) { st.Phase = "banners" })
	s.probe(timeout)

	// The TCP sweep has already made the OS resolve the MAC of every live host.
	s.setStatus(func(st *Status) { st.Phase = "arp" })
	table, err := s.net.ARPTable()
	if err != nil {
		logf("arp: %v", err)
	}
	for ip, mac := range table {
		vendor := lookupVendor(mac)
		s.record(Finding{IP: ip, MAC: mac, Vendor: vendor, Evidence: macEvidence(vendor)})
	}
}

func (s *Scanner) sweep(n *net.IPNet, ports []int, timeout time.Duration) {
	hosts := hostsIn(n)
	total := len(hosts) * len(ports)
	s.setStatus(func(st *Status) { st.Total = total })

	type job struct {
		ip   string
		port int
	}
	jobs := make(chan job)
	var done atomic.Int64
	var wg sync.WaitGroup
	for range 256 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if c, err := s.net.Dial(net.JoinHostPort(j.ip, strconv.Itoa(j.port)), timeout); err == nil {
					c.Close()
					s.record(Finding{IP: j.ip, Port: j.port, Evidence: portEvidence(j.port)})
				}
				if c := int(done.Add(1)); c%64 == 0 || c == total {
					s.setStatus(func(st *Status) { st.Done = max(st.Done, c) })
				}
			}
		}()
	}
	for _, h := range hosts {
		for _, p := range ports {
			jobs <- job{h, p}
		}
	}
	close(jobs)
	wg.Wait()
}

func (s *Scanner) probe(timeout time.Duration) {
	type target struct {
		ip   string
		port int
	}
	var targets []target
	s.mu.Lock()
	for ip, d := range s.devices {
		for _, p := range d.Ports {
			targets = append(targets, target{ip, p})
		}
	}
	s.mu.Unlock()

	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup
	for _, t := range targets {
		var fn func(Network, string, int, time.Duration) []Evidence
		switch probeFor(t.port) {
		case kindRTSP:
			fn = probeRTSP
		case kindHTTP:
			fn = probeHTTP
		default:
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			s.record(Finding{IP: t.ip, Evidence: fn(s.net, t.ip, t.port, timeout)})
		}()
	}
	wg.Wait()
}

// record is the registry's only entry point: it drops anything outside the
// subnet or on this machine, merges into the device and reclassifies.
func (s *Scanner) record(f Finding) {
	if f.Port == 0 && f.MAC == "" && len(f.Evidence) == 0 {
		return
	}
	ip := net.ParseIP(f.IP)
	s.mu.Lock()
	defer s.mu.Unlock()
	if ip == nil || s.subnet == nil || !s.subnet.Contains(ip) || s.local[f.IP] {
		return
	}
	d := s.devices[f.IP]
	if d == nil {
		d = &Device{IP: f.IP, Ports: []int{}, Evidence: []Evidence{}}
		s.devices[f.IP] = d
	}
	if f.Port != 0 && !slices.Contains(d.Ports, f.Port) {
		d.Ports = append(d.Ports, f.Port)
		slices.Sort(d.Ports)
	}
	if f.MAC != "" {
		d.MAC, d.Vendor = f.MAC, f.Vendor
	}
	for _, e := range f.Evidence {
		if !slices.Contains(d.Evidence, e) {
			d.Evidence = append(d.Evidence, e)
		}
	}
	d.Verdict = verdict(d.Evidence)
	s.notifyLocked()
}

func (s *Scanner) setStatus(fn func(st *Status)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.status)
	s.notifyLocked()
}

// notifyLocked only signals that something changed; readers fetch the current State, so coalesced signals lose nothing.
func (s *Scanner) notifyLocked() {
	for ch := range s.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (s *Scanner) subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	return ch, func() {
		s.mu.Lock()
		delete(s.subs, ch)
		s.mu.Unlock()
	}
}

// State returns a sorted copy (likely first, then by IP) with labels filled in.
func (s *Scanner) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := State{Status: s.status, Devices: make([]Device, 0, len(s.devices))}
	st.Status.PhaseLabel = phaseLabels[st.Status.Phase]
	counts := map[string]int{}
	for _, d := range s.devices {
		c := *d
		c.Ports, c.Evidence = slices.Clone(d.Ports), slices.Clone(d.Evidence)
		c.VerdictLabel = verdictLabel(c.Verdict)
		st.Devices = append(st.Devices, c)
		counts[c.Verdict]++
	}
	slices.SortFunc(st.Devices, func(a, b Device) int {
		if r := verdictRank(a.Verdict) - verdictRank(b.Verdict); r != 0 {
			return r
		}
		return bytes.Compare(net.ParseIP(a.IP).To4(), net.ParseIP(b.IP).To4())
	})
	for _, v := range verdicts {
		st.Summary = append(st.Summary, Count{v.Key, v.Label, counts[v.Key]})
	}
	return st
}
