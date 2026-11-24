package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// Network is everything the scan uses from the outside world.
// sysNet talks to the real network; fakeNet (in tests) answers in memory.
type Network interface {
	Dial(addr string, timeout time.Duration) (net.Conn, error)
	HTTPGet(url string, timeout time.Duration) (body string, hdr http.Header, err error)
	// Multicast sends payload and calls handle for each unicast reply until the deadline.
	Multicast(addr string, payload []byte, wait time.Duration, handle func(ip string, data []byte)) error
	ARPTable() (map[string]string, error)
	LocalIPs() map[string]bool
}

type sysNet struct{}

func (sysNet) Dial(addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, timeout)
}

var httpClient = &http.Client{
	Transport: &http.Transport{
		Proxy: nil, // never send LAN traffic to a system-configured proxy
		// Cameras use self-signed certificates; we only read the banner and send nothing sensitive.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || req.URL.Hostname() != via[0].URL.Hostname() {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

func (sysNet) HTTPGet(url string, timeout time.Duration) (string, http.Header, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return string(body), resp.Header, nil
}

// shortcut: uses the default-route interface; on multi-homed machines the other networks are not queried.
func (sysNet) Multicast(addr string, payload []byte, wait time.Duration, handle func(ip string, data []byte)) error {
	dst, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return err
	}
	defer conn.Close()
	for range 2 { // UDP drops packets; two sends are enough
		if _, err := conn.WriteToUDP(payload, dst); err != nil {
			return err
		}
	}
	conn.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 64<<10)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil
		}
		if err != nil {
			return err
		}
		handle(src.IP.String(), buf[:n])
	}
}

func (sysNet) ARPTable() (map[string]string, error) { return readARP() }

func (sysNet) LocalIPs() map[string]bool { return localIPs() }
