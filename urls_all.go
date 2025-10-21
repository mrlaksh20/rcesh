package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	waybackHost = "web.archive.org"
	waybackAddr = "web.archive.org:443"
)

// tuned HTTP transport with keep-alive and timeouts
func makeClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   7 * time.Second,
		KeepAlive: 60 * time.Second,
	}

	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   7 * time.Second,
		ExpectContinueTimeout: 2 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: waybackHost,
		},
	}

	return &http.Client{
		Transport: tr,
		Timeout:   45 * time.Second, // per request ceiling
	}
}

// warmup establishes TCP + TLS and performs a cheap HEAD to prime pools
func warmup(ctx context.Context, c *http.Client) error {
	// Establish a raw TCP to ensure path is open (best-effort)
	d := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	if conn, err := d.DialContext(ctx, "tcp", waybackAddr); err == nil {
		_ = conn.Close()
	}

	// Lightweight HEAD to prime TLS, ALPN, and HTTP/2 session
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+waybackHost+"/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return nil
}

// backoff helper
func retryBackoff(attempt int) time.Duration {
	if attempt <= 0 {
		return 0
	}
	// 400ms * 2^(n-1), capped
	d := 400 * time.Millisecond
	for i := 1; i < attempt; i++ {
		d *= 2
		if d > 6*time.Second {
			d = 6 * time.Second
			break
		}
	}
	// add jitter
	j := time.Duration(int64(d) / 5)
	return d + time.Duration(time.Now().UnixNano()%int64(j))
}

func transient(err error, code int) bool {
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && (ne.Timeout() || ne.Temporary()) {
			return true
		}
		// treat unexpected EOFs and connection resets as transient
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "reset") || strings.Contains(msg, "broken pipe") || strings.Contains(msg, "eof") {
			return true
		}
	}
	// Retry common transient HTTP codes
	if code == http.StatusTooManyRequests || (code >= 500 && code <= 504) {
		return true
	}
	return false
}

func fetchAllURLs(domain string) {
	c := makeClient()

	// Warmup phase with a bounded context (same approach as rcesh.go)
	wctx, cancelWarm := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelWarm()
	_ = warmup(wctx, c) // best-effort; proceed even if this fails

	// Build CDX URL
	cdxURL := fmt.Sprintf("https://%s/cdx/search/cdx?url=*.%s/*&collapse=urlkey&output=text&fl=original", waybackHost, domain)

	// Ensure reports folder exists
	_ = os.MkdirAll("reports", os.ModePerm)
	filePath := fmt.Sprintf("reports/%s_all.txt", domain)
	file, err := os.Create(filePath)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	// Graceful interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nInterrupt received, saving progress...")
		file.Sync()
		os.Exit(0)
	}()

	// Spinner + live count
	spinnerChars := []rune{'-', '\\', '|', '/'}
	count := 0
	spinnerIndex := 0

	done := make(chan bool)
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				fmt.Printf("\r[%c] Fetched: %d URLs", spinnerChars[spinnerIndex], count)
				spinnerIndex = (spinnerIndex + 1) % len(spinnerChars)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	// Request with retries
	var resp *http.Response
	var reqErr error
	const maxAttempts = 5
	for attempt := 0; attempt < maxAttempts; attempt++ {
		reqCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		req, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, cdxURL, nil)
		req.Header.Set("User-Agent", "Laksh-Wayback-Fetcher/1.0")
		resp, reqErr = c.Do(req)
		cancel()

		var code int
		if resp != nil {
			code = resp.StatusCode
		}
		if reqErr == nil && code >= 200 && code < 300 {
			break
		}
		// Close body on error to free connection
		if resp != nil && resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		if !transient(reqErr, code) || attempt == maxAttempts-1 {
			if reqErr != nil {
				fmt.Printf("\nError fetching URLs: %v\n", reqErr)
			} else {
				fmt.Printf("\nHTTP error fetching URLs: %d\n", code)
			}
			done <- true
			return
		}
		time.Sleep(retryBackoff(attempt + 1))
	}
	defer resp.Body.Close()

	// Stream read lines
	scanner := bufio.NewScanner(resp.Body)
	// enlarge buffer to handle long lines
	const maxLine = 2 * 1024 * 1024
	buf := make([]byte, 0, 128*1024)
	scanner.Buffer(buf, maxLine)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		count++
		_, _ = file.WriteString(line + "\n")
	}

	done <- true

	if err := scanner.Err(); err != nil {
		fmt.Println("\nError reading response:", err)
	} else {
		fmt.Printf("\r[✓] Completed! Total: %d URLs\n", count)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run urls_all.go <domain>")
		os.Exit(1)
	}
	domain := os.Args[1]
	fetchAllURLs(domain)
}
