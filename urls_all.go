package main

import (
	"bufio"
	"crypto/tls"
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

// create HTTP client with timeouts
func makeClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   7 * time.Second,
		KeepAlive: 60 * time.Second,
	}
	trans := &http.Transport{
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
		Transport: trans,
		Timeout:   45 * time.Second, // timeout applies to whole request including reading response
	}
}

// retry backoff with jitter
func retryBackoff(attempt int) time.Duration {
	if attempt <= 0 {
		return 0
	}
	d := 400 * time.Millisecond
	for i := 1; i < attempt; i++ {
		d *= 2
		if d > 6*time.Second {
			d = 6 * time.Second
			break
		}
	}
	j := time.Duration(int64(d) / 5)
	return d + time.Duration(time.Now().UnixNano()%int64(j))
}

// check if error or HTTP code is transient
func transient(err error, code int) bool {
	if err != nil {
		if ne, ok := err.(net.Error); ok && (ne.Timeout() || ne.Temporary()) {
			return true
		}
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "reset") || strings.Contains(msg, "broken pipe") || strings.Contains(msg, "eof") {
			return true
		}
	}
	if code == http.StatusTooManyRequests || (code >= 500 && code <= 504) {
		return true
	}
	return false
}

func fetchAllURLs(domain string) {
	client := makeClient()

	cdxURL := fmt.Sprintf("https://%s/cdx/search/cdx?url=*.%s/*&collapse=urlkey&output=text&fl=original", waybackHost, domain)

	// Ensure reports directory
	if err := os.MkdirAll("reports", os.ModePerm); err != nil {
		fmt.Println("Error creating reports directory:", err)
		return
	}

	filePath := fmt.Sprintf("reports/%s_all.txt", domain)
	file, err := os.Create(filePath)
	if err != nil {
		fmt.Println("Error creating output file:", err)
		return
	}
	defer file.Close()

	// Handle interrupts gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nInterrupt received, saving progress...")
		file.Sync()
		os.Exit(0)
	}()

	// Spinner for display
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

	var resp *http.Response
	var reqErr error

	const maxAttempts = 5
	for attempt := 0; attempt < maxAttempts; attempt++ {
		req, _ := http.NewRequest(http.MethodGet, cdxURL, nil)

		// Add realistic headers
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		req.Header.Set("Accept-Language", "en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7,ta;q=0.6,nl;q=0.5,pt;q=0.4")
		req.Header.Set("Cache-Control", "max-age=0")
		req.Header.Set("Cookie", "donation-identifier=91b4e0553da81d3a7631fbaa3e855bff; wb-p-SERVER=wwwb-app242; wb-cdx-SERVER=wwwb-app240")
		req.Header.Set("Sec-Ch-Ua", `"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"`)
		req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
		req.Header.Set("Sec-Ch-Ua-Platform", `"Linux"`)
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		req.Host = waybackHost

		resp, reqErr = client.Do(req)

		var code int
		if resp != nil {
			code = resp.StatusCode
		}

		if reqErr == nil && code >= 200 && code < 300 {
			break
		}

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

	if resp == nil {
		done <- true
		fmt.Println("\nFailed to get a response")
		return
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 0, 128*1024)
	scanner.Buffer(buf, 2*1024*1024) // allow long lines

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
		fmt.Println("Usage: go run yourfile.go <domain>")
		os.Exit(1)
	}
	domain := os.Args[1]
	fetchAllURLs(domain)
}
