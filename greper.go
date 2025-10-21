// greper.go
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"html"
	"log"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
)

var (
	inFile      string
	outFile     string
	cacheOut    string
	dedupeKey   string
	stripAssets bool
)

func init() {
	flag.StringVar(&inFile, "f", "", "input file of URLs (one per line)")
	flag.StringVar(&outFile, "o", "out.txt", "output file of mutated URLs")
	flag.StringVar(&cacheOut, "cache", "param_urls.txt", "optional cache of parameterized URLs before mutation")
	flag.StringVar(&dedupeKey, "dedupe", "url", "dedupe mode: url|path+keys (controls how duplicates are detected)")
	flag.BoolVar(&stripAssets, "no-assets", true, "drop static asset URLs (js, css, images, fonts, media) before mutation")
}

func main() {
	flag.Parse()
	if inFile == "" {
		log.Fatal("usage: go run greper.go -f urls.txt [-o out.txt] [--cache param_urls.txt] [--dedupe url|path+keys] [--no-assets=true]")
	}

	in, err := os.Open(inFile)
	if err != nil {
		log.Fatalf("open input: %v", err)
	}
	defer in.Close()

	var cacheBuf bytes.Buffer
	var outBuf bytes.Buffer

	sc := bufio.NewScanner(in)
	const maxLine = 2 * 1024 * 1024
	buf := make([]byte, 0, 128*1024)
	sc.Buffer(buf, maxLine)

	seen := make(map[string]struct{}) // dedupe set

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		// Step 1: HTML entity unescape (&amp; -> &)
		unescaped := html.UnescapeString(line)

		// Parse; skip non-URLs
		u, err := url.Parse(unescaped)
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}

		// Must have at least one key=value query pair
		if !hasKeyValueQuery(u.RawQuery) {
			continue
		}

		// Dedup BEFORE mutation
		key := dedupeSignature(u, dedupeKey)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		// Optional: filter out static assets BEFORE mutation
		if stripAssets && looksLikeAsset(u.Path) {
			continue
		}

		// Skip URLs whose query is composed entirely of blacklisted analytics params
		if !hasAnyNonBlacklistedKey(u.RawQuery) {
			continue
		}

		// Cache original (post-unescape) parameterized URL
		cacheBuf.WriteString(u.String())
		cacheBuf.WriteByte('\n')

		// Mutate only non-blacklisted params
		mut := *u
		mut.RawQuery = mutateQueryRaw(u.RawQuery)
		outBuf.WriteString(mut.String())
		outBuf.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		log.Fatalf("scan input: %v", err)
	}

	// write outputs
	if cacheOut != "" {
		if err := os.WriteFile(cacheOut, cacheBuf.Bytes(), 0644); err != nil {
			log.Fatalf("write cache: %v", err)
		}
	}
	if err := os.WriteFile(outFile, outBuf.Bytes(), 0644); err != nil {
		log.Fatalf("write out: %v", err)
	}

	fmt.Printf(
		"Wrote %d mutated URLs to %s; cached %d param URLs to %s (dedupe=%s, no-assets=%v)\n",
		bytes.Count(outBuf.Bytes(), []byte{'\n'}), outFile,
		bytes.Count(cacheBuf.Bytes(), []byte{'\n'}), cacheOut,
		dedupeKey, stripAssets,
	)
}

// hasKeyValueQuery checks if the raw query contains at least one key=value pair.
func hasKeyValueQuery(raw string) bool {
	if raw == "" {
		return false
	}
	parts := splitParams(raw)
	for _, p := range parts {
		if p == "" {
			continue
		}
		if i := strings.IndexByte(p, '='); i > 0 && i < len(p) {
			return true
		}
	}
	return false
}

// hasAnyNonBlacklistedKey returns true if raw query has at least one key not in the blacklist.
func hasAnyNonBlacklistedKey(raw string) bool {
	if raw == "" {
		return false
	}
	for _, p := range splitParams(raw) {
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		key := kv[0]
		if !isBlacklistedKey(key) {
			return true
		}
	}
	return false
}

// splitParams splits on & and ; to cover both separators conservatively.
func splitParams(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		return r == '&' || r == ';'
	})
}

// Analytics/attribution blacklist; preserved during mutation and can cause drop if all keys are blacklisted.
var analyticsBlacklist = map[string]struct{}{
	"utm_source": {}, "utm_medium": {}, "utm_campaign": {}, "utm_term": {}, "utm_content": {},
	"gclid": {}, "gclsrc": {}, "dclid": {}, "fbclid": {},
	"msclkid": {}, "ttclid": {},
	"pk_campaign": {}, "pk_source": {}, "pk_kwd": {},
	"ref": {}, "ref_src": {}, "cid": {}, "campaign_id": {}, "mc_cid": {}, "mc_eid": {},
}

func isBlacklistedKey(k string) bool {
	_, ok := analyticsBlacklist[strings.ToLower(k)]
	return ok
}

// mutateQueryRaw replaces each non-blacklisted param value with LAKSH1..N.
// Blacklisted keys retain original values; ordering and duplicates preserved.
func mutateQueryRaw(raw string) string {
	if raw == "" {
		return raw
	}
	parts := splitParams(raw)
	idx := 1
	for i, p := range parts {
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		key := kv[0]
		// If no value present, handle based on blacklist
		if len(kv) == 1 {
			if isBlacklistedKey(key) {
				// Keep key as-is (no synthesized value)
				parts[i] = key
				continue
			}
			newVal := url.QueryEscape("LAKSH" + strconv.Itoa(idx))
			idx++
			parts[i] = key + "=" + newVal
			continue
		}
		// Key with value present
		val := kv[1]
		if isBlacklistedKey(key) {
			// Preserve original value exactly
			parts[i] = key + "=" + val
			continue
		}
		newVal := url.QueryEscape("LAKSH" + strconv.Itoa(idx))
		idx++
		parts[i] = key + "=" + newVal
	}
	return strings.Join(parts, "&")
}

// dedupeSignature builds a dedupe key for a URL based on the chosen mode.
func dedupeSignature(u *url.URL, mode string) string {
	switch mode {
	case "path+keys":
		// Same path + same set of parameter names considered duplicate,
		// regardless of values or order (helps collapse campaign duplicates).
		keys := paramKeys(u.RawQuery)
		return u.Scheme + "://" + u.Host + u.EscapedPath() + "|" + strings.Join(keys, "&")
	case "url":
		// Exact URL string (post-unescape) as key.
		return u.String()
	default:
		return u.String()
	}
}

// paramKeys extracts parameter names in encountered order, preserving duplicates.
func paramKeys(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := splitParams(raw)
	keys := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		keys = append(keys, kv[0])
	}
	return keys
}

// looksLikeAsset returns true if the path ends with common static asset extensions.
func looksLikeAsset(p string) bool {
	ext := strings.ToLower(path.Ext(p))
	if ext == "" {
		return false
	}
	switch ext {
	case ".js", ".mjs", ".css",
		".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".avif",
		".mp4", ".webm", ".mp3", ".wav", ".ogg",
		".woff", ".woff2", ".ttf", ".eot", ".otf",
		".map", ".json": // .json sometimes is API, but many are static configs; adjust if needed
		return true
	default:
		return false
	}
}
