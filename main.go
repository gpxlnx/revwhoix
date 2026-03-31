package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
)

// ─── Banner ───────────────────────────────────────────────────────────────────

const banner = `
                            __          _     
   ________ _   ___      __/ /_  ____  (_)  __
  / ___/ _ \ | / / | /| / / __ \/ __ \/ / |/_/
 / /  /  __/ |/ /| |/ |/ / / / / /_/ / />  <  
/_/   \___/|___/ |__/|__/_/ /_/\____/_/_/|_|  

              [Go Edition — Multi-API Round-Robin]
              by gpxlnx <gpx0x53@proton.me>
`

// ─── User-Agent rotation ──────────────────────────────────────────────────────

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.0; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
}

func randomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

// ─── Round-Robin Key Rotator ──────────────────────────────────────────────────

// KeyRotator distributes API keys evenly using atomic round-robin.
type KeyRotator struct {
	keys    []string
	counter uint64
}

// NewKeyRotator creates a rotator from a slice of API keys.
func NewKeyRotator(keys []string) *KeyRotator {
	return &KeyRotator{keys: keys}
}

// Next returns the next API key in round-robin order.
func (kr *KeyRotator) Next() string {
	n := atomic.AddUint64(&kr.counter, 1)
	return kr.keys[(n-1)%uint64(len(kr.keys))]
}

// Len returns the number of keys.
func (kr *KeyRotator) Len() int {
	return len(kr.keys)
}

// ─── WhoisXML API types ──────────────────────────────────────────────────────

const apiURL = "https://reverse-whois.whoisxmlapi.com/api/v2"

type searchRequest struct {
	APIKey           string           `json:"apiKey"`
	SearchType       string           `json:"searchType"`
	Mode             string           `json:"mode"`
	Punycode         bool             `json:"punycode"`
	BasicSearchTerms basicSearchTerms `json:"basicSearchTerms"`
	SearchAfter      string           `json:"searchAfter,omitempty"`
}

type basicSearchTerms struct {
	Include []string `json:"include"`
}

type apiResponse struct {
	DomainsCount        int      `json:"domainsCount"`
	DomainsList         []string `json:"domainsList"`
	NextPageSearchAfter string   `json:"nextPageSearchAfter"`
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// sanitizeKey strips BOM, non-printable characters, quotes, and whitespace.
func sanitizeKey(s string) string {
	// Strip UTF-8 BOM
	s = strings.TrimPrefix(s, "\xef\xbb\xbf")
	// Remove any non-printable / non-ASCII-graph characters
	var b strings.Builder
	for _, r := range s {
		if r > 31 && r < 127 && !unicode.IsSpace(r) {
			b.WriteRune(r)
		}
	}
	s = b.String()
	// Strip surrounding quotes
	s = strings.Trim(s, `"'`)
	return strings.TrimSpace(s)
}

// maskKey returns a masked version for safe logging: shows first 6 + last 4 chars.
func maskKey(key string) string {
	if len(key) <= 10 {
		return "***"
	}
	return key[:6] + "..." + key[len(key)-4:]
}

// loadKeys reads API keys from a file with aggressive sanitization.
func loadKeys(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var keys []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key := sanitizeKey(scanner.Text())
		if key != "" && !strings.HasPrefix(key, "#") {
			keys = append(keys, key)
		}
	}
	return keys, scanner.Err()
}

// loadLines reads a file and returns non-empty, non-comment lines (trimmed).
func loadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// info prints a message to stderr (only when not silent).
func info(silent bool, format string, a ...interface{}) {
	if !silent {
		fmt.Fprintf(os.Stderr, format+"\n", a...)
	}
}

// ─── API Client ──────────────────────────────────────────────────────────────

func doPost(client *http.Client, body interface{}) (int, []byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return 0, nil, fmt.Errorf("marshalling request: %w", err)
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", randomUserAgent())

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("reading response: %w", err)
	}

	return resp.StatusCode, respBody, nil
}

// doPostWithRetry sends the request and retries with the next API key on 403.
// It will try up to len(keys) times, rotating through keys.
// Keys that return 403 are recorded in failedKeys for the final report.
func doPostWithRetry(client *http.Client, rotator *KeyRotator, failedKeys map[string]bool, mode, keyword, searchAfter string, silent bool) (*apiResponse, error) {
	maxRetries := rotator.Len()

	for attempt := 0; attempt < maxRetries; attempt++ {
		apiKey := rotator.Next()

		reqBody := searchRequest{
			APIKey:     apiKey,
			SearchType: "current",
			Mode:       mode,
			Punycode:   true,
			BasicSearchTerms: basicSearchTerms{
				Include: []string{keyword},
			},
		}
		if searchAfter != "" {
			reqBody.SearchAfter = searchAfter
		}

		statusCode, body, err := doPost(client, reqBody)
		if err != nil {
			return nil, err
		}

		if statusCode == http.StatusOK {
			var result apiResponse
			if err := json.Unmarshal(body, &result); err != nil {
				return nil, fmt.Errorf("unmarshalling response: %w", err)
			}
			return &result, nil
		}

		if statusCode == 403 {
			failedKeys[apiKey] = true
			info(silent, "   ⚠️  Key %s returned 403, trying next key (%d/%d) ...",
				maskKey(apiKey), attempt+1, maxRetries)
			continue
		}

		return nil, fmt.Errorf("API returned status %d: %s", statusCode, string(body))
	}

	return nil, fmt.Errorf("all %d API keys returned 403 — check your keys or DRS credit balance", maxRetries)
}

// preview checks if any domains exist for the keyword.
func preview(client *http.Client, rotator *KeyRotator, failedKeys map[string]bool, keyword string, silent bool) (bool, error) {
	resp, err := doPostWithRetry(client, rotator, failedKeys, "preview", keyword, "", silent)
	if err != nil {
		return false, err
	}
	return resp.DomainsCount > 0, nil
}

// fetchDomains retrieves all domains for a keyword with automatic pagination.
func fetchDomains(client *http.Client, rotator *KeyRotator, failedKeys map[string]bool, keyword string, silent bool) ([]string, error) {
	var allDomains []string
	searchAfter := ""
	page := 1

	for {
		info(silent, "   ⛏️  Fetching page %d ...", page)

		resp, err := doPostWithRetry(client, rotator, failedKeys, "purchase", keyword, searchAfter, silent)
		if err != nil {
			return allDomains, err
		}

		allDomains = append(allDomains, resp.DomainsList...)

		if resp.NextPageSearchAfter == "" || len(resp.DomainsList) == 0 {
			break
		}
		searchAfter = resp.NextPageSearchAfter
		page++
	}

	return allDomains, nil
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	// CLI flags
	keyword := flag.String("k", "", "Single keyword (org name, email, etc.)")
	keywordFile := flag.String("kL", "", "File with one keyword per line")
	keysFile := flag.String("l", "", "File with one API key per line (required)")
	outputFile := flag.String("o", "", "Output file path (optional)")
	silent := flag.Bool("silent", false, "Suppress banner/info, print only domains")
	timeout := flag.Int("t", 30, "HTTP request timeout in seconds")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: revwhoix-go [options]\n\nOptions:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  revwhoix-go -k \"Airbnb, Inc\" -l keys.txt\n")
		fmt.Fprintf(os.Stderr, "  revwhoix-go -kL orgs.txt -l keys.txt -o results.txt\n")
		fmt.Fprintf(os.Stderr, "  revwhoix-go -k \"target@example.com\" -l keys.txt -silent | sort -u\n")
	}
	flag.Parse()

	// ── Validate inputs ──────────────────────────────────────────────────

	if *keysFile == "" {
		fmt.Fprintln(os.Stderr, "❌ -l (API keys file) is required")
		flag.Usage()
		os.Exit(1)
	}

	if *keyword == "" && *keywordFile == "" {
		fmt.Fprintln(os.Stderr, "❌ Either -k (keyword) or -kL (keyword file) is required")
		flag.Usage()
		os.Exit(1)
	}

	// ── Load API keys ────────────────────────────────────────────────────

	apiKeys, err := loadKeys(*keysFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to load API keys from %s: %v\n", *keysFile, err)
		os.Exit(1)
	}
	if len(apiKeys) == 0 {
		fmt.Fprintf(os.Stderr, "❌ No API keys found in %s\n", *keysFile)
		os.Exit(1)
	}

	// ── Load keywords ────────────────────────────────────────────────────

	var keywords []string
	if *keyword != "" {
		keywords = append(keywords, *keyword)
	}
	if *keywordFile != "" {
		kws, err := loadLines(*keywordFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to load keywords from %s: %v\n", *keywordFile, err)
			os.Exit(1)
		}
		keywords = append(keywords, kws...)
	}
	if len(keywords) == 0 {
		fmt.Fprintln(os.Stderr, "❌ No keywords provided")
		os.Exit(1)
	}

	// ── Setup ────────────────────────────────────────────────────────────

	if !*silent {
		fmt.Fprint(os.Stderr, "\033[33;1m"+banner+"\033[0m\n")
	}

	rotator := NewKeyRotator(apiKeys)
	client := &http.Client{Timeout: time.Duration(*timeout) * time.Second}

	info(*silent, "🔑 Loaded %d API key(s) — round-robin enabled", len(apiKeys))
	for i, k := range apiKeys {
		info(*silent, "   [%d] %s", i+1, maskKey(k))
	}
	info(*silent, "🎯 %d keyword(s) to process\n", len(keywords))

	// ── Output file handle ───────────────────────────────────────────────

	var outFile *os.File
	if *outputFile != "" {
		outFile, err = os.OpenFile(*outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to open output file %s: %v\n", *outputFile, err)
			os.Exit(1)
		}
		defer outFile.Close()
	}

	// ── Global dedup + failed keys tracking ─────────────────────────────

	seen := make(map[string]bool)
	failedKeys := make(map[string]bool)
	totalDomains := 0

	// ── Process each keyword ─────────────────────────────────────────────

	for i, kw := range keywords {
		info(*silent, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		info(*silent, "🚀 [%d/%d] Reverse WHOIS lookup: \"%s\"", i+1, len(keywords), kw)

		// Preview
		info(*silent, "   🔍 Checking if domains exist ...")
		exists, err := preview(client, rotator, failedKeys, kw, *silent)
		if err != nil {
			fmt.Fprintf(os.Stderr, "   ❌ Preview failed for \"%s\": %v\n", kw, err)
			continue
		}
		if !exists {
			info(*silent, "   ⚠️  No domains found for \"%s\", skipping", kw)
			continue
		}
		info(*silent, "   ✅ Domains exist")

		// Fetch
		domains, err := fetchDomains(client, rotator, failedKeys, kw, *silent)
		if err != nil {
			fmt.Fprintf(os.Stderr, "   ❌ Fetch failed for \"%s\": %v\n", kw, err)
			continue
		}

		// Dedup + output
		newCount := 0
		for _, d := range domains {
			if seen[d] {
				continue
			}
			seen[d] = true
			newCount++
			totalDomains++

			fmt.Println(d)
			if outFile != nil {
				fmt.Fprintln(outFile, d)
			}
		}

		info(*silent, "   📊 %d new domains (deduped from %d raw)", newCount, len(domains))
	}

	// ── Summary ──────────────────────────────────────────────────────────

	info(*silent, "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	info(*silent, "✅ Done! %d unique domains found across %d keyword(s)", totalDomains, len(keywords))
	if *outputFile != "" {
		info(*silent, "💾 Results saved to %s", *outputFile)
	}

	// ── Failed keys report ─────────────────────────────────────────────

	if len(failedKeys) > 0 {
		info(*silent, "")
		info(*silent, "🚫 API keys sem crédito DRS (%d/%d):", len(failedKeys), len(apiKeys))
		for key := range failedKeys {
			info(*silent, "   ✗ %s", key)
		}
		info(*silent, "")
		info(*silent, "💡 Remova essas keys do seu arquivo para acelerar as buscas.")
	}
}
