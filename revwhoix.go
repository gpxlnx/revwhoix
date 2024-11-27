package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

const configPath = "~/.config/whoisxml.conf"
const apiUrl = "https://reverse-whois.whoisxmlapi.com/api/v2"

// Structs to model the API requests and responses
type WhoisRequest struct {
	ApiKey            string `json:"apiKey"`
	SearchType        string `json:"searchType"`
	Mode              string `json:"mode"`
	Punycode          bool   `json:"punycode"`
	BasicSearchTerms  SearchTerms `json:"basicSearchTerms"`
	SearchAfter       string `json:"searchAfter,omitempty"`
}

type SearchTerms struct {
	Include []string `json:"include"`
}

type WhoisResponse struct {
	DomainsCount     int      `json:"domainsCount"`
	DomainsList      []string `json:"domainsList"`
	NextPageSearchAfter string `json:"nextPageSearchAfter,omitempty"`
}

func main() {
	log.SetFlags(0) // Disables timestamps for simplicity
	log.Println("\033[33;1m\n    ________ _   ___      __/ /_  ____  (_)  __\n   / ___/ _ \\ | / / | /| / / __ \\/ __ \\/ / |/_/\n  / /  /  __/ |/ /| |/ |/ / / / / /_/ / />  <  \n /_/   \\___/|___/ |__/|__/_/ /_/\\____/_/_/|_|  \n                                               \033[36;1m - by Sybil Scan Research <research@sybilscan.com>\033[0m ")

	// Input argument handling
	if len(os.Args) < 2 {
		log.Fatal("❌ Missing required keyword argument")
	}
	keyword := os.Args[1]

	// Read the API key from config file
	apiKey := checkApiKey()
	if len(apiKey) < 2 {
		log.Fatalf("❌ API Key is not present at %s\n", configPath)
	}

	log.Printf("🚀 Performing reverse whois lookup on \"%s\"", keyword)

	// Set up the API request data
	data := WhoisRequest{
		ApiKey:    apiKey,
		SearchType: "current",
		Mode:      "purchase",
		Punycode:  true,
		BasicSearchTerms: SearchTerms{
			Include: []string{keyword},
		},
	}

	// Preview mode check
	previewMode := WhoisRequest{
		ApiKey:    apiKey,
		SearchType: "current",
		Mode:      "preview",
		Punycode:  true,
		BasicSearchTerms: SearchTerms{
			Include: []string{keyword},
		},
	}

	// Check preview mode to validate domains
	if checkPreview(previewMode) {
		var domains []string
		execute(data, &domains, keyword, apiKey)
	}
}

func checkApiKey() string {
	// Get the API key from config file
	configPathExpanded := expandPath(configPath)
	content, err := ioutil.ReadFile(configPathExpanded)
	if err != nil {
		log.Fatalf("❌ Error occurred while reading %s\n", configPathExpanded)
		return ""
	}
	return string(content)
}

func expandPath(path string) string {
	// Expand ~ to the home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("❌ Error expanding path: %s", err)
	}
	// Convert []byte to string after replacing ~ with the user's home directory
	return string(bytes.ReplaceAll([]byte(path), []byte("~"), []byte(homeDir)))
}

func checkPreview(previewMode WhoisRequest) bool {
	log.Println("🔍 Checking if domains exist")
	// Send the preview mode request
	jsonData, err := json.Marshal(previewMode)
	if err != nil {
		log.Fatal("❌ Error marshaling preview mode request:", err)
	}

	req, err := http.NewRequest("POST", apiUrl, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatal("❌ Error creating HTTP request:", err)
	}

	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("❌ Error during HTTP request:", err)
	}
	defer resp.Body.Close()

	var result WhoisResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Fatal("❌ Error decoding response:", err)
	}

	if result.DomainsCount != 0 {
		log.Println("✅ Domains exist")
		log.Println("⛏️ Fetching domains\n")
		return true
	}
	log.Fatal("❌ No domains found")
	return false
}

func execute(data WhoisRequest, domains *[]string, keyword, apiKey string) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Fatal("❌ Error marshaling request data:", err)
	}

	req, err := http.NewRequest("POST", apiUrl, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatal("❌ Error creating HTTP request:", err)
	}

	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("❌ Error during HTTP request:", err)
	}
	defer resp.Body.Close()

	var result WhoisResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Fatal("❌ Error decoding response:", err)
	}

	if result.DomainsCount < 10000 {
		// Domains are less than 10k, no need to iterate
		for _, domain := range result.DomainsList {
			*domains = append(*domains, domain)
			fmt.Println(domain)
		}
	} else {
		// More than 10k domains, paginate
		for _, domain := range result.DomainsList {
			fmt.Println(domain)
		}
		if result.NextPageSearchAfter != "" {
			data.SearchAfter = result.NextPageSearchAfter
			execute(data, domains, keyword, apiKey)
		}
	}
}
