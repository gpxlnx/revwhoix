# revwhoix

Reverse WHOIS lookup utility for the WhoisXML API.

This repository now ships only with the Go CLI.

## Go CLI

### Requirements

- Go 1.25+
- One or more WhoisXML API keys with Reverse WHOIS / DRS credits

### Build

```sh
git clone git@github.com:gpxlnx/revwhoix.git
cd revwhoix
go build -o revwhoix-go .
```

### API key file

Create a file with one API key per line:

```txt
api_key_1
api_key_2
api_key_3
```

### Usage

```sh
./revwhoix-go -k "Airbnb, Inc" -l keys.txt
./revwhoix-go -kL orgs.txt -l keys.txt -o results.txt
./revwhoix-go -k "target@example.com" -l keys.txt -silent | sort -u
```

### Features

- Multiple API keys with round-robin rotation
- Automatic retry when a key returns `403`
- Preview check before purchase requests
- Pagination support for large result sets
- Multiple keywords from file input
- Global deduplication across all collected domains
- Optional output file
- Silent mode for pipeline-friendly output
