# Public Profile Analyzer (Go)

A small OSINT-style utility for analyzing **publicly accessible web profile pages**.

## Features
- Fetch a public HTTP/HTTPS page
- Show final URL and HTTP status
- Extract page title
- Extract meta description
- Extract Open Graph (`og:*`) metadata
- Discover public links to:
  - Facebook
  - Instagram
  - X / Twitter
  - LinkedIn
  - YouTube
  - TikTok
  - GitHub
  - Threads
  - Reddit
  - Pinterest
  - Telegram
- Save a JSON report
- No login bypass
- No private account access
- No password/session/cookie collection

## Author
Coded by Cyber Security Engineer Mr Sabaz Ali Khan

## Requirements
- Go 1.22 or newer

## Run

```bash
go run . -url "https://example.com/profile"
```

Save to a custom report:

```bash
go run . -url "https://example.com/profile" -out sabaz-report.json
```

Build an executable:

### Windows
```cmd
go build -o PublicProfileAnalyzer.exe .
PublicProfileAnalyzer.exe -url "https://example.com/profile"
```

### Linux / Kali
```bash
go build -o public-profile-analyzer .
./public-profile-analyzer -url "https://example.com/profile"
```

## Example JSON

```json
{
  "url": "https://example.com/profile",
  "final_url": "https://example.com/profile",
  "status_code": 200,
  "title": "Example Profile",
  "description": "Public profile description",
  "open_graph": {
    "og:title": "Example Profile"
  },
  "social_links": [
    "https://github.com/example"
  ],
  "generated_at": "2026-09-28T22:30:00-07:00"
}
```

## Responsible use
Use this tool only on public pages and systems you are authorized to access. It intentionally does not attempt to bypass authentication, rate limits, privacy controls, CAPTCHAs, or platform restrictions.
