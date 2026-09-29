package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const banner = `
@@@@@@@  @@@@@@  @@@@@@@  @@@@@@@@ @@@@@@@       @@@@@@@  @@@ @@@       @@@@@@@ @@@ @@@ @@@@@@@  @@@@@@@@ @@@@@@@        @@@@@@ @@@@@@@@  @@@@@@@ @@@  @@@ @@@@@@@  @@@ @@@@@@@ @@@ @@@      @@@@@@@@ @@@  @@@  @@@@@@@  @@@ @@@  @@@ @@@@@@@@ @@@@@@@@ @@@@@@@       @@@@@@@@@@  @@@@@@@        @@@@@@  @@@@@@  @@@@@@@   @@@@@@  @@@@@@@@       @@@@@@  @@@      @@@      @@@  @@@ @@@  @@@  @@@@@@  @@@  @@@
 !@@      @@!  @@@ @@!  @@@ @@!      @@!  @@@      @@!  @@@ @@! !@@      !@@      @@! !@@ @@!  @@@ @@!      @@!  @@@      !@@     @@!      !@@      @@!  @@@ @@!  @@@ @@!   @@!   @@! !@@      @@!      @@!@!@@@ !@@       @@! @@!@!@@@ @@!      @@!      @@!  @@@      @@! @@! @@! @@!  @@@      !@@     @@!  @@@ @@!  @@@ @@!  @@@      @@!      @@!  @@@ @@!      @@!      @@!  !@@ @@!  @@@ @@!  @@@ @@!@!@@@
 !@!      @!@  !@! @!@  !@! @!!!:!   @!@  !@!      @!@!@!@   !@!@!       !@!       !@!@!  @!@!@!@  @!!!:!   @!@!!@!        !@@!!  @!!!:!   !@!      @!@  !@! @!@!!@!  !!@   @!!    !@!@!       @!!!:!   @!@@!!@! !@! @!@!@ !!@ @!@@!!@! @!!!:!   @!!!:!   @!@!!@!       @!! !!@ @!@ @!@!!@!        !@@!!  @!@!@!@! @!@!@!@  @!@!@!@!    @!!        @!@!@!@! @!!      !!@      @!@@!@!  @!@!@!@! @!@!@!@! @!@@!!@!
 :!!      !!:  !!! !!:  !!! !!:      !!:  !!!      !!:  !!!   !!:        :!!        !!:   !!:  !!! !!:      !!: :!!           !:! !!:      :!!      !!:  !!! !!: :!!  !!:   !!:     !!:        !!:      !!:  !!! :!!   !!: !!: !!:  !!! !!:      !!:      !!: :!!       !!:     !!: !!: :!!           !:! !!:  !!! !!:  !!! !!:  !!!  !!:          !!:  !!! !!:      !!:      !!: :!!  !!:  !!! !!:  !!! !!:  !!!
  :: :: :  : :. :  :: :  :  : :: ::: :: :  :       :: : ::    .:          :: :: :   .:    :: : ::  : :: :::  :   : :      ::.: :  : :: :::  :: :: :  :.:: :   :   : : :      :      .:         : :: ::: ::    :   :: :: :  :   ::    :  : :: ::: : :: :::  :   : :       :      :    :   : :      ::.: :   :   : : :: : ::   :   : : :.::.: :       :   : : : ::.: : :         :   :::  :   : :  :   : : ::    :

                 PUBLIC PROFILE ANALYZER
      Coded by Cyber Security Engineer Mr Sabaz Ali Khan
`

type Report struct {
	URL         string            `json:"url"`
	FinalURL    string            `json:"final_url"`
	StatusCode  int               `json:"status_code"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	OpenGraph   map[string]string `json:"open_graph"`
	SocialLinks []string          `json:"social_links"`
	GeneratedAt string            `json:"generated_at"`
}

var (
	titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	metaRE  = regexp.MustCompile(`(?is)<meta\s+[^>]*>`)
	attrRE  = regexp.MustCompile(`(?i)([a-zA-Z_:.-]+)\s*=\s*["']([^"']*)["']`)
	hrefRE  = regexp.MustCompile(`(?is)<a\s+[^>]*href\s*=\s*["']([^"']+)["']`)
	tagRE   = regexp.MustCompile(`(?is)<[^>]+>`)
	spaceRE = regexp.MustCompile(`\s+`)
)

func cleanText(s string) string {
	s = tagRE.ReplaceAllString(s, " ")
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&quot;", `"`)
	s = strings.ReplaceAll(s, "&#39;", "'")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	return strings.TrimSpace(spaceRE.ReplaceAllString(s, " "))
}

func attrsFromTag(tag string) map[string]string {
	out := map[string]string{}
	for _, m := range attrRE.FindAllStringSubmatch(tag, -1) {
		out[strings.ToLower(m[1])] = strings.TrimSpace(m[2])
	}
	return out
}

func normalizeURL(base *url.URL, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") ||
		strings.HasPrefix(strings.ToLower(raw), "javascript:") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return base.ResolveReference(u).String()
}

func isSocialLink(link string) bool {
	l := strings.ToLower(link)
	domains := []string{
		"facebook.com/", "instagram.com/", "x.com/", "twitter.com/",
		"linkedin.com/", "youtube.com/", "youtu.be/", "tiktok.com/",
		"github.com/", "threads.net/", "reddit.com/", "pinterest.com/",
		"t.me/", "telegram.me/",
	}
	for _, d := range domains {
		if strings.Contains(l, d) {
			return true
		}
	}
	return false
}

func analyze(target string, timeout time.Duration) (*Report, error) {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("invalid URL: use http:// or https://")
	}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 8 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "PublicProfileAnalyzer/1.0 (+public-metadata-only)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	const maxBody = 2 << 20 // 2 MiB
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	html := string(body)

	report := &Report{
		URL:         target,
		FinalURL:    resp.Request.URL.String(),
		StatusCode:  resp.StatusCode,
		OpenGraph:   map[string]string{},
		GeneratedAt: time.Now().Format(time.RFC3339),
	}

	if m := titleRE.FindStringSubmatch(html); len(m) > 1 {
		report.Title = cleanText(m[1])
	}

	for _, tag := range metaRE.FindAllString(html, -1) {
		a := attrsFromTag(tag)
		name := strings.ToLower(a["name"])
		prop := strings.ToLower(a["property"])
		content := strings.TrimSpace(a["content"])

		if content == "" {
			continue
		}
		if name == "description" && report.Description == "" {
			report.Description = cleanText(content)
		}
		if strings.HasPrefix(prop, "og:") {
			report.OpenGraph[prop] = cleanText(content)
		}
	}

	base := resp.Request.URL
	seen := map[string]bool{}
	for _, m := range hrefRE.FindAllStringSubmatch(html, -1) {
		if len(m) < 2 {
			continue
		}
		link := normalizeURL(base, m[1])
		if link != "" && isSocialLink(link) && !seen[link] {
			seen[link] = true
			report.SocialLinks = append(report.SocialLinks, link)
		}
	}
	sort.Strings(report.SocialLinks)

	return report, nil
}

func printHuman(r *Report) {
	fmt.Println("\n[+] Analysis Result")
	fmt.Println("URL        :", r.URL)
	fmt.Println("Final URL  :", r.FinalURL)
	fmt.Println("HTTP Status:", r.StatusCode)
	fmt.Println("Title      :", r.Title)
	fmt.Println("Description:", r.Description)

	if len(r.OpenGraph) > 0 {
		fmt.Println("\n[+] Open Graph Metadata")
		keys := make([]string, 0, len(r.OpenGraph))
		for k := range r.OpenGraph {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %-15s %s\n", k, r.OpenGraph[k])
		}
	}

	if len(r.SocialLinks) > 0 {
		fmt.Println("\n[+] Public Social Links")
		for _, link := range r.SocialLinks {
			fmt.Println(" -", link)
		}
	} else {
		fmt.Println("\n[-] No public social links found on this page.")
	}
}

func main() {
	fmt.Print(banner)

	target := flag.String("url", "", "public profile/page URL to analyze")
	outFile := flag.String("out", "report.json", "JSON report output file")
	timeout := flag.Int("timeout", 12, "HTTP timeout in seconds")
	flag.Parse()

	if strings.TrimSpace(*target) == "" {
		fmt.Println("Usage:")
		fmt.Println(`  go run . -url "https://example.com/profile"`)
		fmt.Println(`  go run . -url "https://example.com/profile" -out result.json`)
		os.Exit(1)
	}

	report, err := analyze(*target, time.Duration(*timeout)*time.Second)
	if err != nil {
		fmt.Println("[!] Error:", err)
		os.Exit(1)
	}

	printHuman(report)

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Println("[!] JSON error:", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*outFile, data, 0644); err != nil {
		fmt.Println("[!] Could not save report:", err)
		os.Exit(1)
	}
	fmt.Println("\n[+] JSON report saved to:", *outFile)
}
