// Scanner imports parallel bulk import from
// the certificate transparency logs advertised
// in the Chrome log list.
//
// The certificate-transparency-go project is actually
// extremely heavy for some reason and it would be preferable
// to just HTTP invoke get-entries and unmarshal the responses
// manually. It would probably be significantly faster.
// However, this is a quick project so we sacrifice the memory
// for now.
//
// LICENCE: No licence is provided for this project

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"golang.org/x/net/publicsuffix"
)

const (
	logListUrl = "https://www.gstatic.com/ct/log_list/log_list.json"
)

var (
	db         *sqlx.DB
	activeLogs []string
	cl         *http.Client
	subjRegex  *regexp.Regexp
)

func main() {
	subjRegex = regexp.MustCompile(`\.au$`)

	var err error
	db, err = sqlx.Open("postgres", os.Getenv("SCANNER_DSN"))
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	log.Println("Updating schema ...")
	if err := ensureSchema(); err != nil {
		log.Fatalf("Failed to create schema: %v", err)
	}

	log.Println("Fetching latest Chrome CT list ...")
	if err := updateLogs(); err != nil {
		log.Fatalf("Failed to update log servers: %v", err)
	}
	cl = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
	}

	log.Printf("Will be scanning %d logs.", len(activeLogs))

	for _, ctlog := range activeLogs {
		go worker(ctlog)
	}

	log.Println("Launched all workers.")

	select {}
}

func worker(url string) {
	var startIndex *int64

	for {
		if err := db.Get(&startIndex, "SELECT scanned_until FROM logs WHERE url = $1", url); err != nil {
			log.Printf("Failed to retrieve start index for %v: %v, sleeping", url, err)
			time.Sleep(5 * time.Minute)
			continue
		}

		if startIndex == nil {
			i := int64(0)
			startIndex = &i
		}

		if err := scan(url, *startIndex); err != nil {
			log.Printf("Scan on %s failed: %v, sleeping", url, err)
			time.Sleep(5 * time.Minute)
			continue
		}

		time.Sleep(time.Hour)
	}
}

func scan(url string, startIndex int64) error {
	log.Printf("Starting %s at index %d", url, startIndex)

	logClient, err := client.New("http://"+url, cl, jsonclient.Options{})
	if err != nil {
		return err
	}

	opts := scanner.ScannerOptions{
		Matcher: scanner.MatchSubjectRegex{
			CertificateSubjectRegex:    subjRegex,
			PrecertificateSubjectRegex: subjRegex,
		},
		BatchSize:     1000,
		NumWorkers:    1,
		ParallelFetch: 1,
		StartIndex:    startIndex,
		Quiet:         false,
	}

	var lastSeen int64

	handler := func(e *ct.LogEntry) {
		lastSeen = e.Index

		names := []string{}
		var ts int64
		if e.X509Cert != nil {
			names = append(names, e.X509Cert.Subject.CommonName)
			names = append(names, e.X509Cert.DNSNames...)
			ts = e.X509Cert.NotBefore.Unix()
		} else if e.Precert != nil && e.Precert.TBSCertificate != nil {
			names = append(names, e.Precert.TBSCertificate.Subject.CommonName)
			names = append(names, e.Precert.TBSCertificate.DNSNames...)
			ts = e.Precert.TBSCertificate.NotBefore.Unix()
		}
		if names == nil || len(names) == 0 {
			return
		}

		m := map[string]struct{}{}
		for _, v := range names {
			v = strings.ToLower(v)
			if strings.HasSuffix(v, ".au") {
				m[v] = struct{}{}
			}
		}
		submitNames(m, ts)
	}

	scanner := scanner.NewScanner(logClient, opts)
	scanner.Scan(context.Background(), handler, handler)

	if _, err := db.Exec(`UPDATE logs SET scanned_until = $1 WHERE url = $2;`, lastSeen, url); err != nil {
		log.Printf("Failed to update latest index for %s: %v", url, err)
	}

	return nil
}

func submitNames(names map[string]struct{}, ts int64) {
	for name, _ := range names {
		etld, err := publicsuffix.EffectiveTLDPlusOne(name)
		if err != nil {
			log.Printf("Couldn't determine etld for %s: %v", name, err)
		}

		if _, err := db.Exec(`INSERT INTO domains (domain, first_seen, last_seen, etld) VALUES ($1, $2, $2, $3) ON CONFLICT (domain) DO UPDATE SET last_seen = GREATEST($2,domains.first_seen), first_seen = LEAST(domains.first_seen, $2);`, name, ts, etld); err != nil {
			log.Printf("Failed to insert/update %s: %v", name, err)
		}
	}
}

func ensureSchema() error {
	schema := []string{
		`CREATE TABLE IF NOT EXISTS domains (domain varchar(255) UNIQUE NOT NULL, first_seen bigint, last_seen bigint, etld varchar(255), id serial);`,
		`CREATE INDEX IF NOT EXISTS domain_ngram_idx ON domains USING gin (domain gin_trgm_ops);`,
		`CREATE TABLE IF NOT EXISTS logs (url text PRIMARY KEY, active bool, scanned_until bigint);`,
		`CREATE INDEX IF NOT EXISTS domain_last_seen_and_id_idx ON domains(last_seen, id);`,
	}

	tx := db.MustBegin()
	defer tx.Rollback()

	for _, s := range schema {
		if _, err := tx.Exec(s); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func updateLogs() error {
	resp, err := http.Get(logListUrl)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 || resp.Header.Get("content-type") != "application/json" {
		return fmt.Errorf("unexpected response from log list: %v", resp.StatusCode)
	}

	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var out struct {
		Logs []struct {
			URL            string `json:"url"`
			DisqualifiedAt *int64 `json:"disqualified_at"`
		} `json:"logs"`
	}
	if err := json.Unmarshal(buf, &out); err != nil {
		return err
	}

	tx := db.MustBegin()
	defer tx.Rollback()

	if _, err := tx.Exec("UPDATE logs SET active = false;"); err != nil {
		return err
	}
	activeLogs = []string{}

	for _, ctl := range out.Logs {
		if _, err := tx.Exec(`INSERT INTO logs (url,active) VALUES ($1, $2) ON CONFLICT (url) DO UPDATE SET active = $2;`, ctl.URL, ctl.DisqualifiedAt == nil); err != nil {
			return err
		}

		if ctl.DisqualifiedAt == nil {
			activeLogs = append(activeLogs, ctl.URL)
		}
	}

	return tx.Commit()
}
