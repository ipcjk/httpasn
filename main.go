package main

// httpasn (C) 2018 by Jörg Kost, jk@ip-clear.de
// see LICENSE for LICENSING,  TERMS AND CONDITIONS

import (
	"bufio"
	"flag"
	"fmt"
	"golang.org/x/crypto/acme/autocert"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
)

func main() {
	loadAll := flag.Bool("loadall", false, "loadAll as from the database, default: only load asn in the redirect file")
	ip2asnFile := flag.String("database", "ip2asn-combined.tsv.gz", "path to the ip database")
	certFile := flag.String("cert", "./localhost.pem", "file/path to certificate for tls server")
	certKey := flag.String("key", "./localhost-key.pem", "file/path to private key for tls server")
	ssl := flag.Bool("ssl", false, "start also a thread for a  ssl-server with custom ssl cert/key")
	autoSSL := flag.String("autossl", "", "domain name for LE cert")
	sslCache := flag.String("sslcache", "", "directory to save LE cache certificates")
	httpsAddr := flag.String("https", ":443", "port for the tls listener")
	httpAddr := flag.String("http", ":80", "port for the default non-tls listener")

	flag.Parse()

	asnToUrl, asnList := parseRedirectFile()

	if *loadAll {
		asnList = map[int64]bool{}
	}

	asns, err := loadASN(*ip2asnFile, asnList)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var asn int64
		var ip int

		if _, ok := asnToUrl[r.RequestURI]; !ok {
			fmt.Fprintf(w, "Unknown target / not configured target %q", r.RequestURI)
			return
		}

		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			goto failedTarget
		}

		ip, err = convertIP(host)
		if err != nil {
			goto failedTarget
		}

		asn, err = binSearchForASN(asns, ip)
		if asn == 0 || err != nil {
			goto failedTarget
		}

		if _, ok := asnToUrl[r.RequestURI][asn]; ok {
			http.Redirect(w, r, asnToUrl[r.RequestURI][asn], 301)
			return
		}

	failedTarget:
		http.Redirect(w, r, asnToUrl[r.RequestURI][0], 301)
		return

	})

	var m *autocert.Manager
	wg := sync.WaitGroup{}

	if *ssl {
		go func() {
			defer wg.Done()
			err := http.ListenAndServeTLS(*httpsAddr, *certFile, *certKey, nil)
			log.Fatal(err)
		}()
	}

	if *autoSSL != "" {
		m = &autocert.Manager{
			Cache:      autocert.DirCache(*sslCache),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(*autoSSL)}

		s := &http.Server{
			Addr:      *httpsAddr,
			TLSConfig: m.TLSConfig(),
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.ListenAndServeTLS("", "")
			log.Fatal(err)
		}()

	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := http.ListenAndServe(*httpAddr, m.HTTPHandler(nil))
		log.Fatal(err)
	}()

	wg.Wait()
}

func parseRedirectFile() (map[string]map[int64]string, map[int64]bool) {
	var asnToURL = make(map[string]map[int64]string)
	var asnList = make(map[int64]bool)

	file, err := os.Open("redirects.txt")
	if err != nil {
		log.Fatalf("Cant open redirects.txt - file")
	}

	defer file.Close()
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "#") {
			continue
		}
		row := strings.Split(scanner.Text(), ",")

		if len(row) <= 2 {
			continue
		}

		asn, err := strconv.ParseInt(row[1], 10, 64)
		if err != nil {
			fmt.Println("ignoring broken ASN found in redirectFile:", row[1])
			continue
		}

		if _, ok := asnToURL[row[0]]; !ok {
			asnToURL[row[0]] = make(map[int64]string)
		}

		asnToURL[row[0]][asn] = row[2]
		asnList[asn] = true

	}

	return asnToURL, asnList

}

func convertIP(ip string) (int, error) {
	var sum float64
	octet := strings.Split(ip, ".")

	if len(octet) != 4 {
		return 0, fmt.Errorf("not enough octets found in input ip streing")
	}

	var j = 0
	for i := 3; i >= 0; i-- {
		decimal, err := strconv.ParseFloat(octet[j], 64)
		if err != nil {
			return 0, fmt.Errorf("can't parse input to float: %s", err)
		}

		if int(decimal) > 255 || int(decimal) < 0 {
			return 0, fmt.Errorf("ip octet is an integer that is larger or smaller then allowed 0 or 255")
		}

		sum += math.Pow(256, float64(i)) * decimal
		j++
	}

	return int(sum), nil
}
