package main

// httpasn (C) 2018 by Jörg Kost, jk@ip-clear.de
// see LICENSE for LICENSING,  TERMS AND CONDITIONS

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
)

func main() {
	loadAll := flag.Bool("loadAll", false, "loadAll as from the database, default: only load asn in the redirect file")
	ip2asnFile := flag.String("database", "ip2asn-combined.tsv.gz", "path to the ip database")

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
		var ipInt int

		if _, ok := asnToUrl[r.RequestURI]; !ok {
			fmt.Fprintf(w, "Unknown target / not configured target %q", r.RequestURI)
			return

		}

		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			goto failedTarget
		}

		ipInt, err = convertIP(host)
		if err != nil {
			goto failedTarget
		}

		asn, err = binSearchForASN(asns, ipInt)
		if asn == 0 || err != nil {
			goto failedTarget
		}

		if _, ok := asnToUrl[r.RequestURI][asn]; ok {
			goto goodTarget
		}

	failedTarget:
		http.Redirect(w, r, asnToUrl[r.RequestURI][0]+r.RequestURI, 301)
		return

	goodTarget:
		http.Redirect(w, r, asnToUrl[r.RequestURI][asn]+r.RequestURI, 301)
		return

	})

	log.Fatal(http.ListenAndServe(":8080", nil))

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
