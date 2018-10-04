package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

type ASN struct {
	startIP     int
	endIP       int
	number      int64
	country     string
	description string
}

func binSearchForASN(asn []ASN, ip int) (int64, error) {

	if len(asn) == 0 {
		return 0, nil
	}

	low := 0
	high := len(asn) - 1

	for low <= high {
		mid := (low + high) / 2
		/* is there a range "hit"? */
		if asn[mid].startIP <= ip && asn[mid].endIP >= ip {
			return asn[mid].number, nil
		} else if asn[mid].startIP < ip {
			low = mid + 1
		} else if asn[mid].startIP > ip {
			high = mid - 1
		}
	}

	return 0, nil
}

func loadASN(fileName string, asnList map[int64]bool) ([]ASN, error) {

	var asns []ASN

	file, err := os.Open(fileName)
	if err != nil {
		return asns, fmt.Errorf("cant open database file: %s", err)
	}

	r, err := gzip.NewReader(file)
	if err != nil {
		return asns, fmt.Errorf("cant decompress file: %s", err)
	}

	var row = -1
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		row++
		cols := strings.Split(scanner.Text(), "\t")

		if len(cols) < 5 {
			continue
		}

		asn, err := strconv.ParseInt(cols[2], 10, 32)
		if err != nil {
			continue
		}

		if asn == 0 {
			continue
		}

		/* if no asn list given = loadAll - parameter set, then load all asns */
		if asnList[asn] || len(asnList) == 0 {

			startIP, err := convertIP(cols[0])
			if err != nil {
				continue
			}

			endIP, err := convertIP(cols[1])
			if err != nil {
				continue
			}
			asns = append(asns, ASN{startIP, endIP, asn, cols[3], cols[4]})
		}
	}

	/* sort the slice for binary search */
	sort.Slice(asns, func(i, j int) bool {
		return asns[i].startIP < asns[j].startIP
	})

	return asns, nil

}
