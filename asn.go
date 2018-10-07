package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"
)

type ASN struct {
	startIP     *big.Int
	endIP       *big.Int
	number      int64
	country     string
	description string
}

func binSearchForASN(asn []ASN, ip *big.Int) (int64, error) {
	if len(asn) == 0 {
		return 0, nil
	}

	low := 0
	high := len(asn) - 1

	for low <= high {
		mid := (low + high) / 2

		/* is there a range "hit"? */
		cmp := asn[mid].startIP.Cmp(ip)
		cmp2 := asn[mid].endIP.Cmp(ip)

		if cmp <= 0 && cmp2 >= 0 {
			return asn[mid].number, nil
		} else if cmp == 1 {
			high = mid - 1
		} else {
			low = mid + 1
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

			startIP := convertIP(cols[0])
			endIP := convertIP(cols[1])

			asns = append(asns, ASN{startIP, endIP, asn, cols[3], cols[4]})
		}
	}

	/* sort the slice for binary search */
	sort.Slice(asns, func(i, j int) bool {
		cmp := asns[i].startIP.Cmp(asns[j].startIP)
		if cmp == 0 || cmp == -1 {
			return true
		} else {
			return false
		}
	})

	return asns, nil

}
