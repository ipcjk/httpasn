package main

import (
	"net"
	"testing"
)

func TestConvertIP(t *testing.T) {
	var number int

	host, _, err := net.SplitHostPort("188.192.41.178:60719")
	if err != nil {
		t.Error("splitting hostport gone wrong")
	}

	number, err = convertIP(host)

	if err != nil {
		t.Errorf("Error converting ip address")
	}

	if number != 3166710194 {
		t.Error("Converted number is wrong")
	}

	number, err = convertIP("4.2.2.1")

	if err != nil {
		t.Errorf("Error converting ip address")
	}

	if number != 67240449 {
		t.Error("Converted ip to integer is wrong")
	}

	number, err = convertIP("256.0.3.-1")

	if err == nil {
		t.Errorf("whoops, convertIP() converted broken IP without giving an error")
	}

}

func TestLoadIpASN(t *testing.T) {

	var asnList = map[int64]bool{3320: true, 196922: true, 33891: true, 12337: true, 2914: true}

	asn, err := loadASN("ip2asn-combined.tsv.gz", asnList)

	if err != nil {
		t.Error(err)
	}

	if len(asn) <= 400 {
		t.Errorf("Too less ip subnets found in database file, found only: %d", len(asn))
	}
}

func TestLoadAllIpASN(t *testing.T) {

	var asnList = map[int64]bool{}

	asn, err := loadASN("ip2asn-combined.tsv.gz", asnList)

	if err != nil {
		t.Error(err)
	}

	if len(asn) <= 800000 {
		t.Errorf("Too less ip subnets found in database file, found only: %d", len(asn))
	}
}

func TestBinarySearchForASN(t *testing.T) {
	asns, err := loadASN("ip2asn-combined.tsv.gz", map[int64]bool{})

	if err != nil {
		t.Error(err)
	}

	if len(asns) <= 400 {
		t.Errorf("Too less ip subnets found in database file, found only: %d", len(asns))
	}

	/* search inside */
	ip, err := convertIP("178.248.240.255")
	if err != nil {
		t.Error("Error converting ip address")
	}

	as, err := binSearchForASN(asns, ip)

	if err != nil {
		t.Error(err)
	}
	if as != 196922 {
		t.Errorf("Wrong as-number returned or as-number not found, expected 196922, but got %d", as)
	}

	ip, err = convertIP("31.212.9.5")
	if err != nil {
		t.Error("Error converting ip address")
	}
	as, err = binSearchForASN(asns, ip)

	if err != nil {
		t.Error(err)
	}

	if as != 3320 {
		t.Errorf("Wrong as-number returned or as-number not found, expected 3320, but got %d", as)
	}

	ip, err = convertIP("4.2.2.1")
	if err != nil {
		t.Error("Error converting ip address")
	}

	as, err = binSearchForASN(asns, 3758096127)
	if err != nil {
		t.Error(err)
	}
	if as != 55415 {
		t.Errorf("Wrong as-number returned or as-number not found, expected 55415, but got %d", as)
	}

}
