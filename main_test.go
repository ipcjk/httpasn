package main

import (
	"math/big"
	"net"
	"testing"
)

func TestConvertIP(t *testing.T) {
	var number *big.Int

	host, _, err := net.SplitHostPort("188.192.41.178:60719")
	if err != nil {
		t.Error("splitting hostport gone wrong")
	}

	number = convertIP(host)
	if number.Cmp(big.NewInt(int64(3166710194))) != 0 {
		t.Error("Converted number is wrong")
	}

	number = convertIP("4.2.2.1")
	if number.Cmp(big.NewInt(int64(67240449))) != 0 {
		t.Error("Converted ip to integer is wrong")
	}

	number = convertIP("2a02::1308:66")
	x := big.NewInt(0)
	x.SetString("55837960416683536317216957524752203878 ", 10)
	if number.Cmp(x) != 0 {
		t.Error("Converted ipv6 to integer is wrong", number)
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

	as, err := binSearchForASN(asns, convertIP("178.248.240.6"))

	if err != nil {
		t.Error(err)
	}

	if as != 196922 {
		t.Errorf("Wrong as-number returned or as-number not found, expected 196922, but got %d", as)
	}

	as, err = binSearchForASN(asns, convertIP("31.212.9.5"))

	if err != nil {
		t.Error(err)
	}

	if as != 3320 {
		t.Errorf("Wrong as-number returned or as-number not found, expected 3320, but got %d", as)
	}

	as, err = binSearchForASN(asns, big.NewInt(int64(3758096127)))
	if err != nil {
		t.Error(err)
	}
	if as != 55415 {
		t.Errorf("Wrong as-number returned or as-number not found, expected 55415, but got %d", as)
	}

	as, err = binSearchForASN(asns, convertIP("2a02:1308::1"))
	if err != nil {
		t.Error(err)
	}
	if as != 196922 {
		t.Errorf("Wrong as-number returned or as-number not found, expected 196922, but got %d", as)
	}

}
