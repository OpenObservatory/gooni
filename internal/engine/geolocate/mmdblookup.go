package geolocate

import (
	"net"

	"github.com/ooni/probe-cli/v3/internal/engine/assetsx"
	"github.com/oschwald/geoip2-golang"
)

type mmdbLookupper struct{}

func (mmdbLookupper) LookupASN(ip string) (asn uint, org string, err error) {
	asn, org = DefaultProbeASN, DefaultProbeNetworkName
	dbdata := assetsx.Must(assetsx.ASNDatabaseData())
	db, err := geoip2.FromBytes(dbdata)
	if err != nil {
		return
	}
	defer db.Close()
	record, err := db.ASN(net.ParseIP(ip))
	if err != nil {
		return
	}
	asn = record.AutonomousSystemNumber
	if record.AutonomousSystemOrganization != "" {
		org = record.AutonomousSystemOrganization
	}
	return
}

// LookupASN returns the ASN and the organization associated with the
// given ip using the ASN database at path.
func LookupASN(ip string) (asn uint, org string, err error) {
	return (mmdbLookupper{}).LookupASN(ip)
}

func (mmdbLookupper) LookupCC(ip string) (cc string, err error) {
	cc = DefaultProbeCC
	dbdata := assetsx.Must(assetsx.CountryDatabaseData())
	db, err := geoip2.FromBytes(dbdata)
	if err != nil {
		return
	}
	defer db.Close()
	record, err := db.Country(net.ParseIP(ip))
	if err != nil {
		return
	}
	// With MaxMind DB we used record.RegisteredCountry.IsoCode but that does
	// not seem to work with the db-ip.com database. The record is empty, at
	// least for my own IP address in Italy. --Simone (2020-02-25)
	if record.Country.IsoCode != "" {
		cc = record.Country.IsoCode
	}
	return
}
