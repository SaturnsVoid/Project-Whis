package core

import (
	"github.com/oschwald/geoip2-golang"
	"net"
	"strings"
)

func GetCountryCode(IP string) string {
	ipdb, err := geoip2.Open("static/geoip/GeoIP2-City.mmdb")
	if err != nil {
		return "--"
	}
	defer ipdb.Close()

	ip := net.ParseIP(IP)
	record, err := ipdb.City(ip)
	if err != nil {
		return "--"
	}
	return strings.ToLower(record.Country.IsoCode)
}

func GetCityCode(IP string) string {
	ipdb, err := geoip2.Open("static/geoip/GeoIP2-City.mmdb")
	if err != nil {
		return "--"
	}
	defer ipdb.Close()

	ip := net.ParseIP(IP)
	record, err := ipdb.City(ip)
	if err != nil {
		return "--"
	}
	return strings.ToUpper(record.City.Names["en"] + ", " + record.Subdivisions[0].Names["en"])
}
