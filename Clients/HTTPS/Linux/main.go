package main

import (
	"fmt"
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}
func main() {
	fmt.Println("Linux Client")
	//core.Boot()
	for {
		time.Sleep(15 * time.Millisecond)
	}
}
