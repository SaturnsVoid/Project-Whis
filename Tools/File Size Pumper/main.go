// main.exe C:\path\to\file.exe 5
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
)

var (
	FilePath   string
	SizeToPump int
)

func main() {

	file := flag.String("file", "", "File to Pump")
	size := flag.String("size", "5", "Size in MB that you want to increase")
	flag.Usage = func() {
		fmt.Println("PumpItUp")
		fmt.Println("")
		fmt.Println("Instructions:")
		fmt.Println("Run the program like this 'PumpItUp.exe -file C:\\path\\to\\file.exe -size 5' this will pump the 'file.exe' with 5 MB of bytes")
		fmt.Println("For additional help please refer to the manual.")
		fmt.Println("")
	}

	flag.Parse()
	FilePath = *file
	v := *size
	i, _ := strconv.Atoi(v)
	SizeToPump = i
	var wantedSize = int64(SizeToPump * 1024 * 1024) //Makes a MB

	fmt.Println("PumpItUp")

	fi, _ := os.Stat(FilePath)

	fmt.Println("Starting Size", fi.Size(), "bytes")

	toPump, err := os.OpenFile(FilePath, os.O_RDWR, 0644)
	if err != nil {
		log.Fatalf("Error Opening File: %s", err)
	}
	defer toPump.Close()

	_, err = toPump.WriteAt([]byte{0}, fi.Size()+wantedSize)
	if err != nil {
		log.Fatalf("Error Writing to File: %s", err)
	}

	fi, _ = os.Stat(FilePath)
	fmt.Println("Pumped Size", fi.Size()/1024/1024, "MB")
}
