package core

import (
	"golang.org/x/sys/windows"
	"strconv"
	"time"
	"unsafe"
)

func MCIWorker(lpstrCommand string, lpstrReturnString string, uReturnLength int, hwndCallback int) uintptr {
	i, _, _ := mciSendString.Call(uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(lpstrCommand))),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(lpstrReturnString))),
		uintptr(uReturnLength), uintptr(hwndCallback))
	//fmt.Println("MCI OUTPUT: " + err.Error(), " COMMAND: " + lpstrCommand)
	return i
}

func RecordAudio(Bitrate, length string) bool {
	MCIWorker("open new type waveaudio alias capture", "", 0, 0)
	time.Sleep(125 * time.Millisecond)
	MCIWorker("set capture bitspersample 16", "", 0, 0)
	time.Sleep(125 * time.Millisecond)
	MCIWorker("set capture samplespersec "+Bitrate, "", 0, 0)
	time.Sleep(125 * time.Millisecond)
	MCIWorker("set capture channels 1", "", 0, 0)
	time.Sleep(125 * time.Millisecond)
	MCIWorker("record capture", "", 0, 0)
	i, _ := strconv.Atoi(length)
	time.Sleep(time.Duration(i) * time.Minute)
	MCIWorker("save capture mic.wav", "", 0, 0)
	time.Sleep(125 * time.Millisecond)
	MCIWorker("close capture", "", 0, 0)
	return true
}
