package core

import (
	"archive/zip"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

func randomString(length int) string {
	rand.Seed(time.Now().UnixNano())
	chars := []rune("QAZWSXXEDCRFVTGBYHNUJMIKOLP" + "qazwsxedcrfvtgbyhnujmikolp" + "0123456789")
	var b strings.Builder
	for i := 0; i < length; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}
	return b.String()
}

func base64Encode(str string) string {
	return base64.StdEncoding.EncodeToString([]byte(str))
}

func base64Decode(str string) string {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return ""
	}
	return string(data)
}

func md5Hash(text string) string {
	hash := md5.New()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}

func XXTeaDecrypt(data []byte, key []byte) []byte {
	if data == nil || key == nil || len(data) == 0 || len(key) == 0 {
		return nil
	}
	if len(data)%4 != 0 {
		return nil
	}
	uint32Arr := asUint32Array(data, false)
	decryptedData := btea(uint32Arr, -len(uint32Arr), asKey(key))
	return asByteArray(decryptedData, true)
}

func XXTeaEncrypt(data []byte, key []byte) []byte {
	if data == nil || key == nil || len(data) == 0 || len(key) == 0 {
		return nil
	}
	uint32Arr := asUint32Array(data, true)
	encryptedArr := btea(uint32Arr, len(uint32Arr), asKey(key))
	return asByteArray(encryptedArr, false)
}

func mx(z, y, sum, p, e uint32, key []uint32) uint32 {
	return (((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (key[(p&3)^e] ^ z)))
}

func asKey(key []byte) []uint32 {
	if len(key) > 16 {
		key = key[:16]
	} else if len(key) < 16 {
		padding := make([]byte, 16-len(key))
		key = append(key, padding...)
	}
	return asUint32Array(key, false)
}

func asByteArray(data []uint32, includeLength bool) []byte {
	var result []byte
	dataLen := uint32(len(data))
	size := dataLen << 2
	if includeLength {
		lastByte := data[len(data)-1]
		if lastByte > (size-4) || lastByte < (size-7) {
			return nil
		}
		size = lastByte
		dataLen--
		if size%4 != 0 {
			result = make([]byte, ((size/4)+1)*4)
		} else {
			result = make([]byte, size)
		}
	} else {
		result = make([]byte, size)
	}
	for idx := uint32(0); idx < dataLen; idx++ {
		binary.LittleEndian.PutUint32(result[idx*4:(idx+1)*4], data[idx])
	}
	return result[:size]
}

func asUint32Array(data []byte, includeLength bool) []uint32 {
	var uint32Arr []uint32
	size := uint32(len(data) / 4)
	if len(data)&3 != 0 {
		size++
	}
	if includeLength {
		uint32Arr = make([]uint32, size+1)
		uint32Arr[size] = uint32(len(data))
	} else {
		uint32Arr = make([]uint32, size)
	}
	for idx := uint32(0); idx < size; idx++ {
		uint32Arr[idx] = toUint32(data[idx*4:])
	}

	return uint32Arr
}

func toUint32(b []byte) uint32 {
	switch len(b) {
	case 0:
		return uint32(0)
	case 1:
		return uint32(b[0])
	case 2:
		return uint32(b[0]) | uint32(b[1])<<8
	case 3:
		return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
	default:
		return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	}
}

func btea(v []uint32, n int, key []uint32) []uint32 {
	var y, z, sum uint32
	var p, rounds, e uint32

	if n > 1 {
		rounds = uint32(6 + 52/n)
		sum = 0
		z = v[n-1]
		for i := uint32(0); i < rounds; i++ {
			sum += _Delta
			e = (sum >> 2) & 3
			for p = 0; p < uint32(n-1); p++ {
				y = v[p+1]
				z = v[p] + mx(z, y, sum, p, e, key)
				v[p] = z
			}
			y = v[0]
			z = v[p] + mx(z, y, sum, p, e, key)
			v[p] = z
		}
	} else if n < -1 {
		n = -n
		rounds = uint32(6 + 52/n)
		sum = rounds * _Delta
		y = v[0]
		for i := uint32(0); i < rounds; i++ {
			e = (sum >> 2) & 3
			for p = uint32(n - 1); p > 0; p-- {
				z = v[p-1]
				y = v[p] - mx(z, y, sum, p, e, key)
				v[p] = y
			}
			z = v[n-1]
			y = v[0] - mx(z, y, sum, p, e, key)
			v[0] = y
			sum -= _Delta
		}
	}

	return v
}

func NewLog(path string) {
	file, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	Log = log.New(file, "", log.LstdFlags|log.Lshortfile)
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
	os.MkdirAll(dest, 0755)
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
			os.MkdirAll(path, f.Mode())
		} else {
			os.MkdirAll(filepath.Dir(path), f.Mode())
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

func StripSpaces(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, str)
}
