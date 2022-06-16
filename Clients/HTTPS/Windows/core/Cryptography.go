package core

import "C"
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"unsafe"
)

const (
	_Delta = 0x9e3779b9
)

func MD5Hash(text string) string {
	hash := md5.New()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}

func Base64Encode(str string) string {
	return base64.StdEncoding.EncodeToString([]byte(str))
}

func Base64Decode(str string) string {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return ""
	}
	return string(data)
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

func AESDecrypt(crypt []byte, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	ecb := cipher.NewCBCDecrypter(block, []byte(key))
	decrypted := make([]byte, len(crypt))
	ecb.CryptBlocks(decrypted, crypt)

	return PKCS5Trimming(decrypted)
}

func EncryptTripleDES(key []byte, plaintext string) string {
	c, _ := des.NewTripleDESCipher(key)
	out := make([]byte, len(plaintext))
	c.Encrypt(out, []byte(plaintext))
	return hex.EncodeToString(out)
}

func DecryptTripleDES(key []byte, ct string) string {
	ciphertext, _ := hex.DecodeString(ct)
	c, _ := des.NewTripleDESCipher([]byte(key))
	plain := make([]byte, len(ciphertext))
	c.Decrypt(plain, ciphertext)
	s := string(plain[:])
	return s
}

func Win32CryptUnprotectData(cipherText string, entropy bool) ([]byte, error) {
	var outblob DATA_BLOB
	var inblob = NewBlob([]byte(cipherText))
	checkExist, _, errProcDecryptData := procDecryptData.Call(uintptr(unsafe.Pointer(inblob)), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outblob)))
	if checkExist == 0 {
		return nil, errProcDecryptData
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outblob.pbData)))
	return outblob.ToByteArray(), nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}

func mx(z, y, sum, p, e uint32, key []uint32) uint32 {
	return ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (key[(p&3)^e] ^ z))
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

func binaryToAscii(buffer []byte) string {
	var out bytes.Buffer

	for i := 28; i >= 0; i-- {
		if (29-i)%6 == 0 {
			out.WriteByte('-')
			i--
		}

		out.WriteByte(decodeByte(buffer))
	}

	return string(reverse(out.Bytes()))
}

func reverse(b []byte) []byte {
	for i := len(b)/2 - 1; i >= 0; i-- {
		j := len(b) - 1 - i
		b[i], b[j] = b[j], b[i]
	}
	return b
}

func decodeByte(buffer []byte) byte {
	var acc int = 0
	const chars = "BCDFGHJKMPQRTVWXY2346789"

	for i := 28; i >= 0; i-- {
		acc *= 256
		acc += int(buffer[i])
		buffer[i] = byte((acc / len(chars) & 0xFF))
		acc %= len(chars)
	}

	return chars[acc]
}

func pbkdf2Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}
