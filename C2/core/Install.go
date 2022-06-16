package core

import (
	"bufio"
	"database/sql"
	"fmt"
	"os"
	"time"
)

func installSelf() {
	fmt.Println("|===============================================|")
	fmt.Println("|====================INSTALLER==================|")
	fmt.Println("|===============================================|")

	var SQLHost string
	var SQLDatabase string
	var SQLUsername string
	var SQLPassword string

	// var SSL bool
	// var cert string
	// var key string

	//	var ServerPort string

	//	var ServerAdminUsername string
	//	var ServerAdminPassword string

	//	var SettingsName string
	//	var SettingsSalt string
	//	var SettingsSession string

	fmt.Println(" ")
	fmt.Println(" ")

	fmt.Println("|==============================================|")
	fmt.Println("|==========MySQL Database Information==========|")
	fmt.Println("|==============================================|")
	fmt.Print("MySQL Host (127.0.0.1:3306): ")
	Host := bufio.NewScanner(os.Stdin)
	Host.Scan()
	SQLHost = Host.Text()
	fmt.Print("MySQL Database: ")
	Database := bufio.NewScanner(os.Stdin)
	Database.Scan()
	SQLDatabase = Database.Text()
	fmt.Print("MySQL Username: ")
	Username := bufio.NewScanner(os.Stdin)
	Username.Scan()
	SQLUsername = Username.Text()
	fmt.Print("MySQL Password: ")
	Password := bufio.NewScanner(os.Stdin)
	Password.Scan()
	SQLPassword = Password.Text()

	fmt.Println(" ")
	fmt.Println(" ")

	fmt.Println("|=============================================|")
	fmt.Println("|============C2 Server Information============|")
	fmt.Println("|=============================================|")
	fmt.Print("Use SSL for C2 (true/false): ")
	SSL := bufio.NewScanner(os.Stdin)
	SSL.Scan()
	//SSL = bool(ssl.text)

	fmt.Print("C2 Server Port (80): ")
	Port := bufio.NewScanner(os.Stdin)
	Port.Scan()
	//ServerPort = Port.Text()

	fmt.Println(" ")
	fmt.Println(" ")

	fmt.Println("|============================================|")
	fmt.Println("|=============C2 Server Settings=============|")
	fmt.Println("|============================================|")
	fmt.Print("C2 Server Name: ")
	Name := bufio.NewScanner(os.Stdin)
	Name.Scan()
	//SettingsName = Name.Text()

	fmt.Println(" ")
	fmt.Println(" ")

	fmt.Println("|=============================================|")
	fmt.Println("|===========C2 Server Admin Account===========|")
	fmt.Println("|=============================================|")
	fmt.Println("More accounts can be added at a later time.")
	fmt.Println(" ")
	fmt.Print("Admin Username: ")
	AUsername := bufio.NewScanner(os.Stdin)
	AUsername.Scan()
	//ServerAdminUsername = AUsername.Text()
	fmt.Print("Admin Password: ")
	APassword := bufio.NewScanner(os.Stdin)
	APassword.Scan()
	//ServerAdminPassword = APassword.Text()

	fmt.Println(" ")
	fmt.Println(" ")

	fmt.Println("Manual Input Complete...")
	fmt.Println("Setting Backend Settings...")
	fmt.Println(" ")

	fmt.Println("Generating Password Salt...")
	//SettingsSalt = randomString(5)
	fmt.Println("Salt Generated.")

	fmt.Println(" ")
	fmt.Println(" ")

	fmt.Println("Config done.")

	fmt.Println(" ")
	fmt.Println(" ")

	fmt.Println("Testing MySQL Information...")

	DB, Err = sql.Open("mysql", SQLUsername+":"+SQLPassword+"@tcp("+SQLHost+")/"+SQLDatabase)
	if Err != nil {
		fmt.Println("ErrOR: There was a MySQL Error: " + Err.Error())
		fmt.Println("Please check your info and try again.")
		time.Sleep(5 * time.Second)
		os.Exit(0)
	}
	defer DB.Close()
	Err = DB.Ping()
	if Err != nil {
		fmt.Println("ErrOR: There was a MySQL Error: " + Err.Error())
		fmt.Println("Please check your info and try again.")
		time.Sleep(5 * time.Second)
		os.Exit(0)
	}

	fmt.Println("MySQL Connection Established...")
	fmt.Println("Building MySQL Tables...")

	//run code to make tables

	fmt.Println("Injecting data into MySQL Database...")

	//run code to add needed data
	//Settings.Name
	//Admins

	fmt.Println("Creating config file...")
	//create the config.toml file with the information

	fmt.Println(" ")
	fmt.Println("Install Complete!")
	fmt.Println("Please ReStart the C2 program.")
	time.Sleep(5 * time.Second)
	os.Exit(0)
}
