package core

import (
	"context"
	"io"
	"log"
	"net"
)

const (
	socks5Version          = uint8(5)
	ConnectCommand         = uint8(1)
	BindCommand            = uint8(2)
	AssociateCommand       = uint8(3)
	ipv4Address            = uint8(1)
	fqdnAddress            = uint8(3)
	ipv6Address            = uint8(4)
	successReply     uint8 = iota
	ruleFailure
	networkUnreachable
	hostUnreachable
	connectionRefused
	commandNotSupported
	addrTypeNotSupported
	NoAuth           = uint8(0)
	noAcceptable     = uint8(255)
	UserPassAuth     = uint8(2)
	userAuthVersion  = uint8(1)
	authSuccess      = uint8(0)
	authFailure      = uint8(1)
	ipVersion        = 4
	ipv4MinHeaderLen = 20
	tcpMinHeaderLen  = 20
)

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

type Options struct {
	Width    int
	Prefix   string
	Indent   string
	SortKeys bool
}

type Style struct {
	Key, String, Number [2]string
	True, False, Null   [2]string
	Escape              [2]string
	Append              func(dst []byte, c byte) []byte
}
