//Cross-Platform

//TODO
// - Make it so you select Client from a list

package main

import (
	"flag"
	"fmt"
	"github.com/hashicorp/yamux"
	"io"
	"log"
	"net"
	"os"
)

var session *yamux.Session

func main() {
	listen := flag.String("listen", "8090", "Listen Port")
	socks := flag.String("socks", "127.0.0.1:8080", "Socks Address:Port")
	flag.Usage = func() {
		fmt.Println("Project Whis Socks5 Client")
		fmt.Println("")
		fmt.Println("Instructions:")
		fmt.Println("1) Start Socks5 Client -listen " + *listen + " -socks " + *socks + " *You can change ports. Make sure listen port is Open to the internet.")
		fmt.Println("2) Enter your IP and the Port you are listening on and turn on the Socks5 on your client management page in the C2.")
		fmt.Println("3) Connect to " + *socks + " with any socks5 client.")
		fmt.Println("For additional help please refer to the manual.")
		fmt.Println("")
	}

	flag.Parse()

	fmt.Println("Project Whis Socks5 Client")
	fmt.Println("")
	fmt.Println("Instructions:")
	fmt.Println("1) Start Socks5 Client -listen " + *listen + " -socks " + *socks + " *You can change ports. Make sure listen port is Open to the internet.")
	fmt.Println("2) Enter your IP and the Port you are listening on and turn on the Socks5 on your client management page in the C2.")
	fmt.Println("3) Connect to " + *socks + " with any socks5 client.")
	fmt.Println("For additional help please refer to the manual.")
	fmt.Println("")

	if *listen != "" {
		log.Println("Listening for Clients...")
		go listenForSocks(*listen)
		log.Fatal(listenForClients(*socks))
	}

	fmt.Fprintf(os.Stderr, "You need to have -listen port and a -socks address. Please read the manual for support.")
	os.Exit(1)
}

func listenForSocks(address string) {
	log.Println("Listening for the client...")
	ln, err := net.Listen("tcp", ":"+address)
	if err != nil {
		return
	}
	for {
		conn, err := ln.Accept()
		log.Println("Got a client")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error Accepting Client!")
		}
		session, err = yamux.Client(conn, nil)
	}
}

func listenForClients(address string) error {
	log.Println("Waiting for clients")
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		if session == nil {
			conn.Close()
			continue
		}
		log.Println("Found a Client!")

		log.Println("Opening the stream..")
		stream, err := session.Open()
		if err != nil {
			return err
		}
		go func() {
			log.Println("Starting to copy connection to the stream..")
			io.Copy(conn, stream)
			conn.Close()
		}()
		go func() {
			log.Println("Starting to copy the stream to connection..")
			io.Copy(stream, conn)
			stream.Close()
			log.Println("Done copying the stream to the connection.")
		}()
	}
}
