package core

import (
	"fmt"
	"github.com/hashicorp/yamux"
	"io"
	"log"
	"net"
	"os"
)

var ssession *yamux.Session

func ListenForSocks(address string) {
	log.Println("Listening for the client...")
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return
	}
	for {
		conn, err := ln.Accept()
		log.Println("Got a client")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error Accepting Client!")
		}
		ssession, err = yamux.Client(conn, nil)
	}
}

func ListenForClients(address string) error {
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
		if ssession == nil {
			conn.Close()
			continue
		}
		log.Println("Found a Client!")

		log.Println("Opening the stream..")
		stream, err := ssession.Open()
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
