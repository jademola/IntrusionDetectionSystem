package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

// Define what the alert structure is for the frontend
type Alert struct {
	Timestamp string            `json:"timestamp"`
	Source    string            `json:"source"`
	Message   string            `json:"message"`
	Type      string            `json:"type"`
	Series    map[string]uint64 `json:"series,omitempty"`
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { //Allows connection from Host machine
		return true
	},
}

var clients = make(map[*websocket.Conn]bool) // Connected browsers
var broadcast = make(chan Alert)             // Channel for sending alerts

func StartDashboard() {
	// Start the broadcaster in a background thread
	go handleMessages()

	//define the routes
	http.HandleFunc("/ws", handleConnections)

	// serve the index.html file to the browser
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	})

	go func() {
		addr := ":8080"
		fmt.Printf("Dashboard live at http://192.168.56.102%s\n", addr)
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Printf("Dashboard server: error %v", err)
		}

	}()

}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Upgrade error: %v", err)
		return
	}
	defer ws.Close()

	clients[ws] = true

	for {
		var alert Alert
		err := ws.ReadJSON(&alert)
		if err != nil {
			log.Printf("error: %v", err)
			delete(clients, ws)
			break
		}
	}
}

func handleMessages() {
	for {
		alert := <-broadcast
		for client := range clients {
			err := client.WriteJSON(alert)
			if err != nil {
				log.Printf("error: %v", err)
				client.Close()
				delete(clients, client)
			}
		}
	}
}
