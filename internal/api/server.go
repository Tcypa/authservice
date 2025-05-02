package api

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/getToken", getTokens)
	http.HandleFunc("/refresh", refresh)
	http.HandleFunc("/whoami", whoami)
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

}
