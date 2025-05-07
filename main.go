package main

import (
	"authservice/api"
	"authservice/database"
	"context"
	"log"
	"net/http"
)

func main() {
	ctx := context.Background()
	database.Init(ctx)
	http.HandleFunc("/getToken", api.GetTokens)
	http.HandleFunc("/deauth", api.Deauth)
	http.HandleFunc("/refresh", api.Refresh)
	http.HandleFunc("/whoami", api.Whoami)
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

}
