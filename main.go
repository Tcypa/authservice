package main

import (
	"authservice/api"
	"authservice/database"
	_ "authservice/docs"
	"context"
	"log"
	"net/http"

	httpSwagger "github.com/swaggo/http-swagger"
)

// @title AuthService API
// @version 1.0
// @description API for managing access and refresh tokens
// @host localhost:8080
// @BasePath /
func main() {
	ctx := context.Background()
	database.Init(ctx)
	http.HandleFunc("/getToken", api.GetTokens)
	http.HandleFunc("/deauth", api.Deauth)
	http.HandleFunc("/refresh", api.Refresh)
	http.HandleFunc("/whoami", api.Whoami)
	http.Handle("/swagger/", httpSwagger.WrapHandler)
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

}
