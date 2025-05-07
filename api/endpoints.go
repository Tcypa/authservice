package api

import (
	"authservice/database"
	"authservice/internal"
	"authservice/misc"
	"net/http"
)

func GetTokens(w http.ResponseWriter, r *http.Request) {
	guid := r.URL.Query().Get("guid")
	if guid == "" {
		http.Error(w, "guid is required", http.StatusBadRequest)
		return
	}
	ipAddress, err := misc.GetIp(r)
	if err != nil {
		http.Error(w, "failed get ip", http.StatusBadRequest)
	}
	userAgent := r.Header.Get("User-Agent")

	tokenPair, issued, err := internal.GenPair(guid)
	database.GetStorage().Insert(guid, tokenPair.Refresh, userAgent, ipAddress, issued)

}

func Refresh(w http.ResponseWriter, r *http.Request) {

}

func Whoami(w http.ResponseWriter, r *http.Request) {

}

func Deauth(w http.ResponseWriter, r *http.Request) {

}
