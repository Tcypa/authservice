package api

import (
	"authservice/database"
	"authservice/internal"
	"authservice/misc"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// GetTokens godoc
// @Summary Generate tokens
// @Description Generates a pair of access and refresh tokens for the guid
// @Tags auth
// @Accept json
// @Produce json
// @Param guid query string true "user guid"
// @Success 200 {object} map[string]string "accessToken and refreshToken"
// @Failure 400 {string} string "invalid guid"
// @Failure 500 {string} string "internal server error"
// @Router /getToken [get]
func GetTokens(w http.ResponseWriter, r *http.Request) {
	guid := r.URL.Query().Get("guid")
	if guid == "" {
		http.Error(w, "guid is required", http.StatusBadRequest)
		return
	}
	if _, err := uuid.Parse(guid); err != nil {
		http.Error(w, "invalid guid", http.StatusBadRequest)
		return
	}
	ipAddress, err := misc.GetIp(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userAgent := r.Header.Get("User-Agent")

	tokenPair, issued, err := internal.GenPair(guid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = database.GetStorage().Insert(guid, tokenPair.RefreshBC, userAgent, ipAddress, issued)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string]string{
		"access":  tokenPair.Access,
		"refresh": tokenPair.Refresh,
	})
	if err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

type refreshRequest struct {
	Access  string `json:"accessToken"`
	Refresh string `json:"refreshToken"`
}

// RefreshToken godoc
// @Summary Refresh tokens
// @Description Refreshes the access token using a refresh token
// @Tags auth
// @Accept json
// @Produce json
// @Param   body  body      refreshRequest  true  "Access + refresh tokens"
// @Success 200 {object} map[string]string "accessToken and refreshToken"
// @Failure 400 {string} string "Invalid refresh token"
// @Failure 500 {string} string "Internal server error"
// @Router /refresh [post]
func Refresh(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Access  string `json:"accessToken"`
		Refresh string `json:"refreshToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	currentUserAgent := r.Header.Get("User-Agent")
	currentIP, err := misc.GetIp(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	token, err := jwt.Parse(input.Access, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid signing method")
		}
		return []byte(os.Getenv("secret")), nil
	})
	if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid && !errors.Is(err, jwt.ErrTokenExpired) {
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}
	guid := claims["guid"].(string)

	rawToken, err := base64.StdEncoding.DecodeString(input.Refresh)
	if err != nil {
		http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}
	tokenData, err := database.GetStorage().Read(guid)
	if err != nil {
		http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(tokenData.TokenHash), rawToken); err != nil {
		http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}
	if currentUserAgent != tokenData.UserAgent {
		if err := database.GetStorage().Delete(guid); err != nil {
			log.Printf("error deleting token: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		http.Error(w, "useragent mismatch", http.StatusUnauthorized)
		return
	}

	if currentIP != tokenData.IPAddress {
		if err := misc.SendWebhook(guid, currentIP); err != nil {
			log.Printf("failed to send webhook: %v", err)
		}
	}

	tokenPair, issued, err := internal.GenPair(guid)
	if err != nil {
		log.Printf("error generating tokens: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	err = database.GetStorage().Insert(guid, tokenPair.RefreshBC, currentUserAgent, currentIP, issued)
	if err != nil {
		log.Printf("error inserting token: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"access":  tokenPair.Access,
		"refresh": tokenPair.Refresh,
	}); err != nil {
		log.Printf("error encoding response: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
}

// Whoami godoc
// @Summary Get user guid
// @Description Returns the guid of the user extracted from a valid access token
// @Tags auth
// @Produce json
// @Param   Authorization  header    string  true  "Bearer access_token"
// @Success 200 {object} map[string]string "guid"
// @Failure 401 {string} string "invalid access token"
// @Failure 401 {string} string "invalid token claims"
// @Router /whoami [get]
func Whoami(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "missing or invalid auth header", http.StatusUnauthorized)
		return
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid signing method")
		}
		return []byte(os.Getenv("secret")), nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "invalid token claims", http.StatusUnauthorized)
		return
	}
	guid := claims["guid"].(string)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"guid": guid}); err != nil {
		log.Printf("error encoding: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
}

// Deauth godoc
// @Summary Invalidate tokens
// @Description Deletes refresh token for the current user, effectively logging them out
// @Tags auth
// @Param   Authorization  header    string  true  "Bearer access_token"
// @Failure 401 {string} string "invalid access token"
// @Failure 401 {string} string "missing or invalid auth header"
// @Failure 500 {string} string "internal server error"
// @Router /deauth [post]
func Deauth(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "missing or invalid auth header", http.StatusUnauthorized)
		return
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid signing method")
		}
		return []byte(os.Getenv("secret")), nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "invalid token claims", http.StatusUnauthorized)
		return
	}
	guid := claims["guid"].(string)
	if err := database.GetStorage().Delete(guid); err != nil {
		log.Printf("error deleting token: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
}
