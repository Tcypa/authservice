package internal

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var secret = os.Getenv("secret")

var accessLifetime = 12 * time.Hour
var RefreshLifetime = 72 * time.Hour

type tokenPair struct {
	Access    string
	Refresh   string
	RefreshBC string
}

func genAccess(guid string, n time.Time) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"guid": guid,
		"exp":  n.Add(accessLifetime).Unix(),
	})
	return token.SignedString([]byte(secret))
}
func genRefresh(guid string) (string, string, error) {
	rawToken := make([]byte, 32)
	_, err := rand.Read(rawToken)
	if err != nil {
		return "", "", err
	}
	refreshToken := base64.StdEncoding.EncodeToString(rawToken)
	hash, err := bcrypt.GenerateFromPassword(rawToken, bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	return refreshToken, string(hash), nil
}

func GenPair(guid string) (tokenPair, time.Time, error) {
	var pair tokenPair
	var err error
	issued := time.Now()
	pair.Access, err = genAccess(guid, issued)
	if err != nil {
		return pair, issued, errors.New("faied get access token")
	}
	pair.Refresh, pair.RefreshBC, err = genRefresh(guid)
	if err != nil {
		return pair, issued, errors.New("failed gen refresh token")
	}
	return pair, issued, nil
}
