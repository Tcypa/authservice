package internal

import (
	"encoding/base64"
	"errors"
	"os"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

var secret = os.Getenv("secret")

var accessLifetime = 12 * time.Hour
var RefreshLifetime = 72 * time.Hour

type tokenPair struct {
	Access  string
	Refresh string
}

func genAccess(guid string, n time.Time) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"guid": guid,
		"exp":  n.Add(accessLifetime).Unix(),
	})
	return token.SignedString([]byte(secret))
}
func genRefresh(guid string, n time.Time) string {
	rawToken := []byte(guid + time.Duration(n.Add(RefreshLifetime).UnixNano()).String())
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(rawToken)))
	base64.StdEncoding.Encode(dst, rawToken)
	return string(dst)

}

func GenPair(guid string) (tokenPair, time.Time, error) {
	var pair tokenPair
	var err error
	issued := time.Now()
	pair.Access, err = genAccess(guid, issued)
	if err != nil {
		return pair, issued, errors.New("faied to get access token")
	}
	pair.Refresh = genRefresh(guid, issued)
	return pair, issued, nil
}
