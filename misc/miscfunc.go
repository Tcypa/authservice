package misc

import (
	"errors"
	"net"
	"net/http"
)

func GetIp(r *http.Request) (string, error) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", errors.New("failed get user ip")
	}

	userIP := net.ParseIP(ip)
	if userIP == nil {
		return "", errors.New("failed get user ip")
	}
	return userIP.String(), nil
}
