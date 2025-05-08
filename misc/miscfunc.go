package misc

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
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
func SendWebhook(guid, ip string) error {
	webhookURL := os.Getenv("WebhookURL")
	payload := map[string]string{"guid": guid, "ip": ip}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("webhook failed")
	}
	return nil
}
