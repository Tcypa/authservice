package test

import (
	"authservice/internal"
	"testing"
)

func TestTokenGen(t *testing.T) {

	guid := "1234567"
	tokenPair, _, err := internal.GenPair(guid)

	if err != nil {
		t.Fatal(err)
	}
	t.Log("access token:", tokenPair.Access)
	t.Log("refresh token:", tokenPair.Refresh)

}
