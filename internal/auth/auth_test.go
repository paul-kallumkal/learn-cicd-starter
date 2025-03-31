package auth

import (
	"errors"
	"testing"
)

func TestEmptyAuth(t *testing.T) {
	testHeader := make(map[string][]string)
	expectedResponse := ""
	expectedError := errors.New("no authorization header included")

	resp, err := GetAPIKey(testHeader)

	if resp != expectedResponse || err.Error() != expectedError.Error() {
		t.Errorf(`GetAPIKey({}) = "%s", %s. Wanted "%s", %s`, resp, err, expectedResponse, expectedError)
	}

}

func TestMalformedAuth(t *testing.T) {
	testHeader := map[string][]string{"Authorization": []string{"Malformed API key"}}
	expectedResponse := ""
	expectedError := errors.New("malformed authorization header")

	resp, err := GetAPIKey(testHeader)

	if resp != expectedResponse || err.Error() != expectedError.Error() {
		t.Errorf(`GetAPIKey({}) = "%s", %s. Wanted "%s", %s`, resp, err, expectedResponse, expectedError)
	}

}

func TestAuth(t *testing.T) {
	testHeader := map[string][]string{"Authorization": []string{"ApiKey testKey"}}
	expectedResponse := "testKey"

	resp, err := GetAPIKey(testHeader)

	if resp != expectedResponse || err != nil {
		t.Errorf(`GetAPIKey({}) = "%s", %s. Wanted "%s", nil`, resp, err, expectedResponse)
	}

}
