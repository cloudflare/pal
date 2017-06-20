package pal

import "fmt"

type decryptionRequest struct {
	Ciphertexts map[string]string `json:"ciphertexts,omitempty"`
}

type decryptionResponse struct {
	Error   *decryptionError  `json:"error,omitempty"`
	Secrets map[string]string `json:"secrets,omitempty"`
}

type decryptionError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Secret  string `json:"secret"`
}

// decryptionErrorV1 is used to communicate with legacy client
type decryptionErrorV1 struct {
	Code   int
	Err    string
	Secret string
}

func (e *decryptionError) Error() string {
	return fmt.Sprintf("code: %d, reason: %s", e.Code, e.Message)
}
