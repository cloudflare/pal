package pal

import "fmt"

type decryptionRequest struct {
	Ciphertexts map[string]string `json:"ciphertexts,omitempty"`
}

type decryptionResponse struct {
	Error   *errorMsg         `json:"error,omitempty"`
	Secrets map[string]string `json:"secrets,omitempty"`
}

type errorMsg struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Secret  string `json:"secret"`
}

func (e *errorMsg) Error() string {
	return fmt.Sprintf("code: %d, reason: %s", e.Code, e.Message)
}
