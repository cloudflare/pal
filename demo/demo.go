package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func main() {
	palSecretsYaml := os.Getenv("PAL_SECRETS_YAML")
	envSecret := os.Getenv("SECRET")
	f, err := os.Open("/tmp/secret.txt")
	if err != nil {
		fmt.Printf("Could not open secrets file: %s", err)
		os.Exit(1)
	}
	s, err := ioutil.ReadAll(f)
	if err != nil {
		fmt.Printf("Failed to read secrets file: %s", err)
		os.Exit(1)
	}
	fileSecret := string(s)
	http.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "PAL Secrets Yaml:\n%s\n", palSecretsYaml)
		fmt.Fprintf(w, "Env secret: %s\n", envSecret)
		fmt.Fprintf(w, "File secret: %s\n", fileSecret)
	})
	http.ListenAndServe(":9090", nil)
}
