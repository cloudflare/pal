package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/cloudflare/pal"
	"github.com/cloudflare/pal/log"
)

var (
	Version = "This is filled at build time"

	env        = flag.String("env", "", "Environment name for config section (default is APP_ENV).")
	socket     = flag.String("socket", "/run/pald/pald-rpc.sock", "Socket file for pald.")
	socketType = flag.String("socket.type", "rpc", "Whether to communicate using rpc or http")
	version    = flag.Bool("v", false, "show the version number and exit")
)

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("Version: %s\n", Version)
		os.Exit(0)
	}

	if appEnv := os.Getenv("APP_ENV"); *env == "" {
		*env = appEnv
	}

	secretsYAML := os.Getenv("PAL_SECRETS_YAML")
	if secretsYAML == "" {
		log.Fatal("missing PAL_SECRETS_YAML environment variable")
	}

	if *env == "" {
		log.Fatal("missing -env flag or APP_ENV environment variable")
	}

	var client pal.Client
	switch *socketType {
	case "rpc":
		client = pal.NewClientV2(bytes.NewBufferString(secretsYAML), *socket, *env)
	case "http":
		client = pal.NewClientV1(bytes.NewBufferString(secretsYAML), *socket, *env)
	default:
		log.Fatal("socket.type must be 'rpc' or 'http'")
	}

	if err := client.Decrypt(); err != nil {
		log.Fatal(err)
	}

	args := os.Args[1:]
	for i, arg := range args {
		if arg == "--" {
			args = args[i+1:]
			break
		}
	}

	if err := client.Exec(args, os.Environ()); err != nil {
		log.Fatal(err)
	}
}
