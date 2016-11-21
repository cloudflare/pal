package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/cloudflare/pal"
	"github.com/uber-go/zap"
)

var (
	Version = "This is filled at build time"

	env     = flag.String("env", "", "Environment name for config section (default is APP_ENV).")
	socket  = flag.String("socket", "/run/pald/pald.sock", "Socket file for pald.")
	version = flag.Bool("v", false, "show the version number and exit")

	logger = zap.New(zap.NewTextEncoder())
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
		logger.Fatal("missing PAL_SECRETS_YAML environment variable")
	}

	if *env == "" {
		logger.Fatal("missing -env flag or APP_ENV environment variable")
	}

	client, err := pal.NewClient(bytes.NewBufferString(secretsYAML), *socket, *env)
	if err != nil {
		logger.Fatal("failed to initialize PAL client", zap.Error(err))
	}
	if err := client.Decrypt(); err != nil {
		logger.Fatal("failed to decrypt secrets", zap.Error(err))
	}

	args := os.Args[1:]
	for i, arg := range args {
		if arg == "--" {
			args = args[i+1:]
			break
		}
	}

	if err := client.Exec(args, os.Environ()); err != nil {
		logger.Fatal("failed to execute command",
			zap.Object("args", args),
			zap.Object("env", os.Environ()),
			zap.Error(err))
	}
}
