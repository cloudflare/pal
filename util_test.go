package pal

import "github.com/cloudflare/pal/log"

func init() {
	testMode = true
	log.Disable()
}
