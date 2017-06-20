package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cloudflare/pal"
	"github.com/cloudflare/pal/log"
	"github.com/coreos/go-systemd/activation"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	Version = "This is filled at build time"

	config      = flag.String("config", "config.yaml", "Configuration yaml file.")
	env         = flag.String("env", "", "Environment name for config section (default is APP_ENV).")
	httpAddr    = flag.String("addr.http", "", "Legacy HTTP Daemon socket to connect to. Accepted unix:///path or fd://n")
	rpcAddr     = flag.String("addr.rpc", "", "RPC Daemon socket to connect to. Accepted unix:///path or fd://n")
	metricsAddr = flag.String("metrics-addr", "127.0.0.1:8974", "HTTP listen address for metrics")
	version     = flag.Bool("v", false, "show the version number and exit")
)

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("Version: %s\n", Version)
		os.Exit(0)
	}

	r, err := os.Open(*config)
	if err != nil {
		log.Fatalf("Could not open server configuration file: %v", err)
	}
	conf, err := pal.LoadServerConfigEntry(r, *env)
	if err != nil {
		log.Fatalf("Could not parse server configuration: %v", err)
	}
	srv, err := pal.NewServer(conf)
	if err != nil {
		log.Fatalf("Failed to initialize PAL server: %v", err)
	}

	addrs := []string{}
	if *httpAddr != "" {
		addrs = append(addrs, *httpAddr)
	}
	if *rpcAddr != "" {
		addrs = append(addrs, *rpcAddr)
	}

	listeners, err := getListeners(addrs...)
	if err != nil {
		log.Fatalf("Failed to get listener: %v", err)
	}
	if len(listeners) == 0 {
		log.Fatalf("Failed to get any listener for %v ", addrs)
	}

	errch := make(chan error)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		for _, l := range listeners {
			log.Infof("Closing %s", l.Addr())
			if err := l.Close(); err != nil {
				errch <- fmt.Errorf("Failed to close %s: %v", l.Addr(), err)
				return
			}
		}
		errch <- nil
	}()

	go func() {
		errch <- serveMetrics()
	}()

	if l, ok := listeners[*rpcAddr]; ok {
		go func() {
			log.Infof("Listening to rpc addr: %s", l.Addr())
			errch <- srv.ServeRPC(l)
		}()
	}

	if l, ok := listeners[*httpAddr]; ok {
		go func() {
			log.Infof("Listening to http addr: %s", l.Addr())
			errch <- http.Serve(l, prometheus.InstrumentHandler("pald_HTTP", srv))
		}()
	}

	for err := range errch {
		if err != nil {
			log.Errorf("exit with error: %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
}

func serveMetrics() error {
	return http.ListenAndServe(*metricsAddr, prometheus.Handler())
}

func getListeners(addrs ...string) (map[string]net.Listener, error) {
	fdAddrs := []string{}
	unixAddrs := []string{}
	listeners := make(map[string]net.Listener)

	for _, addr := range addrs {
		if addr == "" {
			continue
		}
		addrParts := strings.SplitN(addr, "://", 2)
		if len(addrParts) != 2 {
			return nil, fmt.Errorf("Bad host format %q, expected proto://addr", addr)
		}
		proto, part := addrParts[0], addrParts[1]
		switch proto {
		case "fd":
			fdAddrs = append(fdAddrs, part)
		case "unix":
			unixAddrs = append(unixAddrs, part)
		}
	}

	fdListeners, err := listenFDAddrs(fdAddrs)
	if err != nil {
		return nil, err
	}
	unixListeners, err := listenUnixAddrs(unixAddrs)
	if err != nil {
		return nil, err
	}
	for addr, l := range fdListeners {
		listeners["fd://"+addr] = l
	}
	for addr, l := range unixListeners {
		listeners["unix://"+addr] = l
	}
	return listeners, nil
}

// listenFDAddrs returns the list of listeners backed by the systemd-activated
// sockets. It returns error if the required listeners are not in the list of
// activated sockets.
func listenFDAddrs(addrs []string) (map[string]net.Listener, error) {
	if len(addrs) == 0 {
		return nil, nil
	}
	allListeners, err := activation.Listeners(true)
	if err != nil {
		return nil, err
	}

	listeners := make(map[string]net.Listener)
	taken := make(map[int]struct{})
	for _, addr := range addrs {
		offset := 0
		// if we require a particular descriptor, asssign the first descriptor we found
		if addr != "" && addr != "*" {
			fd, err := strconv.Atoi(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid systemd fd address %q, expect a number", addr)
			}
			offset = fd - 3
			if len(allListeners) < int(offset)+1 || allListeners[offset] == nil {
				return nil, fmt.Errorf("required socket %d is not in the list of activated systemd sockets", offset+3)
			}
		}
		listeners[addr] = allListeners[offset]
		taken[offset] = struct{}{}
	}

	// close the rest of the listeners if we dont need them
	for i, ls := range allListeners {
		if _, ok := taken[i]; ok || ls == nil {
			continue
		}
		if err := ls.Close(); err != nil {
			log.Errorf("failed to close systemd activated socket %d: %v", i+3, err)
		}
	}
	return listeners, nil
}

// listenUnixAddrs returns list of unix-socket listeners mapped to their
// local addresses
func listenUnixAddrs(addrs []string) (map[string]net.Listener, error) {
	if len(addrs) == 0 {
		return nil, nil
	}
	listeners := make(map[string]net.Listener)
	for _, addr := range addrs {
		if err := os.Remove(addr); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("Failed to remove unix socket %s: %q", addr, err)
		}
		l, err := net.Listen("unix", addr)
		if err != nil {
			return nil, err
		}
		listeners[addr] = l
	}
	return listeners, nil
}
