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
	"github.com/coreos/go-systemd/activation"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/uber-go/zap"
)

var (
	Version = "This is filled at build time"

	config      = flag.String("config", "config.yaml", "Configuration yaml file.")
	env         = flag.String("env", "", "Environment name for config section (default is APP_ENV).")
	addr        = flag.String("addr", "", "Domain socket to listen on. Accepted unix:///path or fd://n")
	metricsAddr = flag.String("metrics-addr", "127.0.0.1:8974", "HTTP listen address for metrics")
	version     = flag.Bool("v", false, "show the version number and exit")

	logger = zap.New(zap.NewTextEncoder())
)

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("Version: %s\n", Version)
		os.Exit(0)
	}

	r, err := os.Open(*config)
	if err != nil {
		logger.Fatal("failed to open server configuration file", zap.Error(err))
	}
	conf, err := pal.LoadServerConfig(r, *env)
	if err != nil {
		logger.Fatal("failed to parse server configuration", zap.Error(err))
	}
	srv, err := pal.NewServer(logger, conf)
	if err != nil {
		logger.Fatal("failed to initialize PAL server", zap.Error(err))
	}

	listeners, err := getListeners(*addr)
	if err != nil {
		logger.Fatal("failed to open listeners", zap.String("addr", *addr), zap.Error(err))
	}
	if len(listeners) == 0 {
		logger.Fatal("failed to get any listener", zap.String("addr", *addr))
	}

	errch := make(chan error)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		for _, l := range listeners {
			logger.Info("closing listener", zap.Stringer("addr", l.Addr()))
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

	if l, ok := listeners[*addr]; ok {
		go func() {
			logger.Info("Listening", zap.Stringer("addr", l.Addr()))
			errch <- srv.ServeRPC(l)
		}()
	}

	for err := range errch {
		if err != nil {
			logger.Error("server exitted", zap.Error(err))
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
			logger.Error("failed to close systemd activated socket", zap.Int("fd", i+3), zap.Error(err))
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
