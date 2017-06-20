package pal

import (
	"errors"
	"net"
	"syscall"
)

type conn struct {
	net.Conn
	*syscall.Ucred
}

func getUcred(conn net.Conn) (*syscall.Ucred, error) {
	uconn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, errors.New("internal listener is not a net.UnixListener")
	}
	f, err := uconn.File()
	if err != nil {
		return nil, err
	}
	return syscall.GetsockoptUcred(int(f.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
}
