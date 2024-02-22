//go:build linux
// +build linux

package tproxy

import (
	"fmt"
	"net"
	"syscall"
)

func ListenTCP(network string, laddr *net.TCPAddr) (*net.TCPListener, error) {
	l, err := net.ListenTCP(network, laddr)
	if err != nil {
		return nil, err
	}

	fileDescriptorSource, err := l.File()
	if err != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: laddr, Err: fmt.Errorf("get file descriptor: %w", err)}
	}
	defer fileDescriptorSource.Close()

	fd := int(fileDescriptorSource.Fd())
	if err = syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: laddr, Err: fmt.Errorf("set IP_TRANSPARENT: %w", err)}
	}

	if err = syscall.SetNonblock(fd, true); err != nil {
		return nil, &net.OpError{Op: "listen", Err: fmt.Errorf("set O_NONBLOCK: %w", err)}
	}

	return l, nil
}
