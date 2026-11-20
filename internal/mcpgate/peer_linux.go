//go:build linux

package mcpgate

import (
	"net"
	"syscall"
)

func peerCredentialsSupported() bool { return true }
func rootPeer(c net.Conn) bool {
	u, ok := c.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := u.SyscallConn()
	if err != nil {
		return false
	}
	var cred *syscall.Ucred
	var readErr error
	err = raw.Control(func(fd uintptr) {
		cred, readErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	return err == nil && readErr == nil && cred != nil && cred.Uid == 0
}
