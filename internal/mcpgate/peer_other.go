//go:build !linux

package mcpgate

import "net"

func peerCredentialsSupported() bool { return false }
func rootPeer(net.Conn) bool         { return false }
