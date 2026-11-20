//go:build linux

package mcpgate

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestKernelUnixPeerCredentials(t *testing.T) {
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	c, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	want := os.Geteuid() == 0
	if rootPeer(c) != want || rootPeer(peer) != want {
		t.Fatal("SO_PEERCRED did not match process identity")
	}
}
