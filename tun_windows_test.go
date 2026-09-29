package tun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// This integration test creates a real TUN and temporarily installs system-wide
// WFP filters. Run it explicitly as Administrator on an otherwise idle test host:
//
//	$env:SING_TUN_TEST_WINDOWS_WFP = '1'
//	go test -run '^TestWindowsStrictRouteIPv6Loopback$' -v
//
//nolint:paralleltest // The WFP filters affect the whole host.
func TestWindowsStrictRouteIPv6Loopback(t *testing.T) {
	if os.Getenv("SING_TUN_TEST_WINDOWS_WFP") != "1" {
		t.Skip("set SING_TUN_TEST_WINDOWS_WFP=1 to exercise Windows TUN/WFP")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("Administrator privileges are required")
	}

	// configure exempts the TUN owner's application ID. A child at the same
	// executable path would also be exempt and give a false positive.
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	client := filepath.Join(t.TempDir(), "wfp-client.exe")
	if err := os.WriteFile(client, data, 0o700); err != nil {
		t.Fatal(err)
	}

	addresses := make(map[string]string)
	for _, network := range []string{"tcp4", "tcp6"} {
		host := "127.0.0.1:0"
		if network == "tcp6" {
			host = "[::1]:0"
		}
		listener, err := net.Listen(network, host)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		addresses[network] = listener.Addr().String()
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				conn.Close()
			}
		}()
	}
	udp, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	addresses["udp6"] = udp.LocalAddr().String()
	go func() {
		var data [1]byte
		for {
			n, addr, err := udp.ReadFrom(data[:])
			if err != nil {
				return
			}
			udp.WriteTo(data[:n], addr)
		}
	}()

	probe := func(t *testing.T, network, address, want string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, client, "-test.run=^TestWindowsWFPProbe$")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.Env = append(os.Environ(), "SING_TUN_WFP_PROBE="+network,
			"SING_TUN_WFP_ADDRESS="+address, "SING_TUN_WFP_WANT="+want)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s %s (want %s): %v\n%s", network, address, want, err, output)
		}
	}

	// Check the environment before installing filters (e.g. another VPN may
	// already block IPv6 loopback).
	for network, address := range addresses {
		probe(t, network, address, "allow")
	}
	if t.Failed() {
		t.Fatal("loopback must work before the test installs WFP filters")
	}

	device, err := New(Options{
		Name:              fmt.Sprintf("sing-tun-test-%d", os.Getpid()),
		MTU:               1500,
		Inet4Address:      []netip.Prefix{netip.MustParsePrefix("198.19.254.1/30")},
		AutoRoute:         true,
		StrictRoute:       true,
		Inet4RouteAddress: []netip.Prefix{netip.MustParsePrefix("198.19.254.0/30")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { device.Close() })

	for _, network := range []string{"tcp4", "tcp6", "udp6"} {
		t.Run(network+"-loopback", func(t *testing.T) {
			probe(t, network, addresses[network], "allow")
		})
	}
	t.Run("tcp6-non-loopback", func(t *testing.T) {
		// Documentation address: no remote service or working Internet is
		// needed. Require WSAEACCES, not just a timeout or routing failure.
		probe(t, "tcp6", "[2001:db8::1]:18558", "block")
	})
	for network, address := range map[string]string{"tcp4": "127.0.0.1:53", "tcp6": "[::1]:53"} {
		t.Run(network+"-dns", func(t *testing.T) {
			// Excluding loopback from the address-family block must not bypass
			// the separate strict-route DNS filters.
			probe(t, network, address, "block")
		})
	}
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	for network, address := range addresses {
		probe(t, network, address, "allow")
	}
}

//nolint:paralleltest // Subprocess helper for the serial WFP integration test.
func TestWindowsWFPProbe(t *testing.T) {
	network := os.Getenv("SING_TUN_WFP_PROBE")
	if network == "" {
		t.Skip("subprocess helper")
	}
	conn, err := net.DialTimeout(network, os.Getenv("SING_TUN_WFP_ADDRESS"), 2*time.Second)
	if err == nil {
		defer conn.Close()
		if network == "udp6" {
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			_, err = conn.Write([]byte{0})
			if err == nil && os.Getenv("SING_TUN_WFP_WANT") == "allow" {
				var reply [1]byte
				_, err = conn.Read(reply[:])
			}
		}
	}
	if os.Getenv("SING_TUN_WFP_WANT") == "block" {
		if !errors.Is(err, windows.WSAEACCES) {
			t.Fatalf("want WSAEACCES, got %v", err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
}
