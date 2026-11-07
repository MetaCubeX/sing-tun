//go:build linux

package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Frozen NativeTun.BatchWrite from MetaCubeX/sing-tun 8daae1bf1858.
// CI checks the body against the pinned baseline, independently of the candidate.
func controlNativeBatchWrite(t *NativeTun, buffers [][]byte, offset int) (int, error) {
	t.writeAccess.Lock()
	defer func() {
		t.tcpGROTable.reset()
		t.udpGROTable.reset()
		t.writeAccess.Unlock()
	}()
	var (
		errs  error
		total int
	)
	t.gsoToWrite = t.gsoToWrite[:0]
	if t.vnetHdr {
		// Callers supply complete checksums when TX checksum offload is disabled.
		// With TX offload enabled, checksums may be unset or partial, so retain
		// validation to avoid coalescing packets with incomplete checksums.
		err := handleGRO(buffers, offset, t.tcpGROTable, t.udpGROTable, t.gro, !t.txChecksumOffload, &t.gsoToWrite)
		if err != nil {
			return 0, err
		}
		offset -= virtioNetHdrLen
	} else {
		for i := range buffers {
			t.gsoToWrite = append(t.gsoToWrite, i)
		}
	}
	for _, toWrite := range t.gsoToWrite {
		n, err := t.tunFile.Write(buffers[toWrite][offset:])
		if errors.Is(err, syscall.EBADFD) {
			return total, os.ErrClosed
		}
		if err != nil {
			errs = errors.Join(errs, err)
		} else {
			total += n
		}
	}
	return total, errs
}

func writePathDevice(file *os.File, vnet bool) *NativeTun {
	return &NativeTun{tunFile: file, vnetHdr: vnet, tcpGROTable: newTCPGROTable(), udpGROTable: newUDPGROTable()}
}

func writePathPackets(n, offset, payloadSize int, ipv6 bool) [][]byte {
	source, target := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("198.18.0.2")
	if ipv6 {
		source, target = netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")
	}
	packets := make([][]byte, n)
	for i := range packets {
		payload := bytes.Repeat([]byte{byte(i + 1)}, payloadSize)
		// Sequence gaps keep this fixture reusable by the multi-flow benchmark:
		// handleGRO does not change packet lengths when these cannot merge.
		packet := tcpPacket(source, target, uint32(100+i*(payloadSize+1)), 200, 16, payload)
		packets[i] = make([]byte, offset+len(packet), int(gsoMaxSize))
		for j := 0; j < offset; j++ {
			packets[i][j] = 0xa5
		}
		copy(packets[i][offset:], packet)
	}
	return packets
}

func TestNativeWritePathEquivalence(t *testing.T) {
	for _, vnet := range []bool{false, true} {
		for _, ipv6 := range []bool{false, true} {
			for _, offset := range []int{0, 3, 10, 14} {
				for _, payload := range []int{1, 64, 1460, 8960} {
					t.Run(fmt.Sprintf("vnet%v/v6%v/off%d/size%d", vnet, ipv6, offset, payload), func(t *testing.T) {
						var outputs [2][]byte
						var counts [2][]int
						var failures [2][]string
						for variant := range outputs {
							file, err := os.CreateTemp(t.TempDir(), "packets")
							if err != nil {
								t.Fatal(err)
							}
							defer file.Close()
							device := writePathDevice(file, vnet)
							for _, size := range []int{8, 1, 2, 1, 0, 1} {
								packets := writePathPackets(size, offset, payload, ipv6)
								var n int
								if variant == 0 {
									n, err = controlNativeBatchWrite(device, packets, offset)
								} else {
									n, err = device.BatchWrite(packets, offset)
								}
								counts[variant] = append(counts[variant], n)
								failures[variant] = append(failures[variant], fmt.Sprint(err))
								if len(device.tcpGROTable.itemsByFlow) != 0 || len(device.udpGROTable.itemsByFlow) != 0 {
									t.Fatal("GRO state retained after write")
								}
							}
							outputs[variant], err = os.ReadFile(file.Name())
							if err != nil {
								t.Fatal(err)
							}
						}
						if !bytes.Equal(outputs[0], outputs[1]) || fmt.Sprint(counts[0]) != fmt.Sprint(counts[1]) || fmt.Sprint(failures[0]) != fmt.Sprint(failures[1]) {
							t.Fatalf("wire/count/error mismatch: counts=%v errors=%v", counts, failures)
						}
					})
				}
			}
		}
	}
}

func TestNativeWritePathErrors(t *testing.T) {
	for _, kind := range []string{"closed", "readonly", "full", "partial"} {
		t.Run(kind, func(t *testing.T) {
			var matches [2]string
			for variant := range matches {
				var file *os.File
				var err error
				peer := -1
				switch kind {
				case "closed", "readonly":
					file, err = os.CreateTemp(t.TempDir(), "packets")
					if err != nil {
						t.Fatal(err)
					}
					if err = file.Close(); err != nil {
						t.Fatal(err)
					}
					if kind == "readonly" {
						file, err = os.Open(file.Name())
					}
				case "full":
					file, err = os.OpenFile("/dev/full", os.O_WRONLY, 0)
				case "partial":
					fds, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
					if e != nil {
						t.Fatal(e)
					}
					defer unix.Close(fds[1])
					peer = fds[1]
					// Fill a small socket send buffer, then time out the remaining
					// write to exercise the batch API's zero-total-on-error rule.
					if err = unix.SetNonblock(fds[0], true); err != nil {
						t.Fatal(err)
					}
					if err = unix.SetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_SNDBUF, 4096); err != nil {
						t.Fatal(err)
					}
					file = os.NewFile(uintptr(fds[0]), "partial-socket")
				}
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				packet := make([]byte, 10+1<<20)
				device := writePathDevice(file, true)
				if kind == "partial" {
					if err = file.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
						t.Fatal(err)
					}
				}
				var n int
				if variant == 0 {
					n, err = controlNativeBatchWrite(device, [][]byte{packet}, 10)
				} else {
					n, err = device.BatchWrite([][]byte{packet}, 10)
				}
				if n != 0 || err == nil {
					t.Fatalf("expected zero total on error, got n=%d err=%v", n, err)
				}
				if kind == "partial" {
					queued, e := unix.IoctlGetInt(peer, unix.TIOCINQ)
					if e != nil || queued == 0 {
						t.Fatalf("partial-write fixture sent no bytes: %d, %v", queued, e)
					}
				}
				matches[variant] = fmt.Sprintf("%T/closed%v/badf%v/nospace%v/timeout%v/short%v", err, errors.Is(err, os.ErrClosed), errors.Is(err, syscall.EBADF), errors.Is(err, syscall.ENOSPC), errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, io.ErrShortWrite))
			}
			if matches[0] != matches[1] {
				t.Fatalf("error contract changed: %v", matches)
			}
		})
	}
}

func TestNativeWritePathConcurrent(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "packets")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	device := writePathDevice(file, true)
	var wg sync.WaitGroup
	failures := make(chan error, 4)
	for writer := 0; writer < 4; writer++ {
		wg.Add(1)
		go func(writer int) {
			defer wg.Done()
			for iteration := 0; iteration < 16; iteration++ {
				n := 1 + iteration%2
				packets := writePathPackets(n, 10, 32, false)
				for i := range packets {
					payload := packets[i][10+40:]
					payload[0], payload[1], payload[2] = byte(writer), byte(iteration), byte(i)
					packet := tcpPacket(netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("198.18.0.2"), uint32(100+i*33), 200, 16, payload)
					copy(packets[i][10:], packet)
				}
				if _, err := device.BatchWrite(packets, 10); err != nil {
					failures <- err
					return
				}
			}
		}(writer)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[[3]byte]bool)
	for len(data) > 0 {
		if len(data) < 10+40 {
			t.Fatal("truncated packet")
		}
		size := int(binary.BigEndian.Uint16(data[10+2:]))
		if size != 40+32 || 10+size > len(data) {
			t.Fatalf("unexpected packet size %d", size)
		}
		payload := data[10+40 : 10+size]
		key := [3]byte{payload[0], payload[1], payload[2]}
		if seen[key] {
			t.Fatal("duplicate packet")
		}
		seen[key] = true
		data = data[10+size:]
	}
	if len(seen) != 4*24 {
		t.Fatalf("lost packets: got %d", len(seen))
	}
}

func BenchmarkNativeWritePath(b *testing.B) {
	for _, n := range []int{1, 2, 8, 32, 64} {
		for _, candidate := range []bool{false, true} {
			b.Run(fmt.Sprintf("n%d/candidate%v", n, candidate), func(b *testing.B) {
				file, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
				if err != nil {
					b.Fatal(err)
				}
				defer file.Close()
				device := writePathDevice(file, true)
				packets := writePathPackets(n, 10, 64, false)
				b.ReportAllocs()
				b.SetBytes(int64(n * 64))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if candidate {
						_, err = device.BatchWrite(packets, 10)
					} else {
						_, err = controlNativeBatchWrite(device, packets, 10)
					}
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func TestNativeWritePathPanicUnlock(t *testing.T) {
	for _, offset := range []int{-1, 2} {
		var failures [2]string
		for variant := range failures {
			file, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = file.Close() })
			device := writePathDevice(file, false)
			func() {
				defer func() { failures[variant] = fmt.Sprint(recover()) }()
				if variant == 0 {
					_, _ = controlNativeBatchWrite(device, [][]byte{{0x45}}, offset)
				} else {
					_, _ = device.BatchWrite([][]byte{{0x45}}, offset)
				}
			}()
			if failures[variant] == "<nil>" || !device.writeAccess.TryLock() {
				t.Fatal("invalid offset did not panic safely or retained the write lock")
			}
			device.writeAccess.Unlock()
		}
		if failures[0] != failures[1] {
			t.Fatalf("offset %d panic changed: %v", offset, failures)
		}
	}
}

func TestNativeWritePathKernel(t *testing.T) {
	if os.Getenv("TUN_WRITE_KERNEL") != "1" {
		t.Skip("requires an explicitly provisioned isolated network namespace")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	init, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if self == init {
		t.Fatal("refusing to create a test TUN in the host network namespace")
	}
	device, err := New(Options{Name: "mh-write-ci", MTU: 9000, GSO: true, Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}})
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	native := device.(*NativeTun)
	if !native.vnetHdr || native.FrontHeadroom() != 10 {
		t.Fatal("GSO/VNET header not enabled")
	}
	for _, n := range []int{1, 2, 8, 32, 64} {
		for _, payloadSize := range []int{64, 1400, 8000} {
			for _, candidate := range []bool{false, true} {
				t.Run(fmt.Sprintf("n%d/size%d/candidate%v", n, payloadSize, candidate), func(t *testing.T) {
					conn, err := net.ListenPacket("udp4", "198.18.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					// The largest burst exceeds the default UDP receive buffer.
					raw, err := conn.(*net.UDPConn).SyscallConn()
					if err != nil {
						t.Fatal(err)
					}
					var socketErr error
					err = raw.Control(func(fd uintptr) {
						socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 4<<20)
					})
					if err != nil || socketErr != nil {
						t.Fatalf("receive buffer: %v %v", err, socketErr)
					}
					if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
						t.Fatal(err)
					}
					port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
					packets := make([][]byte, n)
					for i := range packets {
						payload := bytes.Repeat([]byte{byte(i)}, payloadSize)
						packet := udpPacket(netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("198.18.0.1"), port, payload)
						// GRO headroom must not permit an oversized IP aggregate.
						packets[i] = make([]byte, 10+len(packet), int(gsoMaxSize))
						copy(packets[i][10:], packet)
					}
					done := make(chan error, 1)
					go func() {
						buffer := make([]byte, 9000)
						for i := 0; i < n; i++ {
							count, _, err := conn.ReadFrom(buffer)
							if err != nil {
								done <- err
								return
							}
							if count != payloadSize || !bytes.Equal(buffer[:count], bytes.Repeat([]byte{byte(i)}, payloadSize)) {
								done <- fmt.Errorf("UDP packet %d corrupted or reordered: received %d bytes", i, count)
								return
							}
						}
						done <- nil
					}()
					if candidate {
						_, err = native.BatchWrite(packets, 10)
					} else {
						_, err = controlNativeBatchWrite(native, packets, 10)
					}
					if err != nil {
						t.Fatal(err)
					}
					if err = <-done; err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}
