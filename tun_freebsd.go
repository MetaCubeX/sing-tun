package tun

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/shell"

	"golang.org/x/sys/unix"
)

var _ Tun = (*NativeTun)(nil)

// PacketOffset is the size of the 4-byte address family header that the
// FreeBSD tun(4) driver prepends to each packet once TUNSIFHEAD is enabled.
const PacketOffset = 4

// directFib is the alternate routing table (FIB) that carries the original
// physical routes while TUN auto-route takes over the default FIB (0). mihomo's
// DIRECT outbound sockets bind to this FIB via SO_SETFIB so their traffic
// bypasses the tun interface instead of looping back into the proxy. This is
// FreeBSD's equivalent of Linux's policy-routing table / SO_BINDTODEVICE.
const directFib = 1

// TUNSIFHEAD = _IOW('t', 96, int) on FreeBSD (net/if_tun.h).
// _IOW(g,n,t) = IOC_IN | ((sizeof(t)&IOCPARM_MASK)<<16) | (g<<8) | n
// IOC_IN=0x80000000, IOCPARM_MASK=0x1fff, sizeof(int)=4, 't'=0x74, n=96(0x60).
const _TUNSIFHEAD = 0x80000000 | (4 << 16) | (0x74 << 8) | 96 // 0x80047460

type NativeTun struct {
	tunFd        int
	tunFile      *os.File
	options      Options
	inet4Address [4]byte
	inet6Address [16]byte
}

func New(options Options) (Tun, error) {
	var (
		tunFd   int
		tunFile *os.File
		err     error
	)
	if options.FileDescriptor == 0 {
		tunFile, err = openTun(options.Name)
		if err != nil {
			return nil, err
		}
		tunFd = int(tunFile.Fd())
	} else {
		tunFd = options.FileDescriptor
		tunFile = os.NewFile(uintptr(tunFd), "tun")
	}

	nativeTun := &NativeTun{
		tunFd:   tunFd,
		tunFile: tunFile,
		options: options,
	}
	if len(options.Inet4Address) > 0 {
		nativeTun.inet4Address = options.Inet4Address[0].Addr().As4()
	}
	if len(options.Inet6Address) > 0 {
		nativeTun.inet6Address = options.Inet6Address[0].Addr().As16()
	}

	err = nativeTun.configure()
	if err != nil {
		tunFile.Close()
		return nil, err
	}
	return nativeTun, nil
}

// openTun opens the tun device matching options.Name (e.g. "tun0"). If Name is
// empty or "tun", it uses the cloning device /dev/tun to auto-allocate one.
func openTun(name string) (*os.File, error) {
	devPath := "/dev/" + name
	if name == "" || name == "tun" {
		devPath = "/dev/tun"
	}
	file, err := os.OpenFile(devPath, os.O_RDWR, 0)
	if err != nil {
		return nil, E.Cause(err, "open ", devPath)
	}
	// Enable the 4-byte address-family header so we can carry both IPv4 and IPv6.
	headerMode := 1
	_, _, errno := unix.Syscall(
		syscall.SYS_IOCTL,
		file.Fd(),
		uintptr(_TUNSIFHEAD),
		uintptr(unsafe.Pointer(&headerMode)),
	)
	if errno != 0 {
		file.Close()
		return nil, os.NewSyscallError("TUNSIFHEAD", errno)
	}
	return file, nil
}

func (t *NativeTun) configure() error {
	name := t.options.Name
	// Configure MTU and addresses via ifconfig(8). Using the userspace tool
	// rather than hand-rolled ioctl structs avoids any risk of passing a
	// malformed request to the kernel.
	if t.options.MTU > 0 {
		err := shell.Exec("ifconfig", name, "mtu", strconv.Itoa(int(t.options.MTU))).Run()
		if err != nil {
			return E.Cause(err, "set mtu")
		}
	}
	err := t.setAddresses()
	if err != nil {
		return err
	}
	if t.options.AutoRoute {
		// Mirror the physical default route into the alternate FIB *before*
		// installing the tun routes, so DIRECT traffic has a working escape
		// path that does not loop back through the tun interface.
		err = t.setupDirectFib()
		if err != nil {
			return err
		}
		err = t.setRoutes()
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *NativeTun) Read(p []byte) (n int, err error) {
	return t.tunFile.Read(p)
}

func (t *NativeTun) Write(p []byte) (n int, err error) {
	return t.tunFile.Write(p)
}

func (t *NativeTun) Close() error {
	if t.options.AutoRoute {
		t.teardownDirectFib()
	}
	err := t.tunFile.Close()
	// On FreeBSD a tun(4) interface created by opening /dev/tunN persists after
	// its file descriptor is closed (unlike Linux, where it disappears). Without
	// an explicit destroy, every enable/disable cycle would leak another tunN
	// device and the next start would advance to a higher index. Tear down the
	// interface we created so devices do not accumulate. We only destroy
	// interfaces we opened ourselves; when the fd was supplied by the caller
	// (FileDescriptor != 0) its lifetime is the caller's responsibility.
	if t.options.FileDescriptor == 0 && t.options.Name != "" {
		if destroyErr := exec.Command("ifconfig", t.options.Name, "destroy").Run(); destroyErr != nil && err == nil {
			err = E.Cause(destroyErr, "destroy interface ", t.options.Name)
		}
	}
	return err
}

func (t *NativeTun) setAddresses() error {
	name := t.options.Name
	for _, address := range t.options.Inet4Address {
		// ifconfig tunN inet <addr>/<bits> <addr> alias
		// The repeated address sets the point-to-point peer, matching how
		// tun(4) interfaces are conventionally addressed.
		output, err := shell.Exec("ifconfig", name, "inet", address.String(), address.Addr().String(), "alias").Read()
		if err != nil {
			return E.Cause(err, "add inet4 address: ", address, ": ", strings.TrimSpace(output))
		}
	}
	for _, address := range t.options.Inet6Address {
		output, err := shell.Exec("ifconfig", name, "inet6", address.String(), "alias").Read()
		if err != nil {
			return E.Cause(err, "add inet6 address: ", address, ": ", strings.TrimSpace(output))
		}
	}
	return nil
}

func (t *NativeTun) setRoutes() error {
	routeRanges, err := t.options.BuildAutoRouteRanges(false)
	if err != nil {
		return err
	}
	for _, routeRange := range routeRanges {
		var family string
		if routeRange.Addr().Is4() {
			family = "-inet"
		} else {
			family = "-inet6"
		}
		// FreeBSD's route(8) rejects a literal default prefix (0.0.0.0/0 or
		// ::/0) with "route already in table" because it aliases the existing
		// `default` route. Split it into two half-ranges that together cover
		// the whole address space without colliding with the default route.
		var prefixes []string
		if routeRange.Bits() == 0 {
			if routeRange.Addr().Is4() {
				prefixes = []string{"0.0.0.0/1", "128.0.0.0/1"}
			} else {
				prefixes = []string{"::/1", "8000::/1"}
			}
		} else {
			prefixes = []string{routeRange.String()}
		}
		for _, prefix := range prefixes {
			// route -n add <family> <prefix> -interface <tunN>
			// Routing through the interface itself is appropriate for a
			// point-to-point tun device serving as the system gateway.
			//
			// FreeBSD's route(8) fails with "route already in table" if the
			// prefix is still present from a previous tun that was not fully
			// torn down (e.g. when the interface monitor re-runs configure, or
			// after a crash). Delete any stale entry first, ignoring errors when
			// nothing is there, so reconfiguration is idempotent and does not
			// leave the TUN half-configured.
			_ = shell.Exec("route", "-n", "delete", family, prefix).Run()
			// Use Read() to capture route(8)'s stderr so failures surface the
			// actual reason (e.g. "network is unreachable") instead of a bare
			// "exit status 1".
			output, err := shell.Exec("route", "-n", "add", family, prefix, "-interface", t.options.Name).Read()
			if err != nil {
				return E.Cause(err, "add route: ", prefix, ": ", strings.TrimSpace(output))
			}
		}
	}
	return nil
}

// setupDirectFib ensures the system has at least two FIBs and mirrors the
// current physical IPv4 default route into the alternate FIB (directFib). This
// FIB is later selected by mihomo's DIRECT sockets via SO_SETFIB so their
// traffic egresses the physical interface instead of the tun device.
func (t *NativeTun) setupDirectFib() error {
	if err := ensureFibs(directFib + 1); err != nil {
		return err
	}
	gateway, device, err := defaultInet4Route()
	if err != nil {
		// No usable physical default route: nothing to mirror. Leave the FIB
		// empty rather than failing TUN startup.
		return nil
	}
	fib := strconv.Itoa(directFib)
	// Clear any stale entries from a previous run, ignoring errors.
	_ = exec.Command("route", "-n", "delete", "-fib", fib, "default").Run()
	_ = exec.Command("route", "-n", "delete", "-fib", fib, "-host", gateway).Run()
	// A host route to the gateway via the physical interface makes the gateway
	// reachable inside the otherwise-empty FIB; the default route then resolves
	// through it. This avoids needing the interface's subnet mask.
	if err = shell.Exec("route", "-n", "add", "-fib", fib, "-host", gateway, "-interface", device).Run(); err != nil {
		return E.Cause(err, "mirror gateway route into fib ", fib)
	}
	if err = shell.Exec("route", "-n", "add", "-fib", fib, "default", gateway).Run(); err != nil {
		return E.Cause(err, "mirror default route into fib ", fib)
	}
	return nil
}

// teardownDirectFib removes the mirrored routes from the alternate FIB. Errors
// are ignored because the routes may already be gone.
func (t *NativeTun) teardownDirectFib() {
	fib := strconv.Itoa(directFib)
	_ = exec.Command("route", "-n", "delete", "-fib", fib, "default").Run()
	if gateway, _, err := defaultInet4Route(); err == nil {
		_ = exec.Command("route", "-n", "delete", "-fib", fib, "-host", gateway).Run()
	}
}

// ensureFibs makes sure net.fibs is at least want. On FreeBSD 15 net.fibs is
// writable at runtime (it can only grow), so a fresh sysctl write is enough and
// no reboot/loader.conf change is required.
func ensureFibs(want int) error {
	out, err := exec.Command("sysctl", "-n", "net.fibs").Output()
	if err != nil {
		return E.Cause(err, "read net.fibs")
	}
	current, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return E.Cause(err, "parse net.fibs")
	}
	if current >= want {
		return nil
	}
	if err = shell.Exec("sysctl", "net.fibs="+strconv.Itoa(want)).Run(); err != nil {
		return E.Cause(err, "raise net.fibs to ", want)
	}
	return nil
}

// defaultInet4Route returns the gateway and interface of the current IPv4
// default route in the default FIB, parsed from `netstat -rn -f inet`.
func defaultInet4Route() (gateway string, device string, err error) {
	out, err := exec.Command("netstat", "-rn", "-f", "inet").Output()
	if err != nil {
		return "", "", E.Cause(err, "read routing table")
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "default" {
			gateway = fields[1]
			device = fields[len(fields)-1]
			// Sanity check the gateway is an IP, not an interface link.
			if net.ParseIP(gateway) != nil {
				return gateway, device, nil
			}
		}
	}
	return "", "", E.New("no inet default route found")
}

