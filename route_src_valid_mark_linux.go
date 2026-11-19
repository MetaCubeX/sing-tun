//go:build linux

package tun

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

var errSrcValidMarkChanged = errors.New("src_valid_mark was changed while in use")

// The gate serializes changes to the value. Shared locks on the state file
// last for as long as an instance needs the setting, including across processes.
type srcValidMarkOwner struct {
	leases   map[string]*srcValidMarkLease
	stateDir string
}

type srcValidMarkLease struct {
	gate   string
	path   string
	sysctl *os.File
	state  *os.File
}

func lockSrcValidMarkGate(name string) (*os.File, error) {
	gate, err := os.OpenFile(name+".gate", os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	for {
		err = unix.Flock(int(gate.Fd()), unix.LOCK_EX)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		gate.Close()
		return nil, err
	}
	return gate, nil
}

func (o *srcValidMarkOwner) acquire(path string) error {
	if lease := o.leases[path]; lease != nil {
		previous, err := lease.sysctl.Stat()
		if err != nil && !isMissingSrcValidMark(err) {
			return err
		}
		current, err := os.Stat(path)
		if err != nil {
			return err
		}
		if previous != nil && os.SameFile(previous, current) {
			value, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.TrimSpace(string(value)) != "1" {
				return fmt.Errorf("%s: %w", path, errSrcValidMarkChanged)
			}
			return nil
		}
		if err = o.release(path); err != nil {
			return err
		}
	}
	sysctl, err := os.Open(path)
	if err != nil {
		return err
	}
	kept := false
	defer func() {
		if !kept {
			_ = sysctl.Close()
		}
	}()
	info, err := sysctl.Stat()
	if err != nil {
		return err
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return err
	}
	stat := info.Sys().(*syscall.Stat_t)
	dir := o.stateDir
	if dir == "" {
		dir = fmt.Sprintf("/run/sing-tun-%d", os.Geteuid())
	}
	if err = os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !dirInfo.IsDir() || dirInfo.Mode().Perm() != 0700 || dirInfo.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("invalid src_valid_mark ownership directory %s", dir)
	}
	key := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%d:%s", ns, stat.Dev, stat.Ino, path)))
	name := filepath.Join(dir, fmt.Sprintf("%x", key))
	gatePath := filepath.Join(dir, "sysctl")
	gate, err := lockSrcValidMarkGate(gatePath)
	if err != nil {
		return err
	}
	defer gate.Close()
	state, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if !kept {
			_ = state.Close()
		}
	}()
	leader := unix.Flock(int(state.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if leader != nil && leader != unix.EWOULDBLOCK {
		return leader
	}
	var value [8]byte
	n, err := sysctl.Read(value[:])
	if err != nil {
		return err
	}
	switch strings.TrimSpace(string(value[:n])) {
	case "0":
		if leader != nil {
			return fmt.Errorf("%s: %w", path, errSrcValidMarkChanged)
		}
		// Record ownership before writing so a replacement can recover it
		// if this process exits between the write and unlocking the gate.
		if err = state.Truncate(1); err != nil {
			return err
		}
		if err = writeSrcValidMark(path, info, "1"); err != nil {
			return errors.Join(err, state.Truncate(0))
		}
	case "1":
		// An empty state file means the value belongs to the administrator.
	default:
		return fmt.Errorf("invalid src_valid_mark in %s: %q", path, value[:n])
	}
	if err = unix.Flock(int(state.Fd()), unix.LOCK_SH); err != nil {
		return err
	}
	if o.leases == nil {
		o.leases = make(map[string]*srcValidMarkLease)
	}
	o.leases[path] = &srcValidMarkLease{gate: gatePath, path: path, sysctl: sysctl, state: state}
	kept = true
	return nil
}

func (o *srcValidMarkOwner) release(path string) error {
	lease := o.leases[path]
	if lease == nil {
		return nil
	}
	gate, err := lockSrcValidMarkGate(lease.gate)
	if err != nil {
		return err
	}
	defer gate.Close()
	if err = unix.Flock(int(lease.state.Fd()), unix.LOCK_UN); err != nil {
		return err
	}
	err = unix.Flock(int(lease.state.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		err = lease.restore()
		if err != nil {
			// Keep the lease so a subsequent Close can retry restoration.
			return errors.Join(err, unix.Flock(int(lease.state.Fd()), unix.LOCK_SH))
		}
		err = os.Remove(lease.state.Name())
	} else if err != unix.EWOULDBLOCK {
		return errors.Join(err, unix.Flock(int(lease.state.Fd()), unix.LOCK_SH))
	} else {
		err = nil
	}
	delete(o.leases, path)
	return errors.Join(err, lease.sysctl.Close(), lease.state.Close())
}

func (l *srcValidMarkLease) restore() error {
	state, err := l.state.Stat()
	if err != nil || state.Size() == 0 {
		return err
	}
	old, err := l.sysctl.Stat()
	if isMissingSrcValidMark(err) {
		return l.state.Truncate(0)
	}
	if err != nil {
		return err
	}
	current, err := os.Stat(l.path)
	if isMissingSrcValidMark(err) || err == nil && !os.SameFile(old, current) {
		return l.state.Truncate(0)
	}
	if err != nil {
		return err
	}
	value, err := os.ReadFile(l.path)
	if isMissingSrcValidMark(err) {
		return l.state.Truncate(0)
	}
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(value)) == "1" {
		if err = writeSrcValidMark(l.path, old, "0"); err != nil && !isMissingSrcValidMark(err) {
			return err
		}
	}
	return l.state.Truncate(0)
}

func isMissingSrcValidMark(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENODEV)
}

func writeSrcValidMark(path string, expected os.FileInfo, value string) error {
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	current, err := file.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(current, expected) {
		return fmt.Errorf("source validation interface changed: %s", path)
	}
	_, err = file.WriteString(value)
	return err
}

func (o *srcValidMarkOwner) close() error {
	return o.releaseExcept(nil)
}

func (o *srcValidMarkOwner) releaseExcept(needed map[string]struct{}) error {
	var err error
	for path := range o.leases {
		if _, keep := needed[path]; !keep {
			err = errors.Join(err, o.release(path))
		}
	}
	return err
}

// Prefer the interfaces that perform source validation. Use the namespace
// setting only when an affected interface is not writable.
func (o *srcValidMarkOwner) requireForRPF(conf string, calicoIngress map[string]struct{}) (map[string]struct{}, error) {
	for path := range o.leases {
		if _, err := os.Stat(path); isMissingSrcValidMark(err) {
			if err = o.release(path); err != nil {
				return nil, err
			}
		}
	}
	all := filepath.Join(conf, "all")
	allFilter, err := readRPFilter(filepath.Join(all, "rp_filter"))
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(conf)
	if err != nil {
		return nil, err
	}
	needed := make(map[string]struct{})
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "all" || entry.Name() == "default" {
			continue
		}
		iface := filepath.Join(conf, entry.Name())
		filter, err := readRPFilter(filepath.Join(iface, "rp_filter"))
		if isMissingSrcValidMark(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if allFilter > filter {
			filter = allFilter
		}
		_, calico := calicoIngress[entry.Name()]
		if filter == 1 || filter == 2 && calico {
			needed[filepath.Join(iface, "src_valid_mark")] = struct{}{}
		}
	}
	if len(needed) == 0 {
		return needed, nil
	}
	allMark := filepath.Join(all, "src_valid_mark")
	value, err := os.ReadFile(allMark)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(value)) == "1" {
		return map[string]struct{}{allMark: {}}, o.acquire(allMark)
	}
	var interfaceErr error
	for path := range needed {
		if err := o.acquire(path); err != nil && !isMissingSrcValidMark(err) {
			if errors.Is(err, errSrcValidMarkChanged) {
				return nil, err
			}
			interfaceErr = errors.Join(interfaceErr, err)
		}
	}
	if interfaceErr != nil {
		if err := o.acquire(allMark); err != nil {
			return nil, errors.Join(interfaceErr, err)
		}
		return map[string]struct{}{allMark: {}}, nil
	}
	return needed, nil
}

func (o *srcValidMarkOwner) syncForRPF(conf string, calicoIngress map[string]struct{}) error {
	needed, err := o.requireForRPF(conf, calicoIngress)
	if err != nil {
		return err
	}
	return o.releaseExcept(needed)
}
