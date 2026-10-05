//go:build darwin && !ios

package systemconfiguration

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/ebitengine/purego"
)

func TestDNSDictionary(t *testing.T) {
	functions, err := loadFrameworkAPI()
	if err != nil {
		t.Fatal(err)
	}
	cf, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		t.Fatal(err)
	}
	defer purego.Dlclose(cf)
	var dictionaryGet func(uintptr, uintptr) uintptr
	var arrayCount func(uintptr) int
	var arrayGet func(uintptr, int) uintptr
	var stringGet func(uintptr, []byte, int, uint32) bool
	var numberGet func(uintptr, int, *int32) bool
	purego.RegisterLibFunc(&dictionaryGet, cf, "CFDictionaryGetValue")
	purego.RegisterLibFunc(&arrayCount, cf, "CFArrayGetCount")
	purego.RegisterLibFunc(&arrayGet, cf, "CFArrayGetValueAtIndex")
	purego.RegisterLibFunc(&stringGet, cf, "CFStringGetCString")
	purego.RegisterLibFunc(&numberGet, cf, "CFNumberGetValue")
	for _, servers := range [][]netip.Addr{
		{netip.MustParseAddr("192.0.2.2")},
		{netip.MustParseAddr("2001:db8::2")},
		{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::2")},
	} {
		dict := functions.createDNSDictionary(servers)
		get := func(key string) uintptr {
			ref := functions.createString(key)
			defer functions.cfRelease(ref)
			value := dictionaryGet(dict, ref)
			if value == 0 {
				t.Fatalf("missing key %s", key)
			}
			return value
		}
		readStrings := func(array uintptr) []string {
			values := make([]string, arrayCount(array))
			for i := range values {
				buffer := make([]byte, 128)
				if !stringGet(arrayGet(array, i), buffer, len(buffer), cfStringEncodingUTF8) {
					t.Fatal("CFStringGetCString failed")
				}
				values[i] = strings.TrimRight(string(buffer), "\x00")
			}
			return values
		}
		want := make([]string, len(servers))
		for i, server := range servers {
			want[i] = server.String()
		}
		if got := readStrings(get("ServerAddresses")); !reflect.DeepEqual(got, want) {
			t.Fatalf("servers = %v, want %v", got, want)
		}
		if got := readStrings(get("SupplementalMatchDomains")); !reflect.DeepEqual(got, []string{""}) {
			t.Fatalf("match domains = %v", got)
		}
		orders := get("SupplementalMatchOrders")
		var order int32
		if arrayCount(orders) != 1 || !numberGet(arrayGet(orders, 0), cfNumberSInt32Type, &order) || order != 1 {
			t.Fatalf("unexpected match order %d", order)
		}
		functions.cfRelease(dict)
	}
}

func TestDNSRegistrationLifecycle(t *testing.T) {
	loadedFunctions, err := loadFrameworkAPI()
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"create error", "add error", "success"} {
		t.Run(stage, func(t *testing.T) {
			functions := *loadedFunctions
			// Use real CoreFoundation values, but never publish functions resolver while
			// testing. Only the dynamic store boundary is replaced.
			session := functions.createString("test session")
			releases, adds := 0, 0
			functions.cfRelease = func(ref uintptr) {
				if ref == session {
					releases++
					return
				}
				loadedFunctions.cfRelease(ref)
			}
			defer loadedFunctions.cfRelease(session)
			functions.scDynamicStoreCreate = func(_, _, _, _ uintptr) uintptr {
				if stage == "create error" {
					return 0
				}
				return session
			}
			functions.scDynamicStoreAddTemporaryValue = func(store, key, value uintptr) bool {
				adds++
				if store != session || key == 0 || value == 0 {
					t.Fatal("invalid dynamic store arguments")
				}
				return stage == "success"
			}
			functions.scError = func() int32 {
				return 1003
			}
			dns, err := functions.registerDNS("utun123", "State:/Network/Service/test/DNS", []netip.Addr{netip.MustParseAddr("192.0.2.2")})
			switch stage {
			case "create error":
				if dns != nil || err == nil || adds != 0 || releases != 0 {
					t.Fatalf("unexpected create failure: dns=%v err=%v adds=%d releases=%d", dns, err, adds, releases)
				}
			case "add error":
				if dns != nil || err == nil || adds != 1 || releases != 1 {
					t.Fatalf("unexpected add failure: dns=%v err=%v adds=%d releases=%d", dns, err, adds, releases)
				}
			case "success":
				if err != nil || releases != 0 || adds != 1 {
					t.Fatalf("unexpected setup: err=%v adds=%d releases=%d", err, adds, releases)
				}
				dns.Close()
				dns.Close()
				if releases != 1 {
					t.Fatalf("session released %d times", releases)
				}
			}
		})
	}
}
