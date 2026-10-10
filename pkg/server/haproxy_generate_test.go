package server

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
)

func TestGenerateCompleteHaProxyConfRequestRetry(t *testing.T) {
	confTemplates, err := newConfigTemplates()
	if err != nil {
		t.Fatal(err)
	}
	groups := []cdntypes.OriginGroup{testGroup(1, "default", true, nil, 0)}
	origins := []cdntypes.Origin{
		testOrigin(testUUID(1), "198.51.100.10", 80, false),
		testOrigin(testUUID(1), "198.51.100.11", 443, true),
	}

	serviceIPAddrs := []netip.Addr{
		netip.MustParseAddr("198.51.100.10"),
		netip.MustParseAddr("2001:db8:1337::100"),
	}
	haproxyConf, err := generateCompleteHaProxyConf(confTemplates.haproxy, testUUID(1), testUUID(2), 1, serviceIPAddrs, groups, origins)
	if err != nil {
		t.Fatal(err)
	}

	expectedStrings := []string{
		"http-request disable-l7-retry unless METH_GET || METH_OPTIONS",
		"retry-on conn-failure empty-response",
		"retries 1",
	}

	for _, expectedString := range expectedStrings {
		if !strings.Contains(haproxyConf, expectedString) {
			t.Errorf("haproxy config missing expected string '%s' in :\n%s", expectedString, haproxyConf)
		}
	}
}

func TestGenerateCompleteHaProxyConfNoAcceptProxy(t *testing.T) {
	confTemplates, err := newConfigTemplates()
	if err != nil {
		t.Fatal(err)
	}
	groups := []cdntypes.OriginGroup{testGroup(1, "default", true, nil, 0)}
	origins := []cdntypes.Origin{
		testOrigin(testUUID(1), "198.51.100.10", 80, false),
		testOrigin(testUUID(1), "198.51.100.11", 443, true),
	}

	serviceIPAddrs := []netip.Addr{
		netip.MustParseAddr("198.51.100.10"),
		netip.MustParseAddr("2001:db8:1337::100"),
	}
	haproxyConf, err := generateCompleteHaProxyConf(confTemplates.haproxy, testUUID(1), testUUID(2), 1, serviceIPAddrs, groups, origins)
	if err != nil {
		t.Fatal(err)
	}

	unexpectedStrings := []string{
		"accept-proxy",
	}

	for _, unexpectedString := range unexpectedStrings {
		if strings.Contains(haproxyConf, unexpectedString) {
			t.Errorf("haproxy config has unexpected string '%s' in :\n%s", unexpectedString, haproxyConf)
		}
	}
}
