package realip

import (
	"testing"
	"net/http"
	"net"
)

func TestRealIpUsingCloudflare(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com", nil)
	r.Header.Add("CF-Connecting-IP","192.168.11.111")
	r.RemoteAddr ="192.168.6.66"
	ip := RealIP(r)
	if !ip.Equal(net.IP{192,168,11,111}) {
		t.Fail()
	}
}
func TestRealIpUsingInvalidCloudflare(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com", nil)
	r.Header.Add("CF-Connecting-IP","a192.168.11.111")
	r.RemoteAddr ="192.168.6.66"
	ip := RealIP(r)
	if !ip.Equal(net.IP{192,168,6,66}) {
		t.Fail()
	}
}

func TestRealIpUsingXForwardedForAndCloudflare(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com", nil)
	r.Header.Add("CF-Connecting-IP","192.168.11.111")
	r.Header.Add("X-Forwarded-For","192.168.1.1,192.168.1.2,192.168.1.3,192.168.1.4")
	r.RemoteAddr ="192.168.6.66"
	ip := RealIP(r)
	if !ip.Equal(net.IP{192,168,11,111}) {
		t.Fail()
	}
}

func TestRealIpUsingXRealIpAndXForwardedFor(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com", nil)
	r.Header.Add("X-Real-Ip","192.168.11.112")
	r.Header.Add("X-Forwarded-For","192.168.1.1,192.168.1.2,192.168.1.3,192.168.1.4")
	r.RemoteAddr ="192.168.6.66"
	ip := RealIP(r)
	if !ip.Equal(net.IP{192,168,11,112}) {
		t.Fail()
	}
}
func TestRealIpUsingXRealIpAndXForwardedForAndCloudflare(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com", nil)
	r.Header.Add("CF-Connecting-IP","8.8.8.8")
	r.Header.Add("X-Real-Ip","192.168.11.112")
	r.Header.Add("X-Forwarded-For","192.168.1.1,192.168.1.2,192.168.1.3,192.168.1.4")
	r.RemoteAddr ="192.168.6.66"
	ip := RealIP(r)
	if !ip.Equal(net.IP{8,8,8,8}) {
		t.Fail()
	}
}

func TestRealIpUsingXRealIpAndXForwardedForAndCloudflareIPV6(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com", nil)
	r.Header.Add("CF-Connecting-IP","2380:db3b:52a7:85f4:6b54:9c43:1081:38c2")
	r.Header.Add("X-Real-Ip","192.168.11.112")
	r.Header.Add("X-Forwarded-For","192.168.1.1,192.168.1.2,192.168.1.3,192.168.1.4")
	r.RemoteAddr ="192.168.6.66"
	ip := RealIP(r)
	if !ip.Equal(net.IP{0x23,0x80,0xdb,0x3b,0x52,0xa7,0x85,0xf4,0x6b,0x54,0x9c,0x43,0x10,0x81,0x38,0xc2}) {
		t.Fail()
	}
}

func TestRealIpUsingXForwardedFor(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com", nil)
	r.Header.Add("X-Forwarded-For","192.168.1.1,192.168.1.2,192.168.1.3,192.168.1.4")
	r.RemoteAddr ="192.168.6.66"
	ip := RealIP(r)
	if !ip.Equal(net.IP{192,168,1,1}) {
		t.Fail()
	}
}
func TestRealIpUsingRemoteAddr(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com", nil)
	r.RemoteAddr ="192.168.6.66"
	ip := RealIP(r)
	if !ip.Equal(net.IP{192,168,6,66}) {
		t.Fail()
	}
}
func TestRealIpUsingRemoteAddrWithPort(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com", nil)
	r.RemoteAddr ="192.168.6.66:15561"
	ip := RealIP(r)
	if !ip.Equal(net.IP{192,168,6,66}) {
		t.Fail()
	}
}

