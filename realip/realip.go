package realip

import (
	"net/http"
	"net"
	"strings"
)

func RealIP(r *http.Request) net.IP {
	var remoteIP net.IP
	xRealIP := r.Header.Get("X-Real-Ip")
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	cfIp := r.Header.Get("CF-Connecting-IP")
	remoteIP, correct := checkIp(cfIp)
	if correct {
		return remoteIP
	}
	remoteIP, correct = checkIp(xRealIP)
	if correct {
		return remoteIP
	}
	for _, address := range strings.Split(xForwardedFor, ",") {
		remoteIP, correct = checkIp(address)
		if correct {
			return remoteIP
		}
	}

	return getRemoteAddr(r.RemoteAddr)
}

func checkIp(header string) (net.IP, bool) {
	if header == "" {
		return nil, false
	}
	ip := net.ParseIP(header)
	if ip == nil {
		return nil, false
	}
	return ip, true
}

func getRemoteAddr(remoteAddr string) net.IP {
	if strings.ContainsRune(remoteAddr, ':') {
		remoteAddr, _, _ = net.SplitHostPort(remoteAddr)
	}
	remoteIP, _ := checkIp(remoteAddr)
	return remoteIP
}