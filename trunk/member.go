package trunk

import (
	"errors"
	"strings"
)

// A member's wire is the Hikkari stream channel's: TLS by Chromium's network
// stack to the exit's relay (its real certificate), HTTP/2 CONNECT to Host
// with Naive padding (package chromium dials it). On the exit the Hikkari
// relay answers it behind its own auth (hikkari-control edge/trunk_exit.go)
// and hands the tunnel to Exit.ServeMember; anyone else gets the relay's site.

// Host is the CONNECT authority of a trunk member.
const Host = "trunk.hikkari.arpa:443"

// User is the Proxy-Authorization user of a trunk member; the password is
// the trunk key.
const User = "trunk"

// ParseKey checks a trunk key: printable, no separators, at least 24 bytes.
func ParseKey(key string) error {
	if len(key) < 24 || strings.ContainsAny(key, ":,\r\n\t ") {
		return errors.New("trunk: a key is 24+ characters without ':', ',' or spaces")
	}
	return nil
}
