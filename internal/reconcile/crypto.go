package reconcile

import (
	"crypto/rand"
	"encoding/base64"
	"net"
)

func randRead(b []byte) (int, error) { return rand.Read(b) }

func base64Encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func parseCIDR(s string) (net.IP, *net.IPNet, error) { return net.ParseCIDR(s) }