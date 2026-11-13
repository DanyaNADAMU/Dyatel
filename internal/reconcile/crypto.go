package reconcile

import "net"

// parseCIDR is the one crypto.go helper gen still needs after the wg
// keypair/PSK generation moved to the transport package (Tier-0 library).
func parseCIDR(s string) (net.IP, *net.IPNet, error) { return net.ParseCIDR(s) }
