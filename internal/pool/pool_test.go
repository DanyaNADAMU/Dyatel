package pool

import (
	"context"
	"errors"
	"net"
	"testing"

	"nadamu/dyatel/internal/config"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, cidr, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return cidr
}

type fakeUsage struct {
	ports   map[int]bool
	v4      map[string]bool
	v6      map[string]bool
	portErr error
	ipErr   error
}

func (f *fakeUsage) UsedPorts(_ context.Context, _ string) (map[int]bool, error) {
	if f.portErr != nil {
		return nil, f.portErr
	}
	if f.ports == nil {
		return map[int]bool{}, nil
	}
	return f.ports, nil
}

func (f *fakeUsage) UsedTunnelIPs(_ context.Context, _ string) (map[string]bool, map[string]bool, error) {
	if f.ipErr != nil {
		return nil, nil, f.ipErr
	}
	v4 := f.v4
	if v4 == nil {
		v4 = map[string]bool{}
	}
	v6 := f.v6
	if v6 == nil {
		v6 = map[string]bool{}
	}
	return v4, v6, nil
}

func testConfig() *config.Config {
	return &config.Config{
		TunnelIPv4NetWG:  "10.66.66.0/24",
		TunnelIPv6NetWG:  "fd66:66::/64",
		TunnelIPv4NetAWG: "10.77.77.0/24",
		TunnelIPv6NetAWG: "fd77:77::/64",
		HostIPMin:        2,
		HostIPMax:        10,
		PortPoolWGMin:    51820,
		PortPoolWGMax:    51822,
		PortPoolAWGMin:   51900,
		PortPoolAWGMax:   51901,
		PortPoolXrayMin:  5200,
		PortPoolXrayMax:  5201,
	}
}

func TestHostPort(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig()

	t.Run("auto allocates first free port per transport", func(t *testing.T) {
		a := New(cfg, &fakeUsage{ports: map[int]bool{51820: true}})
		p, err := a.HostPort(ctx, "test", "wireguard", 0)
		if err != nil || p != 51821 {
			t.Fatalf("got (%d, %v), want (51821, nil)", p, err)
		}
		p, err = a.HostPort(ctx, "test", "amneziawg", 0)
		if err != nil || p != 51900 {
			t.Fatalf("awg got (%d, %v), want (51900, nil)", p, err)
		}
		p, err = a.HostPort(ctx, "test", "xray-vless", 0)
		if err != nil || p != 5200 {
			t.Fatalf("xray got (%d, %v), want (5200, nil)", p, err)
		}
	})

	t.Run("preferred port outside pool allowed when valid and free", func(t *testing.T) {
		a := New(cfg, &fakeUsage{})
		p, err := a.HostPort(ctx, "test", "wireguard", 7777)
		if err != nil || p != 7777 {
			t.Fatalf("got (%d, %v), want (7777, nil)", p, err)
		}
	})

	t.Run("rejects invalid, taken, unknown transport, and exhausted pool", func(t *testing.T) {
		a := New(cfg, &fakeUsage{ports: map[int]bool{51820: true, 51821: true, 51822: true, 7777: true}})
		if _, err := a.HostPort(ctx, "test", "bogus", 0); err == nil {
			t.Fatal("expected error for unknown transport")
		}
		if _, err := a.HostPort(ctx, "test", "wireguard", 80); err == nil {
			t.Fatal("expected error for privileged port")
		}
		if _, err := a.HostPort(ctx, "test", "wireguard", 70000); err == nil {
			t.Fatal("expected error for >65535 port")
		}
		if _, err := a.HostPort(ctx, "test", "wireguard", 7777); err == nil {
			t.Fatal("expected error for taken preferred port")
		}
		if _, err := a.HostPort(ctx, "test", "wireguard", 0); err == nil {
			t.Fatal("expected error when pool exhausted")
		}
	})

	t.Run("propagates store error", func(t *testing.T) {
		wantErr := errors.New("db down")
		a := New(cfg, &fakeUsage{portErr: wantErr})
		if _, err := a.HostPort(ctx, "test", "wireguard", 0); !errors.Is(err, wantErr) {
			t.Fatalf("got %v, want %v", err, wantErr)
		}
	})
}

func TestTunnelIPsWith(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig()

	t.Run("allocates first free pair per transport", func(t *testing.T) {
		a := New(cfg, &fakeUsage{
			v4: map[string]bool{"10.66.66.2": true},
			v6: map[string]bool{"fd66:66::2": true},
		})
		v4, v6, err := a.TunnelIPs(ctx, "test", "wireguard")
		if err != nil {
			t.Fatal(err)
		}
		if v4 != "10.66.66.3/32" || v6 != "fd66:66::3/128" {
			t.Fatalf("got (%s, %s), want (10.66.66.3/32, fd66:66::3/128)", v4, v6)
		}
	})

	t.Run("honours single pin and prefers symmetric twin host part", func(t *testing.T) {
		a := New(cfg, &fakeUsage{})
		v4, v6, err := a.TunnelIPsWith(ctx, "test", "amneziawg", "10.77.77.7", "")
		if err != nil {
			t.Fatal(err)
		}
		if v4 != "10.77.77.7/32" || v6 != "fd77:77::7/128" {
			t.Fatalf("got (%s, %s), want (10.77.77.7/32, fd77:77::7/128)", v4, v6)
		}

		v4, v6, err = a.TunnelIPsWith(ctx, "test", "amneziawg", "", "fd77:77::9")
		if err != nil {
			t.Fatal(err)
		}
		if v4 != "10.77.77.9/32" || v6 != "fd77:77::9/128" {
			t.Fatalf("got (%s, %s), want (10.77.77.9/32, fd77:77::9/128)", v4, v6)
		}
	})

	t.Run("rejects reserved, out-of-cidr, and already-taken pins", func(t *testing.T) {
		a := New(cfg, &fakeUsage{
			v4: map[string]bool{"10.66.66.5": true},
			v6: map[string]bool{"fd66:66::6": true},
		})
		cases := []struct {
			name, v4, v6 string
		}{
			{"gateway reserved v4", "10.66.66.1", ""},
			{"gateway reserved v6", "", "fd66:66::1"},
			{"wrong subnet v4", "10.77.77.2", ""},
			{"wrong subnet v6", "", "fd77:77::2"},
			{"taken v4", "10.66.66.5", ""},
			{"taken v6", "", "fd66:66::6"},
			{"unparseable", "not-an-ip", ""},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if _, _, err := a.TunnelIPsWith(ctx, "test", "wireguard", tc.v4, tc.v6); err == nil {
					t.Fatalf("expected error for %s", tc.name)
				}
			})
		}
	})

	t.Run("fails when address pool is exhausted", func(t *testing.T) {
		used4 := map[string]bool{}
		for i := cfg.HostIPMin; i <= cfg.HostIPMax; i++ {
			used4[hostIP(mustCIDR(t, cfg.TunnelIPv4NetWG), i).String()] = true
		}
		a := New(cfg, &fakeUsage{v4: used4})
		if _, _, err := a.TunnelIPs(ctx, "test", "wireguard"); err == nil {
			t.Fatal("expected exhaustion error")
		}
	})
}
