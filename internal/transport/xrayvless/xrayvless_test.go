package xrayvless

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"nadamu/dyatel/internal/config"
	"nadamu/dyatel/internal/store"
)

func testCfg() *config.Config {
	return &config.Config{PublicEndpointHost: "dyatel.test.nada.mu"}
}

func testHost(params string) store.Host {
	return store.Host{
		Name:       "acme",
		Transport:  "xray-vless",
		ListenPort: 5201,
		Params:     []byte(params),
	}
}

const validParams = `{"sni":"acme.example.com","uuid":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","proxer_endpoint":"198.51.100.7"}`

func TestParseXrayParams(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{"valid", validParams, ""},
		{"missing sni", `{"uuid":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","proxer_endpoint":"198.51.100.7"}`, "sni is required"},
		{"missing uuid", `{"sni":"a.example.com","proxer_endpoint":"198.51.100.7"}`, "uuid"},
		{"missing proxer_endpoint", `{"sni":"a.example.com","uuid":"6ba7b810-9dad-11d1-80b4-00c04fd430c8"}`, "proxer_endpoint is required"},
		{"empty params", `{}`, "required"},
		{"reality key", `{"sni":"a","uuid":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","proxer_endpoint":"x","reality":{}}`, "Reality is not supported"},
		{"realitySettings nested", `{"sni":"a","uuid":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","proxer_endpoint":"x","streamSettings":{"realitySettings":{"fingerprint":"chrome"}}}`, "Reality is not supported"},
		{"REALITY case-insensitive", `{"sni":"a","uuid":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","proxer_endpoint":"x","REALITY":{"show":true}}`, "Reality is not supported"},
		{"public_key style", `{"sni":"a","uuid":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","proxer_endpoint":"x","public_key":"abc"}`, "Reality is not supported"},
		{"private_key style", `{"sni":"a","uuid":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","proxer_endpoint":"x","private_key":"abc","short_id":"01"}`, "Reality is not supported"},
		{"whitespace in sni", `{"sni":"a b.example.com","uuid":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","proxer_endpoint":"x"}`, "sni must not contain whitespace"},
		{"whitespace in proxer_endpoint", `{"sni":"a.example.com","uuid":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","proxer_endpoint":"198.51.100.7:443 "}`, "proxer_endpoint must not contain whitespace"},
		{"bad uuid", `{"sni":"a","uuid":"not-a-uuid","proxer_endpoint":"x"}`, "not a valid uuid"},
		{"key_file without cert_file", `{"sni":"a","uuid":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","proxer_endpoint":"x","key_file":"/etc/xray/key.pem"}`, "key_file requires cert_file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParseXrayParams([]byte(tc.raw))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ParseXrayParams(%s): unexpected error: %v", tc.raw, err)
				}
				if p.SNI != "acme.example.com" || p.UUID != "6ba7b810-9dad-11d1-80b4-00c04fd430c8" || p.ProxerEndpoint != "198.51.100.7" {
					t.Fatalf("ParseXrayParams(%s): wrong fields decoded: %+v", tc.raw, p)
				}
				return
			}
			if err == nil {
				t.Fatalf("ParseXrayParams(%s): expected error containing %q, got nil", tc.raw, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ParseXrayParams(%s): error %q does not contain %q", tc.raw, err, tc.wantErr)
			}
		})
	}
}

// Reality must also fail late: the marshaled configs must never carry a
// reality key, even if params somehow slipped past validation.
func TestRenderServerConfigShape(t *testing.T) {
	x := New(testCfg())
	out, err := x.RenderServerConfig(testHost(validParams))
	if err != nil {
		t.Fatalf("RenderServerConfig: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatalf("output is not json: %v", err)
	}
	if low := strings.ToLower(string(out)); strings.Contains(low, "reality") {
		t.Fatalf("rendered server config mentions reality:\n%s", out)
	}
	if !strings.Contains(string(out), `"protocol": "vless"`) {
		t.Fatalf("missing vless inbound:\n%s", out)
	}
	if !strings.Contains(string(out), `"port": 5201`) {
		t.Fatalf("missing listen port 5201:\n%s", out)
	}
	if !strings.Contains(string(out), `"security": "tls"`) {
		t.Fatalf("missing tls stream security:\n%s", out)
	}
	if !strings.Contains(string(out), `"serverName": "acme.example.com"`) {
		t.Fatalf("missing sni in tlsSettings:\n%s", out)
	}
	// Exactly one client, carrying the pair uuid.
	if got := strings.Count(string(out), `"id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8"`); got != 1 {
		t.Fatalf("expected exactly one client id occurrence, got %d:\n%s", got, out)
	}
	// Freedom outbound first (routing default); placeholders embedded in
	// the tls certificates array, plus the // operator note.
	if !strings.Contains(string(out), `"protocol": "freedom"`) {
		t.Fatalf("missing freedom outbound:\n%s", out)
	}
	if !strings.Contains(string(out), CertPlaceholder) || !strings.Contains(string(out), KeyPlaceholder) {
		t.Fatalf("missing cert placeholders:\n%s", out)
	}
	if strings.Contains(string(out), `certificateFile`) {
		t.Fatalf("placeholders must not be mixed with cert files:\n%s", out)
	}
	if !strings.Contains(string(out), `"//"`) {
		t.Fatalf("missing // operator note:\n%s", out)
	}
}

func TestRenderServerConfigMultiAggregates(t *testing.T) {
	x := New(testCfg())
	a := testHost(validParams)
	b := testHost(validParams)
	b.Name = "second"
	b.ListenPort = 5202
	out, err := x.RenderServerConfigMulti([]store.Host{a, b})
	if err != nil {
		t.Fatalf("RenderServerConfigMulti: %v", err)
	}
	s := string(out)
	if got := strings.Count(s, `"protocol": "vless"`); got != 2 {
		t.Fatalf("expected two vless inbounds, got %d:\n%s", got, out)
	}
	if !strings.Contains(s, `"tag": "vless-in-acme"`) || !strings.Contains(s, `"tag": "vless-in-second"`) {
		t.Fatalf("missing per-host inbound tags:\n%s", out)
	}
	if got := strings.Count(s, `"protocol": "freedom"`); got != 1 {
		t.Fatalf("expected exactly one freedom outbound, got %d:\n%s", got, out)
	}
	if got := strings.Count(s, `"port": 5201`); got != 1 || strings.Count(s, `"port": 5202`) != 1 {
		t.Fatalf("missing distinct pool ports:\n%s", out)
	}
	// One bad host fails the whole aggregate: partial configs would leave
	// the node's xray serving a stale host set.
	c := testHost(validParams)
	c.Name = "bad"
	c.Params = []byte(`{"sni":"x"}`)
	if _, err := x.RenderServerConfigMulti([]store.Host{a, c}); err == nil {
		t.Fatal("RenderServerConfigMulti must fail on invalid host params")
	}
}

func TestRenderServerConfigCertFiles(t *testing.T) {
	p := `{"sni":"a.example.com","uuid":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","proxer_endpoint":"198.51.100.7","cert_file":"/etc/xray/cert.pem","key_file":"/etc/xray/key.pem"}`
	out, err := New(testCfg()).RenderServerConfig(testHost(p))
	if err != nil {
		t.Fatalf("RenderServerConfig: %v", err)
	}
	for _, want := range []string{`"certificateFile": "/etc/xray/cert.pem"`, `"keyFile": "/etc/xray/key.pem"`} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("missing %s:\n%s", want, out)
		}
	}
	if strings.Contains(string(out), CertPlaceholder) {
		t.Fatalf("placeholders must not appear when cert files are set:\n%s", out)
	}
}

func TestRenderClientConfig(t *testing.T) {
	x := New(testCfg())
	h := testHost(validParams)
	fwds := []store.Forward{
		{PublicPort: 18001, TargetPort: 22, Proto: "tcp", Label: "ssh"},
		{PublicPort: 18002, TargetPort: 53, Proto: "udp", Label: "dns"},
	}
	out, err := x.RenderClientConfig(h, fwds)
	if err != nil {
		t.Fatalf("RenderClientConfig: %v", err)
	}
	if low := strings.ToLower(string(out)); strings.Contains(low, "reality") {
		t.Fatalf("rendered client config mentions reality:\n%s", out)
	}
	var cfg clientConfig
	if err := json.Unmarshal(bytes.TrimSuffix(out, []byte("\n")), &cfg); err != nil {
		t.Fatalf("output does not round-trip: %v", err)
	}
	if len(cfg.Inbounds) != 2 {
		t.Fatalf("expected 2 dokodemo inbounds, got %d", len(cfg.Inbounds))
	}
	for i, f := range fwds {
		in := cfg.Inbounds[i]
		if in.Listen != "127.0.0.1" || in.Port != f.PublicPort || in.Protocol != "dokodemo-door" {
			t.Fatalf("forward %d: wrong inbound %+v", i, in)
		}
		if in.Settings.Address != "198.51.100.7" {
			t.Fatalf("forward %d: dokodemo address %q, want proxer host", i, in.Settings.Address)
		}
		if in.Settings.Port != f.TargetPort {
			t.Fatalf("forward %d: dokodemo port %d, want %d", i, in.Settings.Port, f.TargetPort)
		}
		if in.Settings.Network != f.Proto {
			t.Fatalf("forward %d: network %q, want %q", i, in.Settings.Network, f.Proto)
		}
		if in.Settings.FollowRedirect {
			t.Fatalf("forward %d: followRedirect must be false", i)
		}
	}
	// Every inbound is routed into the single vless outbound.
	if len(cfg.Routing.Rules) != 2 {
		t.Fatalf("expected 2 route rules, got %d", len(cfg.Routing.Rules))
	}
	for i, r := range cfg.Routing.Rules {
		wantTag := cfg.Inbounds[i].Tag
		if r.Type != "field" || len(r.InboundTag) != 1 || r.InboundTag[0] != wantTag || r.OutboundTag != "vless" {
			t.Fatalf("rule %d: wrong routing rule %+v", i, r)
		}
	}
	if len(cfg.Outbounds) == 0 || cfg.Outbounds[0].Protocol != "vless" || cfg.Outbounds[0].Tag != "vless" {
		t.Fatalf("first outbound must be the vless one: %+v", cfg.Outbounds)
	}
	// Settings is a typed-any in the renderer; round-trip it to check the
	// vnext shape with real types.
	var vset vlessOutboundSettings
	rawSet, err := json.Marshal(cfg.Outbounds[0].Settings)
	if err != nil {
		t.Fatalf("settings marshal: %v", err)
	}
	if err := json.Unmarshal(rawSet, &vset); err != nil {
		t.Fatalf("settings unmarshal: %v", err)
	}
	vnext := vset.Vnext
	if len(vnext) != 1 || vnext[0].Address != "dyatel.test.nada.mu" || vnext[0].Port != 5201 {
		t.Fatalf("vnext must dial the public endpoint, got %+v", vnext)
	}
	if len(vnext[0].Users) != 1 || vnext[0].Users[0].ID != "6ba7b810-9dad-11d1-80b4-00c04fd430c8" {
		t.Fatalf("vnext user must carry the pair uuid, got %+v", vnext[0].Users)
	}
	u := vnext[0].Users[0]
	if u.Flow != "" || u.Security != "auto" || u.Encryption != "none" {
		t.Fatalf("wrong vless user fields: %+v", u)
	}
	if cfg.Outbounds[0].StreamSettings == nil || cfg.Outbounds[0].StreamSettings.Security != "tls" ||
		cfg.Outbounds[0].StreamSettings.TLSSettings.ServerName != "acme.example.com" {
		t.Fatalf("outbound stream settings must be tls with the pair sni")
	}
}

func TestRenderClientConfigEndpointWithPort(t *testing.T) {
	// proxer_endpoint may carry a port; the dokodemo destination host is
	// still only the host part (target_port comes from the forward).
	p := `{"sni":"a.example.com","uuid":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","proxer_endpoint":"198.51.100.7:8443"}`
	out, err := New(testCfg()).RenderClientConfig(testHost(p), []store.Forward{{PublicPort: 18001, TargetPort: 22, Proto: "tcp"}})
	if err != nil {
		t.Fatalf("RenderClientConfig: %v", err)
	}
	if strings.Contains(string(out), "8443") {
		t.Fatalf("proxer endpoint port must not leak into the dokodemo destination:\n%s", out)
	}
	if !strings.Contains(string(out), `"address": "198.51.100.7"`) {
		t.Fatalf("missing proxer host in dokodemo settings:\n%s", out)
	}
}

func TestRenderProxerConfig(t *testing.T) {
	out, err := New(testCfg()).RenderProxerConfig(testHost(validParams))
	if err != nil {
		t.Fatalf("RenderProxerConfig: %v", err)
	}
	s := string(out)
	if strings.HasPrefix(strings.TrimSpace(s), "{") {
		t.Fatalf("proxer config is a plain-text note, not json:\n%s", s)
	}
	for _, want := range []string{"Nothing to run on this side", "acme", "198.51.100.7"} {
		if !strings.Contains(s, want) {
			t.Fatalf("proxer note missing %q:\n%s", want, s)
		}
	}
}

func TestInjectUUID(t *testing.T) {
	// absent / empty / null params get a fresh uuid v4
	kept, err := ParseXrayParams([]byte(`{"uuid":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","sni":"a","proxer_endpoint":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{"empty": "", "empty-obj": `{}`, "null": `null`} {
		out, err := InjectUUID([]byte(raw))
		if err != nil {
			t.Fatalf("InjectUUID(%s): %v", name, err)
		}
		var m map[string]any
		if err := json.Unmarshal(out, &m); err != nil {
			t.Fatalf("InjectUUID(%s): output not json: %v", name, err)
		}
		got, _ := m["uuid"].(string)
		if got == "" || len(got) != 36 {
			t.Fatalf("InjectUUID(%s): no uuid injected: %s", name, out)
		}
	}
	// owner-supplied uuid survives untouched
	orig := `{"uuid":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","sni":"a","proxer_endpoint":"x"}`
	out, err := InjectUUID([]byte(orig))
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParseXrayParams(out)
	if err != nil {
		t.Fatal(err)
	}
	if p.UUID != kept.UUID {
		t.Fatalf("owner-supplied uuid was replaced: %q -> %q", kept.UUID, p.UUID)
	}
	// injected value is a fresh v4 uuid (uuid-only params are still
	// incomplete, so validate the uuid itself rather than the whole set)
	plain, err := InjectUUID([]byte{})
	if err != nil {
		t.Fatal(err)
	}
	var pm map[string]any
	if err := json.Unmarshal(plain, &pm); err != nil {
		t.Fatal(err)
	}
	injected, _ := pm["uuid"].(string)
	if _, err := uuid.Parse(injected); err != nil {
		t.Fatalf("injected uuid does not parse: %q", injected)
	}
	if len(injected) != 36 || injected[14] != '4' {
		t.Fatalf("injected uuid is not a v4 uuid: %q", injected)
	}
}

func TestRenderersRejectBadParams(t *testing.T) {
	x := New(testCfg())
	h := testHost(`{"sni":"a"}`)
	if _, err := x.RenderServerConfig(h); err == nil {
		t.Fatal("RenderServerConfig must reject params without uuid/proxer_endpoint")
	}
	if _, err := x.RenderClientConfig(h, nil); err == nil {
		t.Fatal("RenderClientConfig must reject params without uuid/proxer_endpoint")
	}
	if _, err := x.RenderProxerConfig(h); err == nil {
		t.Fatal("RenderProxerConfig must reject params without uuid/proxer_endpoint")
	}
}

func TestParseXrayParamsModes(t *testing.T) {
	base := `"sni":"acme.example.com","uuid":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","proxer_endpoint":"198.51.100.7"`
	cases := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{"default mode is tls", `{` + base + `}`, ""},
		{"explicit tls mode", `{` + base + `,"mode":"tls"}`, ""},
		{"nginx mode with ws path", `{` + base + `,"mode":"nginx","ws_path":"/api/v1/events"}`, ""},
		{"nginx mode with custom public port", `{` + base + `,"mode":"nginx","ws_path":"/x","public_port":8443}`, ""},
		{"tls mode with fallback", `{` + base + `,"fallback":"127.0.0.1:8080"}`, ""},
		{"unknown mode", `{` + base + `,"mode":"warp"}`, `mode must be "tls" or "nginx"`},
		{"nginx without ws path", `{` + base + `,"mode":"nginx"}`, "ws_path is required in nginx mode"},
		{"nginx relative ws path", `{` + base + `,"mode":"nginx","ws_path":"api/events"}`, "ws_path must be an absolute path"},
		{"nginx ws path with whitespace", `{` + base + `,"mode":"nginx","ws_path":"/a b"}`, "ws_path must be an absolute path"},
		{"nginx with cert_file", `{` + base + `,"mode":"nginx","ws_path":"/x","cert_file":"/etc/c.pem"}`, "cert_file/key_file are tls-mode only"},
		{"nginx public port out of range", `{` + base + `,"mode":"nginx","ws_path":"/x","public_port":70000}`, "public_port must be 1-65535"},
		{"tls with ws path", `{` + base + `,"ws_path":"/x"}`, "ws_path is nginx-mode only"},
		{"tls with public port", `{` + base + `,"public_port":443}`, "public_port is nginx-mode only"},
		{"tls fallback without port", `{` + base + `,"fallback":"127.0.0.1"}`, "fallback must be host:port"},
		{"tls fallback with whitespace", `{` + base + `,"fallback":"127.0.0.1:80 80"}`, "fallback must not contain whitespace"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseXrayParams([]byte(tc.raw))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ParseXrayParams(%s): unexpected error: %v", tc.raw, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ParseXrayParams(%s): expected error containing %q, got nil", tc.raw, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ParseXrayParams(%s): error %q does not contain %q", tc.raw, err, tc.wantErr)
			}
		})
	}
	// nginx mode defaults the public port to the usual vhost TLS port.
	p, err := ParseXrayParams([]byte(`{` + base + `,"mode":"nginx","ws_path":"/api/v1/events"}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != ModeNginx || p.WSPath != "/api/v1/events" || p.PublicPort != 443 {
		t.Fatalf("nginx params not normalized: %+v", p)
	}
}

// Glacier pattern: loopback-only xray with plain VLESS over WS; TLS is
// terminated by the operator's nginx upstream, so no certs, no tlsSettings
// and no placeholders in the rendered config.
func TestRenderServerConfigNginxMode(t *testing.T) {
	x := New(testCfg())
	h := testHost(`{"sni":"git.example.com","uuid":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","proxer_endpoint":"198.51.100.7","mode":"nginx","ws_path":"/api/v1/events"}`)
	out, err := x.RenderServerConfig(h)
	if err != nil {
		t.Fatalf("RenderServerConfig: %v", err)
	}
	s := string(out)
	for _, want := range []string{
		`"listen": "127.0.0.1"`,
		`"port": 5201`,
		`"network": "ws"`,
		`"security": "none"`,
		`"path": "/api/v1/events"`,
		`"destOverride": [`,
		`"quic"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in nginx-mode server config:\n%s", want, out)
		}
	}
	if strings.Contains(s, "tlsSettings") || strings.Contains(s, CertPlaceholder) || strings.Contains(s, KeyPlaceholder) {
		t.Fatalf("nginx mode must not carry TLS material (nginx terminates TLS upstream):\n%s", out)
	}
	if strings.Contains(s, `"listen": "0.0.0.0"`) {
		t.Fatalf("nginx mode must be loopback-only:\n%s", out)
	}
}

// Floe pattern: xray owns the public port with real TLS; the fallback
// sends non-VLESS probes to a real local site.
func TestRenderServerConfigTLSFallback(t *testing.T) {
	x := New(testCfg())
	h := testHost(`{"sni":"cloud.example.com","uuid":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","proxer_endpoint":"198.51.100.7","fallback":"127.0.0.1:8080"}`)
	out, err := x.RenderServerConfig(h)
	if err != nil {
		t.Fatalf("RenderServerConfig: %v", err)
	}
	s := string(out)
	for _, want := range []string{
		`"listen": "0.0.0.0"`,
		`"fallbacks": [`,
		`"dest": "127.0.0.1:8080"`,
		`"destOverride": [`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in tls-mode fallback config:\n%s", want, out)
		}
	}
}

func TestRenderClientConfigNginxMode(t *testing.T) {
	x := New(testCfg())
	h := testHost(`{"sni":"git.example.com","uuid":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","proxer_endpoint":"198.51.100.7","mode":"nginx","ws_path":"/api/v1/events","public_port":8443}`)
	out, err := x.RenderClientConfig(h, []store.Forward{{
		ID:         uuid.New(),
		HostID:     h.ID,
		PublicPort: 15490,
		TargetPort: 5432,
		Proto:      "tcp",
	}})
	if err != nil {
		t.Fatalf("RenderClientConfig: %v", err)
	}
	s := string(out)
	for _, want := range []string{
		`"address": "git.example.com"`,
		`"port": 8443`,
		`"network": "ws"`,
		`"security": "tls"`,
		`"serverName": "git.example.com"`,
		`"path": "/api/v1/events"`,
		`"address": "198.51.100.7"`, // dokodemo destination stays the proxer service
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in nginx-mode client config:\n%s", want, out)
		}
	}
}

func TestRenderClientConfigTLSModeUnchanged(t *testing.T) {
	x := New(testCfg())
	out, err := x.RenderClientConfig(testHost(validParams), nil)
	if err != nil {
		t.Fatalf("RenderClientConfig: %v", err)
	}
	s := string(out)
	for _, want := range []string{
		`"address": "dyatel.test.nada.mu"`,
		`"port": 5201`,
		`"network": "tcp"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in tls-mode client config:\n%s", want, out)
		}
	}
	if strings.Contains(s, "wsSettings") {
		t.Fatalf("tls mode must not carry wsSettings:\n%s", out)
	}
}
