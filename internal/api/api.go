package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"nadamu/dyatel/internal/auth"
	"nadamu/dyatel/internal/config"
	"nadamu/dyatel/internal/pool"
	"nadamu/dyatel/internal/reconcile"
	"nadamu/dyatel/internal/store"
	"nadamu/dyatel/internal/transport/wireguard"
	"nadamu/dyatel/internal/transport/xrayvless"
)

type Server struct {
	cfg *config.Config
	st  *store.Store
	au  *auth.Authenticator
	al  *pool.Allocator
	wg  *wireguard.WG
	xr  *xrayvless.Xray
	rc  *reconcile.Reconciler
}

func New(cfg *config.Config, st *store.Store, rc *reconcile.Reconciler) *Server {
	au := auth.New(cfg, st)
	return &Server{cfg: cfg, st: st, au: au, al: pool.New(cfg, st),
		wg: wireguard.New(cfg), xr: xrayvless.New(cfg), rc: rc}
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(s.authMW)
		r.Get("/me", s.me)
		r.Get("/status", s.status)
		r.Post("/reconcile", s.triggerReconcile)
		r.Get("/users", s.listUsers)
		r.Get("/events", s.listEvents)
		r.Route("/tokens", func(r chi.Router) {
			r.Post("/", s.createToken)
			r.Get("/", s.listTokens)
			r.Delete("/{id}", s.revokeToken)
		})
		r.Route("/hosts", func(r chi.Router) {
			r.Post("/", s.createHost)
			r.Get("/", s.listHosts)
			r.Route("/{id}", func(r chi.Router) {
				r.Get("/", s.getHost)
				r.Patch("/", s.patchHost)
				r.Delete("/", s.deleteHost)
				r.Post("/consumer-key", s.registerConsumerKey)
				r.Post("/state", s.setState)
				r.Get("/config/proxer", s.proxerConfig)
				r.Get("/config/client", s.clientConfig)
				r.Route("/forwards", func(r chi.Router) {
					r.Post("/", s.createForward)
					r.Get("/", s.listForwards)
					r.Delete("/{fid}", s.deleteForward)
				})
			})
		})
	})
	return r
}

func (s *Server) authMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := s.au.Authenticate(r)
		if err != nil {
			http.Error(w, "401: "+err.Error(), http.StatusUnauthorized)
			return
		}
		if id.User == nil {
			http.Error(w, "401: unauthenticated", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithIdentity(r.Context(), id)))
	})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	writeJSON(w, map[string]any{
		"id": id.User.ID, "sub": id.User.AuthentikSub,
		"name": id.User.DisplayName, "is_admin": id.IsAdmin,
		"auth": id.AuthMethod,
	})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	if !id.IsAdmin {
		http.Error(w, "403", http.StatusForbidden)
		return
	}
	writeJSON(w, s.rc.Status(r.Context()))
}

// triggerReconcile runs the loop now instead of waiting for the next tick:
// the CLI and the panel both want "I changed state, show me drift now".
func (s *Server) triggerReconcile(w http.ResponseWriter, r *http.Request) {
	s.rc.Trigger()
	writeJSON(w, map[string]bool{"reconcile_queued": true})
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	// Invitations need a human-readable directory: the panel used to demand
	// a raw UUID, which no operator can know by heart.
	us, err := s.st.Users(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, us)
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	// Admins read the full log (moderation); everyone else sees only their
	// own trail — other users' actions are none of their business.
	var scope *uuid.UUID
	if !id.IsAdmin {
		uid := id.User.ID
		scope = &uid
	}
	evs, err := s.st.Events(r.Context(), scope, limit)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, evs)
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	var in struct {
		Label string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || strings.TrimSpace(in.Label) == "" {
		http.Error(w, "label required", 400)
		return
	}
	// The plaintext secret leaves the server exactly once, here. Only its
	// digest is persisted, so a database dump cannot mint a working token.
	secret := auth.NewToken()
	t, err := s.st.CreateToken(r.Context(), id.User.ID, in.Label, auth.HashToken(secret))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	_ = s.st.Event(r.Context(), id.User.ID, id.AuthMethod, "token.create", "token", t.ID.String(),
		mustMarshal(map[string]string{"label": in.Label}))
	writeJSON(w, struct {
		*store.Token
		Secret string `json:"token"`
	}{t, secret})
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	ts, err := s.st.TokensByUser(r.Context(), id.User.ID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, ts)
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	tid, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "bad id", 400)
		return
	}
	if err := s.st.RevokeToken(r.Context(), id.User.ID, tid); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "404", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), 500)
		return
	}
	_ = s.st.Event(r.Context(), id.User.ID, id.AuthMethod, "token.revoke", "token", tid.String(), []byte(`{}`))
	w.WriteHeader(204)
}

func (s *Server) listHosts(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	// Non-nil slice so the response encodes as [] rather than null; clients
	// (dyatelctl, panel) expect a list even when the caller owns nothing.
	// pgx scans zero rows into a nil slice, so keep the empty default.
	hosts := []store.Host{}
	var err error
	if id.IsAdmin {
		hosts, err = s.st.Hosts(r.Context())
	} else {
		hosts, err = s.st.HostsByUser(r.Context(), id.User.ID)
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if hosts == nil {
		hosts = []store.Host{}
	}
	for i := range hosts {
		hosts[i].GWPrivateKey = ""
		hosts[i].WGPreSharedKey = ""
	}
	writeJSON(w, hosts)
}

func (s *Server) getHost(w http.ResponseWriter, r *http.Request) {
	h, ok := s.hostFromURL(w, r)
	if !ok {
		return
	}
	h.GWPrivateKey = ""
	h.WGPreSharedKey = ""
	writeJSON(w, h)
}

func (s *Server) createHost(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	var in struct {
		Name       string          `json:"name"`
		PublicKey  string          `json:"wg_public_key"` // proxer BYOK
		Transport  string          `json:"transport"`
		ConsumerID string          `json:"consumer_id"` // invitation
		Keepalive  int             `json:"keepalive"`
		Params     json.RawMessage `json:"params"` // transport-specific (awg obfuscation)
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if in.Name == "" || !validName(in.Name) {
		http.Error(w, "bad name (a-z0-9-)", 400)
		return
	}
	if in.Transport == "" {
		in.Transport = "wireguard"
	}
	var params []byte
	switch in.Transport {
	case "wireguard":
		// plain wireguard has no extra knobs today
	case "amneziawg":
		// validate early so bad ranges fail at create, not at reconcile
		if _, err := wireguard.ParseAWGParams(in.Params); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if len(in.Params) > 0 {
			params = in.Params
		}
	case "xray-vless":
		// the VLESS uuid is a pair-shared credential like the PSK, so the
		// core generates it when the owner did not supply one
		injected, err := xrayvless.InjectUUID(in.Params)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		// validate early (sni/proxer_endpoint required, no reality) so bad
		// params fail at create, not at reconcile
		if _, err := xrayvless.ParseXrayParams(injected); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		params = injected
	default:
		http.Error(w, "unknown transport", 400)
		return
	}
	// Consumer is always an invitation target: must exist and differ from owner
	// (DB CHECK owner_id <> consumer_id). Self-hosting both roles = two records.
	if in.ConsumerID == "" {
		http.Error(w, "consumer_id required (invitation)", 400)
		return
	}
	c, err := uuid.Parse(in.ConsumerID)
	if err != nil {
		http.Error(w, "bad consumer_id", 400)
		return
	}
	if c == id.User.ID {
		http.Error(w, "consumer must differ from owner (DB constraint)", 400)
		return
	}
	if _, err := s.st.UserByID(r.Context(), c); err != nil {
		http.Error(w, "unknown consumer", 404)
		return
	}
	consumer := c
	// transport port + tunnel IPs
	port, err := s.al.HostPort(r.Context(), in.Transport)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	tv4, tv6, err := s.al.TunnelIPs(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	h := &store.Host{
		Name: in.Name, Node: s.cfg.Node, OwnerID: id.User.ID, ConsumerID: consumer,
		WGPublicKey: in.PublicKey,
		TunnelIPv4:  tv4, TunnelIPv6: tv6,
		Transport: in.Transport, ListenPort: port,
		Keepalive: orDefault(in.Keepalive, 25),
		Params:    params,
	}
	if err := s.rc.PrepareHost(r.Context(), h); err != nil { // PSK + gw keypair + persist
		http.Error(w, err.Error(), 500)
		return
	}
	_ = s.st.Event(r.Context(), id.User.ID, id.AuthMethod, "host.create", "host", h.ID.String(), []byte(`{}`))
	h.GWPrivateKey = ""
	h.WGPreSharedKey = ""
	writeJSON(w, h)
}

// patchHost is the post-creation edit surface: endpoint, keepalive and the
// invited consumer. BYOK keys are deliberately immutable — rotating a key
// is delete-and-create, because a half-rotated pair has no valid state.
func (s *Server) patchHost(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	h, ok := s.hostFromURL(w, r)
	if !ok {
		return
	}
	if id.RoleOn(*h) != "owner" && !id.IsAdmin {
		http.Error(w, "403", http.StatusForbidden)
		return
	}
	var in struct {
		Endpoint   *string `json:"endpoint"`
		Keepalive  *int    `json:"keepalive"`
		ConsumerID *string `json:"consumer_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if in.Keepalive != nil && (*in.Keepalive < 0 || *in.Keepalive > 65535) {
		http.Error(w, "bad keepalive", 400)
		return
	}
	var consumer *uuid.UUID
	if in.ConsumerID != nil {
		c, err := uuid.Parse(*in.ConsumerID)
		if err != nil {
			http.Error(w, "bad consumer_id", 400)
			return
		}
		if c == h.OwnerID {
			http.Error(w, "consumer must differ from owner (DB constraint)", 400)
			return
		}
		if _, err := s.st.UserByID(r.Context(), c); err != nil {
			http.Error(w, "unknown consumer", 404)
			return
		}
		consumer = &c
	}
	if err := s.st.UpdateHostFields(r.Context(), h.ID, in.Endpoint, in.Keepalive, consumer); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.rc.Trigger()
	_ = s.st.Event(r.Context(), id.User.ID, id.AuthMethod, "host.patch", "host", h.ID.String(), []byte(`{}`))
	nh, err := s.st.Host(r.Context(), h.ID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	nh.GWPrivateKey, nh.WGPreSharedKey = "", ""
	writeJSON(w, nh)
}

func (s *Server) deleteHost(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	h, ok := s.hostFromURL(w, r)
	if !ok {
		return
	}
	if id.RoleOn(*h) != "owner" && !id.IsAdmin {
		http.Error(w, "403", http.StatusForbidden)
		return
	}
	if err := s.st.DeleteHost(r.Context(), h.ID); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.rc.Trigger()
	_ = s.st.Event(r.Context(), id.User.ID, id.AuthMethod, "host.delete", "host", h.ID.String(), []byte(`{}`))
	w.WriteHeader(204)
}

func (s *Server) registerConsumerKey(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	h, ok := s.hostFromURL(w, r)
	if !ok {
		return
	}
	if h.ConsumerID != id.User.ID && !id.IsAdmin {
		http.Error(w, "403", http.StatusForbidden)
		return
	}
	var in struct {
		PublicKey string `json:"wg_public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || len(in.PublicKey) != 44 {
		http.Error(w, "bad key (want 44-char wg public key)", 400)
		return
	}
	tv4, tv6, err := s.al.TunnelIPs(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := s.rc.PrepareConsumer(r.Context(), h, in.PublicKey, tv4, tv6); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.rc.Trigger()
	_ = s.st.Event(r.Context(), id.User.ID, id.AuthMethod, "host.consumer_key", "host", h.ID.String(), []byte(`{}`))
	w.WriteHeader(204)
}

func (s *Server) setState(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	h, ok := s.hostFromURL(w, r)
	if !ok {
		return
	}
	if id.RoleOn(*h) != "owner" && !id.IsAdmin {
		http.Error(w, "403", http.StatusForbidden)
		return
	}
	var in struct {
		State string `json:"state"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil ||
		(in.State != "active" && in.State != "suspended") {
		http.Error(w, "bad state", 400)
		return
	}
	if err := s.st.UpdateHostState(r.Context(), h.ID, in.State); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.rc.Trigger()
	_ = s.st.Event(r.Context(), id.User.ID, id.AuthMethod, "host.state", "host", h.ID.String(),
		[]byte(`{"state":"`+in.State+`"}`))
	w.WriteHeader(204)
}

func (s *Server) proxerConfig(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	h, ok := s.hostFromURL(w, r)
	if !ok {
		return
	}
	if h.OwnerID != id.User.ID && !id.IsAdmin {
		http.Error(w, "403", http.StatusForbidden)
		return
	}
	// xray-vless ships an operator note on this side (berg dials the proxer
	// directly), not a tunnel client config
	if h.Transport == "xray-vless" {
		cfg, err := s.xr.RenderProxerConfig(*h)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(cfg)
		return
	}
	cfg, err := s.wg.RenderProxerConfig(*h)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write(cfg)
}

func (s *Server) clientConfig(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	h, ok := s.hostFromURL(w, r)
	if !ok {
		return
	}
	if h.ConsumerID != id.User.ID && !id.IsAdmin {
		http.Error(w, "403", http.StatusForbidden)
		return
	}
	// xray-vless client config needs the forwards: one dokodemo-door
	// inbound per forward, so we cannot reuse the wg renderer
	if h.Transport == "xray-vless" {
		fs, err := s.st.ForwardsByHost(r.Context(), h.ID)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		cfg, err := s.xr.RenderClientConfig(*h, fs)
		if err != nil {
			http.Error(w, "412: "+err.Error(), http.StatusPreconditionFailed)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(cfg)
		return
	}
	cfg, err := s.wg.RenderClientConfig(*h)
	if err != nil {
		http.Error(w, "412: "+err.Error(), http.StatusPreconditionFailed)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write(cfg)
}

func (s *Server) listForwards(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	h, ok := s.hostFromURL(w, r)
	if !ok {
		return
	}
	if !id.CanSeeHost(*h) {
		http.Error(w, "403", http.StatusForbidden)
		return
	}
	// Non-nil for [] instead of null on empty results (see listHosts);
	// pgx scans zero rows into a nil slice, so restore the empty default.
	fs := []store.Forward{}
	f, err := s.st.ForwardsByHost(r.Context(), h.ID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if f == nil {
		f = []store.Forward{}
	}
	fs = f
	writeJSON(w, fs)
}

func (s *Server) createForward(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	h, ok := s.hostFromURL(w, r)
	if !ok {
		return
	}
	if id.RoleOn(*h) != "owner" && !id.IsAdmin {
		http.Error(w, "403", http.StatusForbidden)
		return
	}
	var in struct {
		PublicPort int    `json:"public_port"`
		TargetPort int    `json:"target_port"`
		Proto      string `json:"proto"`
		Label      string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil ||
		(in.Proto != "tcp" && in.Proto != "udp") ||
		in.PublicPort < 1 || in.PublicPort > 65535 ||
		in.TargetPort < 1 || in.TargetPort > 65535 {
		http.Error(w, "bad forward", 400)
		return
	}
	f := &store.Forward{HostID: h.ID, PublicPort: in.PublicPort,
		TargetPort: in.TargetPort, Proto: in.Proto, Label: in.Label}
	if err := s.st.CreateForward(r.Context(), f); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	s.rc.Trigger()
	_ = s.st.Event(r.Context(), id.User.ID, id.AuthMethod, "forward.create", "forward", f.ID.String(), []byte(`{}`))
	writeJSON(w, f)
}

func (s *Server) deleteForward(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	h, ok := s.hostFromURL(w, r)
	if !ok {
		return
	}
	if id.RoleOn(*h) != "owner" && !id.IsAdmin {
		http.Error(w, "403", http.StatusForbidden)
		return
	}
	fid, err := uuid.Parse(chi.URLParam(r, "fid"))
	if err != nil {
		http.Error(w, "bad fid", 400)
		return
	}
	fs, err := s.st.ForwardsByHost(r.Context(), h.ID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	found := false
	for _, f := range fs {
		if f.ID == fid {
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "404", 404)
		return
	}
	if err := s.st.DeleteForward(r.Context(), fid); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.rc.Trigger()
	_ = s.st.Event(r.Context(), id.User.ID, id.AuthMethod, "forward.delete", "forward", fid.String(), []byte(`{}`))
	w.WriteHeader(204)
}

// helpers

// hostFromURL loads the host and writes the error response itself.
func (s *Server) hostFromURL(w http.ResponseWriter, r *http.Request) (*store.Host, bool) {
	id := auth.From(r.Context())
	hid, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "bad id", 400)
		return nil, false
	}
	h, err := s.st.Host(r.Context(), hid)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "404", 404)
		return nil, false
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return nil, false
	}
	if !id.CanSeeHost(*h) {
		http.Error(w, "403", http.StatusForbidden)
		return nil, false
	}
	return h, true
}

func validName(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func orDefault(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

// mustMarshal builds an audit detail blob without hand-rolled JSON, so a
// label containing quotes or newlines cannot corrupt the event row.
func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`{}`)
	}
	return b
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}
