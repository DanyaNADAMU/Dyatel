// Package client is the HTTP client for the dyatel-core daemon API.
//
// It is a thin transport layer for cmd/dyatelctl and must stay free of any
// daemon internals (reconcile, store, auth): the CLI talks to the daemon
// only through this package over /api/v1.
package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const apiPrefix = "/api/v1"

// APIError carries a non-2xx daemon response. The daemon writes plain-text
// error bodies ("400: bad name (a-z0-9-)") that explain the rejection, so
// the body text is kept verbatim and surfaced to the user.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	body := strings.TrimSpace(e.Body)
	if body == "" {
		return fmt.Sprintf("daemon returned %d", e.Status)
	}
	return fmt.Sprintf("%d: %s", e.Status, body)
}

// Client talks to one daemon over HTTP. Exactly one credential flavor is
// expected (Bearer PAT or Basic fallback admin); Bearer wins when both are
// set, mirroring the daemon's auth order (PAT before Basic use is not the
// deciding factor — the CLI just never sends both).
type Client struct {
	base string
	hc   *http.Client

	token    string
	user     string
	password string
}

// New builds a client for a daemon base URL (e.g. http://127.0.0.1:8100).
// token is a dyatel_* personal access token; user/password are the
// break-glass admin credentials. Prefer token when both are provided.
func New(base, token, user, password string) *Client {
	return &Client{
		base:     strings.TrimRight(base, "/"),
		hc:       http.DefaultClient,
		token:    token,
		user:     user,
		password: password,
	}
}

// Do performs an API call and returns the raw response body. Errors are
// *APIError; raw bytes are what --json passthrough prints, so no
// re-serialization can drop fields the CLI does not model yet.
func (c *Client) Do(method, path string, body any) ([]byte, error) {
	var payload io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode request: %w", err)
		}
		payload = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+apiPrefix+path, payload)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.authorize(req)

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("daemon unreachable: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, &APIError{Status: resp.StatusCode, Body: string(raw)}
	}
	return raw, nil
}

// authorize attaches credentials; Bearer PAT wins over Basic, matching the
// CLI contract rather than leaving header precedence to the server.
func (c *Client) authorize(req *http.Request) {
	switch {
	case c.token != "":
		req.Header.Set("Authorization", "Bearer "+c.token)
	case c.user != "" || c.password != "":
		req.SetBasicAuth(c.user, c.password)
	}
}

// Me is the /me identity document.
type Me struct {
	ID      string `json:"id"`
	Sub     string `json:"sub"`
	Name    string `json:"name"`
	IsAdmin bool   `json:"is_admin"`
	Auth    string `json:"auth"`
}

func (c *Client) Me() (Me, error) {
	raw, err := c.Do(http.MethodGet, "/me", nil)
	if err != nil {
		return Me{}, err
	}
	var me Me
	return me, json.Unmarshal(raw, &me)
}

// Status returns the admin-only reconcile status document untouched.
func (c *Client) Status() ([]byte, error) {
	return c.Do(http.MethodGet, "/status", nil)
}

// Token is a PAT row as exposed by the API: metadata only, no secret.
type Token struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	RevokedAt  string `json:"revoked_at,omitempty"`
	// Secret is populated only by CreateToken — the one time the daemon
	// hands out the plaintext value.
	Secret string `json:"token,omitempty"`
}

func (c *Client) CreateToken(label string) (Token, error) {
	raw, err := c.Do(http.MethodPost, "/tokens", map[string]string{"label": label})
	if err != nil {
		return Token{}, err
	}
	var t Token
	return t, json.Unmarshal(raw, &t)
}

func (c *Client) ListTokens() ([]Token, error) {
	raw, err := c.Do(http.MethodGet, "/tokens", nil)
	if err != nil {
		return nil, err
	}
	ts := []Token{}
	return ts, json.Unmarshal(raw, &ts)
}

func (c *Client) RevokeToken(id string) error {
	_, err := c.Do(http.MethodDelete, "/tokens/"+id, nil)
	return err
}

// TriggerReconcile asks the daemon to run a loop pass right now.
func (c *Client) TriggerReconcile() error {
	_, err := c.Do(http.MethodPost, "/reconcile", nil)
	return err
}

// User is one directory entry the invitation picker can name.
type User struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	IsAdmin     bool   `json:"is_admin"`
}

func (c *Client) ListUsers(q string) ([]User, error) {
	path := "/users"
	if q != "" {
		path += "?q=" + url.QueryEscape(q)
	}
	raw, err := c.Do(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	us := []User{}
	return us, json.Unmarshal(raw, &us)
}

// Event is one audit row from the daemon event feed.
type Event struct {
	ID         int64  `json:"id"`
	At         string `json:"at"`
	AuthMethod string `json:"auth_method"`
	Action     string `json:"action"`
	ObjectType string `json:"object_type"`
	ObjectID   string `json:"object_id"`
}

func (c *Client) ListEvents(limit int) ([]Event, error) {
	path := "/events"
	if limit > 0 {
		path += "?limit=" + strconv.Itoa(limit)
	}
	raw, err := c.Do(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	evs := []Event{}
	return evs, json.Unmarshal(raw, &evs)
}

// PatchHost edits the mutable host knobs (endpoint, keepalive, consumer).
func (c *Client) PatchHost(id string, endpoint *string, keepalive *int, consumerID *string) (Host, error) {
	body := map[string]any{}
	if endpoint != nil {
		body["endpoint"] = *endpoint
	}
	if keepalive != nil {
		body["keepalive"] = *keepalive
	}
	if consumerID != nil {
		body["consumer_id"] = *consumerID
	}
	raw, err := c.Do(http.MethodPatch, "/hosts/"+id, body)
	if err != nil {
		return Host{}, err
	}
	var h Host
	return h, json.Unmarshal(raw, &h)
}

// Host mirrors the daemon's wire format. The daemon serializes store.Host
// directly and its snake_case json tags are the canonical contract; the tags
// here pin the same names so a casing drift fails loudly instead of relying
// on encoding/json's case-insensitive fallback.
type Host struct {
	ID                  string          `json:"id"`
	Name                string          `json:"name"`
	Node                string          `json:"node"`
	OwnerID             string          `json:"owner_id"`
	ConsumerID          string          `json:"consumer_id"`
	WGPublicKey         string          `json:"wg_public_key"`
	GWPublicKey         string          `json:"gw_public_key"`
	TunnelIPv4          string          `json:"tunnel_ipv4"`
	TunnelIPv6          string          `json:"tunnel_ipv6"`
	ConsumerWGPublicKey *string         `json:"consumer_wg_public_key,omitempty"`
	ConsumerTunnelIPv4  *string         `json:"consumer_tunnel_ipv4,omitempty"`
	ConsumerTunnelIPv6  *string         `json:"consumer_tunnel_ipv6,omitempty"`
	Endpoint            *string         `json:"endpoint,omitempty"`
	Transport           string          `json:"transport"`
	ListenPort          int             `json:"listen_port"`
	Params              json.RawMessage `json:"params,omitempty"`
	Keepalive           int             `json:"keepalive"`
	State               string          `json:"state"`
}

// DecodedParams returns the transport params as the JSON object the owner
// submitted. On the wire Params is a []byte field, which encoding/json
// envelopes as a base64 string; unwrap that, but pass through anything
// that is already a raw JSON object so a tagged server response keeps
// working.
func (h Host) DecodedParams() (json.RawMessage, error) {
	if len(h.Params) == 0 {
		return nil, nil
	}
	if h.Params[0] == '{' {
		return h.Params, nil
	}
	var b64 string
	if err := json.Unmarshal(h.Params, &b64); err != nil {
		return nil, fmt.Errorf("params: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("params base64: %w", err)
	}
	return json.RawMessage(decoded), nil
}

// CreateHostRequest is the POST /hosts payload (snake_case, matching the
// daemon's explicit request tags).
type CreateHostRequest struct {
	Name          string          `json:"name"`
	Node          string          `json:"node,omitempty"`
	PreferredIPv4 string          `json:"preferred_ipv4,omitempty"`
	PreferredIPv6 string          `json:"preferred_ipv6,omitempty"`
	PreferredPort int             `json:"preferred_port,omitempty"`
	WGPublicKey   string          `json:"wg_public_key,omitempty"` // BYOK
	Transport     string          `json:"transport,omitempty"`
	ConsumerID    string          `json:"consumer_id"`
	Keepalive     int             `json:"keepalive,omitempty"` // 0 lets the daemon apply its default (25)
	Params        json.RawMessage `json:"params,omitempty"`    // awg obfuscation knobs
}

func (c *Client) CreateHost(req CreateHostRequest) (Host, error) {
	raw, err := c.Do(http.MethodPost, "/hosts/", req)
	if err != nil {
		return Host{}, err
	}
	var h Host
	return h, json.Unmarshal(raw, &h)
}

func (c *Client) ListHosts() ([]Host, error) {
	raw, err := c.Do(http.MethodGet, "/hosts/", nil)
	if err != nil {
		return nil, err
	}
	var hs []Host
	return hs, json.Unmarshal(raw, &hs)
}

func (c *Client) GetHost(id string) (Host, error) {
	raw, err := c.Do(http.MethodGet, "/hosts/"+id+"/", nil)
	if err != nil {
		return Host{}, err
	}
	var h Host
	return h, json.Unmarshal(raw, &h)
}

func (c *Client) DeleteHost(id string) error {
	_, err := c.Do(http.MethodDelete, "/hosts/"+id+"/", nil)
	return err
}

func (c *Client) SetState(id, state string) error {
	_, err := c.Do(http.MethodPost, "/hosts/"+id+"/state", map[string]string{"state": state})
	return err
}

func (c *Client) RegisterConsumerKey(id, publicKey string) error {
	_, err := c.Do(http.MethodPost, "/hosts/"+id+"/consumer-key",
		map[string]string{"wg_public_key": publicKey})
	return err
}

// ProxerConfig returns the owner-side wg-quick configuration (text/plain).
func (c *Client) ProxerConfig(id string) ([]byte, error) {
	return c.Do(http.MethodGet, "/hosts/"+id+"/config/proxer", nil)
}

// ClientConfig returns the consumer-side configuration. The daemon answers
// 412 until the consumer key is registered; that surfaces as *APIError.
func (c *Client) ClientConfig(id string) ([]byte, error) {
	return c.Do(http.MethodGet, "/hosts/"+id+"/config/client", nil)
}

// Forward mirrors the daemon wire format (same untagged-store serialization
// as Host).
type Forward struct {
	ID         string `json:"id"`
	HostID     string `json:"host_id"`
	PublicPort int    `json:"public_port"`
	TargetPort int    `json:"target_port"`
	Proto      string `json:"proto"`
	Label      string `json:"label"`
}

// CreateForwardRequest is the POST /hosts/{id}/forwards payload.
type CreateForwardRequest struct {
	PublicPort int    `json:"public_port"`
	TargetPort int    `json:"target_port"`
	Proto      string `json:"proto"`
	Label      string `json:"label,omitempty"`
}

func (c *Client) ListForwards(hostID string) ([]Forward, error) {
	raw, err := c.Do(http.MethodGet, "/hosts/"+hostID+"/forwards", nil)
	if err != nil {
		return nil, err
	}
	var fs []Forward
	return fs, json.Unmarshal(raw, &fs)
}

func (c *Client) CreateForward(hostID string, req CreateForwardRequest) (Forward, error) {
	raw, err := c.Do(http.MethodPost, "/hosts/"+hostID+"/forwards", req)
	if err != nil {
		return Forward{}, err
	}
	var f Forward
	return f, json.Unmarshal(raw, &f)
}

func (c *Client) DeleteForward(hostID, forwardID string) error {
	_, err := c.Do(http.MethodDelete, "/hosts/"+hostID+"/forwards/"+forwardID, nil)
	return err
}

// DNSRecord is an optional hostname bound to one forward.
type DNSRecord struct {
	ID           string `json:"id"`
	ForwardID    string `json:"forward_id"`
	Name         string `json:"name"`
	CloudflareID string `json:"cloudflare_id,omitempty"`
	CreatedAt    string `json:"created_at"`
}

func (c *Client) ListHostDNS(hostID string) ([]DNSRecord, error) {
	raw, err := c.Do(http.MethodGet, "/hosts/"+hostID+"/dns", nil)
	if err != nil {
		return nil, err
	}
	ds := []DNSRecord{}
	return ds, json.Unmarshal(raw, &ds)
}

func (c *Client) SetForwardDNS(forwardID, name string) (DNSRecord, error) {
	raw, err := c.Do(http.MethodPost, "/forwards/"+forwardID+"/dns", map[string]string{"name": name})
	if err != nil {
		return DNSRecord{}, err
	}
	var d DNSRecord
	return d, json.Unmarshal(raw, &d)
}

func (c *Client) DeleteForwardDNS(forwardID string) error {
	_, err := c.Do(http.MethodDelete, "/forwards/"+forwardID+"/dns", nil)
	return err
}
