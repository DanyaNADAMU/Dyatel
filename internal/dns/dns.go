package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const defaultBaseURL = "https://api.cloudflare.com/client/v4"

// ManagedPrefix marks Cloudflare records the core owns. Records without it
// belong to somebody else and are never overwritten or pruned: a typo in a
// panel binding must not take down an unrelated site.
const ManagedPrefix = "dyatel "

// ErrForeignRecord means the requested name already exists and is not managed
// by Dyatel, so the core refuses to take it over.
var ErrForeignRecord = errors.New("dns record exists and is not managed by dyatel")

// Client synchronizes Dyatel forward A/AAAA records against Cloudflare DNS.
type Client struct {
	baseURL string
	token   string
	hc      *http.Client

	mu     sync.Mutex
	zoneID map[string]string // zone name -> Cloudflare zone ID
}

// New creates a Cloudflare DNS sync client. An empty token disables sync.
func New(token string) *Client {
	return &Client{
		baseURL: defaultBaseURL,
		token:   strings.TrimSpace(token),
		hc:      &http.Client{Timeout: 10 * time.Second},
		zoneID:  map[string]string{},
	}
}

// WithBaseURL overrides the Cloudflare API base URL (used in tests).
func (c *Client) WithBaseURL(base string) *Client {
	c.baseURL = strings.TrimRight(base, "/")
	return c
}

// Enabled reports whether Cloudflare credentials are configured.
func (c *Client) Enabled() bool {
	return c != nil && c.token != ""
}

type cfRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment,omitempty"`
}

type cfEnvelope[T any] struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result T `json:"result"`
}

// UpsertForwardRecord converges A and optional AAAA records for fqdn in the
// Cloudflare zone hosting zoneName. Returns a stable comma-separated list of
// Cloudflare record IDs. A foreign record with the same name/type is a hard
// conflict: Dyatel never overwrites DNS it does not own.
func (c *Client) UpsertForwardRecord(ctx context.Context, zoneName, fqdn, ipv4, ipv6, comment string) (string, error) {
	if !c.Enabled() {
		return "", nil
	}
	zid, err := c.resolveZoneID(ctx, zoneName)
	if err != nil {
		return "", err
	}
	existing, err := c.listRecords(ctx, zid, fqdn)
	if err != nil {
		return "", err
	}
	byType := map[string][]cfRecord{}
	for _, r := range existing {
		byType[r.Type] = append(byType[r.Type], r)
	}

	var ids []string
	desired := []struct {
		typ, content string
	}{
		{"A", strings.TrimSpace(ipv4)},
		{"AAAA", strings.TrimSpace(ipv6)},
	}
	for _, want := range desired {
		recs := byType[want.typ]
		// Cloudflare allows several records of one type for a name; the core
		// owns exactly one, so extras are deleted. Foreign records block the
		// whole operation instead of being silently clobbered.
		var cur *cfRecord
		for i := range recs {
			r := recs[i]
			if !strings.HasPrefix(r.Comment, ManagedPrefix) {
				return "", fmt.Errorf("%w: %s %s", ErrForeignRecord, r.Type, r.Name)
			}
			if cur == nil {
				cur = &recs[i]
				continue
			}
			if err := c.deleteRecord(ctx, zid, r.ID); err != nil {
				return "", err
			}
		}
		if want.content == "" {
			if cur != nil {
				if err := c.deleteRecord(ctx, zid, cur.ID); err != nil {
					return "", err
				}
			}
			continue
		}
		if cur != nil {
			if cur.Content == want.content && cur.Comment == comment && !cur.Proxied {
				ids = append(ids, cur.ID)
				continue
			}
			updated, err := c.putRecord(ctx, zid, cur.ID, cfRecord{
				Type:    want.typ,
				Name:    fqdn,
				Content: want.content,
				TTL:     120,
				Proxied: false,
				Comment: comment,
			})
			if err != nil {
				return "", err
			}
			ids = append(ids, updated.ID)
			continue
		}
		created, err := c.postRecord(ctx, zid, cfRecord{
			Type:    want.typ,
			Name:    fqdn,
			Content: want.content,
			TTL:     120,
			Proxied: false,
			Comment: comment,
		})
		if err != nil {
			return "", err
		}
		ids = append(ids, created.ID)
	}
	return strings.Join(ids, ","), nil
}

// PruneOrphans deletes A/AAAA records tagged with commentPrefix whose FQDN is
// absent from want. Non-Dyatel records (without commentPrefix) and non-address
// types are untouched.
func (c *Client) PruneOrphans(ctx context.Context, zoneName, commentPrefix string, want map[string]bool) error {
	if !c.Enabled() {
		return nil
	}
	zid, err := c.resolveZoneID(ctx, zoneName)
	if err != nil {
		return err
	}
	recs, err := c.listRecords(ctx, zid, "")
	if err != nil {
		return err
	}
	for _, rec := range recs {
		if rec.Type != "A" && rec.Type != "AAAA" {
			continue
		}
		if !strings.HasPrefix(rec.Comment, commentPrefix) {
			continue
		}
		if want[strings.ToLower(rec.Name)] {
			continue
		}
		if err := c.deleteRecord(ctx, zid, rec.ID); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) resolveZoneID(ctx context.Context, zoneName string) (string, error) {
	cand := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zoneName)), ".")
	c.mu.Lock()
	if id := c.zoneID[cand]; id != "" {
		c.mu.Unlock()
		return id, nil
	}
	c.mu.Unlock()

	// Walk up subdomains (e.g. test.nada.mu -> nada.mu) so staging and prod
	// zones resolve against the apex zone in Cloudflare.
	cur := cand
	for strings.Contains(cur, ".") {
		var env cfEnvelope[[]struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}]
		if err := c.doJSON(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(cur), nil, &env); err != nil {
			return "", err
		}
		if len(env.Result) > 0 {
			zid := env.Result[0].ID
			c.mu.Lock()
			c.zoneID[cand] = zid
			c.mu.Unlock()
			return zid, nil
		}
		_, rest, ok := strings.Cut(cur, ".")
		if !ok {
			break
		}
		cur = rest
	}
	return "", fmt.Errorf("cloudflare zone not found for %q", zoneName)
}

func (c *Client) listRecords(ctx context.Context, zid, fqdn string) ([]cfRecord, error) {
	var all []cfRecord
	for page := 1; ; page++ {
		path := fmt.Sprintf("/zones/%s/dns_records?per_page=100&page=%d", zid, page)
		if fqdn != "" {
			path += "&name=" + url.QueryEscape(fqdn)
		}
		var env cfEnvelope[[]cfRecord]
		if err := c.doJSON(ctx, http.MethodGet, path, nil, &env); err != nil {
			return nil, err
		}
		all = append(all, env.Result...)
		if len(env.Result) < 100 {
			break
		}
	}
	return all, nil
}

func (c *Client) postRecord(ctx context.Context, zid string, rec cfRecord) (cfRecord, error) {
	var env cfEnvelope[cfRecord]
	err := c.doJSON(ctx, http.MethodPost, fmt.Sprintf("/zones/%s/dns_records", zid), rec, &env)
	return env.Result, err
}

func (c *Client) putRecord(ctx context.Context, zid, rid string, rec cfRecord) (cfRecord, error) {
	var env cfEnvelope[cfRecord]
	err := c.doJSON(ctx, http.MethodPut, fmt.Sprintf("/zones/%s/dns_records/%s", zid, rid), rec, &env)
	return env.Result, err
}

func (c *Client) deleteRecord(ctx context.Context, zid, rid string) error {
	var env cfEnvelope[map[string]any]
	return c.doJSON(ctx, http.MethodDelete, fmt.Sprintf("/zones/%s/dns_records/%s", zid, rid), nil, &env)
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("cloudflare %s %s: %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return err
	}
	return nil
}
