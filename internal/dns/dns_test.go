package dns

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUpsertAndPruneRecords(t *testing.T) {
	records := map[string]cfRecord{
		"keep-unrelated": {
			ID:      "keep-unrelated",
			Type:    "A",
			Name:    "forgejo.nada.mu",
			Content: "1.2.3.4",
			TTL:     120,
			Comment: "managed elsewhere",
		},
		"stale-dyatel": {
			ID:      "stale-dyatel",
			Type:    "A",
			Name:    "old.test.nada.mu",
			Content: "81.30.105.65",
			TTL:     120,
			Comment: "dyatel node=test fwd=old",
		},
		"other-node": {
			ID:      "other-node",
			Type:    "A",
			Name:    "prod.nada.mu",
			Content: "195.58.153.219",
			TTL:     120,
			Comment: "dyatel node=glacier fwd=prod",
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			name := r.URL.Query().Get("name")
			if name == "nada.mu" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": true,
					"result":  []map[string]string{{"id": "z1", "name": "nada.mu"}},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []any{}})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/z1/dns_records":
			filter := r.URL.Query().Get("name")
			var out []cfRecord
			for _, rec := range records {
				if filter == "" || rec.Name == filter {
					out = append(out, rec)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": out})
		case r.Method == http.MethodPost && r.URL.Path == "/zones/z1/dns_records":
			var rec cfRecord
			if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
				t.Fatal(err)
			}
			rec.ID = "id-" + rec.Type
			records[rec.ID] = rec
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": rec})
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/zones/z1/dns_records/"):
			id := strings.TrimPrefix(r.URL.Path, "/zones/z1/dns_records/")
			var rec cfRecord
			if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
				t.Fatal(err)
			}
			rec.ID = id
			records[id] = rec
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": rec})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/zones/z1/dns_records/"):
			id := strings.TrimPrefix(r.URL.Path, "/zones/z1/dns_records/")
			delete(records, id)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": id}})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	c := New("cf-test-token")
	c.baseURL = srv.URL

	ids, err := c.UpsertForwardRecord(
		context.Background(),
		"test.nada.mu",
		"mc1.test.nada.mu",
		"81.30.105.65",
		"2a13:d207:494:21::1",
		"dyatel node=test fwd=f1",
	)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if ids != "id-A,id-AAAA" {
		t.Fatalf("ids = %q, want id-A,id-AAAA", ids)
	}
	if records["id-A"].Proxied || records["id-AAAA"].Proxied {
		t.Fatal("game forward DNS records must not be proxied")
	}

	if err := c.PruneOrphans(context.Background(), "test.nada.mu", "dyatel node=test ", map[string]bool{
		"mc1.test.nada.mu": true,
	}); err != nil {
		t.Fatalf("prune: %v", err)
	}

	if _, ok := records["stale-dyatel"]; ok {
		t.Fatal("stale dyatel record for this node should have been deleted")
	}
	if _, ok := records["keep-unrelated"]; !ok {
		t.Fatal("non-dyatel record must never be deleted")
	}
	if _, ok := records["other-node"]; !ok {
		t.Fatal("other node record must never be deleted")
	}
	if _, ok := records["id-A"]; !ok {
		t.Fatal("active record id-A should remain")
	}
}

// A name that already carries somebody else's record must never be taken over:
// binding a panel forward to a live site would otherwise rewrite it.
func TestUpsertRefusesForeignRecord(t *testing.T) {
	var writes int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result":  []map[string]string{{"id": "z1", "name": "nada.mu"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/z1/dns_records":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result": []map[string]any{{
					"id": "www", "type": "A", "name": "www.nada.mu",
					"content": "195.58.153.219", "comment": "managed elsewhere",
				}},
			})
		default:
			writes++
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{}})
		}
	}))
	defer srv.Close()

	c := New("tok").WithBaseURL(srv.URL)
	_, err := c.UpsertForwardRecord(context.Background(), "nada.mu", "www.nada.mu", "81.30.105.65", "", "dyatel node=test fwd=f1")
	if !errors.Is(err, ErrForeignRecord) {
		t.Fatalf("err = %v, want ErrForeignRecord", err)
	}
	if writes != 0 {
		t.Fatalf("foreign record was modified: %d write calls", writes)
	}
}

// Cloudflare permits several records of one type per name; the core owns one,
// so stale duplicates must be removed instead of lingering forever.
func TestUpsertCollapsesDuplicateManagedRecords(t *testing.T) {
	records := map[string]cfRecord{
		"a1": {ID: "a1", Type: "A", Name: "mc1.nada.mu", Content: "81.30.105.65", Comment: "dyatel node=test fwd=f1"},
		"a2": {ID: "a2", Type: "A", Name: "mc1.nada.mu", Content: "81.30.105.65", Comment: "dyatel node=test fwd=f1"},
	}
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result":  []map[string]string{{"id": "z1", "name": "nada.mu"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/z1/dns_records":
			out := []cfRecord{}
			for _, rec := range records {
				out = append(out, rec)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": out})
		case r.Method == http.MethodDelete:
			id := strings.TrimPrefix(r.URL.Path, "/zones/z1/dns_records/")
			deleted = append(deleted, id)
			delete(records, id)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": id}})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	c := New("tok").WithBaseURL(srv.URL)
	ids, err := c.UpsertForwardRecord(context.Background(), "nada.mu", "mc1.nada.mu", "81.30.105.65", "", "dyatel node=test fwd=f1")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if ids != "a1" && ids != "a2" {
		t.Fatalf("ids = %q, want the surviving A record", ids)
	}
	if len(deleted) != 1 {
		t.Fatalf("deleted = %v, want exactly one duplicate", deleted)
	}
	if len(records) != 1 {
		t.Fatalf("records left = %d, want 1", len(records))
	}
}

// Prune only owns address records; a dyatel-commented TXT (or any future type)
// is not ours to delete.
func TestPruneIgnoresNonAddressTypes(t *testing.T) {
	records := map[string]cfRecord{
		"txt": {ID: "txt", Type: "TXT", Name: "_acme.nada.mu", Content: "challenge", Comment: "dyatel node=test"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result":  []map[string]string{{"id": "z1", "name": "nada.mu"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/z1/dns_records":
			out := []cfRecord{}
			for _, rec := range records {
				out = append(out, rec)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": out})
		case r.Method == http.MethodDelete:
			t.Fatalf("unexpected delete of %s", r.URL.Path)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	c := New("tok").WithBaseURL(srv.URL)
	if err := c.PruneOrphans(context.Background(), "nada.mu", "dyatel node=test ", map[string]bool{}); err != nil {
		t.Fatalf("prune: %v", err)
	}
}
