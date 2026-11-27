package auth

import (
	"crypto/sha256"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"nadamu/dyatel/internal/store"
)

func TestHashTokenAndNewToken(t *testing.T) {
	t1 := NewToken()
	t2 := NewToken()
	if !strings.HasPrefix(t1, "dyatel_") {
		t.Fatalf("unexpected token prefix: %q", t1)
	}
	if len(t1) != len("dyatel_")+43 {
		t.Fatalf("unexpected token length %d: %q", len(t1), t1)
	}
	if t1 == t2 {
		t.Fatal("two minted tokens collided")
	}

	d1 := HashToken(t1)
	d2 := HashToken(t1)
	if !slices.Equal(d1, d2) {
		t.Fatal("HashToken is not deterministic")
	}
	if len(d1) != sha256.Size {
		t.Fatalf("digest len = %d, want %d", len(d1), sha256.Size)
	}
	if slices.Equal(d1, HashToken(t2)) {
		t.Fatal("different tokens produced identical digests")
	}
}

func TestVerifyPHC(t *testing.T) {
	// Test hash from api_test.go for password "correcthorse".
	const phc = "$argon2id$v=19$m=65536,t=2,p=1$0Zh50ymKo7qzu6LzLbJbyw$++EE7ecjdmShgjkPBEIKolDFe0PuLkQ5OqyZrqUmhL0"

	if !verifyPHC(phc, "correcthorse") {
		t.Fatal("valid password rejected")
	}
	if verifyPHC(phc, "wrongpass") {
		t.Fatal("wrong password accepted")
	}
	if verifyPHC("$argon2id$v=18$m=65536,t=2,p=1$0Zh50ymKo7qzu6LzLbJbyw$++EE", "correcthorse") {
		t.Fatal("unsupported argon2 version accepted")
	}
	if verifyPHC("$argon2id$v=19$m=65536,t=2,p=1$%%%$++EE", "correcthorse") {
		t.Fatal("invalid base64 salt accepted")
	}
	if !verifyPHC("plain-secret", "plain-secret") || verifyPHC("plain-secret", "other") {
		t.Fatal("constant-time fallback comparison failed")
	}
}

func TestIdentityVisibilityAndRole(t *testing.T) {
	ownerID := uuid.New()
	consumerID := uuid.New()
	strangerID := uuid.New()
	host := store.Host{OwnerID: ownerID, ConsumerID: consumerID}

	cases := []struct {
		name string
		id   Identity
		see  bool
		role string
	}{
		{"admin", Identity{User: &store.User{ID: strangerID}, IsAdmin: true}, true, roleAdmin},
		{"owner", Identity{User: &store.User{ID: ownerID}}, true, roleOwner},
		{"consumer", Identity{User: &store.User{ID: consumerID}}, true, roleConsumer},
		{"stranger", Identity{User: &store.User{ID: strangerID}}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.id.CanSeeHost(host); got != tc.see {
				t.Fatalf("CanSeeHost = %v, want %v", got, tc.see)
			}
			if got := tc.id.RoleOn(host); got != tc.role {
				t.Fatalf("RoleOn = %q, want %q", got, tc.role)
			}
		})
	}
}
