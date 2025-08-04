// internal/store/file_store_test.go
package store_test

import (
	"testing"

	"ciphera/internal/domain"
	"ciphera/internal/store"
)

func TestIdentity_SaveLoad_OK(t *testing.T) {
	home := t.TempDir()
	pass := "pass"

	var ids domain.IdentityStore = store.NewFileStore(home)

	id := domain.Identity{
		XPub:   domain.X25519Public{1},
		XPriv:  domain.X25519Private{2},
		EdPub:  domain.Ed25519Public{3},
		EdPriv: domain.Ed25519Private{4},
	}

	if err := ids.Save(pass, id); err != nil {
		t.Fatalf("save identity: %v", err)
	}

	got, err := ids.LoadIdentity(pass)
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	if got.XPub != id.XPub || got.EdPub != id.EdPub {
		t.Fatalf("mismatch after load")
	}
}

func TestIdentity_WrongPassphrase_Fails(t *testing.T) {
	home := t.TempDir()
	var ids domain.IdentityStore = store.NewFileStore(home)

	id := domain.Identity{XPub: domain.X25519Public{1}, XPriv: domain.X25519Private{2}}

	if err := ids.Save("correct", id); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	if _, err := ids.LoadIdentity("wrong"); err == nil {
		t.Fatal("expected error with wrong passphrase")
	}
}
