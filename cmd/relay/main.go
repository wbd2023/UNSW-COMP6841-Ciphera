package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"ciphera/internal/domain"
)

type memoryStore struct {
	mu      sync.RWMutex
	bundles map[string]domain.PrekeyBundle
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		bundles: make(map[string]domain.PrekeyBundle),
	}
}

func main() {
	ms := newMemoryStore()

	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var b domain.PrekeyBundle
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		ms.mu.Lock()
		ms.bundles[b.Username] = b
		ms.mu.Unlock()
		fmt.Println("Received /register bundle for", b.Username)
		w.WriteHeader(200)
	})

	http.HandleFunc("/prekey/", func(w http.ResponseWriter, r *http.Request) {
		username := r.URL.Path[len("/prekey/"):]
		ms.mu.RLock()
		b, ok := ms.bundles[username]
		ms.mu.RUnlock()
		if !ok {
			http.Error(w, "not found", 404)
			return
		}
		_ = json.NewEncoder(w).Encode(b)
	})

	log.Println("relay listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
