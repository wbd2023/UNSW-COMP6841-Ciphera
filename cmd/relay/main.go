package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type PrekeyBundle struct {
	Username string `json:"username"`
	// TODO: rest ignored for now
}

func main() {
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var b map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		fmt.Println("Received /register bundle for", b["Username"])
		w.WriteHeader(200)
	})

	log.Println("relay listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
