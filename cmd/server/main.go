package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"grantgate/internal/grants"
)

func main() {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	ctx := context.Background()
	var store *grants.Store
	var err error
	for attempt := 0; attempt < 30; attempt++ {
		store, err = grants.NewStore(ctx, databaseURL)
		if err == nil {
			break
		}
		log.Printf("waiting for database: %v", err)
		time.Sleep(time.Second)
	}
	if err != nil {
		log.Fatalf("connect database: %v", err)
	}
	defer store.Close()

	log.Printf("grantgate api listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, grants.NewServer(store)))
}
