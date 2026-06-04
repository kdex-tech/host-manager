package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	http.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ECHO %s", r.URL.Path)
	})
	http.HandleFunc("/env", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "AUDIENCE=%q JWKS_URL=%q PKS_URL=%q",
			os.Getenv("AUDIENCE"), os.Getenv("JWKS_URL"), os.Getenv("PKS_URL"))
	})
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
