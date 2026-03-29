package handlers

import (
	"encoding/json"
	"net/http"

	"backend/internal/buildinfo"
)

// HealthHandler returns a simple status check.
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": buildinfo.Version,
	})
}
