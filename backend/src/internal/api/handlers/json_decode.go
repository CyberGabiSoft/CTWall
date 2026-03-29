package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// decodeJSON parses JSON payload into dst and rejects unknown fields or trailing data.
func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return errors.New("invalid JSON payload")
	}
	return nil
}

// decodeOptionalJSON parses JSON when present; empty body is allowed.
func decodeOptionalJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return errors.New("invalid JSON payload")
	}
	return nil
}
