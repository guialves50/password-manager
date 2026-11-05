package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

const MaxBody = 64 << 10

func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func Error(w http.ResponseWriter, status int, code string) {
	JSON(w, status, map[string]string{"error": code})
}

func Locked(w http.ResponseWriter, minutes int) {
	JSON(w, http.StatusLocked, map[string]any{"error": "locked", "minutes": minutes})
}

func Decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBody))
	err := dec.Decode(v)
	if err == nil && dec.Decode(&struct{}{}) != io.EOF {
		err = errors.New("trailing data")
	}
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		Error(w, http.StatusRequestEntityTooLarge, "too_large")
		return false
	case err != nil:
		Error(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

func Limit(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > MaxBody {
			Error(w, http.StatusRequestEntityTooLarge, "too_large")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
		h.ServeHTTP(w, r)
	})
}

func Gate(n int) func(http.Handler) http.Handler {
	slots := make(chan struct{}, n)
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
				h.ServeHTTP(w, r)
			default:
				Error(w, http.StatusServiceUnavailable, "busy")
			}
		})
	}
}
