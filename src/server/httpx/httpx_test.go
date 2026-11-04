package httpx

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func bigJSON(n int) string {
	return `{"email":"` + strings.Repeat("a", n) + `"}`
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type %q", ct)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", rec.Body, err)
	}
	return body["error"].(string)
}

type payload struct {
	Email string `json:"email"`
}

func decode(body string) (*httptest.ResponseRecorder, payload, bool) {
	rec := httptest.NewRecorder()
	var p payload
	ok := Decode(rec, httptest.NewRequest("POST", "/", strings.NewReader(body)), &p)
	return rec, p, ok
}

func TestDecodeValid(t *testing.T) {
	rec, p, ok := decode(`{"email":"a@b.com"}`)
	if !ok || p.Email != "a@b.com" || rec.Body.Len() != 0 {
		t.Fatalf("ok=%v p=%+v body=%q", ok, p, rec.Body)
	}
	if _, _, ok := decode(bigJSON(MaxBody - 20)); !ok {
		t.Fatal("body under 64 KiB rejected")
	}
}

func TestDecodeTooLarge(t *testing.T) {
	rec, _, ok := decode(bigJSON(65 << 10))
	if ok || rec.Code != http.StatusRequestEntityTooLarge || errorCode(t, rec) != "too_large" {
		t.Fatalf("ok=%v code=%d body=%q", ok, rec.Code, rec.Body)
	}
}

func TestDecodeInvalid(t *testing.T) {
	for _, body := range []string{"", "{", "not json", `{"email":1}`, `{"email":"a"} {}`} {
		rec, _, ok := decode(body)
		if ok || rec.Code != http.StatusBadRequest || errorCode(t, rec) != "invalid_request" {
			t.Errorf("%q: ok=%v code=%d body=%q", body, ok, rec.Code, rec.Body)
		}
	}
}

func TestErrorAndLockedFormat(t *testing.T) {
	rec := httptest.NewRecorder()
	Error(rec, http.StatusConflict, "email_taken")
	if rec.Code != http.StatusConflict || strings.TrimSpace(rec.Body.String()) != `{"error":"email_taken"}` {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	Locked(rec, 7)
	if rec.Code != http.StatusLocked || strings.TrimSpace(rec.Body.String()) != `{"error":"locked","minutes":7}` {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	JSON(rec, http.StatusCreated, map[string]int{"n": 1})
	if rec.Code != http.StatusCreated || rec.Header().Get("Content-Type") != "application/json" || strings.TrimSpace(rec.Body.String()) != `{"n":1}` {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
}

func TestLimit(t *testing.T) {
	var read int
	h := Limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		read = len(b)
		if err != nil {
			Error(w, http.StatusRequestEntityTooLarge, "too_large")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	read = -1
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/", strings.NewReader(bigJSON(65<<10))))
	if rec.Code != http.StatusRequestEntityTooLarge || errorCode(t, rec) != "too_large" || read != -1 {
		t.Fatalf("known length: code=%d read=%d", rec.Code, read)
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", io.MultiReader(strings.NewReader(bigJSON(65<<10))))
	req.ContentLength = -1
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge || read > MaxBody {
		t.Fatalf("chunked: code=%d read=%d", rec.Code, read)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/", strings.NewReader("{}")))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("small: %d", rec.Code)
	}
}
