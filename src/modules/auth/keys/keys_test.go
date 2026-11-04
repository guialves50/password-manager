package keys

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"regexp"
	"testing"
)

var cheap = Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}

func TestDefaultParams(t *testing.T) {
	if DefaultParams != (Params{Time: 3, MemoryKiB: 65536, Threads: 4}) {
		t.Fatalf("got %+v", DefaultParams)
	}
}

func TestDerive(t *testing.T) {
	salt1, _ := Random(16)
	salt2, _ := Random(16)
	a := Derive([]byte("Senha123"), salt1, cheap)
	b := Derive([]byte("Senha123"), salt1, cheap)
	c := Derive([]byte("Senha123"), salt2, cheap)
	if len(a) != 32 {
		t.Fatalf("len %d", len(a))
	}
	if !bytes.Equal(a, b) {
		t.Fatal("not deterministic")
	}
	if bytes.Equal(a, c) {
		t.Fatal("same key for different salts")
	}
}

func TestSealOpen(t *testing.T) {
	key, _ := Random(32)
	other, _ := Random(32)
	vault, _ := Random(32)
	aad := []byte("pm/master/v1|a@b.com")
	blob, err := Seal(key, vault, aad)
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) != 12+32+16 {
		t.Fatalf("blob len %d", len(blob))
	}
	got, err := Open(key, blob, aad)
	if err != nil || !bytes.Equal(got, vault) {
		t.Fatalf("round-trip failed: %v", err)
	}
	if _, err := Open(other, blob, aad); err == nil {
		t.Fatal("opened with wrong key")
	}
	if _, err := Open(key, blob, []byte("pm/master/v1|c@d.com")); err == nil {
		t.Fatal("opened with different aad")
	}
	tampered := bytes.Clone(blob)
	tampered[len(tampered)-1] ^= 1
	if _, err := Open(key, tampered, aad); err == nil {
		t.Fatal("opened tampered blob")
	}
	if _, err := Open(key, blob[:5], aad); err == nil {
		t.Fatal("opened truncated blob")
	}
}

func TestRandom(t *testing.T) {
	a, _ := Random(16)
	b, _ := Random(16)
	if len(a) != 16 || bytes.Equal(a, b) {
		t.Fatal("bad random")
	}
}

func TestZero(t *testing.T) {
	b := []byte{1, 2, 3}
	Zero(b)
	if !bytes.Equal(b, []byte{0, 0, 0}) {
		t.Fatal(b)
	}
}

func TestRecoveryKey(t *testing.T) {
	k, err := NewRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[A-Z2-7]{4}(-[A-Z2-7]{4}){7}$`).MatchString(k) {
		t.Fatalf("bad format %q", k)
	}
	k2, _ := NewRecoveryKey()
	if k == k2 {
		t.Fatal("not random")
	}
	want := NormalizeRecoveryKey([]byte(k))
	if len(want) != 32 {
		t.Fatalf("normalized len %d", len(want))
	}
	for _, in := range []string{"abcd-efgh ijkl", " ABCDEFGHIJKL ", "aBcD efGH-IjKl"} {
		if got := NormalizeRecoveryKey([]byte(in)); string(got) != "ABCDEFGHIJKL" {
			t.Errorf("%q -> %q", in, got)
		}
	}
}

func TestSealNoncesUnique(t *testing.T) {
	key, _ := Random(32)
	vault, _ := Random(32)
	aad := []byte("pm/master/v1|a@b.com")
	a, err := Seal(key, vault, aad)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Seal(key, vault, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a[:12], b[:12]) || bytes.Equal(a, b) {
		t.Fatal("nonce reused")
	}
}

func TestSplit(t *testing.T) {
	master, _ := Random(32)
	auth, enc, err := Split(master)
	if err != nil {
		t.Fatal(err)
	}
	if len(auth) != 32 || len(enc) != 32 {
		t.Fatalf("lens %d %d", len(auth), len(enc))
	}
	if bytes.Equal(auth, enc) {
		t.Fatal("auth == enc")
	}
	auth2, enc2, _ := Split(master)
	if !bytes.Equal(auth, auth2) || !bytes.Equal(enc, enc2) {
		t.Fatal("not deterministic")
	}
	wantAuth, _ := hkdf.Key(sha256.New, master, nil, "pm/auth/v1", 32)
	wantEnc, _ := hkdf.Key(sha256.New, master, nil, "pm/enc/v1", 32)
	if !bytes.Equal(auth, wantAuth) || !bytes.Equal(enc, wantEnc) {
		t.Fatal("labels swapped or wrong")
	}
	other, _ := Random(32)
	if a, _, _ := Split(other); bytes.Equal(a, auth) {
		t.Fatal("same auth for different master")
	}
}
