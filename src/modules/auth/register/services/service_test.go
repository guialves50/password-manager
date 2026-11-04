package services

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	prelogin "github.com/guialves50/password-manager/src/modules/auth/prelogin/dto"
	"github.com/guialves50/password-manager/src/modules/auth/register/dto"
)

var testParams = keys.Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}

type fakeAPI struct {
	got   dto.Request
	raw   []byte
	calls int
	err   error
}

func (f *fakeAPI) Register(_ context.Context, req dto.Request) error {
	f.calls++
	f.raw, _ = json.Marshal(req)
	f.got = req
	f.got.AuthHash = bytes.Clone(req.AuthHash)
	f.got.RecoveryAuthHash = bytes.Clone(req.RecoveryAuthHash)
	return f.err
}

func input(email, pw, confirm string) dto.Input {
	return dto.Input{Email: email, Password: []byte(pw), Confirm: []byte(confirm)}
}

func assertNoSecrets(t *testing.T, payload []byte, secrets map[string][]byte) {
	t.Helper()
	for name, s := range secrets {
		for _, form := range []string{string(s), hex.EncodeToString(s), base64.StdEncoding.EncodeToString(s), base64.RawStdEncoding.EncodeToString(s), base64.RawURLEncoding.EncodeToString(s)} {
			if strings.Contains(string(payload), form) {
				t.Fatalf("request contains the %s: %s", name, payload)
			}
		}
	}
}

func TestRegisterSendsOnlyDerivedMaterial(t *testing.T) {
	api := &fakeAPI{}
	svc := &Service{API: api, Params: testParams}
	in := input("  Alice@Example.COM ", "SenhaForte1", "SenhaForte1")

	out, err := svc.Register(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[A-Z2-7]{4}(-[A-Z2-7]{4}){7}$`).MatchString(out.RecoveryKey) {
		t.Fatalf("recovery key %q", out.RecoveryKey)
	}
	r := api.got
	if api.calls != 1 || r.Email != "alice@example.com" {
		t.Fatalf("calls %d email %q", api.calls, r.Email)
	}
	if r.KDF != (prelogin.KDF{Time: testParams.Time, MemoryKiB: testParams.MemoryKiB, Threads: testParams.Threads}) {
		t.Fatalf("kdf %+v", r.KDF)
	}
	if len(r.MasterSalt) != 16 || len(r.RecoverySalt) != 16 || bytes.Equal(r.MasterSalt, r.RecoverySalt) {
		t.Fatalf("salts %x %x", r.MasterSalt, r.RecoverySalt)
	}
	if len(r.MasterBlob) != 60 || len(r.RecoveryBlob) != 60 || len(r.AuthHash) != 32 || len(r.RecoveryAuthHash) != 32 {
		t.Fatalf("lens %d %d %d %d", len(r.MasterBlob), len(r.RecoveryBlob), len(r.AuthHash), len(r.RecoveryAuthHash))
	}

	master := keys.Derive([]byte("SenhaForte1"), r.MasterSalt, testParams)
	auth, enc, _ := keys.Split(master)
	if !bytes.Equal(auth, r.AuthHash) {
		t.Fatal("auth hash is not HKDF(master, pm/auth/v1)")
	}
	v1, err := keys.Open(enc, r.MasterBlob, []byte("pm/master/v1|alice@example.com"))
	if err != nil {
		t.Fatalf("open master blob with encKey: %v", err)
	}
	recSecret := keys.NormalizeRecoveryKey([]byte(out.RecoveryKey))
	recMaster := keys.Derive(recSecret, r.RecoverySalt, testParams)
	recAuth, recEnc, _ := keys.Split(recMaster)
	if !bytes.Equal(recAuth, r.RecoveryAuthHash) {
		t.Fatal("recovery auth hash mismatch")
	}
	v2, err := keys.Open(recEnc, r.RecoveryBlob, []byte("pm/recovery/v1|alice@example.com"))
	if err != nil {
		t.Fatalf("open recovery blob: %v", err)
	}
	if len(v1) != 32 || !bytes.Equal(v1, v2) || bytes.Equal(v1, make([]byte, 32)) {
		t.Fatalf("vault keys %x %x", v1, v2)
	}

	assertNoSecrets(t, api.raw, map[string][]byte{
		"master password": []byte("SenhaForte1"), "recovery key": []byte(out.RecoveryKey), "normalized recovery key": recSecret,
		"vault key": v1, "master key": master, "encKey": enc, "recovery master key": recMaster, "recovery encKey": recEnc,
	})
	if !bytes.Equal(in.Password, make([]byte, len(in.Password))) || !bytes.Equal(in.Confirm, make([]byte, len(in.Confirm))) {
		t.Fatal("input secrets not zeroed")
	}
}

func TestRegisterUniqueMaterialPerUser(t *testing.T) {
	api := &fakeAPI{}
	svc := &Service{API: api, Params: testParams}
	out1, _ := svc.Register(context.Background(), input("a@example.com", "SenhaForte1", "SenhaForte1"))
	r1 := api.got
	out2, _ := svc.Register(context.Background(), input("b@example.com", "SenhaForte1", "SenhaForte1"))
	r2 := api.got
	if out1.RecoveryKey == out2.RecoveryKey || bytes.Equal(r1.MasterSalt, r2.MasterSalt) || bytes.Equal(r1.AuthHash, r2.AuthHash) {
		t.Fatal("random material repeated across users")
	}
}

func TestRegisterValidationNeverCallsServer(t *testing.T) {
	cases := []struct {
		name string
		in   dto.Input
		want error
	}{
		{"empty email", input("", "SenhaForte1", "SenhaForte1"), autherrors.ErrInvalidEmail},
		{"no at", input("alice.example.com", "SenhaForte1", "SenhaForte1"), autherrors.ErrInvalidEmail},
		{"255 chars", input(strings.Repeat("a", 243)+"@example.com", "SenhaForte1", "SenhaForte1"), autherrors.ErrInvalidEmail},
		{"7 chars", input("a@example.com", "Senha12", "Senha12"), autherrors.ErrPasswordLength},
		{"129 chars", input("a@example.com", "A"+strings.Repeat("a", 128), "A"+strings.Repeat("a", 128)), autherrors.ErrPasswordLength},
		{"lowercase only", input("a@example.com", "senhafraca", "senhafraca"), autherrors.ErrPasswordCase},
		{"uppercase only", input("a@example.com", "SENHAFRACA", "SENHAFRACA"), autherrors.ErrPasswordCase},
		{"mismatch", input("a@example.com", "SenhaForte1", "SenhaForte2"), autherrors.ErrPasswordMismatch},
	}
	for _, c := range cases {
		api := &fakeAPI{}
		_, err := (&Service{API: api, Params: testParams}).Register(context.Background(), c.in)
		if err != c.want || api.calls != 0 {
			t.Errorf("%s: got %v, calls %d", c.name, err, api.calls)
		}
	}
}

func TestRegisterServerErrors(t *testing.T) {
	for _, want := range []error{autherrors.ErrEmailTaken, autherrors.ErrUnreachable, errors.New("api: status 500")} {
		api := &fakeAPI{err: want}
		out, err := (&Service{API: api, Params: testParams}).Register(context.Background(), input("a@example.com", "SenhaForte1", "SenhaForte1"))
		if !errors.Is(err, want) || out.RecoveryKey != "" {
			t.Errorf("%v: got %q, %v", want, out.RecoveryKey, err)
		}
	}
}
