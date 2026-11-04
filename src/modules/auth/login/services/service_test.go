package services

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/login/dto"
	prelogin "github.com/guialves50/password-manager/src/modules/auth/prelogin/dto"
)

var testParams = keys.Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}

type fakeAPI struct {
	salt, blob, authHash []byte
	preErr, loginErr     error
	prelogins            []string
	logins               []dto.Request
	raw                  [][]byte
}

func (f *fakeAPI) Prelogin(_ context.Context, email string) (prelogin.Response, error) {
	f.prelogins = append(f.prelogins, email)
	raw, _ := json.Marshal(prelogin.Request{Email: email})
	f.raw = append(f.raw, raw)
	kdf := prelogin.KDF{Time: testParams.Time, MemoryKiB: testParams.MemoryKiB, Threads: testParams.Threads}
	return prelogin.Response{KDF: kdf, MasterSalt: f.salt, RecoverySalt: bytes.Repeat([]byte{7}, 16)}, f.preErr
}

func (f *fakeAPI) Login(_ context.Context, req dto.Request) (dto.Response, error) {
	raw, _ := json.Marshal(req)
	f.raw = append(f.raw, raw)
	req.AuthHash = bytes.Clone(req.AuthHash)
	f.logins = append(f.logins, req)
	if f.loginErr != nil {
		return dto.Response{}, f.loginErr
	}
	if !bytes.Equal(req.AuthHash, f.authHash) {
		return dto.Response{}, autherrors.ErrInvalidCredentials
	}
	return dto.Response{Token: "tok", UserID: 42, MasterBlob: f.blob}, nil
}

func seed(t *testing.T, email, pw string) (*fakeAPI, []byte, [][]byte) {
	t.Helper()
	vk, _ := keys.Random(32)
	salt, _ := keys.Random(16)
	blob, auth, err := keys.Wrap([]byte(pw), salt, testParams, vk, []byte("pm/master/v1|"+email))
	if err != nil {
		t.Fatal(err)
	}
	master := keys.Derive([]byte(pw), salt, testParams)
	_, enc, _ := keys.Split(master)
	return &fakeAPI{salt: salt, blob: blob, authHash: auth}, vk, [][]byte{master, enc}
}

func assertNoSecrets(t *testing.T, payloads [][]byte, secrets map[string][]byte) {
	t.Helper()
	for _, payload := range payloads {
		for name, s := range secrets {
			for _, form := range []string{string(s), hex.EncodeToString(s), base64.StdEncoding.EncodeToString(s), base64.RawStdEncoding.EncodeToString(s), base64.RawURLEncoding.EncodeToString(s)} {
				if strings.Contains(string(payload), form) {
					t.Fatalf("request contains the %s: %s", name, payload)
				}
			}
		}
	}
}

func TestLoginSuccess(t *testing.T) {
	api, vk, derived := seed(t, "alice@example.com", "SenhaForte1")
	in := dto.Input{Email: " Alice@Example.com ", Password: []byte("SenhaForte1")}

	s, err := (&Service{API: api}).Login(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if s.UserID != 42 || s.Email != "alice@example.com" || s.Token != "tok" || !bytes.Equal(s.VaultKey, vk) {
		t.Fatalf("session %+v", s)
	}
	if len(api.prelogins) != 1 || api.prelogins[0] != "alice@example.com" || len(api.logins) != 1 || api.logins[0].Email != "alice@example.com" {
		t.Fatalf("prelogins %q logins %+v", api.prelogins, api.logins)
	}
	assertNoSecrets(t, api.raw, map[string][]byte{"master password": []byte("SenhaForte1"), "vault key": vk, "master key": derived[0], "encKey": derived[1]})
	if !bytes.Equal(in.Password, make([]byte, len(in.Password))) {
		t.Fatal("password not zeroed")
	}
}

func TestLoginWrongPassword(t *testing.T) {
	api, _, _ := seed(t, "alice@example.com", "SenhaForte1")
	s, err := (&Service{API: api}).Login(context.Background(), dto.Input{Email: "alice@example.com", Password: []byte("SenhaErrada1")})
	if s != nil || !errors.Is(err, autherrors.ErrInvalidCredentials) || len(api.logins) != 1 {
		t.Fatalf("got %v, %v, logins %d", s, err, len(api.logins))
	}
	assertNoSecrets(t, api.raw, map[string][]byte{"master password": []byte("SenhaErrada1")})
}

func TestLoginInvalidEmailSendsNothing(t *testing.T) {
	api, _, _ := seed(t, "alice@example.com", "SenhaForte1")
	s, err := (&Service{API: api}).Login(context.Background(), dto.Input{Email: "not-an-email", Password: []byte("SenhaForte1")})
	if s != nil || err != autherrors.ErrInvalidCredentials || len(api.raw) != 0 {
		t.Fatalf("got %v, %v, requests %d", s, err, len(api.raw))
	}
}

func TestLoginServerErrorsPropagate(t *testing.T) {
	locked := &autherrors.LockedError{Minutes: 15}
	cases := []struct {
		name             string
		preErr, loginErr error
		logins           int
	}{
		{"prelogin unreachable", autherrors.ErrUnreachable, nil, 0},
		{"locked", nil, locked, 1},
		{"unknown email", nil, autherrors.ErrInvalidCredentials, 1},
		{"internal", nil, errors.New("api: status 500"), 1},
	}
	for _, c := range cases {
		api, _, _ := seed(t, "alice@example.com", "SenhaForte1")
		api.preErr, api.loginErr = c.preErr, c.loginErr
		want := c.preErr
		if want == nil {
			want = c.loginErr
		}
		s, err := (&Service{API: api}).Login(context.Background(), dto.Input{Email: "alice@example.com", Password: []byte("SenhaForte1")})
		if s != nil || !errors.Is(err, want) || len(api.logins) != c.logins {
			t.Errorf("%s: got %v, %v, logins %d", c.name, s, err, len(api.logins))
		}
	}
}

func TestLoginBlobBoundToEmail(t *testing.T) {
	api, _, _ := seed(t, "bob@example.com", "SenhaForte1")
	api.blob = func() []byte {
		vk, _ := keys.Random(32)
		blob, _, _ := keys.Wrap([]byte("SenhaForte1"), api.salt, testParams, vk, []byte("pm/master/v1|alice@example.com"))
		return blob
	}()
	s, err := (&Service{API: api}).Login(context.Background(), dto.Input{Email: "bob@example.com", Password: []byte("SenhaForte1")})
	if s != nil || err == nil || autherrors.Message(err) != "erro interno" {
		t.Fatalf("got %v, %v", s, err)
	}
}
