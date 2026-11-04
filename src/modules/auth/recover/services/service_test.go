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
	"github.com/guialves50/password-manager/src/modules/auth/recover/dto"
)

var testParams = keys.Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}

func input(email, rk, pw, confirm string) dto.Input {
	return dto.Input{Email: email, RecoveryKey: []byte(rk), Password: []byte(pw), Confirm: []byte(confirm)}
}

type fakeAPI struct {
	email                       string
	recoverySalt, recoveryBlob  []byte
	recoveryAuth                []byte
	preErr, startErr, finishErr error
	prelogins, starts, finishes int
	finished                    dto.FinishRequest
	raw                         [][]byte
}

func (f *fakeAPI) Prelogin(_ context.Context, email string) (prelogin.Response, error) {
	f.prelogins++
	raw, _ := json.Marshal(prelogin.Request{Email: email})
	f.raw = append(f.raw, raw)
	kdf := prelogin.KDF{Time: testParams.Time, MemoryKiB: testParams.MemoryKiB, Threads: testParams.Threads}
	return prelogin.Response{KDF: kdf, MasterSalt: bytes.Repeat([]byte{1}, 16), RecoverySalt: f.recoverySalt}, f.preErr
}

func (f *fakeAPI) RecoverStart(_ context.Context, req dto.StartRequest) (dto.StartResponse, error) {
	f.starts++
	raw, _ := json.Marshal(req)
	f.raw = append(f.raw, raw)
	if f.startErr != nil {
		return dto.StartResponse{}, f.startErr
	}
	if req.Email != f.email || !bytes.Equal(req.RecoveryAuthHash, f.recoveryAuth) {
		return dto.StartResponse{}, autherrors.ErrInvalidRecovery
	}
	return dto.StartResponse{RecoveryBlob: f.recoveryBlob}, nil
}

func (f *fakeAPI) RecoverFinish(_ context.Context, req dto.FinishRequest) error {
	f.finishes++
	raw, _ := json.Marshal(req)
	f.raw = append(f.raw, raw)
	f.finished = req
	f.finished.RecoveryAuthHash = bytes.Clone(req.RecoveryAuthHash)
	f.finished.AuthHash = bytes.Clone(req.AuthHash)
	f.finished.NewRecoveryAuthHash = bytes.Clone(req.NewRecoveryAuthHash)
	return f.finishErr
}

func seed(t *testing.T, email string) (*fakeAPI, []byte, string) {
	t.Helper()
	vk, _ := keys.Random(32)
	rs, _ := keys.Random(16)
	rk, _ := keys.NewRecoveryKey()
	blob, auth, err := keys.Wrap(keys.NormalizeRecoveryKey([]byte(rk)), rs, testParams, vk, []byte("pm/recovery/v1|"+email))
	if err != nil {
		t.Fatal(err)
	}
	return &fakeAPI{email: email, recoverySalt: rs, recoveryBlob: blob, recoveryAuth: auth}, vk, rk
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

func TestRecoverRotatesThroughServer(t *testing.T) {
	api, vk, oldKey := seed(t, "alice@example.com")
	messy := " " + strings.ToLower(strings.ReplaceAll(oldKey, "-", " ")) + " "
	in := input(" Alice@Example.com ", messy, "SenhaNova1", "SenhaNova1")

	out, err := (&Service{API: api}).Recover(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[A-Z2-7]{4}(-[A-Z2-7]{4}){7}$`).MatchString(out.RecoveryKey) || out.RecoveryKey == oldKey {
		t.Fatalf("new recovery key %q (old %q)", out.RecoveryKey, oldKey)
	}
	if api.prelogins != 1 || api.starts != 1 || api.finishes != 1 {
		t.Fatalf("calls %d %d %d", api.prelogins, api.starts, api.finishes)
	}
	f := api.finished
	if f.Email != "alice@example.com" || !bytes.Equal(f.RecoveryAuthHash, api.recoveryAuth) {
		t.Fatalf("finish not authenticated with the old recovery auth hash: %+v", f)
	}
	if len(f.MasterSalt) != 16 || len(f.RecoverySalt) != 16 || bytes.Equal(f.MasterSalt, f.RecoverySalt) || bytes.Equal(f.RecoverySalt, api.recoverySalt) {
		t.Fatal("salts not renewed")
	}
	if len(f.MasterBlob) != 60 || len(f.RecoveryBlob) != 60 || len(f.AuthHash) != 32 || len(f.NewRecoveryAuthHash) != 32 || bytes.Equal(f.NewRecoveryAuthHash, api.recoveryAuth) {
		t.Fatalf("finish fields %+v", f)
	}

	master := keys.Derive([]byte("SenhaNova1"), f.MasterSalt, testParams)
	auth, enc, _ := keys.Split(master)
	v1, err := keys.Open(enc, f.MasterBlob, []byte("pm/master/v1|alice@example.com"))
	if err != nil || !bytes.Equal(auth, f.AuthHash) {
		t.Fatalf("new master blob: %v", err)
	}
	newSecret := keys.NormalizeRecoveryKey([]byte(out.RecoveryKey))
	recMaster := keys.Derive(newSecret, f.RecoverySalt, testParams)
	recAuth, recEnc, _ := keys.Split(recMaster)
	v2, err := keys.Open(recEnc, f.RecoveryBlob, []byte("pm/recovery/v1|alice@example.com"))
	if err != nil || !bytes.Equal(recAuth, f.NewRecoveryAuthHash) {
		t.Fatalf("new recovery blob: %v", err)
	}
	if !bytes.Equal(v1, vk) || !bytes.Equal(v2, vk) {
		t.Fatal("vault key changed")
	}

	oldSecret := keys.NormalizeRecoveryKey([]byte(oldKey))
	oldMaster := keys.Derive(oldSecret, api.recoverySalt, testParams)
	_, oldEnc, _ := keys.Split(oldMaster)
	assertNoSecrets(t, api.raw, map[string][]byte{
		"new password": []byte("SenhaNova1"), "old recovery key": []byte(oldKey), "old normalized recovery key": oldSecret,
		"new recovery key": []byte(out.RecoveryKey), "new normalized recovery key": newSecret, "vault key": vk,
		"master key": master, "encKey": enc, "old recovery master key": oldMaster, "old recovery encKey": oldEnc,
		"new recovery master key": recMaster, "new recovery encKey": recEnc,
	})
	for _, b := range [][]byte{in.RecoveryKey, in.Password, in.Confirm} {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatal("input secrets not zeroed")
		}
	}
}

func TestRecoverPolicyErrorsSendNothing(t *testing.T) {
	cases := []struct {
		name string
		in   dto.Input
		want error
	}{
		{"short", input("alice@example.com", "x", "Senha12", "Senha12"), autherrors.ErrPasswordLength},
		{"long", input("alice@example.com", "x", "A"+strings.Repeat("a", 128), "A"+strings.Repeat("a", 128)), autherrors.ErrPasswordLength},
		{"lowercase", input("alice@example.com", "x", "senhafraca", "senhafraca"), autherrors.ErrPasswordCase},
		{"uppercase", input("alice@example.com", "x", "SENHAFRACA", "SENHAFRACA"), autherrors.ErrPasswordCase},
		{"mismatch", input("alice@example.com", "x", "SenhaNova1", "SenhaNova2"), autherrors.ErrPasswordMismatch},
		{"invalid email", input("not-an-email", "x", "SenhaNova1", "SenhaNova1"), autherrors.ErrInvalidRecovery},
	}
	for _, c := range cases {
		api, _, _ := seed(t, "alice@example.com")
		_, err := (&Service{API: api}).Recover(context.Background(), c.in)
		if err != c.want || len(api.raw) != 0 {
			t.Errorf("%s: got %v, requests %d", c.name, err, len(api.raw))
		}
	}
}

func TestRecoverWrongKeyNeverFinishes(t *testing.T) {
	api, _, _ := seed(t, "alice@example.com")
	other, _ := keys.NewRecoveryKey()
	out, err := (&Service{API: api}).Recover(context.Background(), input("alice@example.com", other, "SenhaNova1", "SenhaNova1"))
	if !errors.Is(err, autherrors.ErrInvalidRecovery) || out.RecoveryKey != "" || api.finishes != 0 {
		t.Fatalf("got %q, %v, finishes %d", out.RecoveryKey, err, api.finishes)
	}
	assertNoSecrets(t, api.raw, map[string][]byte{"recovery key": []byte(other), "normalized recovery key": keys.NormalizeRecoveryKey([]byte(other))})
}

func TestRecoverServerErrorsPropagate(t *testing.T) {
	cases := []struct {
		name                        string
		preErr, startErr, finishErr error
		finishes                    int
	}{
		{"unreachable", autherrors.ErrUnreachable, nil, nil, 0},
		{"locked", nil, &autherrors.LockedError{Minutes: 15}, nil, 0},
		{"unknown email", nil, autherrors.ErrInvalidRecovery, nil, 0},
		{"concurrent rotation", nil, nil, autherrors.ErrInvalidRecovery, 1},
		{"internal", nil, nil, errors.New("api: status 500"), 1},
	}
	for _, c := range cases {
		api, _, rk := seed(t, "alice@example.com")
		api.preErr, api.startErr, api.finishErr = c.preErr, c.startErr, c.finishErr
		want := errors.Join(c.preErr, c.startErr, c.finishErr)
		out, err := (&Service{API: api}).Recover(context.Background(), input("alice@example.com", rk, "SenhaNova1", "SenhaNova1"))
		if err == nil || autherrors.Message(err) != autherrors.Message(want) || out.RecoveryKey != "" || api.finishes != c.finishes {
			t.Errorf("%s: got %q, %v, finishes %d", c.name, out.RecoveryKey, err, api.finishes)
		}
	}
}

func TestRecoverBlobBoundToEmail(t *testing.T) {
	api, _, rk := seed(t, "alice@example.com")
	api.email = "bob@example.com"
	_, auth, _ := keys.Wrap(keys.NormalizeRecoveryKey([]byte(rk)), api.recoverySalt, testParams, make([]byte, 32), nil)
	api.recoveryAuth = auth
	out, err := (&Service{API: api}).Recover(context.Background(), input("bob@example.com", rk, "SenhaNova1", "SenhaNova1"))
	if err == nil || out.RecoveryKey != "" || api.finishes != 0 {
		t.Fatalf("got %q, %v, finishes %d", out.RecoveryKey, err, api.finishes)
	}
}
