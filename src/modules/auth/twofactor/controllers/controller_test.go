package controllers

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/guialves50/password-manager/src/cli"
	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/twofactor/dto"
)

const uri = "otpauth://totp/Guardian:ana@x.com?issuer=Guardian&secret=AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"

type spy struct {
	arts   [][]string
	checks int
	codes  []string
	token  string
}

func (s *spy) prompter(input string) (*cli.Prompter, *bytes.Buffer) {
	var out bytes.Buffer
	return &cli.Prompter{
		In:        bufio.NewReader(strings.NewReader(input)),
		Out:       &out,
		ShowArt:   func(l []string) { s.arts = append(s.arts, l) },
		ShowCheck: func() { s.checks++ },
	}, &out
}

func (s *spy) setup(err error) SetupFunc {
	return func(_ context.Context, sess *cli.Session) (dto.SetupResponse, error) {
		s.token = sess.Token
		return dto.SetupResponse{Secret: "AAAABBBB", URI: uri}, err
	}
}

func (s *spy) confirm(err error) ConfirmFunc {
	return func(_ context.Context, _ *cli.Session, code string) error {
		s.codes = append(s.codes, code)
		return err
	}
}

var sess = &cli.Session{Token: "tok"}

func TestActivateShowsQRThenCheck(t *testing.T) {
	sp := &spy{}
	p, out := sp.prompter(" 123456 \n")
	if err := New(sp.setup(nil), sp.confirm(nil))(context.Background(), p, sess, ""); err != nil {
		t.Fatal(err)
	}
	if sp.token != "tok" || len(sp.codes) != 1 || sp.codes[0] != "123456" {
		t.Fatalf("token %q codes %q", sp.token, sp.codes)
	}
	if len(sp.arts) != 1 || sp.arts[0][len(sp.arts[0])-1] != "chave: AAAABBBB" || !strings.Contains(sp.arts[0][0], "▀") {
		t.Fatalf("arts %q", sp.arts)
	}
	if out.String() != "código 2FA: 2FA ativado\n" || sp.checks != 1 {
		t.Fatalf("out %q checks %d", out.String(), sp.checks)
	}
}

func TestActivateFailures(t *testing.T) {
	cases := []struct {
		name               string
		input              string
		setupErr, confErr  error
		want               string
		wantArts, confirms int
	}{
		{"wrong code", "000000\n", nil, autherrors.ErrInvalidTOTP, "código 2FA: código 2FA inválido\n", 2, 1},
		{"locked", "000000\n", nil, &autherrors.LockedError{Minutes: 10}, "código 2FA: conta bloqueada, tente novamente em 10 minutos\n", 2, 1},
		{"no pending", "000000\n", nil, autherrors.ErrNoPendingTOTP, "código 2FA: rode 2fa novamente\n", 2, 1},
		{"cancelled", "", nil, nil, "código 2FA: operação cancelada\n", 2, 0},
		{"already active", "", autherrors.ErrTOTPEnabled, nil, "2FA já está ativo\n", 1, 0},
	}
	for _, c := range cases {
		sp := &spy{}
		p, out := sp.prompter(c.input)
		err := New(sp.setup(c.setupErr), sp.confirm(c.confErr))(context.Background(), p, sess, "")
		if err == nil || out.String() != c.want || sp.checks != 0 || len(sp.codes) != c.confirms {
			t.Errorf("%s: err %v out %q checks %d codes %q", c.name, err, out.String(), sp.checks, sp.codes)
		}
		if len(sp.arts) != c.wantArts || sp.arts[len(sp.arts)-1] != nil {
			t.Errorf("%s: art not cleared: %d", c.name, len(sp.arts))
		}
		if c.name == "cancelled" && !errors.Is(err, io.EOF) {
			t.Errorf("cancel err %v", err)
		}
	}
}

func TestActivateWithoutTUIPrintsQR(t *testing.T) {
	sp := &spy{}
	p, out := sp.prompter("123456\n")
	p.ShowArt, p.ShowCheck = nil, nil
	if err := New(sp.setup(nil), sp.confirm(nil))(context.Background(), p, sess, ""); err != nil {
		t.Fatal(err)
	}
	o := out.String()
	if !strings.Contains(o, "▀") || !strings.Contains(o, "\nchave: AAAABBBB\ncódigo 2FA: 2FA ativado\n") {
		t.Fatalf("out %q", o)
	}
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func TestQRIsSquareWithLightQuietZone(t *testing.T) {
	lines, err := QR(uri)
	if err != nil {
		t.Fatal(err)
	}
	width := utf8.RuneCountInString(ansi.ReplaceAllString(lines[0], ""))
	if width < 25 || len(lines) != (width+1)/2 {
		t.Fatalf("width %d rows %d", width, len(lines))
	}
	for _, l := range lines {
		if utf8.RuneCountInString(ansi.ReplaceAllString(l, "")) != width {
			t.Fatalf("ragged line %q", l)
		}
	}
	if strings.Contains(lines[0], "38;5;16m") || strings.Contains(lines[0], "48;5;16m") {
		t.Fatal("quiet zone row has dark modules")
	}
	if !strings.Contains(lines[1], "38;5;16m") {
		t.Fatal("finder pattern missing on second row")
	}
}

// TFA-02 AC2: the drawn modules are exactly the QR symbol of the URI.
func TestQREncodesURI(t *testing.T) {
	q, err := qrcode.New(uri, qrcode.Low)
	if err != nil {
		t.Fatal(err)
	}
	q.DisableBorder = true
	want := q.Bitmap()
	lines, err := QR(uri)
	if err != nil {
		t.Fatal(err)
	}
	cell := regexp.MustCompile(`\x1b\[38;5;(\d+)m\x1b\[48;5;(\d+)m▀`)
	var grid [][]bool
	for _, l := range lines {
		top, bot := []bool{}, []bool{}
		for _, m := range cell.FindAllStringSubmatch(l, -1) {
			top, bot = append(top, m[1] == "16"), append(bot, m[2] == "16")
		}
		grid = append(grid, top, bot)
	}
	n := len(want)
	for y := range n {
		for x := range n {
			if grid[y+2][x+2] != want[y][x] {
				t.Fatalf("module (%d,%d) differs", x, y)
			}
		}
	}
}
