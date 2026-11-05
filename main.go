package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/guialves50/password-manager/src/api"
	"github.com/guialves50/password-manager/src/cli"
	"github.com/guialves50/password-manager/src/database"
	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	login "github.com/guialves50/password-manager/src/modules/auth/login/router"
	recover "github.com/guialves50/password-manager/src/modules/auth/recover/router"
	register "github.com/guialves50/password-manager/src/modules/auth/register/router"
	twofactor "github.com/guialves50/password-manager/src/modules/auth/twofactor/router"
	items "github.com/guialves50/password-manager/src/modules/vault/items/router"
	"github.com/guialves50/password-manager/src/server"
	"github.com/guialves50/password-manager/src/tui"
	"golang.org/x/term"
	"gorm.io/gorm"
)

func usage(stderr io.Writer) int {
	fmt.Fprintln(stderr, "uso: guardian <serve|register|login|recover>")
	return 2
}

func run(args []string, routes map[string]cli.Command, p *cli.Prompter, stderr io.Writer) int {
	if len(args) == 0 || routes[args[0]] == nil {
		return usage(stderr)
	}
	if err := routes[args[0]](context.Background(), p); err != nil {
		return 1
	}
	return 0
}

func start(args []string, p *cli.Prompter, stderr io.Writer) int {
	if len(args) == 0 {
		return usage(stderr)
	}
	switch args[0] {
	case "serve":
		return serve(database.Connect, p.Out, stderr)
	case "register", "login", "recover":
	default:
		return usage(stderr)
	}
	routes, err := clientRoutes()
	if err != nil {
		fmt.Fprintln(stderr, autherrors.Message(err))
		return 1
	}
	return run(args, routes, p, stderr)
}

func serverURL() string {
	return cmp.Or(os.Getenv("PM_SERVER"), "http://127.0.0.1:8080")
}

func clientRoutes() (map[string]cli.Command, error) {
	c, err := api.New(serverURL())
	if err != nil {
		return nil, err
	}
	routes := register.Routes(c)
	cmds := items.Routes(c)
	maps.Copy(cmds, twofactor.Routes(c))
	maps.Copy(routes, login.Routes(c, cmds))
	maps.Copy(routes, recover.Routes(c))
	return routes, nil
}

func home(routes map[string]cli.Command, p *cli.Prompter) {
	for {
		line, err := p.Line("")
		if err != nil {
			return
		}
		switch line = strings.TrimSpace(line); {
		case line == "exit":
			return
		case routes[line] != nil:
			routes[line](context.Background(), p)
		case line != "":
			fmt.Fprintln(p.Out, "comando desconhecido")
		}
	}
}

func interactive(stderr io.Writer) int {
	routes, err := clientRoutes()
	if err != nil {
		fmt.Fprintln(stderr, autherrors.Message(err))
		return 1
	}
	if err := tui.Run(serverURL(), func(p *cli.Prompter) { home(routes, p) }); err != nil {
		fmt.Fprintln(stderr, "não foi possível abrir a interface:", err)
		return 1
	}
	return 0
}

func serve(connect func() (*gorm.DB, error), stdout, stderr io.Writer) int {
	addr := cmp.Or(os.Getenv("PM_ADDR"), "127.0.0.1:8080")
	certFile, keyFile := os.Getenv("PM_TLS_CERT"), os.Getenv("PM_TLS_KEY")
	if (certFile == "") != (keyFile == "") {
		fmt.Fprintln(stderr, "PM_TLS_CERT e PM_TLS_KEY devem ser definidos juntos")
		return 1
	}
	secret, err := serverSecret(stderr)
	if err != nil {
		fmt.Fprintln(stderr, "PM_SERVER_SECRET deve ter 32 bytes em hexadecimal")
		return 1
	}
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: time.Minute, IdleTimeout: 2 * time.Minute}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			fmt.Fprintln(stderr, "não foi possível carregar o certificado TLS")
			return 1
		}
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	db, err := connect()
	if err != nil {
		fmt.Fprintln(stderr, "não foi possível preparar o banco de dados")
		return 1
	}
	srv.Handler = server.New(db, server.Config{Secret: secret, AuthParams: keys.DefaultParams})
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(stderr, "não foi possível escutar em", addr)
		return 1
	}
	fmt.Fprintln(stdout, "servidor ouvindo em", ln.Addr())
	if srv.TLSConfig != nil {
		err = srv.ServeTLS(ln, "", "")
	} else {
		err = srv.Serve(ln)
	}
	fmt.Fprintln(stderr, err)
	return 1
}

func serverSecret(stderr io.Writer) ([]byte, error) {
	h := os.Getenv("PM_SERVER_SECRET")
	if h == "" {
		fmt.Fprintln(stderr, "aviso: PM_SERVER_SECRET não definido; respostas de pré-login para emails não cadastrados mudam a cada reinício")
		return keys.Random(32)
	}
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		return nil, errors.New("invalid server secret")
	}
	return b, nil
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 && term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())) {
		os.Exit(interactive(os.Stderr))
	}
	os.Exit(start(args, cli.NewTerminalPrompter(), os.Stderr))
}
