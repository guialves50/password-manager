package main

import (
	"context"
	"fmt"
	"io"
	"maps"
	"os"

	"github.com/guialves50/password-manager/src/cli"
	"github.com/guialves50/password-manager/src/database"
	login "github.com/guialves50/password-manager/src/modules/auth/login/router"
	recover "github.com/guialves50/password-manager/src/modules/auth/recover/router"
	register "github.com/guialves50/password-manager/src/modules/auth/register/router"
)

func run(args []string, routes map[string]cli.Command, p *cli.Prompter, stderr io.Writer) int {
	if len(args) == 0 || routes[args[0]] == nil {
		fmt.Fprintln(stderr, "uso: pm <register|login|recover>")
		return 2
	}
	if err := routes[args[0]](context.Background(), p); err != nil {
		return 1
	}
	return 0
}

func main() {
	db, err := database.Connect()
	if err != nil {
		fmt.Fprintln(os.Stderr, "não foi possível conectar ao banco de dados")
		os.Exit(1)
	}
	routes := register.Routes(db)
	maps.Copy(routes, login.Routes(db))
	maps.Copy(routes, recover.Routes(db))
	os.Exit(run(os.Args[1:], routes, cli.NewTerminalPrompter(), os.Stderr))
}
