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
	items "github.com/guialves50/password-manager/src/modules/vault/items/router"
	"gorm.io/gorm"
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

func start(connect func() (*gorm.DB, error), args []string, p *cli.Prompter, stderr io.Writer) int {
	db, err := connect()
	if err != nil {
		fmt.Fprintln(stderr, "não foi possível conectar ao banco de dados")
		return 1
	}
	routes := register.Routes(db)
	maps.Copy(routes, login.Routes(db, items.Routes(db)))
	maps.Copy(routes, recover.Routes(db))
	return run(args, routes, p, stderr)
}

func main() {
	os.Exit(start(database.Connect, os.Args[1:], cli.NewTerminalPrompter(), os.Stderr))
}
