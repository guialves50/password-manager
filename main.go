package main

import (
	"log"

	"github.com/guialves50/password-manager/src/database"
)

func main() {
	if _, err := database.Connect(); err != nil {
		log.Fatal(err)
	}
	log.Println("database connected")
}
