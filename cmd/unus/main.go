package main

import (
	"log"

	"code.leif.uk/lwg/unus/internal/unus"
)

func main() {
	log.Println("Unus: One time secret sharing.")
	log.Fatal(unus.Serve(":8080"))
}
