package main

import (
	"fmt"
	"os"

	"github.com/perplext/zerodaybuddy/internal/auth"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run cmd/hashpass/main.go <password>")
		os.Exit(1)
	}

	password := os.Args[1]
	hash, err := auth.HashPassword(password)
	if err != nil {
		fmt.Printf("Error hashing password: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Password hash: %s\n", hash)
}