package main

import (
  "fmt"
  "os"

  "backend/internal/core/auth"
)

func main() {
  if len(os.Args) < 2 {
    panic("password required")
  }
  h, err := auth.HashPassword(os.Args[1])
  if err != nil {
    panic(err)
  }
  fmt.Print(h)
}
