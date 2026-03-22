package main

import (
	"fmt"
	"os"
	"sort"
)

func main() {
	env := os.Environ()
	sort.Strings(env)
	for _, e := range env {
		fmt.Printf("%s\n", e)
	}
}
