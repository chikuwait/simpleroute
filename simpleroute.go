package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Arg Err")
		os.Exit(1)
	}
	s_addr := os.Args[1]
	fmt.Printf("s_addr %s\n",s_addr)
}
