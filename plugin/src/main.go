package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "daemon" {
		if len(os.Args) > 2 {
			switch os.Args[2] {
			case "status":
				daemonStatus()
			case "stop":
				daemonStop()
			case "restart":
				daemonRestart()
			default:
				fmt.Fprintf(os.Stderr, "unknown daemon command: %s\n", os.Args[2])
				os.Exit(1)
			}
			return
		}
		runDaemon()
		return
	}
	runClient()
}
