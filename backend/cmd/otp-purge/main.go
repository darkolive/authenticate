package main

import (
	"flag"
	"fmt"
	"os"

	"backend/agents/auth/CharonOTP"
)

func main() {
	var hours int
	flag.IntVar(&hours, "hours", 24, "Retention window in hours; OTPs expired or verified/used older than this will be purged")
	flag.Parse()

	deleted, err := CharonOTP.PurgeExpiredOTPs(hours)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Purge failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Purged %d ChannelOTP records (retention %d hours)\n", deleted, hours)
}
