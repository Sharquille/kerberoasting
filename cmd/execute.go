package cmd

import (
	"fmt"
	"os"
)

// Execute runs the root command-line execution by passing control to the
// root cobra command structure. If an error occurs, it is output to he cli
// and the programs exits ith an error status.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("❌ Fatal Error: %v\n", err)
		os.Exit(1)
	}
}
