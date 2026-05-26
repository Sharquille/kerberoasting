package kerberos

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// GenerateHash validates inputs, cleans hex data, separates checksum and
// edata2 segments, and generates a valid Hashcat-formatted string.
func GenerateHash(c HashComponents) (*HashResult, error) {
	// Initialize validation of inputs
	if err := validateComponents(c); err != nil {
		return nil, err
	}
	// clean input cipher: strip spaces, colons, newlines, and tabs
	cipher := strings.ToUpper(c.Cipher)
	replacer := strings.NewReplacer(" ", "", ":", "", "\n", "", "\r", "", "\t", "")
	cipher = replacer.Replace(cipher)

	// 3. Size-sanity checks
	if len(cipher) < 24 {
		return nil, errors.New("cipher too short: need at least 24 hex characters for the checksum segment")
	}

	if len(cipher)%2 != 0 {
		return nil, errors.New("cipher string length must be even to represent valid hex values")
	}

	if !isValidHex(cipher) {
		return nil, errors.New("cipher contains invalid hex characters (only 0-9 and A-F are allowed)")
	}

	// Extract Checksum and remaining data
	// Standard Kerberos AES configurations place the 12-byte (24-hex-char) checksum at the tail.
	checksumStart := len(cipher) - 24
	checksum := cipher[checksumStart:]
	edata2 := cipher[:checksumStart]

	// 5. Construct the specific $krb5tgs$ structure
	// Format: $krb5tgs$etype$*user$domain$spn*$checksum$edata2
	hash := fmt.Sprintf("$krb5tgs$%s$*%s$%s$%s*$%s$%s",
		c.EType, c.User, strings.ToUpper(c.Domain), c.SPN, checksum, edata2)

	return &HashResult{
		Hash:     hash,
		Checksum: checksum,
		EData2:   edata2,
		Length:   len(cipher),
		Valid:    validateHashFormat(hash),
	}, nil
}

// validateComponents checks that one of the target parameters are missing
func validateComponents(c HashComponents) error {
	if strings.TrimSpace(c.User) == "" {
		return ValidationError{Feild: "user", Message: "username cannot be blank"}
	}

	if strings.TrimSpace(c.Domain) == "" {
		return ValidationError{Feild: "domain", Message: "domain cannot be blank"}
	}
	if strings.TrimSpace(c.SPN) == "" {
		return ValidationError{Feild: "spn => service", Message: "spn or service cannot be blank"}
	}
	if strings.TrimSpace(c.Cipher) == "" {
		return ValidationError{Feild: "cipher", Message: "cipher cannot be blank"}
	}
	if strings.TrimSpace(c.EType) == "" {
		return ValidationError{Feild: "etype", Message: "etype cannot be blank"}
	}

	// SPN validation (expects service/host or service/host.domain)
	spnRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]+\/[a-zA-Z0-9.-]+$`)
	if !spnRegex.MatchString(c.SPN) {
		return ValidationError{Feild: "spn = service", Message: "invalid SPN format (expected: service/host.domain)"}
	}
	return nil

}

// isValidHex validates that the target string contains only valid hex numerals.
func isValidHex(s string) bool {
	hexRegex := regexp.MustCompile(`^[0-9A-Fa-f]+$`)
	return hexRegex.MatchString(s)
}

// validateHashFormat checks the layout of the finished string to ensure compatibility.
func validateHashFormat(hash string) bool {
	parts := strings.Split(hash, "$")

	// Expecting: ["", "krb5tgs", "etype", "*user$domain$spn*", "checksum", "edata2"]
	if len(parts) != 6 {
		return false
	}

	if parts[1] != "krb5tgs" {
		return false
	}

	// Verify that the etype is a standard recognizable integer
	if parts[2] != "17" && parts[2] != "18" && parts[2] != "23" {
		return false
	}

	// Verify the SPN wraps around asterisk bounds
	spnSection := parts[3]
	if !strings.HasPrefix(spnSection, "*") || !strings.HasSuffix(spnSection, "*") {
		return false
	}

	// Extract content within asterisks and split by dollar sign
	spnContent := spnSection[1 : len(spnSection)-1]
	spnParts := strings.Split(spnContent, "$")
	if len(spnParts) != 3 {
		return false
	}

	// Double-check the extracted checksum structure
	checksum := parts[4]
	if len(checksum) != 24 || !isValidHex(checksum) {
		return false
	}

	// Double-check that remaining cipher bytes look syntactically correct
	edata2 := parts[5]
	if len(edata2) < 24 || !isValidHex(edata2) {
		return false
	}

	return true
}

// GetHashcatMode maps supported etype values to their Hashcat execution modes.
func GetHashcatMode(etype string) (string, string) {
	switch etype {
	case "17":
		return "19600", "AES128-CTS-HMAC-SHA1-96"
	case "18":
		return "19700", "AES256-CTS-HMAC-SHA1-96"
	case "23":
		return "13100", "RC4-HMAC"
	default:
		return "19700", "AES256-CTS-HMAC-SHA1-96" // Standard Default

	}
}
