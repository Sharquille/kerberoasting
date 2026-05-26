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
		return nil, errors.New(
			"cipher too short: need at least 24 hex characters for the checksum segment",
		)
	}

	if len(cipher)%2 != 0 {
		return nil, errors.New("cipher string length must be even to represent valid hex values")
	}

	if !isValidHex(cipher) {
		return nil, errors.New(
			"cipher contains invalid hex characters (only 0-9 and A-F are allowed)",
		)
	}

	// Extract Checksum and remaining data
	// Standard Kerberos AES configurations place the 12-byte (24-hex-char) checksum at the tail.
	checksumStart := len(cipher) - 24
	checksum := cipher[checksumStart:]
	edata2 := cipher[:checksumStart]

	// 5. Construct the specific $krb5tgs$ structure
	// Format: $krb5tgs$etype$*user$domain$spn*$checksum$edata2
	hash := fmt.Sprintf("$krb5tgs$%s$%s$%s$*%s*$%s$%s",
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
		return ValidationError{
			Feild:   "spn = service",
			Message: "invalid SPN format (expected: service/host.domain)",
		}
	}
	return nil
}

// isValidHex validates that the target string contains only valid hex numerals.
func isValidHex(s string) bool {
	hexRegex := regexp.MustCompile(`^[0-9A-Fa-f]+$`)
	return hexRegex.MatchString(s)
}

// validateHashFormat performs comprehensive format validation on the generated hash
func validateHashFormat(hash string) bool {
	parts := strings.Split(hash, "$")

	// The format is: $krb5tgs$etype$*user$domain$spn*$checksum$edata2
	// When split by "$", this yields exactly 8 parts:
	// parts[0]: ""
	// parts[1]: "krb5tgs"
	// parts[2]: etype (e.g., "17", "18", "23")
	// parts[3]: "*user"
	// parts[4]: "domain"
	// parts[5]: "spn*"
	// parts[6]: "checksum"
	// parts[7]: "edata2"
	if len(parts) != 8 {
		return false
	}

	if parts[1] != "krb5tgs" {
		return false
	}

	etype := parts[2]
	if etype != "17" && etype != "18" && etype != "23" {
		return false
	}

	// Validate SPN outer asterisk boundaries
	if !strings.HasPrefix(parts[3], "*") || !strings.HasSuffix(parts[5], "*") {
		return false
	}

	// Validate checksum length based on etype
	checksum := parts[6]
	if etype == "18" || etype == "17" {
		// AES128/AES256 checksums are exactly 12 bytes (24 hex characters)
		if len(checksum) != 24 || !isValidHex(checksum) {
			return false
		}
	} else if etype == "23" {
		// RC4-HMAC checksums are 16 bytes (32 hex characters)
		if len(checksum) != 32 || !isValidHex(checksum) {
			return false
		}
	}

	// EData2 should be valid hex and of reasonable length
	edata2 := parts[7]
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
