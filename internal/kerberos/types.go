// Package kerberos contains core business logic, types, and mathematical format
// computations required to structure raw ticket granting service (TGS) data
// for offline cracking.
package kerberos

import "fmt"

// HashComponents represents the gathered pieces of information neccessary to
// generate  Hashcat-compatible offlinehash string.
type HashComponents struct {
	EType  string `json:"etype"`  // Encryption type (e.g., 17, 18, 23)
	User   string `json:"user"`   // Kerberos client name (Target user account)
	Domain string `json:"domain"` // Active Directory domain realm name
	SPN    string `json:"spn"`    // Service Principal Name (e.g., cifs/DC01)
	Cipher string `json:"cipher"` // Raw hex string containing the ticket body
}

// HashResult contains the formatted offline cracking target long with
// detailed diagnostic metadata.
type HashResult struct {
	Hash     string `json:"hash"`          // Prepared Hashcat-compatible hash
	Checksum string `json:"checksum"`      // The extracted 12-byte (24 hex characters) tail
	EData2   string `json:"edata2"`        // Remaining cipher data payload
	Length   int    `json:"cipher_length"` // Calculated length of the raw cipher string
	Valid    bool   `json:"valid"`         // Evaluation output verifying hash format rules
}

// ValidationError defines a custom struct for input anomalies identified
// during string sanitization checks.
type ValidationError struct {
	Feild   string // Name of the invalid field
	Message string // User-friendly description of the validation failure
}

// Error formats the structural validation error details for CLI presentation.
func (e ValidationError) Error() string {
	return fmt.Sprintf("validattion error in '%s': '%s", e.Feild, e.Message)
}
