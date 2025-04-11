package model

import "time"

// ACMEAccount represents the data we need to store for an ACME account.
type ACMEAccount struct {
	ID         int64     // Unique identifier for the account
	Email      string    // Account email
	PrivateKey []byte    // Account private key (PEM-encoded)
	URI        string    // Account URI from the ACME server
	CreatedAt  time.Time // Time the account was created
}
