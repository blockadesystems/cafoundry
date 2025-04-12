package model

import "time"

// ACMEAccount represents the data we need to store for an ACME account.
// type ACMEAccount struct {
// 	ID         int64     // Unique identifier for the account
// 	Email      string    // Account email
// 	PrivateKey []byte    // Account private key (PEM-encoded)
// 	URI        string    // Account URI from the ACME server
// 	CreatedAt  time.Time // Time the account was created
// }

// Account represents an ACME account
type Account struct {
	ID             string    `json:"id"`
	Key            []byte    `json:"key"`
	Contact        []string  `json:"contact"`
	Status         string    `json:"status"`
	TermsOfService bool      `json:"termsOfServiceAgreed"`
	CreatedAt      time.Time `json:"createdAt"`
	LastModifiedAt time.Time `json:"lastModifiedAt"`
}

// Order represents a certificate order
type Order struct {
	ID             string       `json:"id"`
	AccountID      string       `json:"accountId"`
	Status         string       `json:"status"`
	Expires        time.Time    `json:"expires"`
	Identifiers    []Identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	FinalizeURL    string       `json:"finalize"`
	CertificateURL string       `json:"certificate,omitempty"`
	CreatedAt      time.Time    `json:"createdAt"`
	LastModifiedAt time.Time    `json:"lastModifiedAt"`
}

// Identifier represents a domain or other identifier
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}
