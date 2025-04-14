package model

import (
	"encoding/json" // Added for ProblemDetails potentially storing subproblems as JSON
	"time"
)

// Account represents an ACME account on the server.
type Account struct {
	ID                     string          `json:"id" db:"id"`                                // Unique account identifier (e.g., UUID or generated)
	PublicKeyJWK           string          `json:"-" db:"public_key_jwk"`                     // Public key in JWK format (JSON string), not exposed in standard account responses
	Contact                []string        `json:"contact,omitempty" db:"contact"`            // Contact URLs (e.g., "mailto:...")
	Status                 string          `json:"status" db:"status"`                        // e.g., "valid", "deactivated", "revoked"
	TermsOfService         bool            `json:"termsOfServiceAgreed" db:"tos_agreed"`      // Client agreed to terms
	ExternalAccountBinding json.RawMessage `json:"externalAccountBinding,omitempty" db:"eab"` // Optional EAB info (JSON)
	CreatedAt              time.Time       `json:"-" db:"created_at"`                         // Timestamp of creation (internal)
	LastModifiedAt         time.Time       `json:"-" db:"last_modified_at"`                   // Timestamp of last modification (internal)
}

// Order represents a certificate order.
type Order struct {
	ID                string          `json:"id" db:"id"`                          // Unique order identifier
	AccountID         string          `json:"-" db:"account_id"`                   // Link to the owning Account (internal)
	Status            string          `json:"status" db:"status"`                  // e.g., "pending", "ready", "processing", "valid", "invalid"
	Expires           time.Time       `json:"expires" db:"expires_at"`             // Time when the order expires
	Identifiers       []Identifier    `json:"identifiers" db:"-"`                  // Identifiers requested (fetched separately or stored denormalized) - Needs DB mapping strategy
	NotBefore         time.Time       `json:"notBefore,omitempty" db:"not_before"` // Requested certificate start validity
	NotAfter          time.Time       `json:"notAfter,omitempty" db:"not_after"`   // Requested certificate end validity
	Error             *ProblemDetails `json:"error,omitempty" db:"-"`              // Error if order failed (fetched separately or stored denormalized) - Needs DB mapping strategy
	Authorizations    []string        `json:"authorizations" db:"-"`               // URLs of Authorization resources (constructed dynamically)
	FinalizeURL       string          `json:"finalize" db:"-"`                     // URL to finalize the order (constructed dynamically)
	CertificateURL    string          `json:"certificate,omitempty" db:"-"`        // URL for the certificate (constructed dynamically, appears when status is 'valid')
	CertificateSerial string          `json:"-" db:"certificate_serial,omitempty"` // Link to issued certificate (internal)
	CreatedAt         time.Time       `json:"-" db:"created_at"`                   // Timestamp of creation (internal)
	LastModifiedAt    time.Time       `json:"-" db:"last_modified_at"`             // Timestamp of last modification (internal)

	// Storage helper - denormalized Identifiers JSON for easier DB storage
	IdentifiersJSON string `json:"-" db:"identifiers_json"`
	// Storage helper - denormalized Error JSON for easier DB storage
	ErrorJSON string `json:"-" db:"error_json,omitempty"`
}

// Identifier represents a domain or other identifier in an order.
type Identifier struct {
	Type  string `json:"type"`  // e.g., "dns"
	Value string `json:"value"` // e.g., "example.com"
}

// Authorization represents the state of an identifier authorization.
type Authorization struct {
	ID         string       `json:"id" db:"id"`                        // Unique authorization identifier
	AccountID  string       `json:"-" db:"account_id"`                 // Link to the owning Account (internal)
	OrderID    string       `json:"-" db:"order_id"`                   // Link to the associated Order (internal)
	Identifier Identifier   `json:"identifier" db:"-"`                 // The identifier being authorized (needs DB mapping)
	Status     string       `json:"status" db:"status"`                // e.g., "pending", "valid", "invalid", "deactivated", "expired", "revoked"
	Expires    time.Time    `json:"expires,omitempty" db:"expires_at"` // Time when the authorization expires
	Challenges []*Challenge `json:"challenges" db:"-"`                 // Associated challenges (fetched separately)
	Wildcard   bool         `json:"wildcard" db:"wildcard"`            // Is this for a wildcard domain?
	CreatedAt  time.Time    `json:"-" db:"created_at"`                 // Timestamp of creation (internal)

	// Storage helper - denormalized Identifier JSON for easier DB storage
	IdentifierJSON string `json:"-" db:"identifier_json"`
}

// Challenge represents an ACME challenge to prove control over an identifier.
type Challenge struct {
	ID              string          `json:"id" db:"id"`                            // Unique challenge identifier
	AuthorizationID string          `json:"-" db:"authorization_id"`               // Link to the parent Authorization (internal)
	Type            string          `json:"type" db:"type"`                        // e.g., "http-01", "dns-01"
	URL             string          `json:"url" db:"-"`                            // URL of this challenge resource (constructed dynamically)
	Status          string          `json:"status" db:"status"`                    // e.g., "pending", "processing", "valid", "invalid"
	Token           string          `json:"token" db:"token"`                      // Challenge token value
	Validated       time.Time       `json:"validated,omitempty" db:"validated_at"` // Timestamp when validation succeeded
	Error           *ProblemDetails `json:"error,omitempty" db:"-"`                // Error details if validation failed (needs DB mapping)
	CreatedAt       time.Time       `json:"-" db:"created_at"`                     // Timestamp of creation (internal)

	// Storage helper - denormalized Error JSON for easier DB storage
	ErrorJSON string `json:"-" db:"error_json,omitempty"`
}

// Nonce represents an ACME nonce for preventing replay attacks (storage model).
type Nonce struct {
	Value     string    `db:"value"`      // The nonce value (Primary Key)
	ExpiresAt time.Time `db:"expires_at"` // Expiry time
	IssuedAt  time.Time `db:"issued_at"`  // Issuance time
}

// CertificateData represents stored information about an issued certificate (storage model).
type CertificateData struct {
	SerialNumber     string    `db:"serial_number"`               // Certificate serial number (Primary Key)
	CertificatePEM   string    `db:"certificate_pem"`             // PEM encoded certificate
	ChainPEM         string    `db:"chain_pem"`                   // PEM encoded issuing chain (optional)
	IssuedAt         time.Time `db:"issued_at"`                   // Timestamp of issuance
	ExpiresAt        time.Time `db:"expires_at"`                  // Timestamp of expiry
	AccountID        string    `db:"account_id"`                  // Link to the account that ordered it
	OrderID          string    `db:"order_id"`                    // Link to the order it fulfilled
	Revoked          bool      `db:"revoked"`                     // Is the certificate revoked?
	RevokedAt        time.Time `db:"revoked_at,omitempty"`        // Timestamp of revocation
	RevocationReason int       `db:"revocation_reason,omitempty"` // CRL reason code (optional)
}

// ProblemDetails represents an ACME error object (RFC 7807 / RFC 8555 Section 6.7).
type ProblemDetails struct {
	Type        string          `json:"type"`                  // URL identifying the specific error type (e.g., "urn:ietf:params:acme:error:...")
	Detail      string          `json:"detail"`                // Human-readable explanation
	Status      int             `json:"status,omitempty"`      // HTTP status code associated with this error
	Instance    string          `json:"instance,omitempty"`    // URL identifying the specific occurrence of the problem (optional)
	Subproblems json.RawMessage `json:"subproblems,omitempty"` // For compound errors (structured JSON)
}
