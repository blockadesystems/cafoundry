package config

import (
	"crypto/x509"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DataDir                 string                  // Directory to store CA data (keys, certificates, CRLs)
	Organization            string                  // Organization name for the CA certificate
	Country                 string                  // Country code for the CA certificate
	Province                string                  // Province for the CA certificate
	Locality                string                  // Locality for the CA certificate
	CommonName              string                  // Common Name for the CA certificate
	CACertValidityYears     int                     // Validity period of the CA certificate in years
	DefaultCertValidityDays int                     // Default validity period for issued certificates in days
	CRLValidityHours        int                     // Validity period for the CRL in hours
	StorageType             string                  // Storage type: "postgres"
	DBHost                  string                  // PostgreSQL host
	DBUser                  string                  // PostgreSQL user
	DBPassword              string                  // PostgreSQL password
	DBName                  string                  // PostgreSQL database name
	DBPort                  int                     // PostgreSQL port
	DBSSLMode               string                  // PostgreSQL SSL mode
	DBCert                  string                  // PostgreSQL client certificate file
	DBKey                   string                  // PostgreSQL client private key file
	DBRootCert              string                  // PostgreSQL root CA certificate file
	CertificatePolicies     CertificatePolicies     // Certificate policies
	HTTPSCertFile           string                  // Path to the HTTPS certificate file
	HTTPSKeyFile            string                  // Path to the HTTPS private key file
	HTTPSAddress            string                  // The address to listen on for HTTPS
	HTTPAddress             string                  // The address to listen on for HTTP
	ExternalURL             string                  // The external URL for the CA service
	ACMEDirectoryMeta       ACMEDirectoryMetaConfig // New struct for ACME meta fields
	NonceLifetime           time.Duration           // How long ACME nonces are valid
	OrderLifetime           time.Duration           // How long ACME orders are valid (e.g., 7 days)
	AuthorizationLifetime   time.Duration           // How long ACME authorizations are valid (e.g., 30 days)
	CRLDistributionPoints   []string                // URLs for CRL Distribution Points extension
	OCSPServer              []string                // URLs for OCSP servers (AIA extension)
	IssuingCertificateURL   []string                // URLs for CA issuer cert (AIA extension)
	DNSResolver             string                  // Address (ip:port) for DNS resolver used for validation
	// Add other configuration options here later
}

// Add new struct for ACME Directory Meta fields
type ACMEDirectoryMetaConfig struct {
	TermsOfServiceURL       string   `json:"termsOfService,omitempty"`
	WebsiteURL              string   `json:"website,omitempty"`
	CaaIdentities           []string `json:"caaIdentities,omitempty"`           // Domain names the CA controls
	ExternalAccountRequired bool     `json:"externalAccountRequired,omitempty"` // Typically false
}

// APIKey defines an API key and its associated roles.
type APIKey struct {
	Roles []string
}

// CertificatePolicies defines certificate issuance policies.
type CertificatePolicies struct {
	DefaultValidityDays int                // Default validity period for certificates
	AllowedKeyUsages    []x509.KeyUsage    // Allowed key usages
	AllowedExtKeyUsages []x509.ExtKeyUsage // Allowed extended key usages
	AllowedKeyTypes     []string           `json:"allowedKeyTypes"`    // Allowed key types (e.g., "RSA", "ECDSA", "Ed25519") - case-insensitive check
	MinRSASize          int                `json:"minRsaSize"`         // Minimum RSA key size in bits
	AllowedECDSACurves  []string           `json:"allowedEcdsaCurves"` // Allowed ECDSA curve names (e.g., "P256", "P384", "P521") - case-insensitive check
}

const (
	defaultDataDir             = "./data"
	defaultOrganization        = "CA Foundry Authority"
	defaultCountry             = "US"
	defaultProvince            = "NC"
	defaultLocality            = "Raleigh"
	defaultCommonName          = "CA Foundry Root CA"
	defaultCACertValidityYears = 10
	defaultCertValidityDays    = 365
	defaultCRLValidityHours    = 24
	defaultStorageType         = "postgres"
	defaultDBHost              = "localhost"
	defaultDBUser              = "cafoundry"
	defaultDBPassword          = "password"
	defaultDBName              = "cafoundry"
	defaultDBPort              = 5432
	defaultDBSSLMode           = "disable" // Default to disable SSL
	defaultDBCert              = ""
	defaultDBKey               = ""
	defaultDBRootCert          = ""
	defaultHTTPSCertFile       = "./data/https.crt"
	defaultHTTPSKeyFile        = "./data/https.key"
	defaultHTTPSAddress        = ":8443"
	defaultHTTPAddress         = ":8080"
	defaultExternalURL         = "https://localhost:8443"
	defaultTermsOfServiceURL   = ""             // Recommend setting via env
	defaultWebsiteURL          = ""             // Recommend setting via env
	defaultCaaIdentities       = ""             // Comma-separated list in env var
	defaultNonceLifetimeSecs   = 3600           // 1 hour in seconds
	defaultOrderLifetimeSecs   = 7 * 24 * 3600  // 7 days
	defaultAuthzLifetimeSecs   = 30 * 24 * 3600 // 30 days
	defaultCRLDPs              = ""             // Comma-separated URLs
	defaultOCSPUrls            = ""             // Comma-separated URLs
	defaultIssuerUrls          = ""             // Comma-separated URLs
	defaultDNSResolver         = ""             // "ip:port" for DNS resolver used for validation (127.0.0.1:8053, etc.)
	defaultAllowedKeyTypes     = "RSA,ECDSA"    // Allow RSA and ECDSA by default
	defaultMinRSASize          = 2048
	defaultAllowedECDSACurves  = "P256,P384" // Allow P256 and P384 by default (P521 less common)
)

var defaultCertificatePolicies = CertificatePolicies{
	DefaultValidityDays: 365,
	AllowedKeyUsages:    []x509.KeyUsage{x509.KeyUsageDigitalSignature, x509.KeyUsageKeyEncipherment},
	AllowedExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	AllowedKeyTypes:     strings.Split(defaultAllowedKeyTypes, ","),
	MinRSASize:          defaultMinRSASize,
	AllowedECDSACurves:  strings.Split(defaultAllowedECDSACurves, ","),
}

// LoadConfig loads the CA configuration from environment variables or defaults.
func LoadConfig() (*Config, error) {
	nonceLifetime := getEnvAsDurationSec("CAFOUNDRY_NONCE_LIFETIME_SECONDS", defaultNonceLifetimeSecs)
	orderLifetime := getEnvAsDurationSec("CAFOUNDRY_ORDER_LIFETIME_SECONDS", defaultOrderLifetimeSecs)
	authzLifetime := getEnvAsDurationSec("CAFOUNDRY_AUTHZ_LIFETIME_SECONDS", defaultAuthzLifetimeSecs)
	crlDPs := getEnvAsStringSlice("CAFOUNDRY_CRL_DP", defaultCRLDPs)
	ocspUrls := getEnvAsStringSlice("CAFOUNDRY_OCSP_URL", defaultOCSPUrls)
	issuerUrls := getEnvAsStringSlice("CAFOUNDRY_ISSUER_URL", defaultIssuerUrls)
	allowedKeyTypes := getEnvAsStringSlice("CAFOUNDRY_POLICY_KEY_TYPES", defaultAllowedKeyTypes)
	minRsaSize := getEnvAsInt("CAFOUNDRY_POLICY_MIN_RSA_SIZE", defaultMinRSASize)
	allowedCurves := getEnvAsStringSlice("CAFOUNDRY_POLICY_ECDSA_CURVES", defaultAllowedECDSACurves)

	// Populate CertificatePolicies with loaded/default values
	certPolicies := defaultCertificatePolicies // Start with code defaults
	if len(allowedKeyTypes) > 0 {              // Only override if env var is set and not empty
		certPolicies.AllowedKeyTypes = allowedKeyTypes
	}
	// Ensure minimum RSA size isn't set ridiculously low
	if minRsaSize >= 1024 { // Basic sanity check
		certPolicies.MinRSASize = minRsaSize
	} else {
		log.Printf("Warning: Invalid or too small value for CAFOUNDRY_POLICY_MIN_RSA_SIZE (%d), using default: %d", minRsaSize, defaultMinRSASize)
		certPolicies.MinRSASize = defaultMinRSASize
	}
	if len(allowedCurves) > 0 { // Only override if env var is set and not empty
		certPolicies.AllowedECDSACurves = allowedCurves
	}
	// TODO: Load AllowedKeyUsages/ExtKeyUsages from env vars too?

	cfg := &Config{
		DataDir:                 getEnv("CAFOUNDRY_DATA_DIR", defaultDataDir),
		Organization:            getEnv("CAFOUNDRY_ORGANIZATION", defaultOrganization),
		Country:                 getEnv("CAFOUNDRY_COUNTRY", defaultCountry),
		Province:                getEnv("CAFOUNDRY_PROVINCE", defaultProvince),
		Locality:                getEnv("CAFOUNDRY_LOCALITY", defaultLocality),
		CommonName:              getEnv("CAFOUNDRY_COMMON_NAME", defaultCommonName),
		CACertValidityYears:     getEnvAsInt("CAFOUNDRY_CA_VALIDITY_YEARS", defaultCACertValidityYears),
		DefaultCertValidityDays: getEnvAsInt("CAFOUNDRY_DEFAULT_CERT_VALIDITY_DAYS", defaultCertValidityDays),
		CRLValidityHours:        getEnvAsInt("CAFOUNDRY_CRL_VALIDITY_HOURS", defaultCRLValidityHours),
		StorageType:             getEnv("CAFOUNDRY_STORAGE_TYPE", defaultStorageType),
		DBHost:                  getEnv("CAFOUNDRY_DB_HOST", defaultDBHost),
		DBUser:                  getEnv("CAFOUNDRY_DB_USER", defaultDBUser),
		DBPassword:              getEnv("CAFOUNDRY_DB_PASSWORD", defaultDBPassword),
		DBName:                  getEnv("CAFOUNDRY_DB_NAME", defaultDBName),
		DBPort:                  getEnvAsInt("CAFOUNDRY_DB_PORT", defaultDBPort),
		DBSSLMode:               getEnv("CAFOUNDRY_DB_SSLMODE", defaultDBSSLMode),
		DBCert:                  getEnv("CAFOUNDRY_DB_CERT", defaultDBCert),
		DBKey:                   getEnv("CAFOUNDRY_DB_KEY", defaultDBKey),
		DBRootCert:              getEnv("CAFOUNDRY_DB_ROOTCERT", defaultDBRootCert),
		CertificatePolicies:     certPolicies,
		HTTPSCertFile:           getEnv("CAFOUNDRY_HTTPS_CERT_FILE", defaultHTTPSCertFile),
		HTTPSKeyFile:            getEnv("CAFOUNDRY_HTTPS_KEY_FILE", defaultHTTPSKeyFile),
		HTTPSAddress:            getEnv("CAFOUNDRY_HTTPS_ADDRESS", defaultHTTPSAddress),
		HTTPAddress:             getEnv("CAFOUNDRY_HTTP_ADDRESS", defaultHTTPAddress),
		ExternalURL:             strings.TrimSuffix(getEnv("CAFOUNDRY_EXTERNAL_URL", defaultExternalURL), "/"), // Ensure no trailing slash
		NonceLifetime:           nonceLifetime,
		OrderLifetime:           orderLifetime,
		AuthorizationLifetime:   authzLifetime,
		ACMEDirectoryMeta: ACMEDirectoryMetaConfig{
			TermsOfServiceURL:       getEnv("CAFOUNDRY_ACME_TOS_URL", defaultTermsOfServiceURL),
			WebsiteURL:              getEnv("CAFOUNDRY_ACME_WEBSITE_URL", defaultWebsiteURL),
			CaaIdentities:           getEnvAsStringSlice("CAFOUNDRY_ACME_CAA_IDENTITIES", defaultCaaIdentities),
			ExternalAccountRequired: getEnvAsBool("CAFOUNDRY_ACME_EAB_REQUIRED", false), // Default EAB to false
		},
		CRLDistributionPoints: crlDPs,
		OCSPServer:            ocspUrls,
		IssuingCertificateURL: issuerUrls,
		DNSResolver:           getEnv("CAFOUNDRY_DNS_RESOLVER", defaultDNSResolver),
	}
	// Add more configuration loading logic here later
	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func getEnvAsInt(key string, defaultValue int) int {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		log.Printf("Warning: Invalid integer value for %s (%s), using default: %d", key, valueStr, defaultValue)
		return defaultValue
	}
	return value
}

// New helper for duration in seconds
func getEnvAsDurationSec(key string, defaultValue int) time.Duration {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return time.Duration(defaultValue) * time.Second
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		log.Printf("Warning: Invalid integer value for %s (%s), using default: %d seconds", key, valueStr, defaultValue)
		return time.Duration(defaultValue) * time.Second
	}
	return time.Duration(value) * time.Second
}

// New helper for boolean
func getEnvAsBool(key string, defaultValue bool) bool {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.ParseBool(strings.ToLower(valueStr))
	if err != nil {
		log.Printf("Warning: Invalid boolean value for %s (%s), using default: %t", key, valueStr, defaultValue)
		return defaultValue
	}
	return value
}

// New helper for comma-separated string slice
func getEnvAsStringSlice(key string, defaultValue string) []string {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		valueStr = defaultValue
	}
	if valueStr == "" { // Handle case where default is also empty
		return nil
	}
	// Trim whitespace around commas and filter empty strings
	parts := strings.Split(valueStr, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
