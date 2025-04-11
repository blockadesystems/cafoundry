package config

import (
	"crypto/x509"
	"log"
	"os"
	"strconv"
)

type Config struct {
	DataDir                 string              // Directory to store CA data (keys, certificates, CRLs)
	Organization            string              // Organization name for the CA certificate
	Country                 string              // Country code for the CA certificate
	Province                string              // Province for the CA certificate
	Locality                string              // Locality for the CA certificate
	CommonName              string              // Common Name for the CA certificate
	CACertValidityYears     int                 // Validity period of the CA certificate in years
	DefaultCertValidityDays int                 // Default validity period for issued certificates in days
	CRLValidityHours        int                 // Validity period for the CRL in hours
	StorageType             string              // Storage type: "postgres"
	DBHost                  string              // PostgreSQL host
	DBUser                  string              // PostgreSQL user
	DBPassword              string              // PostgreSQL password
	DBName                  string              // PostgreSQL database name
	DBPort                  int                 // PostgreSQL port
	DBSSLMode               string              // PostgreSQL SSL mode
	DBCert                  string              // PostgreSQL client certificate file
	DBKey                   string              // PostgreSQL client private key file
	DBRootCert              string              // PostgreSQL root CA certificate file
	Users                   map[string]User     // User credentials and roles (Deprecated)
	APIKeys                 map[string]APIKey   // API keys and their roles
	CertificatePolicies     CertificatePolicies // Certificate policies
	HTTPSCertFile           string              // Path to the HTTPS certificate file
	HTTPSKeyFile            string              // Path to the HTTPS private key file
	HTTPSAddress            string              // The address to listen on for HTTPS
	// Add other configuration options here later
}

// User defines a user with credentials and roles. (Deprecated)
type User struct {
	Password string
	Roles    []string
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
)

var defaultAPIKeys = map[string]APIKey{
	"issuer-api-key":  {Roles: []string{"issuer"}},
	"revoker-api-key": {Roles: []string{"revoker"}},
}

var defaultUsers = map[string]User{ // Deprecated
	"issuer":  {Password: "issuerpass", Roles: []string{"issuer"}},
	"revoker": {Password: "revokerpass", Roles: []string{"revoker"}},
}

var defaultCertificatePolicies = CertificatePolicies{
	DefaultValidityDays: 365,
	AllowedKeyUsages:    []x509.KeyUsage{x509.KeyUsageDigitalSignature, x509.KeyUsageKeyEncipherment},
	AllowedExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
}

// LoadConfig loads the CA configuration from environment variables or defaults.
func LoadConfig() (*Config, error) {
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
		Users:                   defaultUsers,   // Deprecated
		APIKeys:                 defaultAPIKeys, // Use API keys instead
		CertificatePolicies:     defaultCertificatePolicies,
		HTTPSCertFile:           getEnv("CAFOUNDRY_HTTPS_CERT_FILE", defaultHTTPSCertFile),
		HTTPSKeyFile:            getEnv("CAFOUNDRY_HTTPS_KEY_FILE", defaultHTTPSKeyFile),
		HTTPSAddress:            getEnv("CAFOUNDRY_HTTPS_ADDRESS", defaultHTTPSAddress),
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
