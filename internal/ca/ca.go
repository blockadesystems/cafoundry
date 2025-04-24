package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/blockadesystems/cafoundry/internal/config"
	"github.com/blockadesystems/cafoundry/internal/storage"
	// Import model if needed for revocation reasons etc.
	// "github.com/blockadesystems/cafoundry/internal/model"
)

const (
	caKeySize         = 4096                 // RSA key size for CA
	defaultSerialBits = 128                  // Bit size for serial number randomness
	httpsKeySize      = 2048                 // RSA key size for HTTPS cert
	httpsCertLifetime = 365 * 24 * time.Hour // 1 year validity for self-signed HTTPS
)

var logger *zap.Logger

// Initialize package logger
func init() {
	// Assuming logger is initialized globally or passed differently.
	// For simplicity, using zap's global logger here, but ideally, pass it in New().
	globalLogger, err := zap.NewDevelopment() // Use Development for easy reading initially
	if err != nil {
		panic(fmt.Sprintf("ca: failed to initialize zap logger: %v", err))
	}
	logger = globalLogger.With(zap.String("package", "ca"))
}

// ErrCANotInitialized indicates the CA keypair could not be loaded or generated.
var ErrCANotInitialized = errors.New("ca: CA certificate or private key is not initialized")

// CAService defines the interface for CA operations (optional but good practice).
type CAService interface {
	SignCSR(ctx context.Context, csr *x509.CertificateRequest, lifetime time.Duration, profile string) (*x509.Certificate, error)
	RevokeCertificate(ctx context.Context, serialNumber string, reasonCode int) error
	GenerateCRL(ctx context.Context) ([]byte, error)
	GetCACertificate() *x509.Certificate // Returns the loaded CA cert
	IsInitialized() bool
}

// Service implements the CA logic.
type Service struct {
	cfg       *config.Config
	store     storage.Storage
	caCert    *x509.Certificate
	caKey     crypto.Signer // Interface matching private key types (*rsa.PrivateKey, *ecdsa.PrivateKey)
	crlTicker *time.Ticker  // For periodic CRL generation (optional)
	crlMutex  sync.RWMutex  // Protects CRL generation/access if concurrent
	initErr   error         // Store initialization error
}

// Ensure Service implements CAService (compile-time check).
var _ CAService = (*Service)(nil)

// New creates and initializes the CA Service.
// It attempts to load the CA key/cert from storage, generating them if not found.
func New(cfg *config.Config, store storage.Storage) (*Service, error) {
	s := &Service{
		cfg:   cfg,
		store: store,
	}

	logger.Info("Initializing CA service...")
	ctx := context.Background() // Use background context for initialization

	// 1. Try loading CA private key from storage
	pemKeyBytes, err := store.GetCAPrivateKey(ctx)
	if err != nil {
		s.initErr = fmt.Errorf("failed to get CA private key from storage: %w", err)
		logger.Error("CA Init failed", zap.Error(s.initErr))
		return s, s.initErr // Return service even on error, IsInitialized will be false
	}

	// 2. Try loading CA certificate from storage
	pemCertBytes, err := store.GetCACertificate(ctx)
	if err != nil {
		s.initErr = fmt.Errorf("failed to get CA certificate from storage: %w", err)
		logger.Error("CA Init failed", zap.Error(s.initErr))
		return s, s.initErr
	}

	// 3. If Key or Cert not found in storage, generate them
	if pemKeyBytes == nil || pemCertBytes == nil {
		logger.Info("CA key or certificate not found in storage, generating new ones...")
		newKey, newCert, err := generateCAKeyAndCert(cfg)
		if err != nil {
			s.initErr = fmt.Errorf("failed to generate CA key/cert: %w", err)
			logger.Error("CA Init failed", zap.Error(s.initErr))
			return s, s.initErr
		}

		s.caKey = newKey
		s.caCert = newCert

		// Encode and save the new key/cert
		pemKeyBytes, err = encodePrivateKey(newKey)
		if err != nil {
			s.initErr = fmt.Errorf("failed to encode generated CA private key: %w", err)
			logger.Error("CA Init failed", zap.Error(s.initErr))
			return s, s.initErr
		}
		if err := store.SaveCAPrivateKey(ctx, pemKeyBytes); err != nil {
			s.initErr = fmt.Errorf("failed to save generated CA private key: %w", err)
			logger.Error("CA Init failed", zap.Error(s.initErr))
			return s, s.initErr
		}

		pemCertBytes = EncodeCertificate(newCert)
		if err := store.SaveCACertificate(ctx, pemCertBytes); err != nil {
			s.initErr = fmt.Errorf("failed to save generated CA certificate: %w", err)
			logger.Error("CA Init failed", zap.Error(s.initErr))
			return s, s.initErr
		}
		logger.Info("New CA key and certificate generated and saved.")

	} else {
		// 4. Parse loaded key and cert
		logger.Info("Loading CA key and certificate from storage...")
		s.caKey, err = parsePrivateKey(pemKeyBytes)
		if err != nil {
			s.initErr = fmt.Errorf("failed to parse stored CA private key: %w", err)
			logger.Error("CA Init failed", zap.Error(s.initErr))
			return s, s.initErr
		}
		s.caCert, err = parseCertificate(pemCertBytes)
		if err != nil {
			s.initErr = fmt.Errorf("failed to parse stored CA certificate: %w", err)
			logger.Error("CA Init failed", zap.Error(s.initErr))
			return s, s.initErr
		}
		logger.Info("CA key and certificate loaded successfully.")
	}

	// 5. Initial CRL Generation (and potentially start ticker)
	if s.caKey != nil && s.caCert != nil {
		logger.Info("Generating initial CRL...")
		if _, err := s.GenerateCRL(ctx); err != nil {
			// Log warning, but don't necessarily fail initialization
			logger.Warn("Failed to generate initial CRL", zap.Error(err))
		}
		// TODO: Implement periodic CRL generation using s.crlTicker if needed
	}

	return s, nil // s.initErr will be nil if successful
}

// IsInitialized returns true if the CA key and certificate were loaded/generated successfully.
func (s *Service) IsInitialized() bool {
	return s.initErr == nil && s.caKey != nil && s.caCert != nil
}

// GetCACertificate returns the loaded CA certificate.
func (s *Service) GetCACertificate() *x509.Certificate {
	return s.caCert
}

// computeSubjectKeyID calculates the SKI according to RFC 5280 section 4.2.1.2 Method (1)
// (SHA-1 hash of the BIT STRING SubjectPublicKey (excluding tag, length, and unused bits))
func computeSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	// Marshal the public key to SubjectPublicKeyInfo ASN.1 DER encoding
	derBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Decode the SubjectPublicKeyInfo to access the SubjectPublicKey BIT STRING
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(derBytes, &spki)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal SubjectPublicKeyInfo: %w", err)
	}

	// Calculate SHA-1 hash of the SubjectPublicKey BIT STRING bytes
	// (These bytes directly represent the public key according to its algorithm)
	hash := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return hash[:], nil // Return slice of the hash array
}

// SignCSR validates a CSR against policy and signs it using the CA key.
func (s *Service) SignCSR(ctx context.Context, csr *x509.CertificateRequest, lifetime time.Duration, profile string) (*x509.Certificate, error) {
	if !s.IsInitialized() {
		return nil, ErrCANotInitialized
	}
	l := logger.With(zap.Strings("dns_names", csr.DNSNames), zap.String("profile", profile))
	l.Info("Received CSR for signing")

	// 1. Validate CSR Signature
	if err := csr.CheckSignature(); err != nil {
		l.Warn("CSR signature validation failed", zap.Error(err))
		return nil, fmt.Errorf("invalid CSR signature: %w", err)
	}
	l.Debug("CSR signature validated")

	// 2. Validate Public Key (Policy)
	l.Debug("Validating CSR Public Key against policy")
	keyAllowed := false
	switch pub := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		if !isTypeAllowed("RSA", s.cfg.CertificatePolicies.AllowedKeyTypes) {
			l.Warn("CSR contains disallowed key type: RSA")
			return nil, errors.New("key type RSA is not allowed by CA policy")
		}
		keySize := pub.N.BitLen()
		minSize := s.cfg.CertificatePolicies.MinRSASize
		l.Debug("CSR contains RSA key", zap.Int("size", keySize), zap.Int("min_allowed", minSize))
		if keySize < minSize {
			l.Warn("RSA key size too small", zap.Int("size", keySize), zap.Int("min_allowed", minSize))
			return nil, fmt.Errorf("RSA key size (%d bits) is less than the minimum allowed (%d bits)", keySize, minSize)
		}
		keyAllowed = true
	case *ecdsa.PublicKey:
		if !isTypeAllowed("ECDSA", s.cfg.CertificatePolicies.AllowedKeyTypes) {
			l.Warn("CSR contains disallowed key type: ECDSA")
			return nil, errors.New("key type ECDSA is not allowed by CA policy")
		}
		curveName := pub.Curve.Params().Name
		l.Debug("CSR contains ECDSA key", zap.String("curve", curveName))
		allowed := false
		for _, allowedCurve := range s.cfg.CertificatePolicies.AllowedECDSACurves {
			// Case-insensitive comparison for curve names
			if strings.EqualFold(curveName, allowedCurve) {
				allowed = true
				break
			}
		}
		if !allowed {
			l.Warn("ECDSA curve not allowed", zap.String("curve", curveName), zap.Strings("allowed", s.cfg.CertificatePolicies.AllowedECDSACurves))
			return nil, fmt.Errorf("ECDSA curve '%s' is not allowed by CA policy", curveName)
		}
		keyAllowed = true
	case ed25519.PublicKey:
		// Ed25519 doesn't have size/curve parameters in the same way
		if !isTypeAllowed("Ed25519", s.cfg.CertificatePolicies.AllowedKeyTypes) {
			l.Warn("CSR contains disallowed key type: Ed25519")
			return nil, errors.New("key type Ed25519 is not allowed by CA policy")
		}
		l.Debug("CSR contains Ed25519 key")
		keyAllowed = true
	default:
		l.Warn("CSR contains unknown public key type")
		return nil, errors.New("unsupported public key type in CSR")
	}
	// This check should be redundant due to default case, but belt-and-suspenders
	if !keyAllowed {
		return nil, errors.New("CSR key type not allowed by policy")
	}
	l.Info("CSR Public Key validation passed")

	// 3. Validate Subject/SANs against DB Policy
	// ... (Domain/IP validation logic using store.IsDomainAllowed as implemented previously) ...
	l.Debug("Validating CSR Subject/SANs against stored policy")
	hasCheckedSANs := false
	for _, dnsName := range csr.DNSNames {
		hasCheckedSANs = true
		normName := strings.ToLower(strings.TrimSpace(dnsName))
		allowed, err := s.store.IsDomainAllowed(ctx, normName)
		// ... (handle errors and !allowed as before) ...
		if err != nil {
			return nil, fmt.Errorf("policy check failed for %s: %w", normName, err)
		}
		if !allowed {
			return nil, fmt.Errorf("domain name %s is not allowed by CA policy", normName)
		}
	}
	for _, ipAddr := range csr.IPAddresses {
		hasCheckedSANs = true
		ipStr := ipAddr.String()
		allowed, err := s.store.IsDomainAllowed(ctx, ipStr)
		// ... (handle errors and !allowed as before) ...
		if err != nil {
			return nil, fmt.Errorf("policy check failed for %s: %w", ipStr, err)
		}
		if !allowed {
			return nil, fmt.Errorf("IP address %s is not allowed by CA policy", ipStr)
		}
	}
	if !hasCheckedSANs {
		return nil, errors.New("CSR must contain at least one DNSName or IPAddress SAN allowed by policy")
	}
	l.Info("CSR Subject/SAN validation passed against stored policy")

	// 4. Validate & Calculate Lifetime (Policy)
	maxLifetime := time.Duration(s.cfg.DefaultCertValidityDays) * 24 * time.Hour
	if lifetime <= 0 || lifetime > maxLifetime {
		l.Warn("Requested lifetime out of bounds or zero, using default/max", zap.Duration("requested", lifetime), zap.Duration("max", maxLifetime))
		lifetime = maxLifetime
	}
	notBefore := time.Now().Add(-2 * time.Minute)
	notAfter := notBefore.Add(lifetime)
	if notAfter.After(s.caCert.NotAfter) {
		l.Warn("Requested/calculated lifetime exceeds CA certificate validity, adjusting", zap.Time("original_notAfter", notAfter), zap.Time("ca_notAfter", s.caCert.NotAfter))
		notAfter = s.caCert.NotAfter
	}
	l.Info("Calculated certificate validity", zap.Time("notBefore", notBefore), zap.Time("notAfter", notAfter))

	// 5. Construct Certificate Template
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	ski, err := computeSubjectKeyID(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute subject key identifier: %w", err)
	}

	subject := pkix.Name{Organization: []string{s.cfg.Organization}}
	if len(csr.DNSNames) > 0 {
		subject.CommonName = csr.DNSNames[0]
	}

	// Combine Allowed Key Usages from config policy
	var combinedKeyUsage x509.KeyUsage = 0
	for _, ku := range s.cfg.CertificatePolicies.AllowedKeyUsages {
		combinedKeyUsage |= ku
	}

	template := x509.Certificate{
		SerialNumber:   serialNumber,
		Subject:        subject,
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		URIs:           csr.URIs,
		EmailAddresses: csr.EmailAddresses,

		NotBefore: notBefore,
		NotAfter:  notAfter,

		// *** USE POLICY FROM CONFIG ***
		KeyUsage:    combinedKeyUsage,
		ExtKeyUsage: s.cfg.CertificatePolicies.AllowedExtKeyUsages,

		BasicConstraintsValid: true,
		IsCA:                  false,

		// Extensions from Config / CA Cert
		SubjectKeyId:          ski,
		AuthorityKeyId:        s.caCert.SubjectKeyId, // AKI matches CA's SKI
		OCSPServer:            s.cfg.OCSPServer,
		IssuingCertificateURL: s.cfg.IssuingCertificateURL,
		CRLDistributionPoints: s.cfg.CRLDistributionPoints,
	}
	l.Debug("Constructed certificate template", zap.Any("template", template))

	// 6. Sign the certificate using CA key
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, s.caCert, csr.PublicKey, s.caKey)
	if err != nil {
		l.Error("Failed to create/sign certificate", zap.Error(err))
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// 7. Parse and return the signed certificate
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		l.Error("Failed to parse newly created certificate DER bytes", zap.Error(err))
		return nil, fmt.Errorf("failed to parse created certificate: %w", err)
	}

	l.Info("Successfully signed certificate", zap.String("serial", cert.SerialNumber.Text(16)), zap.Time("expiry", cert.NotAfter))
	return cert, nil
}

// Helper function for case-insensitive check if key type is allowed
func isTypeAllowed(keyType string, allowedTypes []string) bool {
	for _, allowed := range allowedTypes {
		if strings.EqualFold(keyType, allowed) {
			return true
		}
	}
	return false
}

// RevokeCertificate marks a certificate as revoked in storage.
func (s *Service) RevokeCertificate(ctx context.Context, serialNumber string, reasonCode int) error {
	if !s.IsInitialized() {
		return ErrCANotInitialized
	}

	l := logger.With(zap.String("serial", serialNumber), zap.Int("reasonCode", reasonCode))
	l.Info("Revoking certificate")

	// Check if already revoked? GetCertificateData first maybe? Optional.

	// Update storage
	// Use time.Now() for revocation time unless a specific time is needed
	err := s.store.UpdateCertificateRevocation(ctx, serialNumber, true, time.Now(), reasonCode)
	if err != nil {
		l.Error("Failed to update certificate revocation status in storage", zap.Error(err))
		return fmt.Errorf("failed to update storage for revocation: %w", err)
	}

	// Trigger CRL regeneration (could be async)
	l.Info("Triggering CRL regeneration after revocation")
	go func() {
		// Use background context for background task
		crlCtx := context.Background()
		if _, err := s.GenerateCRL(crlCtx); err != nil {
			l.Error("Failed to regenerate CRL after revocation", zap.Error(err))
		}
	}()

	l.Info("Certificate marked as revoked")
	return nil
}

// GenerateCRL creates, signs, and saves a new CRL.
func (s *Service) GenerateCRL(ctx context.Context) ([]byte, error) {
	if !s.IsInitialized() {
		return nil, ErrCANotInitialized
	}

	// Lock mutex if using concurrent CRL generation/access
	s.crlMutex.Lock()
	defer s.crlMutex.Unlock()

	l := logger.With(zap.Time("generation_time", time.Now()))
	l.Info("Generating new CRL")

	// 1. Get list of revoked certificates from storage
	revokedList, err := s.store.ListRevokedCertificates(ctx)
	if err != nil {
		l.Error("Failed to list revoked certificates for CRL generation", zap.Error(err))
		return nil, fmt.Errorf("failed to list revoked certificates: %w", err)
	}

	crlEntries := make([]pkix.RevokedCertificate, len(revokedList))
	for i, certData := range revokedList {
		serialInt := new(big.Int)
		serialInt.SetString(certData.SerialNumber, 16) // Assuming serial stored as hex

		crlEntries[i] = pkix.RevokedCertificate{
			SerialNumber:   serialInt,
			RevocationTime: certData.RevokedAt,
			// TODO: Add extensions like ReasonCode if available/needed
			// Extensions: []pkix.Extension{...},
		}
	}
	l.Info("Fetched revoked certificates for CRL", zap.Int("count", len(crlEntries)))

	// 2. Create CRL
	crlExpiry := time.Now().Add(time.Duration(s.cfg.CRLValidityHours) * time.Hour)
	crlBytes, err := s.caCert.CreateCRL(rand.Reader, s.caKey, crlEntries, time.Now(), crlExpiry)
	if err != nil {
		l.Error("Failed to create CRL", zap.Error(err))
		return nil, fmt.Errorf("failed to create CRL: %w", err)
	}

	// 3. Save CRL to storage
	if err := s.store.SaveCRL(ctx, crlBytes); err != nil {
		l.Error("Failed to save generated CRL to storage", zap.Error(err))
		return nil, fmt.Errorf("failed to save CRL: %w", err)
	}

	l.Info("Successfully generated and saved new CRL")
	return crlBytes, nil
}

// --- Helper Functions ---

// generateSerialNumber creates a secure random serial number.
func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), defaultSerialBits) // 2^128 limit
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	// Ensure positive serial? RFC5280 requires positive. rand.Int should be positive.
	if serialNumber.Sign() != 1 {
		// Highly unlikely, but handle defensively
		return nil, errors.New("generated non-positive serial number")
	}
	return serialNumber, nil
}

// generateCAKeyAndCert creates a new RSA private key and self-signed CA certificate.
func generateCAKeyAndCert(cfg *config.Config) (crypto.Signer, *x509.Certificate, error) {
	// Generate Private Key
	privateKey, err := rsa.GenerateKey(rand.Reader, caKeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}
	publicKey := &privateKey.PublicKey

	// Create Certificate Template
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	subject := pkix.Name{
		Organization: []string{cfg.Organization},
		Country:      []string{cfg.Country},
		Province:     []string{cfg.Province},
		Locality:     []string{cfg.Locality},
		CommonName:   cfg.CommonName, // e.g., "My ACME Intermediate CA"
	}

	notBefore := time.Now().Add(-5 * time.Minute) // Valid slightly in the past
	notAfter := notBefore.AddDate(cfg.CACertValidityYears, 0, 0)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,    // Or 1 if intermediate, 0 means can only sign end-entity
		MaxPathLenZero:        true, // Indicates MaxPathLen is 0, not absent
	}

	// Create self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create self-signed CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse generated CA certificate: %w", err)
	}

	return privateKey, cert, nil
}

// encodePrivateKey encodes a crypto.Signer (RSA or ECDSA) into PEM format.
func encodePrivateKey(key crypto.Signer) ([]byte, error) {
	var pemType string
	var keyBytes []byte
	var err error

	switch k := key.(type) {
	case *rsa.PrivateKey:
		pemType = "RSA PRIVATE KEY"
		keyBytes = x509.MarshalPKCS1PrivateKey(k)
	case *ecdsa.PrivateKey:
		pemType = "EC PRIVATE KEY"
		keyBytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal ECDSA private key: %w", err)
		}
	default:
		return nil, errors.New("unsupported private key type")
	}

	pemBlock := &pem.Block{
		Type:  pemType,
		Bytes: keyBytes,
	}
	return pem.EncodeToMemory(pemBlock), nil
}

// parsePrivateKey parses a PEM-encoded private key (RSA or ECDSA).
func parsePrivateKey(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	var privKey crypto.Signer
	var err error

	switch block.Type {
	case "RSA PRIVATE KEY":
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		privKey, err = x509.ParseECPrivateKey(block.Bytes)
	// TODO: Add support for PKCS#8 keys? (x509.ParsePKCS8PrivateKey)
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return privKey, nil
}

// encodeCertificate encodes an x509 certificate into PEM format.
func EncodeCertificate(cert *x509.Certificate) []byte {
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(pemBlock)
}

// parseCertificate parses a PEM-encoded x509 certificate.
func parseCertificate(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing certificate")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unexpected PEM block type: %s", block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert, nil
}

// EnsureHTTPSCertificates checks for existing certs or generates self-signed ones.
// NOTE: This self-signed approach is primarily for local dev/testing.
// Production might use cert-manager itself or another mechanism.
func EnsureHTTPSCertificates(cfg *config.Config) (string, string, error) {
	certFile := cfg.HTTPSCertFile
	keyFile := cfg.HTTPSKeyFile

	// Ensure data directory exists (where certs might be written)
	dataDir := filepath.Dir(certFile) // Assume key is in same dir
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		logger.Info("Data directory for HTTPS certs not found, creating...", zap.String("dir", dataDir))
		if err = os.MkdirAll(dataDir, 0750); err != nil {
			return "", "", fmt.Errorf("failed to create data directory '%s': %w", dataDir, err)
		}
	}

	// Check if both files already exist
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			logger.Info("Using existing HTTPS certificate and key files", zap.String("cert", certFile), zap.String("key", keyFile))
			return certFile, keyFile, nil
		}
		logger.Warn("HTTPS certificate file exists, but key file is missing. Will generate new pair.", zap.String("cert", certFile), zap.String("key", keyFile))
	} else if !os.IsNotExist(err) {
		// Error stating the cert file (other than NotExist)
		return "", "", fmt.Errorf("failed to check HTTPS certificate file '%s': %w", certFile, err)
	} else {
		// Cert file does not exist. Check if key file exists (it shouldn't ideally)
		if _, err := os.Stat(keyFile); err == nil {
			logger.Warn("HTTPS key file exists, but certificate file is missing. Will generate new pair.", zap.String("cert", certFile), zap.String("key", keyFile))
		}
	}

	// Generate new self-signed cert and key
	logger.Info("Generating new self-signed HTTPS certificate and key", zap.String("cert", certFile), zap.String("key", keyFile))

	privKey, err := rsa.GenerateKey(rand.Reader, httpsKeySize)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate HTTPS private key: %w", err)
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return "", "", err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"CA Foundry Development"},
			CommonName:   "localhost", // Common name for self-signed cert
		},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:   time.Now().Add(-1 * time.Minute),
		NotAfter:    time.Now().Add(httpsCertLifetime),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create self-signed HTTPS certificate: %w", err)
	}

	// Write cert to file
	certOut, err := os.Create(certFile)
	if err != nil {
		return "", "", fmt.Errorf("failed to open cert file for writing '%s': %w", certFile, err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		certOut.Close() // Attempt close even on error
		return "", "", fmt.Errorf("failed to write data to cert file '%s': %w", certFile, err)
	}
	if err := certOut.Close(); err != nil {
		return "", "", fmt.Errorf("failed to close cert file '%s': %w", certFile, err)
	}
	logger.Info("HTTPS certificate generated", zap.String("file", certFile))

	// Write key to file
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) // Write private key with restricted permissions
	if err != nil {
		return "", "", fmt.Errorf("failed to open key file for writing '%s': %w", keyFile, err)
	}
	privBytes := x509.MarshalPKCS1PrivateKey(privKey)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		keyOut.Close()
		return "", "", fmt.Errorf("failed to write data to key file '%s': %w", keyFile, err)
	}
	if err := keyOut.Close(); err != nil {
		return "", "", fmt.Errorf("failed to close key file '%s': %w", keyFile, err)
	}
	logger.Info("HTTPS private key generated", zap.String("file", keyFile))

	return certFile, keyFile, nil
}
