package ca

import (
	"bytes"
	"math/big"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"

	"github.com/blockadesystems/cafoundry/internal/config"
	"github.com/blockadesystems/cafoundry/internal/storage"
)

var logger *zap.Logger

func init() {
	cfg := zap.NewDevelopmentConfig()
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	l, err := cfg.Build()
	if err != nil {
		panic(err)
	}
	logger = l.With(zap.String("package", "ca"))
}

// Service represents the CA service.
type Service struct {
	config       *config.Config
	storage      storage.Storage
	caKey        *rsa.PrivateKey
	caCert       *x509.Certificate
	initialized  bool
	revokedCerts sync.Map // In-memory storage for revoked certificates (serial -> time)
}

// New creates a new CA service and initializes the CA if needed.
func New(cfg *config.Config, store storage.Storage) (*Service, error) {
	s := &Service{
		config:       cfg,
		storage:      store,
		revokedCerts: sync.Map{},
	}

	err := s.initializeCA()
	if err != nil {
		return nil, fmt.Errorf("ca: failed to initialize CA: %w", err)
	}
	s.initialized = true
	return s, nil
}

func (s *Service) initializeCA() error {
	caCertBytes, err := s.storage.GetCACertificate()
	if err != nil {
		return fmt.Errorf("ca: failed to get CA certificate from storage: %w", err)
	}
	if len(caCertBytes) > 0 {
		block, _ := pem.Decode(caCertBytes)
		if block == nil || block.Type != "CERTIFICATE" {
			return fmt.Errorf("ca: invalid CA certificate format in storage")
		}
		s.caCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("ca: failed to parse CA certificate: %w", err)
		}

		caKeyBytes, err := s.storage.GetCAPrivateKey()
		if err != nil {
			return fmt.Errorf("ca: failed to get CA private key from storage: %w", err)
		}
		if err == nil && len(caKeyBytes) > 0 {
			block, _ = pem.Decode(caKeyBytes)
			if block == nil || block.Type != "RSA PRIVATE KEY" {
				return fmt.Errorf("ca: invalid CA private key format in storage")
			}
			s.caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return fmt.Errorf("ca: failed to parse CA private key: %w", err)
			}
			logger.Info("loaded existing CA key and certificate from storage.")
			return nil
		}
		logger.Info("found CA certificate in storage but not the private key. Generating a new key...")
	} else {
		logger.Info("no existing CA key or certificate found. Generating a new CA...")
	}

	return s.generateAndStoreCA()
}

func (s *Service) generateAndStoreCA() error {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("ca: failed to generate CA private key: %w", err)
	}
	s.caKey = privKey

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("ca: failed to generate CA serial number: %w", err)
	}

	subject := pkix.Name{
		Organization: []string{s.config.Organization},
		Country:      []string{s.config.Country},
		Province:     []string{s.config.Province},
		Locality:     []string{s.config.Locality},
		CommonName:   s.config.CommonName,
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		Issuer:                subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(s.config.CACertValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          generateSubjectKeyID(&privKey.PublicKey),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return fmt.Errorf("ca: failed to create CA certificate: %w", err)
	}
	s.caCert, err = x509.ParseCertificate(derBytes)
	if err != nil {
		return fmt.Errorf("ca: failed to parse generated CA certificate: %w", err)
	}

	// Store the CA key and certificate
	err = s.storeCA(privKey, s.caCert)
	if err != nil {
		return fmt.Errorf("ca: failed to store CA key and certificate: %w", err)
	}

	logger.Info("generated and stored a new CA key and certificate.")
	return nil
}

func (s *Service) storeCA(privKey *rsa.PrivateKey, cert *x509.Certificate) error {
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	if privKeyBytes == nil {
		return fmt.Errorf("ca: failed to marshal CA private key") // Added error check
	}
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	certBytes := cert.Raw
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	err := s.storage.SaveCAPrivateKey(privKeyPEM)
	if err != nil {
		return fmt.Errorf("ca: failed to save CA private key to storage: %w", err)
	}
	err = s.storage.SaveCACertificate(certPEM)
	if err != nil {
		return fmt.Errorf("ca: failed to save CA certificate to storage: %w", err)
	}
	return nil
}

// GetCACertificate returns the CA certificate.
func (s *Service) GetCACertificate() *x509.Certificate {
	return s.caCert
}

// GetCAPublicKey returns the CA public key.
func (s *Service) GetCAPublicKey() *rsa.PublicKey {
	return &s.caKey.PublicKey
}

// IsInitialized returns the initialization status of the CA.
func (s *Service) IsInitialized() bool {
	return s.initialized
}

// RevokeCertificate revokes a certificate with the given serial number.
func (s *Service) RevokeCertificate(serialNumber string) error {
	if _, ok := s.revokedCerts.Load(serialNumber); ok {
		return fmt.Errorf("ca: certificate with serial number %s is already revoked", serialNumber)
	}
	s.revokedCerts.Store(serialNumber, time.Now())
	logger.Info("certificate has been revoked.", zap.String("serial", serialNumber))
	// In a real-world scenario, you might want to persist this revocation immediately.
	return nil
}

// SignCertificate takes a PEM-encoded CSR, validates it, signs it, and returns the PEM-encoded certificate.
func (s *Service) SignCertificate(csrPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("ca: failed to decode PEM encoded certificate request")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: failed to parse certificate request: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("ca: invalid certificate request signature: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("ca: failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		Issuer:                s.caCert.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(s.config.DefaultCertValidityDays, 0, 0), // Use default validity
		PublicKey:             csr.PublicKey,
		SignatureAlgorithm:    csr.SignatureAlgorithm,
		SubjectKeyId:          generateSubjectKeyID(csr.PublicKey),
		AuthorityKeyId:        s.caCert.SubjectKeyId,
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,               // Basic usage
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, // Common extended usages
	}

	// Apply Certificate Policies
	if err := ValidateKeyUsage(template.KeyUsage, s.config.CertificatePolicies.AllowedKeyUsages); err != nil {
		return nil, fmt.Errorf("ca: invalid key usage: %w", err)
	}

	if err := ValidateExtKeyUsage(template.ExtKeyUsage, s.config.CertificatePolicies.AllowedExtKeyUsages); err != nil {
		return nil, fmt.Errorf("ca: invalid extended key usage: %w", err)
	}

	// Validity period validation
	requestedNotAfter := time.Now().AddDate(0, 0, s.config.CertificatePolicies.DefaultValidityDays)
	if err := ValidateValidityPeriod(requestedNotAfter, time.Now(), s.config.CertificatePolicies.DefaultValidityDays); err != nil {
		return nil, fmt.Errorf("ca: invalid validity period: %w", err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, s.caCert, csr.PublicKey, s.caKey)
	if err != nil {
		return nil, fmt.Errorf("ca: failed to create certificate: %w", err)
	}

	certPEM := new(bytes.Buffer)
	if err := pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, fmt.Errorf("ca: failed to encode certificate to PEM: %w", err)
	}

	// Store the issued certificate
	err = s.storage.SaveCertificate(serialNumber.String(), derBytes)
	if err != nil {
		logger.Error("error saving issued certificate", zap.Error(err))
		// We don't want to fail the signing if storage fails, but we should log it.
	}

	return certPEM.Bytes(), nil
}

// generateSubjectKeyID generates a Subject Key Identifier for the given public key.
func generateSubjectKeyID(pub interface{}) (ski []byte) {
	var spkiASN1 []byte
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		spkiASN1, _ = x509.MarshalPKIXPublicKey(pub)
	default:
		return nil // Or handle other key types
	}

	var digest = make([]byte, 20)
	h := sha1.New()
	h.Write(spkiASN1)
	digest = h.Sum(nil)
	return digest
}

// GenerateCRL generates a Certificate Revocation List.
func (s *Service) GenerateCRL() ([]byte, error) {
	var revokedList []pkix.RevokedCertificate

	s.revokedCerts.Range(func(key, value interface{}) bool {
		serial, ok := key.(string)
		if !ok {
			logger.Warn("invalid key type in revokedCerts", zap.Any("key", key))
			return true // Continue iteration
		}
		revocationTime, ok := value.(time.Time)
		if !ok {
			logger.Warn("invalid value type in revokedCerts", zap.String("serial", serial), zap.Any("value", value))
			return true // Continue iteration
		}

		serialNumber := new(big.Int)
		serialNumber.SetString(serial, 10) // Assuming serial numbers are stored as base-10 strings

		revokedList = append(revokedList, pkix.RevokedCertificate{
			SerialNumber:   serialNumber,
			RevocationTime: revocationTime,
		})
		return true
	})

	revocationList := &x509.RevocationList{
		Number:              big.NewInt(1), // Increment this for each new CRL
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(time.Duration(s.config.CRLValidityHours) * time.Hour),
		RevokedCertificates: revokedList,
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, revocationList, s.caCert, s.caKey)
	if err != nil {
		return nil, fmt.Errorf("ca: failed to create CRL: %w", err)
	}

	// Store the generated CRL
	err = s.storage.SaveCRL(crlBytes)
	if err != nil {
		logger.Error("error saving CRL to storage", zap.Error(err))
		// Non-fatal error, we can still serve the CRL.
	}

	return crlBytes, nil
}
