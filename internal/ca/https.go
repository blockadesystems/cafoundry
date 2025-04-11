package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"go.uber.org/zap"

	"github.com/blockadesystems/cafoundry/internal/config"
)

// var logger *zap.Logger

func init() {
	logger = zap.L().With(zap.String("package", "ca"))
}

// EnsureHTTPSCertificates checks if the HTTPS certificate and key files exist.
// If they don't, it generates a self-signed certificate and saves them to the configured paths.
// It returns the paths to the certificate and key files.
func EnsureHTTPSCertificates(cfg *config.Config) (certFile string, keyFile string, err error) {
	if _, err := os.Stat(cfg.HTTPSCertFile); os.IsNotExist(err) {
		if _, err := os.Stat(cfg.HTTPSKeyFile); os.IsNotExist(err) {
			// Generate self-signed certificate
			err = generateSelfSignedCert(cfg.HTTPSCertFile, cfg.HTTPSKeyFile, cfg.CommonName)
			if err != nil {
				return "", "", fmt.Errorf("ca: failed to generate self-signed certificate: %w", err)
			}
			logger.Info("generated self-signed HTTPS certificate", zap.String("cert_file", cfg.HTTPSCertFile), zap.String("key_file", cfg.HTTPSKeyFile))
		} else {
			return "", "", fmt.Errorf("ca: key file exists but cert file does not")
		}
	} else if _, err := os.Stat(cfg.HTTPSKeyFile); os.IsNotExist(err) {
		return "", "", fmt.Errorf("ca: cert file exists but key file does not")
	} else {
		logger.Info("found existing HTTPS certificate and key", zap.String("cert_file", cfg.HTTPSCertFile), zap.String("key_file", cfg.HTTPSKeyFile))
	}

	return cfg.HTTPSCertFile, cfg.HTTPSKeyFile, nil
}

// generateSelfSignedCert generates a self-signed certificate for HTTPS.
func generateSelfSignedCert(certFile string, keyFile string, commonName string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("ca: failed to generate private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("ca: failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: commonName},
		Issuer:                pkix.Name{CommonName: commonName},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // 1 year validity
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")}, // Add localhost as a valid IP
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("ca: failed to create self-signed certificate: %w", err)
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("ca: failed to create certificate file: %w", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("ca: failed to write certificate file: %w", err)
	}

	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("ca: failed to create private key file: %w", err)
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return fmt.Errorf("ca: failed to write private key file: %w", err)
	}

	return nil
}
