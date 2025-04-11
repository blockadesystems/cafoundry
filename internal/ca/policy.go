package ca

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"
)

// ValidateKeyUsage checks if all requested key usages are allowed by the CA policy.
func ValidateKeyUsage(certKeyUsage x509.KeyUsage, allowedUsages []x509.KeyUsage) error {
	for _, allowedUsage := range allowedUsages {
		if certKeyUsage&allowedUsage == 0 {
			return fmt.Errorf("ca: requested key usage %v is not allowed", allowedUsage)
		}
	}
	return nil
}

// ValidateExtKeyUsage checks if all requested extended key usages are allowed by the CA policy.
func ValidateExtKeyUsage(certExtKeyUsages []x509.ExtKeyUsage, allowedExtKeyUsages []x509.ExtKeyUsage) error {
	for _, allowedUsage := range allowedExtKeyUsages {
		found := false
		for _, certUsage := range certExtKeyUsages {
			if certUsage == allowedUsage {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("ca: requested extended key usage %v is not allowed", allowedUsage)
		}
	}
	return nil
}

var (
	oidExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// ValidateValidityPeriod checks if the requested validity period is within the allowed range.
// For now, we'll just check against the default validity period.
func ValidateValidityPeriod(requestedNotAfter time.Time, requestedNotBefore time.Time, defaultValidityDays int) error {
	maxNotAfter := requestedNotBefore.AddDate(0, 0, defaultValidityDays)
	if requestedNotAfter.After(maxNotAfter) {
		return fmt.Errorf("ca: requested validity period exceeds the allowed maximum")
	}
	return nil
}
