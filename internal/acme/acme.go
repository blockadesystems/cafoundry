package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"

	"github.com/blockadesystems/cafoundry/internal/ca"
	"github.com/blockadesystems/cafoundry/internal/config"
	"github.com/blockadesystems/cafoundry/internal/model"
	"github.com/blockadesystems/cafoundry/internal/storage"
	// "github.com/blockadesystems/cafoundry/internal/ca" // Import if/when caService methods are used
)

var logger *zap.Logger

// Define the signature algorithms your server accepts
var allowedSignatureAlgorithms = []jose.SignatureAlgorithm{
	jose.ES256, // ECDSA using P-256 and SHA-256 (Recommended)
	jose.RS256, // RSASSA-PKCS1-v1_5 using SHA-256
	// Add other algorithms like ES384, PS256 etc. if you intend to support them
}

// --- Structs ---

// Directory represents the ACME directory object
type Directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"` // Optional: Implement later if needed
	Meta       *Meta  `json:"meta,omitempty"`
}

// Meta contains metadata for the directory
type Meta struct {
	TermsOfService          string   `json:"termsOfService,omitempty"`
	Website                 string   `json:"website,omitempty"`
	CaaIdentities           []string `json:"caaIdentities,omitempty"`
	ExternalAccountRequired bool     `json:"externalAccountRequired,omitempty"`
}

// jwsVerifyResult holds the outcome of verifying a JWS request
type jwsVerifyResult struct {
	Payload         []byte
	Account         *model.Account
	Jwk             *jose.JSONWebKey
	Nonce           string
	ProtectedHeader jose.Header
}

// NewAccountPayload represents the expected JSON body for a new account request.
type NewAccountPayload struct {
	Contact                []string        `json:"contact"`
	TermsOfServiceAgreed   bool            `json:"termsOfServiceAgreed"`
	OnlyReturnExisting     bool            `json:"onlyReturnExisting"`
	ExternalAccountBinding json.RawMessage `json:"externalAccountBinding,omitempty"`
}

// AccountUpdatePayload represents the fields allowed in an account update request body.
type AccountUpdatePayload struct {
	Contact *[]string `json:"contact,omitempty"`
	Status  *string   `json:"status,omitempty"`
}

// NewOrderPayload represents the expected JSON body for a new order request.
type NewOrderPayload struct {
	Identifiers []model.Identifier `json:"identifiers"`
	NotBefore   string             `json:"notBefore,omitempty"` // Use string initially for RFC3339 parsing
	NotAfter    string             `json:"notAfter,omitempty"`  // Use string initially for RFC3339 parsing
}

// FinalizePayload represents the JWS payload for a finalize request.
type FinalizePayload struct {
	CSR string `json:"csr"` // Contains base64url-encoded DER CSR
}

// RevokePayload represents the JWS payload for a certificate revocation request.
type RevokePayload struct {
	Certificate string `json:"certificate"`      // base64url(DER-encoded certificate)
	Reason      *int   `json:"reason,omitempty"` // Optional CRL reason code
}

// --- Constants ---
const (
	contentTypeACMEJSON         = "application/problem+json"
	contentTypeJOSEJSON         = "application/jose+json"
	contentTypePEMChain         = "application/pem-certificate-chain"
	errTypeServerInternal       = "urn:ietf:params:acme:error:serverInternal"
	errTypeBadNonce             = "urn:ietf:params:acme:error:badNonce"
	errTypeMalformed            = "urn:ietf:params:acme:error:malformed"
	errTypeUnauthorized         = "urn:ietf:params:acme:error:unauthorized"
	errTypeUnsupportedAlgorithm = "urn:ietf:params:acme:error:badSignatureAlgorithm"
	errTypeInvalidContact       = "urn:ietf:params:acme:error:invalidContact"
	errTypeAccountDoesNotExist  = "urn:ietf:params:acme:error:accountDoesNotExist"
	errTypeUserActionRequired   = "urn:ietf:params:acme:error:userActionRequired" // For TOS agreement
	errTypeRejectedIdentifier   = "urn:ietf:params:acme:error:rejectedIdentifier"
	errTypeNotImplemented       = "urn:ietf:params:acme:error:malformed" // Use malformed for unimplemented for now
	errTypeBadCSR               = "urn:ietf:params:acme:error:badCSR"
	errTypeOrderNotReady        = "urn:ietf:params:acme:error:orderNotReady"
	errTypeBadCertificate       = "urn:ietf:params:acme:error:badCertificate"
	errTypeAlreadyRevoked       = "urn:ietf:params:acme:error:alreadyRevoked"
)

// Default CRL Reason Code (see RFC 5280 Section 5.3.1)
const defaultRevocationReason = 0 // unspecified

// --- Helpers ---

// computeKeyAuthorization generates the string needed for challenge validation.
// keyAuthz = token + "." + base64url(sha256(jwk_thumbprint))
func computeKeyAuthorization(token string, jwk *jose.JSONWebKey) (string, error) {
	if jwk == nil {
		return "", errors.New("cannot compute key authorization without JWK")
	}

	// Calculate JWK Thumbprint (RFC 7638)
	thumbprintBytes, err := jwk.Thumbprint(crypto.SHA256) // Use SHA256
	if err != nil {
		return "", fmt.Errorf("failed to compute JWK thumbprint: %w", err)
	}

	keyAuthz := fmt.Sprintf("%s.%s", token, base64.RawURLEncoding.EncodeToString(thumbprintBytes))
	return keyAuthz, nil
}

// Helper to generate ACME Problem Details response
func acmeError(c echo.Context, status int, errType string, detail string) error {
	logger := c.Get("logger").(*zap.Logger)
	logger.Warn("ACME Error Response",
		zap.Int("status", status),
		zap.String("type", errType),
		zap.String("detail", detail),
	)
	c.Response().Header().Set(echo.HeaderContentType, contentTypeACMEJSON)
	c.Response().Header().Del("Replay-Nonce") // Remove nonce on error

	prob := model.ProblemDetails{
		Type:   errType,
		Detail: detail,
		Status: status,
	}
	// Avoid sending JSON body for 204 No Content
	if status == http.StatusNoContent {
		return c.NoContent(status)
	}
	return c.JSON(status, prob)
}

// generateNonceValue creates a new secure random nonce value (base64url encoded).
func generateNonceValue() (string, error) {
	nonceBytes := make([]byte, 16) // 16 bytes = 128 bits
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random nonce bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(nonceBytes), nil
}

// generateChallengeToken creates a new secure random token (base64url encoded).
func generateChallengeToken() (string, error) {
	tokenBytes := make([]byte, 16) // 16 bytes = 128 bits
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random token bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(tokenBytes), nil
}

// verifyJWSRequest parses and verifies the JWS signature and headers.
// It handles nonce consumption and key lookup (via kid or jwk).
func verifyJWSRequest(c echo.Context) (*jwsVerifyResult, error) {
	logger := c.Get("logger").(*zap.Logger)
	store := c.Get("store").(storage.Storage)
	cfg := c.Get("cfg").(*config.Config)
	ctx := c.Request().Context()

	if c.Request().Header.Get("Content-Type") != contentTypeJOSEJSON {
		return nil, acmeError(c, http.StatusBadRequest, errTypeMalformed, "Incorrect Content-Type")
	}

	bodyBytes, err := io.ReadAll(c.Request().Body)
	if err != nil {
		logger.Error("Failed to read request body", zap.Error(err))
		return nil, acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Failed to read request")
	}
	c.Request().Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Rewind

	// Call ParseSigned with allowed algorithms. It handles the algorithm check internally.
	jws, err := jose.ParseSigned(string(bodyBytes), allowedSignatureAlgorithms)
	if err != nil {
		logger.Warn("Failed to parse JWS (or unsupported algorithm)", zap.Error(err))
		// Note: err might indicate unsupported algorithm here. Map to badSignatureAlgorithm?
		// Checking error type/string might be needed for specific ACME error.
		// Example: if strings.Contains(err.Error(), "algorithm not supported") { return nil, acmeError(...) }
		return nil, acmeError(c, http.StatusBadRequest, errTypeMalformed, "Failed to parse JWS: "+err.Error())
	}
	if len(jws.Signatures) != 1 {
		logger.Warn("Expected exactly one signature in JWS", zap.Int("signature_count", len(jws.Signatures)))
		return nil, acmeError(c, http.StatusBadRequest, errTypeMalformed, "Invalid JWS structure")
	}
	signature := jws.Signatures[0]
	protected := signature.Protected // This is jose.Header

	// --- Header Verification ---
	// Log algorithm (already validated by ParseSigned)
	alg := protected.Algorithm
	logger.Debug("JWS Algorithm", zap.String("alg", string(alg)))

	// Verify Nonce
	nonce := protected.Nonce
	if nonce == "" {
		return nil, acmeError(c, http.StatusBadRequest, errTypeBadNonce, "Missing Replay-Nonce")
	}
	consumedNonceDetails, err := store.ConsumeNonce(ctx, nonce)
	if err != nil {
		return nil, acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Nonce validation error")
	}
	if consumedNonceDetails == nil {
		return nil, acmeError(c, http.StatusBadRequest, errTypeBadNonce, "Invalid Replay-Nonce")
	}
	logger.Debug("Nonce verified and consumed", zap.String("nonce", nonce))

	// Verify URL
	reqURL := c.Request().URL
	scheme := c.Scheme()
	if scheme == "" {
		scheme = "https"
	}
	reqURLStr := fmt.Sprintf("%s://%s%s", scheme, c.Request().Host, reqURL.Path)
	var jwsURL string
	if urlVal, ok := signature.Header.ExtraHeaders["url"].(string); ok {
		jwsURL = urlVal
	}
	if jwsURL == "" {
		if urlVal, ok := protected.ExtraHeaders["url"].(string); ok {
			jwsURL = urlVal
		}
	}
	if jwsURL == "" {
		return nil, acmeError(c, http.StatusBadRequest, errTypeMalformed, "Missing URL")
	}
	if subtle.ConstantTimeCompare([]byte(jwsURL), []byte(reqURLStr)) != 1 {
		return nil, acmeError(c, http.StatusBadRequest, errTypeMalformed, "JWS URL mismatch")
	}
	logger.Debug("JWS URL verified", zap.String("url", jwsURL))

	// --- Signature Verification ---
	var payload []byte
	var result jwsVerifyResult
	result.Nonce = nonce
	result.ProtectedHeader = protected

	jwkHeaderKey := protected.JSONWebKey
	kidHeader := protected.KeyID
	hasJwk := (jwkHeaderKey != nil)
	hasKid := (kidHeader != "")

	if hasJwk && hasKid {
		return nil, acmeError(c, http.StatusBadRequest, errTypeMalformed, "Request must not have both 'jwk' and 'kid' header")
	}

	if hasJwk {
		logger.Debug("Verifying JWS using 'jwk' header")
		jwk := jwkHeaderKey
		// TODO: Check public key policy against jwk.Key
		payload, err = jws.Verify(jwk)
		if err != nil {
			return nil, acmeError(c, http.StatusUnauthorized, errTypeUnauthorized, "JWS verification error: "+err.Error())
		}
		result.Payload = payload
		result.Jwk = jwk

	} else if hasKid {
		logger.Debug("Verifying JWS using 'kid' header", zap.String("kid", kidHeader))
		accountURLPrefix := cfg.ExternalURL + "/acme/account/"
		if !strings.HasPrefix(kidHeader, accountURLPrefix) {
			return nil, acmeError(c, http.StatusBadRequest, errTypeMalformed, "Invalid 'kid' format")
		}
		accountID := strings.TrimPrefix(kidHeader, accountURLPrefix)

		account, err := store.GetAccount(ctx, accountID)
		if err != nil {
			return nil, acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Account lookup error")
		}
		if account == nil {
			return nil, acmeError(c, http.StatusUnauthorized, errTypeUnauthorized, "Account not found")
		}
		if account.Status != "valid" {
			return nil, acmeError(c, http.StatusUnauthorized, errTypeUnauthorized, "Account invalid")
		}

		accountJWK := &jose.JSONWebKey{}
		if err := json.Unmarshal([]byte(account.PublicKeyJWK), accountJWK); err != nil {
			logger.Error("Failed to unmarshal stored JWK for account", zap.String("accountID", accountID), zap.Error(err))
			return nil, acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Failed to process account key")
		}

		payload, err = jws.Verify(accountJWK)
		if err != nil {
			return nil, acmeError(c, http.StatusUnauthorized, errTypeUnauthorized, "JWS verification error: "+err.Error())
		}
		result.Payload = payload
		result.Account = account

	} else {
		// Neither jwk nor kid present
		return nil, acmeError(c, http.StatusBadRequest, errTypeMalformed, "Request must have either 'jwk' or 'kid' header")
	}

	logger.Debug("JWS verification successful")
	return &result, nil
}

// Specific errors for validation functions
var (
	errValidationMismatch = errors.New("validation content mismatch")
	errValidationNotFound = errors.New("required validation record/content not found")
	errValidationComms    = errors.New("communication error during validation")
	errValidationInternal = errors.New("internal error during validation setup")
)

// =============================================
// ACME Handler Implementations
// =============================================

// HandleDirectory serves the directory endpoint using config values.
func HandleDirectory(c echo.Context) error {
	cfg := c.Get("cfg").(*config.Config)
	logger := c.Get("logger").(*zap.Logger)

	baseURL := cfg.ExternalURL + "/acme"

	directory := Directory{
		NewNonce:   baseURL + "/new-nonce",
		NewAccount: baseURL + "/new-account",
		NewOrder:   baseURL + "/new-order",
		RevokeCert: baseURL + "/revoke-cert",
		// KeyChange:  baseURL + "/key-change", // Add if implementing
		Meta: &Meta{
			TermsOfService:          cfg.ACMEDirectoryMeta.TermsOfServiceURL,
			Website:                 cfg.ACMEDirectoryMeta.WebsiteURL,
			CaaIdentities:           cfg.ACMEDirectoryMeta.CaaIdentities,
			ExternalAccountRequired: cfg.ACMEDirectoryMeta.ExternalAccountRequired,
		},
	}
	logger.Debug("Serving ACME directory")
	// Add required Link header pointing back to the directory
	c.Response().Header().Set("Link", fmt.Sprintf("<%s/acme/directory>;rel=\"index\"", cfg.ExternalURL))
	return c.JSON(http.StatusOK, directory)
}

// HandleNewNonce generates, stores, and returns a new nonce.
func HandleNewNonce(c echo.Context) error {
	cfg := c.Get("cfg").(*config.Config)
	store := c.Get("store").(storage.Storage)
	logger := c.Get("logger").(*zap.Logger)

	nonceValue, err := generateNonceValue()
	if err != nil {
		logger.Error("Failed to generate nonce value", zap.Error(err))
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Failed to generate nonce")
	}

	now := time.Now()
	nonce := model.Nonce{
		Value:     nonceValue,
		IssuedAt:  now,
		ExpiresAt: now.Add(cfg.NonceLifetime),
	}

	ctx := c.Request().Context()
	if err := store.SaveNonce(ctx, &nonce); err != nil {
		logger.Error("Failed to save nonce to storage", zap.Error(err), zap.String("nonce", nonceValue))
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Failed to store nonce")
	}

	c.Response().Header().Set("Replay-Nonce", nonceValue)
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("Link", fmt.Sprintf("<%s/acme/directory>;rel=\"index\"", cfg.ExternalURL))

	if c.Request().Method == http.MethodHead {
		logger.Debug("Served new nonce via HEAD")
		return c.NoContent(http.StatusNoContent)
	}

	logger.Debug("Served new nonce via POST", zap.String("nonce", nonceValue))
	return c.NoContent(http.StatusOK)
}

// HandleNewAccount creates a new ACME account.
func HandleNewAccount(c echo.Context) error {
	cfg := c.Get("cfg").(*config.Config)
	store := c.Get("store").(storage.Storage)
	logger := c.Get("logger").(*zap.Logger)
	ctx := c.Request().Context()

	// 1. Verify JWS (expecting 'jwk' header)
	jwsResult, err := verifyJWSRequest(c)
	if err != nil {
		return nil
	} // Error response already sent
	if jwsResult == nil {
		// This means verifyJWSRequest likely called acmeError, sent the response,
		// and indicated failure by returning a nil result pointer, even though err is nil.
		logger.Info("Stopping handler because verifyJWSRequest indicated failure without explicit error")
		// Response was already sent by acmeError called within verifyJWSRequest
		return nil // Stop processing
	}
	if jwsResult.Jwk == nil {
		logger.Error("Internal error: JWS verification for new-account did not return JWK")
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Key processing error")
	}

	// 2. Parse Payload
	var payload NewAccountPayload
	if err := json.Unmarshal(jwsResult.Payload, &payload); err != nil {
		logger.Warn("Failed to unmarshal new account payload", zap.Error(err))
		return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Invalid payload: "+err.Error())
	}

	// 3. Handle Existing Account / OnlyReturnExisting
	jwkBytes, _ := jwsResult.Jwk.MarshalJSON()
	jwkString := string(jwkBytes)

	existingAccount, err := store.GetAccountByKeyID(ctx, jwkString)
	if err != nil {
		logger.Error("Storage error looking up account by key", zap.Error(err))
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Database error")
	}

	accountURL := ""
	if existingAccount != nil {
		logger.Info("NewAccount request matches existing account", zap.String("accountID", existingAccount.ID))
		accountURL = fmt.Sprintf("%s/acme/account/%s", cfg.ExternalURL, existingAccount.ID)
		c.Response().Header().Set("Location", accountURL)
		// Note: Don't set response nonce here yet, wait until response is ready
		// Return existing account object
	} else {
		// Account does not exist...
		if payload.OnlyReturnExisting {
			logger.Info("OnlyReturnExisting specified, but account does not exist")
			return acmeError(c, http.StatusBadRequest, errTypeAccountDoesNotExist, "No account found with the provided key")
		}

		// 4. Create New Account
		logger.Info("Creating new ACME account")

		// Validate Payload further
		if cfg.ACMEDirectoryMeta.TermsOfServiceURL != "" && !payload.TermsOfServiceAgreed {
			logger.Warn("TOS agreement required but not provided", zap.String("tosURL", cfg.ACMEDirectoryMeta.TermsOfServiceURL))
			c.Response().Header().Set("Link", fmt.Sprintf("<%s>;rel=\"terms-of-service\"", cfg.ACMEDirectoryMeta.TermsOfServiceURL))
			return acmeError(c, http.StatusConflict, errTypeUserActionRequired, "Terms of service must be agreed")
		}
		// TODO: Validate contact formats

		newAccountID := uuid.NewString()
		newAccount := model.Account{
			ID:                     newAccountID,
			PublicKeyJWK:           jwkString,
			Contact:                payload.Contact,
			Status:                 "valid",
			TermsOfService:         payload.TermsOfServiceAgreed,
			ExternalAccountBinding: payload.ExternalAccountBinding,
		}
		if err := store.SaveAccount(ctx, &newAccount); err != nil {
			logger.Error("Failed to save new account", zap.Error(err), zap.String("accountID", newAccountID))
			return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Failed to save account")
		}
		logger.Info("New account created successfully", zap.String("accountID", newAccount.ID))
		existingAccount = &newAccount // Use the newly created account for the response
		accountURL = fmt.Sprintf("%s/acme/account/%s", cfg.ExternalURL, newAccount.ID)
		c.Response().Header().Set("Location", accountURL)
	}

	// 5. Return Response (200 OK or 201 Created)
	// Generate and save a new nonce for the response header
	respNonceValue, err := generateNonceValue()
	if err != nil {
		logger.Error("Failed to generate response nonce value", zap.Error(err))
		// Proceed without nonce header
	} else {
		now := time.Now()
		respNonce := model.Nonce{Value: respNonceValue, IssuedAt: now, ExpiresAt: now.Add(cfg.NonceLifetime)}
		if err := store.SaveNonce(ctx, &respNonce); err != nil {
			logger.Error("Failed to save response nonce", zap.String("nonce", respNonceValue), zap.Error(err))
		} else {
			c.Response().Header().Set("Replay-Nonce", respNonceValue) // Set only if saved successfully
		}
	}

	// Determine status code based on whether account existed previously
	statusCode := http.StatusOK                                          // Default to 200 OK for existing
	if existingAccount.CreatedAt.Equal(existingAccount.LastModifiedAt) { // Approximation: if created == modified, it's likely new
		statusCode = http.StatusCreated
	}

	return c.JSON(statusCode, existingAccount)
}

// HandleAccount manages existing accounts (retrieval, updates).
func HandleAccount(c echo.Context) error {
	// cfg := c.Get("cfg").(*config.Config)
	store := c.Get("store").(storage.Storage)
	logger := c.Get("logger").(*zap.Logger)
	ctx := c.Request().Context()
	requestedAccountID := c.Param("accountID")

	// 1. Verify JWS (expecting 'kid' matching URL)
	jwsResult, err := verifyJWSRequest(c)
	if err != nil {
		return nil
	}
	if jwsResult.Account == nil {
		logger.Error("Internal error: JWS verification for account URL did not return account")
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Account key processing error")
	}
	account := jwsResult.Account

	if account.ID != requestedAccountID {
		logger.Warn("Account ID in JWS 'kid' header does not match account ID in URL path",
			zap.String("kid_account_id", account.ID),
			zap.String("url_account_id", requestedAccountID),
		)
		return acmeError(c, http.StatusForbidden, errTypeUnauthorized, "JWS key ID does not match account URL")
	}
	logger = logger.With(zap.String("accountID", account.ID)) // Add accountID to logger

	// 2. Parse Payload (optional)
	var payload AccountUpdatePayload
	updateRequested := false
	madeChanges := false
	if c.Request().Header.Get(echo.HeaderContentLength) != "0" && len(jwsResult.Payload) > 0 {
		// Allow empty JSON object {} for fetching via POST
		if string(jwsResult.Payload) != "{}" {
			if err := json.Unmarshal(jwsResult.Payload, &payload); err != nil {
				logger.Warn("Failed to unmarshal account update payload", zap.Error(err))
				return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Invalid payload: "+err.Error())
			}
			updateRequested = true
		}
	}

	// 3. Apply Updates (if requested)
	if updateRequested {
		// Update Status (only allowed change is to "deactivated")
		if payload.Status != nil {
			if *payload.Status == "deactivated" {
				if account.Status != "deactivated" {
					account.Status = "deactivated"
					madeChanges = true
					logger.Info("Deactivating account")
				}
			} else {
				logger.Warn("Invalid status update requested for account", zap.String("requestedStatus", *payload.Status))
				return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Invalid account status update requested (only 'deactivated' allowed)")
			}
		}

		// Update Contact
		if payload.Contact != nil {
			// TODO: Validate contact URIs
			account.Contact = *payload.Contact
			madeChanges = true
			logger.Info("Updating account contacts")
		}

		// 4. Save if changes were made
		if madeChanges {
			// LastModifiedAt updated automatically by SaveAccount helper/trigger usually
			// Or set it explicitly: account.LastModifiedAt = time.Now()
			if err := store.SaveAccount(ctx, account); err != nil {
				logger.Error("Failed to save updated account", zap.Error(err))
				return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Failed to update account")
			}
			logger.Info("Account updated successfully")
		} else {
			logger.Info("Account POST request received, but no valid changes requested.")
		}
	} else {
		logger.Info("Account GET request (via POST) successful.")
	}

	// 5. Return Response (200 OK with current/updated account state)
	respNonceValue, err := generateNonceValue()
	if err != nil {
		logger.Error("Failed to generate response nonce value", zap.Error(err))
	} else {
		now := time.Now()
		respNonce := model.Nonce{Value: respNonceValue, IssuedAt: now, ExpiresAt: now.Add(c.Get("cfg").(*config.Config).NonceLifetime)}
		if err := store.SaveNonce(ctx, &respNonce); err != nil {
			logger.Error("Failed to save response nonce", zap.String("nonce", respNonceValue), zap.Error(err))
		} else {
			c.Response().Header().Set("Replay-Nonce", respNonceValue)
		}
	}

	return c.JSON(http.StatusOK, account)
}

// HandleNewOrder creates a new certificate order.
func HandleNewOrder(c echo.Context) error {
	cfg := c.Get("cfg").(*config.Config)
	store := c.Get("store").(storage.Storage)
	logger := c.Get("logger").(*zap.Logger)
	// caSvc := c.Get("caService").(ca.CAService) // TODO: Use for policy checks?
	ctx := c.Request().Context()

	// 1. Verify JWS (expecting 'kid' header)
	jwsResult, err := verifyJWSRequest(c)
	if err != nil {
		return nil
	}
	if jwsResult.Account == nil {
		logger.Error("Internal error: JWS verification for new-order did not return account")
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Account key processing error")
	}
	account := jwsResult.Account
	logger = logger.With(zap.String("accountID", account.ID))

	// 2. Parse Payload
	var payload NewOrderPayload
	if err := json.Unmarshal(jwsResult.Payload, &payload); err != nil {
		logger.Warn("Failed to unmarshal new order payload", zap.Error(err))
		return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Invalid payload: "+err.Error())
	}
	var notBefore, notAfter time.Time
	if payload.NotBefore != "" {
		notBefore, err = time.Parse(time.RFC3339, payload.NotBefore)
		if err != nil {
			return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Invalid notBefore time format: "+err.Error())
		}
	}
	if payload.NotAfter != "" {
		notAfter, err = time.Parse(time.RFC3339, payload.NotAfter)
		if err != nil {
			return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Invalid notAfter time format: "+err.Error())
		}
	}

	// 3. Validate Identifiers
	if len(payload.Identifiers) == 0 {
		return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Order must contain at least one identifier")
	}
	if len(payload.Identifiers) > 100 {
		return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Too many identifiers requested (max 100)")
	}
	uniqueIdentifiers := make(map[string]model.Identifier)
	validatedIdentifiers := make([]model.Identifier, 0, len(payload.Identifiers))
	for _, ident := range payload.Identifiers {
		if ident.Type != "dns" {
			return acmeError(c, http.StatusBadRequest, errTypeRejectedIdentifier, "Unsupported identifier type: "+ident.Type)
		}
		if ident.Value == "" {
			return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Identifier value cannot be empty")
		}
		// TODO: Add robust DNS name validation & policy/CAA checks
		normalizedValue := strings.ToLower(ident.Value)
		ident.Value = normalizedValue
		key := fmt.Sprintf("%s:%s", ident.Type, ident.Value)
		if _, exists := uniqueIdentifiers[key]; exists {
			return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Duplicate identifier: "+ident.Value)
		}
		uniqueIdentifiers[key] = ident
		validatedIdentifiers = append(validatedIdentifiers, ident)
	}

	// 4. Prepare DB Objects
	now := time.Now()
	orderID := uuid.NewString()
	authzExpiry := now.Add(cfg.AuthorizationLifetime)
	orderExpiry := now.Add(cfg.OrderLifetime)
	if orderExpiry.Before(authzExpiry) {
		orderExpiry = authzExpiry
	} // Ensure order lives at least as long as authz

	order := &model.Order{
		ID: orderID, AccountID: account.ID, Status: "pending", Expires: orderExpiry,
		Identifiers: validatedIdentifiers, NotBefore: notBefore, NotAfter: notAfter,
		CreatedAt: now, LastModifiedAt: now,
	}
	authorizations := make([]*model.Authorization, 0, len(validatedIdentifiers))
	allChallenges := make([]*model.Challenge, 0, len(validatedIdentifiers)*2)

	for _, ident := range validatedIdentifiers {
		authzID := uuid.NewString()
		isWildcard := strings.HasPrefix(ident.Value, "*.")
		authz := &model.Authorization{
			ID: authzID, AccountID: account.ID, OrderID: orderID, Identifier: ident,
			Status: "pending", Expires: authzExpiry, Wildcard: isWildcard, CreatedAt: now,
		}
		authorizations = append(authorizations, authz)
		challengeTypes := []string{"dns-01"}
		if !isWildcard {
			challengeTypes = append(challengeTypes, "http-01")
		}
		for _, chalType := range challengeTypes {
			chalID := uuid.NewString()
			chalToken, err := generateChallengeToken()
			if err != nil {
				return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Failed to generate challenge token")
			}
			challenge := &model.Challenge{
				ID: chalID, AuthorizationID: authzID, Type: chalType, Status: "pending", Token: chalToken, CreatedAt: now,
			}
			allChallenges = append(allChallenges, challenge)
		}
	}

	// 5. Save to Storage (within a transaction)
	err = store.WithinTransaction(ctx, func(ctx context.Context, txStore storage.Storage) error {
		if err := txStore.SaveOrder(ctx, order); err != nil {
			return fmt.Errorf("save order: %w", err)
		}
		for _, authz := range authorizations {
			if err := txStore.SaveAuthorization(ctx, authz); err != nil {
				return fmt.Errorf("save authz %s: %w", authz.ID, err)
			}
		}
		for _, chal := range allChallenges {
			if err := txStore.SaveChallenge(ctx, chal); err != nil {
				return fmt.Errorf("save challenge %s: %w", chal.ID, err)
			}
		}
		return nil
	})
	if err != nil {
		logger.Error("Failed to save new order transaction", zap.Error(err))
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Failed to save order details")
	}
	logger.Info("New order created successfully", zap.String("orderID", order.ID))

	// 6. Construct Response Object
	order.Authorizations = make([]string, len(authorizations))
	for i, authz := range authorizations {
		order.Authorizations[i] = fmt.Sprintf("%s/acme/authz/%s", cfg.ExternalURL, authz.ID)
	}
	order.FinalizeURL = fmt.Sprintf("%s/acme/finalize/%s", cfg.ExternalURL, order.ID)

	// 7. Return Response (201 Created)
	respNonceValue, _ := generateNonceValue() // Error handled below
	if respNonceValue != "" {
		now = time.Now()
		respNonce := model.Nonce{Value: respNonceValue, IssuedAt: now, ExpiresAt: now.Add(cfg.NonceLifetime)}
		if err := store.SaveNonce(ctx, &respNonce); err != nil {
			logger.Error("Failed to save response nonce", zap.String("nonce", respNonceValue), zap.Error(err))
		} else {
			c.Response().Header().Set("Replay-Nonce", respNonceValue)
		}
	}
	orderURL := fmt.Sprintf("%s/acme/order/%s", cfg.ExternalURL, order.ID)
	c.Response().Header().Set("Location", orderURL)
	return c.JSON(http.StatusCreated, order)
}

// HandleGetOrder handles requests to fetch an existing order's status and details.
// Uses POST-as-GET (JWS signed request with empty payload).
func HandleGetOrder(c echo.Context) error {
	cfg := c.Get("cfg").(*config.Config)
	store := c.Get("store").(storage.Storage)
	logger := c.Get("logger").(*zap.Logger)
	ctx := c.Request().Context()
	orderID := c.Param("orderID")
	logger = logger.With(zap.String("orderID", orderID))

	// 1. Verify JWS (expecting 'kid' header)
	jwsResult, err := verifyJWSRequest(c)
	if err != nil {
		return nil
	} // Error response sent by helper
	if jwsResult.Account == nil {
		logger.Error("Internal error: JWS verification for get-order did not return account")
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Account key processing error")
	}
	account := jwsResult.Account
	logger = logger.With(zap.String("accountID", account.ID)) // Add account ID to logger context

	// 2. Fetch Order from Storage
	order, err := store.GetOrder(ctx, orderID)
	if err != nil {
		logger.Error("Storage error fetching order", zap.Error(err))
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Database error fetching order")
	}
	if order == nil {
		logger.Warn("Order not found")
		// Treat not found as unauthorized, as client shouldn't know about orders they don't own.
		return acmeError(c, http.StatusNotFound, errTypeUnauthorized, "Order not found")
	}

	// 3. Authorization Check: Ensure the order belongs to the authenticated account
	if order.AccountID != account.ID {
		logger.Warn("Account attempted to access unauthorized order",
			zap.String("order_account_id", order.AccountID),
		)
		// RFC 8555 says forbidden if account is deactivated, unauthorized if wrong account.
		// Let's return unauthorized for mismatch.
		return acmeError(c, http.StatusUnauthorized, errTypeUnauthorized, "Order does not belong to the authenticated account")
	}

	// 4. Fetch Associated Authorizations to build URLs
	authzs, err := store.GetAuthorizationsByOrderID(ctx, orderID)
	if err != nil {
		logger.Error("Storage error fetching authorizations for order", zap.Error(err))
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Database error fetching authorizations")
	}

	// 5. Populate Order URLs for the response
	order.Authorizations = make([]string, len(authzs))
	for i, authz := range authzs {
		order.Authorizations[i] = fmt.Sprintf("%s/acme/authz/%s", cfg.ExternalURL, authz.ID)
	}
	order.FinalizeURL = fmt.Sprintf("%s/acme/finalize/%s", cfg.ExternalURL, order.ID)
	if order.Status == "valid" && order.CertificateSerial != "" {
		// TODO: Decide on the Cert ID format. Using Serial for now.
		certID := url.PathEscape(order.CertificateSerial) // Ensure serial is URL-safe if needed
		order.CertificateURL = fmt.Sprintf("%s/acme/cert/%s", cfg.ExternalURL, certID)
	} else {
		order.CertificateURL = "" // Ensure cert URL is empty if not valid/issued
	}

	// 6. Generate and save response nonce, set header
	respNonceValue, _ := generateNonceValue() // Error handled below
	if respNonceValue != "" {
		now := time.Now()
		respNonce := model.Nonce{Value: respNonceValue, IssuedAt: now, ExpiresAt: now.Add(cfg.NonceLifetime)}
		if err := store.SaveNonce(ctx, &respNonce); err != nil {
			logger.Error("Failed to save response nonce", zap.String("nonce", respNonceValue), zap.Error(err))
		} else {
			c.Response().Header().Set("Replay-Nonce", respNonceValue)
		}
	}

	// 7. Return Response (200 OK)
	logger.Info("Returning order details", zap.String("status", order.Status))
	return c.JSON(http.StatusOK, order)
}

// HandleAuthorization handles requests to fetch an existing authorization's status and details.
// Uses POST-as-GET (JWS signed request with empty payload).
// TODO: Handle POST requests for deactivation (RFC 8555 Section 7.5.2) later.
func HandleAuthorization(c echo.Context) error {
	cfg := c.Get("cfg").(*config.Config)
	store := c.Get("store").(storage.Storage)
	logger := c.Get("logger").(*zap.Logger)
	ctx := c.Request().Context()
	authzID := c.Param("authzID")
	logger = logger.With(zap.String("authzID", authzID))

	// 1. Verify JWS (expecting 'kid' header)
	jwsResult, err := verifyJWSRequest(c)
	if err != nil {
		return nil
	} // Error response sent by helper
	if jwsResult.Account == nil {
		logger.Error("Internal error: JWS verification for get-authorization did not return account")
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Account key processing error")
	}
	account := jwsResult.Account
	logger = logger.With(zap.String("accountID", account.ID))

	// 2. Fetch Authorization from Storage
	authz, err := store.GetAuthorization(ctx, authzID)
	if err != nil {
		logger.Error("Storage error fetching authorization", zap.Error(err))
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Database error fetching authorization")
	}
	if authz == nil {
		logger.Warn("Authorization not found")
		// Treat not found as unauthorized.
		return acmeError(c, http.StatusNotFound, errTypeUnauthorized, "Authorization not found")
	}

	// 3. Authorization Check: Ensure the authz belongs to the authenticated account
	if authz.AccountID != account.ID {
		logger.Warn("Account attempted to access unauthorized authorization",
			zap.String("authz_account_id", authz.AccountID),
		)
		return acmeError(c, http.StatusUnauthorized, errTypeUnauthorized, "Authorization does not belong to the authenticated account")
	}

	// 4. Fetch Associated Challenges to populate response
	challenges, err := store.GetChallengesByAuthorizationID(ctx, authzID)
	if err != nil {
		logger.Error("Storage error fetching challenges for authorization", zap.Error(err))
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Database error fetching challenges")
	}

	// 5. Populate Authorization.Challenges URLs for the response
	authz.Challenges = make([]*model.Challenge, len(challenges)) // Re-slice to correct length
	for i, chal := range challenges {
		// Construct the dynamic URL for each challenge
		chal.URL = fmt.Sprintf("%s/acme/chall/%s", cfg.ExternalURL, chal.ID)
		authz.Challenges[i] = chal // Assign the challenge object (with URL) back
	}

	// 6. Generate and save response nonce, set header
	respNonceValue, _ := generateNonceValue() // Error handled below
	if respNonceValue != "" {
		now := time.Now()
		respNonce := model.Nonce{Value: respNonceValue, IssuedAt: now, ExpiresAt: now.Add(cfg.NonceLifetime)}
		if err := store.SaveNonce(ctx, &respNonce); err != nil {
			logger.Error("Failed to save response nonce", zap.String("nonce", respNonceValue), zap.Error(err))
		} else {
			c.Response().Header().Set("Replay-Nonce", respNonceValue)
		}
	}

	// 7. Return Response (200 OK)
	logger.Info("Returning authorization details", zap.String("status", authz.Status))
	// Note: We return the authz object directly. Ensure JSON tags in model.Authorization match ACME spec.
	return c.JSON(http.StatusOK, authz)
}

// HandleChallenge processes requests from clients asking the server to validate a challenge.
func HandleChallenge(c echo.Context) error {
	cfg := c.Get("cfg").(*config.Config)
	store := c.Get("store").(storage.Storage)
	logger := c.Get("logger").(*zap.Logger)
	ctx := c.Request().Context() // Base context for initial operations
	challengeID := c.Param("challengeID")
	logger = logger.With(zap.String("challengeID", challengeID))

	// 1. Verify JWS (expecting 'kid' header, empty payload '{}')
	jwsResult, err := verifyJWSRequest(c)
	if err != nil {
		return nil
	}
	if jwsResult.Account == nil {
		logger.Error("Internal error: JWS verification for challenge did not return account")
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Account key processing error")
	}
	account := jwsResult.Account
	logger = logger.With(zap.String("accountID", account.ID))

	// Verify payload is empty JSON object {}
	// Note: This check might be better placed inside verifyJWSRequest if desired
	trimmedPayload := strings.TrimSpace(string(jwsResult.Payload))
	if trimmedPayload != "{}" && trimmedPayload != "" { // Allow empty or exactly "{}"
		logger.Warn("Challenge POST payload was not empty", zap.String("payload", trimmedPayload))
		return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Challenge request payload must be an empty JSON object")
	}

	// 2. Fetch Challenge and Parent Authorization
	chal, err := store.GetChallenge(ctx, challengeID)
	if err != nil {
		logger.Error("Storage error fetching challenge", zap.Error(err))
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Database error fetching challenge")
	}
	if chal == nil {
		logger.Warn("Challenge not found")
		return acmeError(c, http.StatusNotFound, errTypeMalformed, "Challenge not found") // Use malformed as client used wrong URL
	}
	logger = logger.With(zap.String("challengeType", chal.Type), zap.String("challengeToken", chal.Token))

	authz, err := store.GetAuthorization(ctx, chal.AuthorizationID)
	if err != nil {
		logger.Error("Storage error fetching parent authorization", zap.String("authzID", chal.AuthorizationID), zap.Error(err))
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Database error fetching authorization")
	}
	if authz == nil {
		logger.Error("Parent authorization not found for challenge", zap.String("authzID", chal.AuthorizationID))
		// This indicates data inconsistency
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Authorization inconsistency")
	}
	logger = logger.With(zap.String("authzID", authz.ID), zap.String("identifier", authz.Identifier.Value))

	// 3. Authorization Check
	if authz.AccountID != account.ID {
		logger.Warn("Account attempted to respond to unauthorized challenge",
			zap.String("authz_account_id", authz.AccountID),
		)
		return acmeError(c, http.StatusUnauthorized, errTypeUnauthorized, "Challenge does not belong to the authenticated account")
	}

	// 4. State Check (Challenge, Authz, Order)
	if authz.Status != "pending" {
		logger.Warn("Challenge response sent for authorization that is not pending", zap.String("authzStatus", authz.Status))
		// If authz is already valid/invalid etc, just return the current challenge state
		chal.URL = fmt.Sprintf("%s/acme/chall/%s", cfg.ExternalURL, chal.ID) // Populate URL for response
		return c.JSON(http.StatusOK, chal)                                   // Status OK, client sees current state
	}
	if chal.Status != "pending" {
		logger.Info("Challenge response sent for challenge that is not pending", zap.String("challengeStatus", chal.Status))
		// If challenge already processing/valid/invalid, return current state
		chal.URL = fmt.Sprintf("%s/acme/chall/%s", cfg.ExternalURL, chal.ID) // Populate URL for response
		return c.JSON(http.StatusOK, chal)                                   // Status OK
	}
	// Check order status? Fetching order might be overkill here unless needed for policy. Assume authz state is sufficient.

	// 5. Update Status to "processing" and Respond Immediately
	logger.Info("Challenge received, updating status to processing")
	chal.Status = "processing"
	if err := store.SaveChallenge(ctx, chal); err != nil {
		logger.Error("Storage error updating challenge status to processing", zap.Error(err))
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Database error updating challenge")
	}

	reqLogger := c.Get("logger").(*zap.Logger) // Get request-scoped logger

	// Trigger validation asynchronously
	go performValidation(cfg, store, account, authz, chal, reqLogger)

	// Generate response nonce FIRST (before returning response)
	// respNonceValue, _ := generateNonceValue() // Error handled below
	// if respNonceValue != "" {
	// 	now := time.Now()
	// 	respNonce := model.Nonce{Value: respNonceValue, IssuedAt: now, ExpiresAt: now.Add(cfg.NonceLifetime)}
	// 	// Use background context for saving response nonce? Or original context?
	// 	// Using original might be okay if it hasn't expired yet.
	// 	if err := store.SaveNonce(ctx, &respNonce); err != nil {
	// 		logger.Error("Failed to save response nonce", zap.String("nonce", respNonceValue), zap.Error(err))
	// 	} else {
	// 		c.Response().Header().Set("Replay-Nonce", respNonceValue)
	// 	}
	// }
	respNonceValue, err := generateNonceValue()
	if err != nil {
		// Log error, but still proceed to send response without nonce
		logger.Error("Failed to generate response nonce value", zap.Error(err))
	} else {
		// Always set the header if nonce was generated
		c.Response().Header().Set("Replay-Nonce", respNonceValue)
		// Attempt to save the nonce, but log error non-fatally if it fails
		now := time.Now()
		respNonce := model.Nonce{Value: respNonceValue, IssuedAt: now, ExpiresAt: now.Add(cfg.NonceLifetime)}
		if err := store.SaveNonce(ctx, &respNonce); err != nil {
			// Log the specific pq error here for investigation, but DO NOT prevent response/header
			logger.Error("Failed to save response nonce (non-fatal for response header)",
				zap.String("nonce", respNonceValue),
				zap.Error(err), // This will contain the "pq: bind message..." error
			)
		}
	}

	chal.URL = fmt.Sprintf("%s/acme/chall/%s", cfg.ExternalURL, chal.ID)   // Populate URL for response
	authzURL := fmt.Sprintf("%s/acme/authz/%s", cfg.ExternalURL, authz.ID) // authz object is available from earlier fetch
	c.Response().Header().Set("Link", fmt.Sprintf("<%s>;rel=\"up\"", authzURL))

	return c.JSON(http.StatusOK, chal) // Respond with challenge in "processing" state
}

// performValidation runs the actual challenge check asynchronously.
func performValidation(cfg *config.Config, store storage.Storage, account *model.Account, authz *model.Authorization, chal *model.Challenge, logParam *zap.Logger) {
	// Use a background context for the async task
	// Add deadline slightly shorter than overall timeout?
	valCtx, cancel := context.WithTimeout(context.Background(), 55*time.Second) // e.g., 55 sec timeout for validation check
	defer cancel()

	bgLogger := logParam.With( // <-- Use the function parameter 'logParam'
		// zap.String("request_id", ???), // Can't easily get Req ID here
		zap.String("accountID", account.ID),
		zap.String("authzID", authz.ID),
		zap.String("challengeID", chal.ID),
		zap.String("challengeType", chal.Type),
		zap.String("identifier", authz.Identifier.Value),
	)
	bgLogger.Info("Starting background validation")

	var validationErr error
	var isValid bool

	// Get the account key for computing key authorization
	jwk := &jose.JSONWebKey{}
	if err := json.Unmarshal([]byte(account.PublicKeyJWK), jwk); err != nil {
		bgLogger.Error("Failed to unmarshal account JWK for validation", zap.Error(err))
		validationErr = errValidationInternal // Internal error
	} else {
		// Compute expected key authorization
		keyAuthz, err := computeKeyAuthorization(chal.Token, jwk)
		if err != nil {
			bgLogger.Error("Failed to compute key authorization", zap.Error(err))
			validationErr = errValidationInternal
		} else {
			// Perform validation based on type
			switch chal.Type {
			case "http-01":
				isValid, validationErr = validateHTTP01(valCtx, bgLogger, authz.Identifier.Value, chal.Token, keyAuthz)
			case "dns-01":
				// Ensure domain for DNS check doesn't have wildcard prefix if present
				domainForDNS := strings.TrimPrefix(authz.Identifier.Value, "*.")
				isValid, validationErr = validateDNS01(valCtx, cfg, bgLogger, domainForDNS, keyAuthz)
			default:
				validationErr = fmt.Errorf("unsupported challenge type: %s", chal.Type)
			}
		}
	}

	// --- Update status based on validation result ---
	if isValid {
		bgLogger.Info("Challenge validation successful")
		chal.Status = "valid"
		chal.Validated = time.Now()
		chal.Error = nil
		chal.ErrorJSON = ""
	} else {
		bgLogger.Warn("Challenge validation failed", zap.Error(validationErr))
		chal.Status = "invalid"
		// Map internal validation errors to ACME problem details
		acmeProb := model.ProblemDetails{Status: http.StatusBadRequest} // Default status
		switch {
		case errors.Is(validationErr, errValidationMismatch):
			acmeProb.Type = "urn:ietf:params:acme:error:unauthorized" // Spec suggests unauthorized for mismatch
			acmeProb.Detail = "Key authorization mismatch"
			acmeProb.Status = http.StatusUnauthorized
		case errors.Is(validationErr, errValidationNotFound):
			acmeProb.Type = "urn:ietf:params:acme:error:unauthorized" // Also unauthorized if file/record not found
			acmeProb.Detail = "Required validation file/record not found"
			acmeProb.Status = http.StatusUnauthorized
		case errors.Is(validationErr, errValidationComms):
			acmeProb.Type = "urn:ietf:params:acme:error:connection" // Or dns?
			acmeProb.Detail = fmt.Sprintf("Communication error during validation: %v", validationErr)
			acmeProb.Status = http.StatusBadRequest // Or internal error?
		case errors.Is(validationErr, errValidationInternal):
			acmeProb.Type = errTypeServerInternal
			acmeProb.Detail = fmt.Sprintf("Internal error during validation: %v", validationErr)
			acmeProb.Status = http.StatusInternalServerError
		default: // Generic / unknown error
			acmeProb.Type = errTypeServerInternal
			acmeProb.Detail = fmt.Sprintf("Challenge validation failed: %v", validationErr)
			acmeProb.Status = http.StatusInternalServerError
		}
		probBytes, _ := json.Marshal(acmeProb)
		chal.ErrorJSON = string(probBytes)
		chal.Error = &acmeProb // Keep temporarily
	}

	// Save updated challenge status
	saveCtx, saveCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer saveCancel()
	if err := store.SaveChallenge(saveCtx, chal); err != nil {
		bgLogger.Error("Failed to save updated challenge status", zap.Error(err))
		return // Critical error if we can't save state
	}
	bgLogger.Info("Challenge status updated in storage", zap.String("newStatus", chal.Status))

	// If challenge is now valid, check and update parent authorization status
	if chal.Status == "valid" {
		// Use background context for cascading updates
		updateAuthzStatus(context.Background(), bgLogger, store, authz.ID)
	}
}

// validateHTTP01 performs the check for an http-01 challenge.
func validateHTTP01(ctx context.Context, log *zap.Logger, domain string, token string, expectedKeyAuthz string) (bool, error) {
	// Construct URL: http://<domain>/.well-known/acme-challenge/<token> (MUST be HTTP, port 80)
	validationURL := fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", domain, token)
	log.Info("Performing HTTP-01 validation", zap.String("url", validationURL))

	httpClient := http.Client{
		Timeout: 15 * time.Second, // Slightly longer timeout for network ops
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// ACME spec requires validators MUST NOT follow redirects for HTTP-01
			log.Warn("HTTP-01 validation encountered redirect (not allowed)", zap.String("target", req.URL.String()))
			return http.ErrUseLastResponse // Treat redirect as failure
		},
		// Consider custom Transport for DNS resolution control if needed
	}

	req, err := http.NewRequestWithContext(ctx, "GET", validationURL, nil)
	if err != nil {
		log.Error("Failed to create HTTP-01 request object", zap.Error(err))
		return false, fmt.Errorf("%w: request creation failed: %v", errValidationInternal, err)
	}
	req.Header.Set("User-Agent", "CAFoundry ACME Validator/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Warn("HTTP-01 request execution failed", zap.Error(err))
		// Distinguish network errors? url.Error, net.OpError
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return false, fmt.Errorf("%w: connection timeout", errValidationComms)
		}
		return false, fmt.Errorf("%w: %v", errValidationComms, err)
	}
	defer resp.Body.Close()

	log.Info("HTTP-01 response received", zap.Int("status", resp.StatusCode))

	if resp.StatusCode != http.StatusOK {
		// Map specific HTTP errors? e.g., 404 -> not found, 5xx -> comms error?
		if resp.StatusCode == http.StatusNotFound {
			return false, fmt.Errorf("%w: resource not found (status %d)", errValidationNotFound, resp.StatusCode)
		}
		return false, fmt.Errorf("%w: unexpected status code %d", errValidationComms, resp.StatusCode)
	}

	// Read body, limiting size to prevent abuse (e.g., 1MB)
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		log.Warn("Failed to read HTTP-01 response body", zap.Error(err))
		return false, fmt.Errorf("%w: failed reading body: %v", errValidationComms, err)
	}
	// Response body MUST be *only* the key authorization string.
	// Trim whitespace which might be added by some servers.
	body := strings.TrimSpace(string(bodyBytes))

	// Constant time comparison is important if timing attacks are a concern,
	// though less critical for challenge validation compared to password checks.
	if subtle.ConstantTimeCompare([]byte(body), []byte(expectedKeyAuthz)) == 1 {
		log.Info("HTTP-01 validation succeeded: key authorization match")
		return true, nil
	}

	log.Warn("HTTP-01 key authorization mismatch", zap.Int("expected_len", len(expectedKeyAuthz)), zap.Int("got_len", len(body)))
	return false, errValidationMismatch
}

// validateDNS01 performs the check for a dns-01 challenge.
func validateDNS01(ctx context.Context, cfg *config.Config, log *zap.Logger, domain string, expectedKeyAuthz string) (bool, error) {
	// Construct FQDN for TXT record: _acme-challenge.<domain>.
	// Ensure domain is absolute by potentially adding a dot if missing (LookupTXT might handle this)
	fqdn := fmt.Sprintf("_acme-challenge.%s", domain)
	log.Info("Performing DNS-01 validation", zap.String("fqdn", fqdn))

	// Using Go's default resolver unless DNSResolver is configured.
	// Add timeout via context deadline if not already present.
	resolver := net.DefaultResolver
	resolverAddr := cfg.DNSResolver
	if resolverAddr != "" {
		resolver = &net.Resolver{
			PreferGo: true, // Use Go's built-in resolver
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				// Force dialing to the specific resolver address
				d := net.Dialer{Timeout: 5 * time.Second} // Add timeout
				return d.DialContext(ctx, network, resolverAddr)
			},
		}
	}

	txtRecords, err := resolver.LookupTXT(ctx, fqdn)

	if err != nil {
		log.Warn("DNS-01 TXT lookup failed", zap.Error(err))
		// Check for NXDOMAIN or similar "not found" errors
		if dnsErr, ok := err.(*net.DNSError); ok {
			if dnsErr.IsNotFound {
				return false, fmt.Errorf("%w: TXT record not found (NXDOMAIN or no record)", errValidationNotFound)
			}
			if dnsErr.Timeout() {
				return false, fmt.Errorf("%w: DNS query timed out", errValidationComms)
			}
		}
		// Treat other DNS errors as communication errors
		return false, fmt.Errorf("%w: %v", errValidationComms, err)
	}

	if len(txtRecords) == 0 {
		log.Warn("DNS-01 TXT lookup returned no records")
		return false, fmt.Errorf("%w: no TXT records found", errValidationNotFound)
	}

	log.Info("DNS-01 TXT records found", zap.Strings("records", txtRecords), zap.Int("count", len(txtRecords)))

	// Check if any record matches the expected key authorization
	for _, record := range txtRecords {
		// Constant time compare isn't strictly necessary here, but harmless.
		if subtle.ConstantTimeCompare([]byte(record), []byte(expectedKeyAuthz)) == 1 {
			log.Info("DNS-01 validation succeeded: key authorization match found")
			return true, nil
		}
	}

	log.Warn("DNS-01 expected key authorization not found in TXT records")
	return false, errValidationMismatch
}

// updateAuthzStatus checks if an authorization is complete after a challenge succeeds
// and updates the parent order if all authzs are valid.
func updateAuthzStatus(ctx context.Context, log *zap.Logger, store storage.Storage, authzID string) {
	updateCtx, cancel := context.WithTimeout(ctx, 30*time.Second) // Use background ctx passed in
	defer cancel()

	log.Info("Checking parent authorization status after challenge update")

	authz, err := store.GetAuthorization(updateCtx, authzID)
	if err != nil || authz == nil {
		log.Error("Failed to refetch authorization after challenge validation", zap.Error(err))
		return
	}
	// Check if authz is already in a final state
	if authz.Status == "valid" || authz.Status == "invalid" || authz.Status == "revoked" || authz.Status == "expired" {
		log.Debug("Parent authorization already in final state", zap.String("status", authz.Status))
		return // Already finalized, no need to check challenges
	}

	challenges, err := store.GetChallengesByAuthorizationID(updateCtx, authzID)
	if err != nil {
		log.Error("Failed to fetch challenges to update authorization status", zap.Error(err))
		return
	}

	// Check if *any* challenge is now valid. If so, the authorization becomes valid.
	var oneChallengeIsValid bool = false
	for _, ch := range challenges {
		if ch.Status == "valid" {
			oneChallengeIsValid = true
			break // Found a valid challenge, no need to check others
		}
	}

	newAuthzStatus := ""
	if oneChallengeIsValid {
		newAuthzStatus = "valid"
	} else {
		// If no challenge is valid yet, check if *all* challenges are finalized (invalid)
		allChallengesFinalized := true
		for _, ch := range challenges {
			if ch.Status == "pending" || ch.Status == "processing" {
				allChallengesFinalized = false
				break
			}
		}
		if allChallengesFinalized { // All challenges are done, but none were valid
			newAuthzStatus = "invalid"
		}
	}

	// If status needs changing, save it and potentially update order
	if newAuthzStatus != "" && newAuthzStatus != authz.Status {
		log.Info("Authorization status changing", zap.String("oldStatus", authz.Status), zap.String("newStatus", newAuthzStatus))
		authz.Status = newAuthzStatus
		if err := store.SaveAuthorization(updateCtx, authz); err != nil {
			log.Error("Failed to save authorization status", zap.String("status", newAuthzStatus), zap.Error(err))
			return // Stop processing if save fails
		}

		// If the authorization just became valid OR invalid, check the order status
		if newAuthzStatus == "valid" || newAuthzStatus == "invalid" {
			updateOrderStatus(context.Background(), log, store, authz.OrderID)
		}
	} else {
		log.Debug("Authorization status remains", zap.String("status", authz.Status))
	}
}

// updateOrderStatus checks if an order is ready after an authorization succeeds/fails.
func updateOrderStatus(ctx context.Context, log *zap.Logger, store storage.Storage, orderID string) {
	updateCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	log = log.With(zap.String("orderID", orderID))
	log.Info("Checking parent order status")

	order, err := store.GetOrder(updateCtx, orderID)
	if err != nil || order == nil {
		log.Error("Failed to refetch order after authorization update", zap.Error(err))
		return
	}
	// Avoid re-processing if order already finalized/invalid
	if order.Status != "pending" && order.Status != "processing" { // Can order be processing? Let's allow check from pending/processing.
		log.Warn("Order status changed unexpectedly or already final", zap.String("status", order.Status))
		return
	}

	// Get all authorizations for this order
	authzs, err := store.GetAuthorizationsByOrderID(updateCtx, orderID)
	if err != nil {
		log.Error("Failed to fetch authorizations to update order status", zap.Error(err))
		return
	}

	allAuthzsFinalized := true
	allAuthzsValid := true
	for _, az := range authzs {
		if az.Status == "pending" {
			allAuthzsFinalized = false
			allAuthzsValid = false // Cannot be valid if any are pending
			break
		}
		if az.Status != "valid" {
			allAuthzsValid = false // Not all are valid
			// Keep checking if all are finalized though
		}
		if az.Status == "invalid" || az.Status == "revoked" || az.Status == "expired" { // Check other failure states
			allAuthzsValid = false
			// If any authz fails, the whole order fails
			log.Warn("Order has failed/expired authorization, marking order invalid", zap.String("authzID", az.ID), zap.String("authzStatus", az.Status))
			order.Status = "invalid"
			// TODO: Set order.Error?
			if err := store.SaveOrder(updateCtx, order); err != nil {
				log.Error("Failed to save order status as invalid", zap.Error(err))
			}
			return // Stop processing order
		}
	}

	if allAuthzsValid {
		// All authorizations are valid! Order is ready.
		log.Info("Order ready, updating status to ready")
		order.Status = "ready"
		if err := store.SaveOrder(updateCtx, order); err != nil {
			log.Error("Failed to save order status as ready", zap.Error(err))
		}
	} else if allAuthzsFinalized && !allAuthzsValid {
		// All authz are done, but at least one is not 'valid' (and none were 'invalid')
		// This case shouldn't happen if invalid check above works, but defensively:
		log.Warn("Order invalid, all authorizations finalized but not all are valid")
		order.Status = "invalid"
		if err := store.SaveOrder(updateCtx, order); err != nil {
			log.Error("Failed to save order status as invalid (fallback)", zap.Error(err))
		}
	} else {
		// Still pending authorizations
		log.Debug("Order still has pending authorizations")
	}
}

// HandleHTTP01Challenge responds to validation requests for HTTP-01 challenges.
// It's typically called by the CA itself (or another validator) via an unauthenticated GET request.
func HandleHTTP01Challenge(c echo.Context) error {
	// NOTE: This handler does NOT verify JWS. It's an unauthenticated GET.
	store := c.Get("store").(storage.Storage)
	logger := c.Get("logger").(*zap.Logger) // Get logger from context middleware
	ctx := c.Request().Context()
	token := c.Param("token")
	logger = logger.With(zap.String("token", token)) // Add token to logger context

	logger.Info("Handling HTTP-01 challenge request")

	// 1. Find challenge by token
	chal, err := store.GetChallengeByToken(ctx, token)
	if err != nil {
		logger.Error("Storage error fetching challenge by token", zap.Error(err))
		// Don't reveal internal errors, just return not found
		return c.String(http.StatusNotFound, "Challenge token lookup error")
	}

	// 2. Validate Challenge State
	// Must exist, be http-01, and be in a state where validation is expected
	if chal == nil || chal.Type != "http-01" || (chal.Status != "pending" && chal.Status != "processing") {
		logger.Warn("HTTP-01 challenge not found, not http-01, or not in valid state",
			zap.Bool("found", chal != nil),
			zap.String("type", chal.Type), // Safe even if chal is nil due to short-circuiting logic (Go guarantees)
			zap.String("status", chal.Status),
		)
		// Return generic Not Found to avoid leaking information
		return c.String(http.StatusNotFound, "Challenge not found or invalid")
	}
	logger = logger.With(zap.String("challengeID", chal.ID)) // Add challenge ID now we know it

	// 3. Get Account Key (via Authz -> Account)
	authz, err := store.GetAuthorization(ctx, chal.AuthorizationID)
	if err != nil || authz == nil {
		logger.Error("Storage error fetching parent authorization for HTTP-01", zap.String("authzID", chal.AuthorizationID), zap.Error(err))
		return c.String(http.StatusInternalServerError, "Internal error fetching authorization") // Or NotFound?
	}

	account, err := store.GetAccount(ctx, authz.AccountID)
	if err != nil || account == nil {
		logger.Error("Storage error fetching parent account for HTTP-01", zap.String("accountID", authz.AccountID), zap.Error(err))
		return c.String(http.StatusInternalServerError, "Internal error fetching account") // Or NotFound?
	}
	logger = logger.With(zap.String("accountID", account.ID))

	// 4. Compute Expected Key Authorization
	jwk := &jose.JSONWebKey{}
	if err := json.Unmarshal([]byte(account.PublicKeyJWK), jwk); err != nil {
		logger.Error("Failed to unmarshal account JWK for key authorization", zap.Error(err))
		return c.String(http.StatusInternalServerError, "Internal key processing error")
	}

	keyAuthz, err := computeKeyAuthorization(chal.Token, jwk)
	if err != nil {
		logger.Error("Failed to compute key authorization string", zap.Error(err))
		return c.String(http.StatusInternalServerError, "Internal key authorization error")
	}

	// 5. Return Key Authorization
	logger.Info("Successfully providing HTTP-01 key authorization")
	// Set Content-Type (spec recommends application/octet-stream, text/plain often works too)
	c.Response().Header().Set(echo.HeaderContentType, "application/octet-stream")
	return c.String(http.StatusOK, keyAuthz)
}

// HandleFinalize processes a CSR when an order is ready.
func HandleFinalize(c echo.Context) error {
	cfg := c.Get("cfg").(*config.Config)
	store := c.Get("store").(storage.Storage)
	caSvc := c.Get("caService").(ca.CAService) // Get CA Service
	logger := c.Get("logger").(*zap.Logger)
	ctx := c.Request().Context()
	orderID := c.Param("orderID")
	logger = logger.With(zap.String("orderID", orderID))

	// 1. Verify JWS (expecting 'kid' header)
	jwsResult, err := verifyJWSRequest(c)
	if err != nil {
		return nil
	}
	if jwsResult.Account == nil {
		logger.Error("Internal error: JWS verification for finalize did not return account")
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Account key processing error")
	}
	account := jwsResult.Account
	logger = logger.With(zap.String("accountID", account.ID))

	// 2. Fetch Order & Check Ownership/State
	order, err := store.GetOrder(ctx, orderID)
	if err != nil {
		logger.Error("Storage error fetching order for finalize", zap.Error(err))
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Database error fetching order")
	}
	if order == nil {
		logger.Warn("Finalize request for non-existent order")
		return acmeError(c, http.StatusNotFound, errTypeMalformed, "Order not found") // Malformed URL used
	}
	if order.AccountID != account.ID {
		logger.Warn("Account attempted to finalize unauthorized order")
		return acmeError(c, http.StatusUnauthorized, errTypeUnauthorized, "Order does not belong to the authenticated account")
	}

	// Check Order Status
	// If already valid/invalid/processing, return current status
	switch order.Status {
	case "pending":
		logger.Warn("Finalize request for pending order")
		return acmeError(c, http.StatusForbidden, errTypeOrderNotReady, "Order is not ready for finalization (status: pending)")
	case "processing", "valid", "invalid":
		logger.Info("Finalize request for already processed/valid/invalid order", zap.String("status", order.Status))
		// Repopulate URLs for response consistency
		order.FinalizeURL = fmt.Sprintf("%s/acme/finalize/%s", cfg.ExternalURL, order.ID)
		if order.Status == "valid" && order.CertificateSerial != "" {
			certID := url.PathEscape(order.CertificateSerial)
			order.CertificateURL = fmt.Sprintf("%s/acme/cert/%s", cfg.ExternalURL, certID)
		}
		// Fetch and populate authz URLs if needed, or maybe not required if order is final? Let's skip for now.
		return c.JSON(http.StatusOK, order) // Return current state
	case "ready":
		// Proceed with finalization
		logger.Info("Order is ready, proceeding with finalization")
	default:
		logger.Error("Order has unknown status", zap.String("status", order.Status))
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Order has unexpected status: "+order.Status)
	}

	// 3. Parse Payload (CSR)
	var payload FinalizePayload
	if err := json.Unmarshal(jwsResult.Payload, &payload); err != nil {
		logger.Warn("Failed to unmarshal finalize payload", zap.Error(err))
		return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Invalid payload: "+err.Error())
	}
	if payload.CSR == "" {
		logger.Warn("Missing CSR in finalize payload")
		return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Missing 'csr' field in payload")
	}

	// 4. Decode and Parse CSR
	derBytes, err := base64.RawURLEncoding.DecodeString(payload.CSR)
	if err != nil {
		logger.Warn("Failed to base64url-decode CSR", zap.Error(err))
		return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Invalid base64url encoding for CSR")
	}
	csr, err := x509.ParseCertificateRequest(derBytes)
	if err != nil {
		logger.Warn("Failed to parse DER CSR", zap.Error(err))
		return acmeError(c, http.StatusBadRequest, errTypeBadCSR, "Failed to parse CSR: "+err.Error())
	}
	logger.Info("CSR parsed successfully")

	// 5. Validate CSR
	if err := csr.CheckSignature(); err != nil {
		logger.Warn("CSR signature validation failed", zap.Error(err))
		return acmeError(c, http.StatusBadRequest, errTypeBadCSR, "CSR signature check failed: "+err.Error())
	}
	logger.Debug("CSR signature validated")

	// Check if CSR domains match order identifiers EXACTLY
	// Note: Order matters for comparison if not sorted. Let's sort both lists first.
	csrDomains := append([]string{}, csr.DNSNames...) // Copy slices
	orderDomains := make([]string, len(order.Identifiers))
	for i, ident := range order.Identifiers {
		orderDomains[i] = ident.Value
	}
	sort.Strings(csrDomains)
	sort.Strings(orderDomains)

	if !reflect.DeepEqual(csrDomains, orderDomains) {
		logger.Warn("CSR domains do not match order identifiers", zap.Strings("csr", csrDomains), zap.Strings("order", orderDomains))
		return acmeError(c, http.StatusForbidden, errTypeBadCSR, "CSR identifiers do not match order identifiers")
	}
	logger.Debug("CSR identifiers match order")
	// TODO: Add other CSR policy checks (key type, etc.) if needed

	// 6. Update Order Status to "processing"
	logger.Info("Updating order status to processing")
	order.Status = "processing"
	order.LastModifiedAt = time.Now()
	// Use a separate context for this intermediate save? Maybe not critical.
	if err := store.SaveOrder(ctx, order); err != nil {
		logger.Error("Failed to update order status to processing", zap.Error(err))
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Failed to update order status")
	}

	// 7. Request Certificate from CA Service
	logger.Info("Requesting certificate issuance from CA service")
	certLifetime := time.Duration(cfg.DefaultCertValidityDays) * 24 * time.Hour // Use default for now
	// TODO: Consider NotBefore/NotAfter from order if policy allows

	signedCert, err := caSvc.SignCSR(ctx, csr, certLifetime, "acme") // Use "acme" as example profile
	if err != nil {
		logger.Error("CA service failed to sign CSR", zap.Error(err))
		// Update order to "invalid" with an error message
		order.Status = "invalid"
		acmeProb := model.ProblemDetails{Type: errTypeServerInternal, Detail: "Certificate issuance failed: " + err.Error()}
		probBytes, _ := json.Marshal(acmeProb) // Ignore marshal error
		order.ErrorJSON = string(probBytes)
		order.LastModifiedAt = time.Now()
		if saveErr := store.SaveOrder(ctx, order); saveErr != nil {
			logger.Error("Failed to save order status as invalid after signing error", zap.Error(saveErr))
			// Return the original signing error if we can't save invalid status
			return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Certificate issuance failed and failed to update order status")
		}
		// Return the ACME error corresponding to the signing failure
		return acmeError(c, http.StatusInternalServerError, acmeProb.Type, acmeProb.Detail)
	}
	logger.Info("Certificate issued successfully by CA service", zap.String("serial", signedCert.SerialNumber.Text(16)))

	// 8. Store Issued Certificate
	// TODO: Get issuer chain from caSvc if needed? Assume chain is handled separately or appended by client.
	certPEM := ca.EncodeCertificate(signedCert) // Use helper from ca package? Assume it exists.
	issuerCert := caSvc.GetCACertificate()      // Get the CA cert object from the service
	var issuerCertPEM []byte
	if issuerCert != nil {
		issuerCertPEM = ca.EncodeCertificate(issuerCert)
	} else {
		// Should not happen if CA is initialized, but handle defensively
		logger.Error("Could not retrieve CA certificate to build chain")
		// Decide how to handle this - fail finalize? proceed without chain?
		// Let's proceed without chain but log error. Client might complain later.
	}
	certData := &model.CertificateData{
		SerialNumber:   signedCert.SerialNumber.Text(16), // Store hex serial
		CertificatePEM: string(certPEM),
		ChainPEM:       string(issuerCertPEM),
		IssuedAt:       signedCert.NotBefore, // Use actual cert times
		ExpiresAt:      signedCert.NotAfter,
		AccountID:      account.ID,
		OrderID:        orderID,
		Revoked:        false,
	}
	if err := store.SaveCertificateData(ctx, certData); err != nil {
		logger.Error("Failed to save issued certificate data", zap.String("serial", certData.SerialNumber), zap.Error(err))
		// Order is processing but cert not saved! Critical issue. Mark order invalid?
		order.Status = "invalid"
		acmeProb := model.ProblemDetails{Type: errTypeServerInternal, Detail: "Failed to store issued certificate"}
		probBytes, _ := json.Marshal(acmeProb)
		order.ErrorJSON = string(probBytes)
		order.LastModifiedAt = time.Now()
		if saveErr := store.SaveOrder(ctx, order); saveErr != nil {
			logger.Error("Failed to save order status as invalid after cert storage error", zap.Error(saveErr))
		}
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Failed to store issued certificate")
	}
	logger.Info("Issued certificate data saved", zap.String("serial", certData.SerialNumber))

	// 9. Update Order Status to "valid"
	logger.Info("Updating order status to valid")
	order.Status = "valid"
	order.CertificateSerial = certData.SerialNumber
	order.Error = nil // Clear previous error
	order.ErrorJSON = ""
	order.LastModifiedAt = time.Now()
	if err := store.SaveOrder(ctx, order); err != nil {
		logger.Error("Failed to update order status to valid", zap.Error(err))
		// Certificate *was* issued and stored, but order status update failed.
		// Client might retry finalize? Return internal error.
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Failed to update order status after issuance")
	}

	// 10. Construct Response Object URLs
	order.FinalizeURL = fmt.Sprintf("%s/acme/finalize/%s", cfg.ExternalURL, order.ID)
	// Need authz URLs? Spec says optional for final order. Let's omit for now.
	order.Authorizations = nil
	// Construct Cert URL
	certID := url.PathEscape(order.CertificateSerial)
	order.CertificateURL = fmt.Sprintf("%s/acme/cert/%s", cfg.ExternalURL, certID)

	// 11. Return Response
	respNonceValue, _ := generateNonceValue() // Error handled below
	if respNonceValue != "" {
		now := time.Now()
		respNonce := model.Nonce{Value: respNonceValue, IssuedAt: now, ExpiresAt: now.Add(cfg.NonceLifetime)}
		if err := store.SaveNonce(ctx, &respNonce); err != nil {
			logger.Error("Failed to save response nonce", zap.String("nonce", respNonceValue), zap.Error(err))
		} else {
			c.Response().Header().Set("Replay-Nonce", respNonceValue)
		}
	}

	logger.Info("Finalize successful, returning valid order")
	return c.JSON(http.StatusOK, order)
}

// HandleCertificate serves the issued certificate upon authenticated request.
// Uses POST-as-GET (JWS signed request with empty payload).
func HandleCertificate(c echo.Context) error {
	cfg := c.Get("cfg").(*config.Config) // Needed for Link header potentially
	store := c.Get("store").(storage.Storage)
	logger := c.Get("logger").(*zap.Logger)
	ctx := c.Request().Context()
	certIDParam := c.Param("certID") // This is likely the URL-escaped Serial Number
	logger = logger.With(zap.String("certIDParam", certIDParam))

	// 1. Verify JWS (expecting 'kid' header, empty payload '{}')
	jwsResult, err := verifyJWSRequest(c)
	if err != nil {
		return nil
	} // Error response sent by helper
	if jwsResult.Account == nil {
		logger.Error("Internal error: JWS verification for get-certificate did not return account")
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Account key processing error")
	}
	account := jwsResult.Account
	logger = logger.With(zap.String("accountID", account.ID))

	// 2. Decode Certificate Identifier (assuming it's the serial number)
	// The ID might contain URL-encoded characters if the serial had them (unlikely for hex).
	serialNumber, err := url.PathUnescape(certIDParam)
	if err != nil {
		logger.Warn("Failed to unescape certificate ID parameter", zap.Error(err))
		return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Invalid certificate identifier encoding")
	}
	logger = logger.With(zap.String("serialNumber", serialNumber))

	// 3. Fetch Certificate Data from Storage
	certData, err := store.GetCertificateData(ctx, serialNumber)
	if err != nil {
		logger.Error("Storage error fetching certificate data", zap.Error(err))
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Database error fetching certificate")
	}
	if certData == nil {
		logger.Warn("Certificate data not found")
		// Return Not Found - client used a URL that doesn't exist or was maybe revoked/deleted?
		return acmeError(c, http.StatusNotFound, errTypeMalformed, "Certificate not found")
	}

	// 4. Authorization Check: Ensure the cert belongs to the authenticated account
	if certData.AccountID != account.ID {
		logger.Warn("Account attempted to access unauthorized certificate",
			zap.String("cert_account_id", certData.AccountID),
		)
		// Return Not Found to prevent leaking info about cert existence
		return acmeError(c, http.StatusNotFound, errTypeUnauthorized, "Certificate not found")
	}

	// 5. Check if Certificate is Revoked (Optional, but good practice)
	// Although ACME spec doesn't strictly forbid downloading revoked certs via this URL,
	// returning an error or different status might be desirable. Let's allow download for now.
	if certData.Revoked {
		logger.Info("Serving revoked certificate", zap.Bool("revoked", true))
		// Potentially add a Warning header? "Warning: 299 - \"Certificate is revoked\""
	}

	// 6. Prepare Response Body (PEM Chain)
	// Start with the end-entity certificate
	pemChain := new(strings.Builder)
	pemChain.WriteString(strings.TrimSpace(certData.CertificatePEM)) // Trim potential whitespace
	pemChain.WriteString("\n")                                       // Ensure newline separation

	// Append chain PEM if it exists
	if certData.ChainPEM != "" {
		pemChain.WriteString(strings.TrimSpace(certData.ChainPEM))
		pemChain.WriteString("\n")
	}
	responseBody := pemChain.String()

	// 7. Generate and save response nonce, set header
	respNonceValue, _ := generateNonceValue() // Error handled below
	if respNonceValue != "" {
		now := time.Now()
		respNonce := model.Nonce{Value: respNonceValue, IssuedAt: now, ExpiresAt: now.Add(cfg.NonceLifetime)}
		if err := store.SaveNonce(ctx, &respNonce); err != nil {
			logger.Error("Failed to save response nonce", zap.String("nonce", respNonceValue), zap.Error(err))
		} else {
			c.Response().Header().Set("Replay-Nonce", respNonceValue)
		}
	}

	// 8. Set Headers and Return Response
	c.Response().Header().Set(echo.HeaderContentType, contentTypePEMChain)
	// Add Link header pointing to directory index (optional but good practice)
	c.Response().Header().Set("Link", fmt.Sprintf("<%s/acme/directory>;rel=\"index\"", cfg.ExternalURL))

	logger.Info("Returning certificate data")
	return c.String(http.StatusOK, responseBody)
}

// HandleRevokeCertificate handles requests to revoke a certificate.
// Authentication can be via account key (kid) or certificate key (jwk).
func HandleRevokeCertificate(c echo.Context) error {
	cfg := c.Get("cfg").(*config.Config)
	store := c.Get("store").(storage.Storage)
	caSvc := c.Get("caService").(ca.CAService)
	logger := c.Get("logger").(*zap.Logger)
	ctx := c.Request().Context()

	if c.Request().Header.Get("Content-Type") != contentTypeJOSEJSON {
		return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Incorrect Content-Type")
	}

	// 1. Initial JWS Parse
	bodyBytes, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Failed to read request")
	}
	c.Request().Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Rewind

	jws, err := jose.ParseSigned(string(bodyBytes), allowedSignatureAlgorithms)
	if err != nil {
		return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Failed to parse JWS: "+err.Error())
	}
	if len(jws.Signatures) != 1 {
		return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Invalid JWS structure")
	}
	signature := jws.Signatures[0]
	protected := signature.Protected

	// 2. Header Checks (Nonce, URL, Alg)
	// Verify Nonce
	nonce := protected.Nonce
	if nonce == "" {
		return acmeError(c, http.StatusBadRequest, errTypeBadNonce, "Missing Replay-Nonce")
	}
	consumedNonceDetails, err := store.ConsumeNonce(ctx, nonce)
	if err != nil {
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Nonce validation error")
	}
	if consumedNonceDetails == nil {
		return acmeError(c, http.StatusBadRequest, errTypeBadNonce, "Invalid Replay-Nonce")
	}
	logger.Debug("Nonce verified and consumed for revokeCert", zap.String("nonce", nonce))
	// Verify URL
	reqURL := c.Request().URL
	scheme := c.Scheme()
	if scheme == "" {
		scheme = "https"
	}
	reqURLStr := fmt.Sprintf("%s://%s%s", scheme, c.Request().Host, reqURL.Path)
	var jwsURL string
	if urlVal, ok := signature.Header.ExtraHeaders["url"].(string); ok {
		jwsURL = urlVal
	}
	if jwsURL == "" {
		if urlVal, ok := protected.ExtraHeaders["url"].(string); ok {
			jwsURL = urlVal
		}
	}
	if jwsURL == "" {
		return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Missing URL")
	}
	if subtle.ConstantTimeCompare([]byte(jwsURL), []byte(reqURLStr)) != 1 {
		return acmeError(c, http.StatusBadRequest, errTypeMalformed, "JWS URL mismatch")
	}
	// Verify Algorithm
	alg := jose.SignatureAlgorithm(protected.Algorithm)
	if alg == "" {
		return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Missing algorithm")
	}
	// TODO: Check alg allowlist

	// 3. Authentication & Payload Retrieval (based on kid or jwk)
	jwkHeaderJSON, hasJwk := protected.ExtraHeaders["jwk"].(map[string]interface{})
	kidHeader, hasKid := protected.ExtraHeaders["kid"].(string)
	var payloadBytes []byte            // To store payload after verification
	var authorized bool = false        // Initialize to false
	var owningAccount *model.Account   // Store account if auth via kid
	var certToRevoke *x509.Certificate // Store parsed cert

	if hasJwk && hasKid {
		return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Request must not have both 'jwk' and 'kid' header")
	}

	if hasJwk {
		// --- Auth via Certificate Key ---
		logger.Debug("Authenticating revocation via certificate key (jwk)")
		jwkBytes, _ := json.Marshal(jwkHeaderJSON)
		jwk := &jose.JSONWebKey{}
		if err := json.Unmarshal(jwkBytes, jwk); err != nil {
			return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Invalid 'jwk' header")
		}

		// Verify JWS signature using the JWK from header -> This yields the payload
		payloadBytes, err = jws.Verify(jwk)
		if err != nil {
			logger.Warn("JWS verification failed using 'jwk' header for revoke", zap.Error(err))
			return acmeError(c, http.StatusUnauthorized, errTypeUnauthorized, "JWS verification error: "+err.Error())
		}

		// Parse Payload first to get certificate for key comparison
		var payload RevokePayload
		if err := json.Unmarshal(payloadBytes, &payload); err != nil {
			return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Invalid payload: "+err.Error())
		}
		if payload.Certificate == "" {
			return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Missing 'certificate' field")
		}
		derBytes, err := base64.RawURLEncoding.DecodeString(payload.Certificate)
		if err != nil {
			return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Invalid base64url encoding for certificate")
		}
		certToRevoke, err = x509.ParseCertificate(derBytes)
		if err != nil {
			return acmeError(c, http.StatusBadRequest, errTypeBadCertificate, "Failed to parse certificate: "+err.Error())
		}

		// Verify header JWK matches certificate's public key
		if !comparePublicKeys(jwk.Key, certToRevoke.PublicKey) {
			logger.Warn("JWK header does not match public key of certificate being revoked")
			return acmeError(c, http.StatusUnauthorized, errTypeUnauthorized, "JWK does not match certificate key")
		}
		logger.Debug("Revocation authorized by certificate key match")
		authorized = true // Mark as authorized

	} else if hasKid {
		// --- Auth via Account Key ---
		logger.Debug("Authenticating revocation via account key (kid)")
		accountURLPrefix := cfg.ExternalURL + "/acme/account/"
		if !strings.HasPrefix(kidHeader, accountURLPrefix) {
			return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Invalid 'kid' format")
		}
		accountID := strings.TrimPrefix(kidHeader, accountURLPrefix)
		logger = logger.With(zap.String("accountID", accountID))

		account, err := store.GetAccount(ctx, accountID)
		if err != nil {
			return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Account lookup error")
		}
		if account == nil {
			return acmeError(c, http.StatusUnauthorized, errTypeUnauthorized, "Account not found")
		}
		if account.Status != "valid" {
			return acmeError(c, http.StatusUnauthorized, errTypeUnauthorized, "Account invalid")
		}

		accountJWK := &jose.JSONWebKey{}
		if err := json.Unmarshal([]byte(account.PublicKeyJWK), accountJWK); err != nil {
			return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Failed to process account key")
		}

		// Verify JWS signature using the account key -> This yields the payload
		payloadBytes, err = jws.Verify(accountJWK)
		if err != nil {
			logger.Warn("JWS verification failed using 'kid' account key for revoke", zap.Error(err))
			return acmeError(c, http.StatusUnauthorized, errTypeUnauthorized, "JWS verification error: "+err.Error())
		}
		owningAccount = account // Store the account

		// Parse Payload first to get certificate for ownership check
		var payload RevokePayload
		if err := json.Unmarshal(payloadBytes, &payload); err != nil {
			return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Invalid payload: "+err.Error())
		}
		if payload.Certificate == "" {
			return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Missing 'certificate' field")
		}
		derBytes, err := base64.RawURLEncoding.DecodeString(payload.Certificate)
		if err != nil {
			return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Invalid base64url encoding for certificate")
		}
		certToRevoke, err = x509.ParseCertificate(derBytes)
		if err != nil {
			return acmeError(c, http.StatusBadRequest, errTypeBadCertificate, "Failed to parse certificate: "+err.Error())
		}
		serialNumberCheck := certToRevoke.SerialNumber.Text(16)

		// Check if this account *owns* the certificate AFTER signature verification
		certDataCheck, err := store.GetCertificateData(ctx, serialNumberCheck)
		if err != nil {
			return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Certificate ownership check error")
		}
		if certDataCheck == nil {
			return acmeError(c, http.StatusNotFound, errTypeBadCertificate, "Certificate to revoke not found")
		}
		if certDataCheck.AccountID != owningAccount.ID {
			logger.Warn("Account attempted to revoke unauthorized certificate", zap.String("cert_account_id", certDataCheck.AccountID))
			return acmeError(c, http.StatusUnauthorized, errTypeUnauthorized, "Account not authorized to revoke certificate")
		}
		logger.Debug("Revocation authorized by account ownership")
		authorized = true // Mark as authorized

	} else {
		return acmeError(c, http.StatusBadRequest, errTypeMalformed, "Request must have either 'jwk' or 'kid' header for revocation")
	}

	// 4. Final Authorization Check
	if !authorized {
		logger.Error("Authorization flag not set after authentication checks") // Should not happen
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Internal authorization state error")
	}

	// We have the parsed certToRevoke now from either path
	serialNumber := certToRevoke.SerialNumber.Text(16)
	logger = logger.With(zap.String("serialNumber", serialNumber))
	logger.Info("Revocation request authorized for certificate")

	// 5. Check if Already Revoked
	certData, err := store.GetCertificateData(ctx, serialNumber)
	if err != nil {
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Certificate lookup error")
	}
	if certData == nil {
		// This implies auth was via JWK but we never issued this cert (or it was deleted?)
		logger.Warn("Attempt to revoke certificate not issued by this CA", zap.String("serial", serialNumber))
		return acmeError(c, http.StatusNotFound, errTypeBadCertificate, "Certificate not found or not issued by this CA")
	}

	if certData.Revoked {
		logger.Info("Certificate already revoked")
		// Set response nonce
		respNonceValue, _ := generateNonceValue()
		if respNonceValue != "" {
			now := time.Now()
			respNonce := model.Nonce{Value: respNonceValue, IssuedAt: now, ExpiresAt: now.Add(cfg.NonceLifetime)}
			if err := store.SaveNonce(ctx, &respNonce); err == nil {
				c.Response().Header().Set("Replay-Nonce", respNonceValue)
			}
		}
		return c.NoContent(http.StatusOK) // 200 OK, no body
	}

	// 6. Perform Revocation via CA Service
	// Re-parse payload to get reason code (needed because payloadBytes scope ends)
	var payload RevokePayload
	_ = json.Unmarshal(payloadBytes, &payload) // Ignore error here, already parsed once
	reason := defaultRevocationReason
	if payload.Reason != nil {
		reason = *payload.Reason
		// TODO: Validate reason code?
	}
	logger.Info("Requesting revocation via CA service", zap.Int("reason", reason))
	err = caSvc.RevokeCertificate(ctx, serialNumber, reason)
	if err != nil {
		logger.Error("CA service failed to revoke certificate", zap.Error(err))
		return acmeError(c, http.StatusInternalServerError, errTypeServerInternal, "Revocation failed: "+err.Error())
	}
	logger.Info("Certificate revoked successfully")

	// 7. Return Response (200 OK)
	respNonceValue, _ := generateNonceValue()
	if respNonceValue != "" {
		now := time.Now()
		respNonce := model.Nonce{Value: respNonceValue, IssuedAt: now, ExpiresAt: now.Add(cfg.NonceLifetime)}
		if err := store.SaveNonce(ctx, &respNonce); err == nil {
			c.Response().Header().Set("Replay-Nonce", respNonceValue)
		}
	}
	c.Response().Header().Set("Link", fmt.Sprintf("<%s/acme/directory>;rel=\"index\"", cfg.ExternalURL))

	return c.NoContent(http.StatusOK) // 200 OK, no body
}

// --- Helper Functions ---
func min(a, b int) int { // Keep helper for logging potentially long keys/ids
	if a < b {
		return a
	}
	return b
}

// comparePublicKeys checks if two crypto.PublicKey instances are equivalent.
// Handles RSA, ECDSA, and Ed25519 keys. Returns false for unsupported types.
func comparePublicKeys(key1, key2 crypto.PublicKey) bool {
	if key1 == nil || key2 == nil {
		return false
	}

	switch k1 := key1.(type) {
	case *rsa.PublicKey:
		k2, ok := key2.(*rsa.PublicKey)
		if !ok {
			return false // Types don't match
		}
		// Compare modulus and public exponent
		return k1.N.Cmp(k2.N) == 0 && k1.E == k2.E

	case *ecdsa.PublicKey:
		k2, ok := key2.(*ecdsa.PublicKey)
		if !ok {
			return false // Types don't match
		}
		// Compare curve and public point (X, Y)
		return k1.Curve == k2.Curve && k1.X.Cmp(k2.X) == 0 && k1.Y.Cmp(k2.Y) == 0

	case ed25519.PublicKey:
		// ed25519.PublicKey is a []byte
		k2, ok := key2.(ed25519.PublicKey)
		if !ok {
			return false // Types don't match
		}
		// Compare byte slices
		return bytes.Equal(k1, k2)

	default:
		// Unsupported key type
		logger.Warn("comparePublicKeys encountered unsupported key type", zap.Any("type", k1)) // Use package logger if needed
		return false
	}
}
