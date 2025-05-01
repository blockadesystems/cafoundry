// internal/acme/account_test.go
package acme_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/blockadesystems/cafoundry/internal/acme" // Import needed for payload struct access
	"github.com/blockadesystems/cafoundry/internal/model"
	"github.com/blockadesystems/cafoundry/internal/testutils" // Import test helpers
	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create a JWS for testing
// Uses Flattened JWS JSON Serialization as required by ACME
func createTestJWS(t *testing.T, url string, nonce string, payload []byte, signingKey jose.SigningKey, pubKey *jose.JSONWebKey, includeJWK bool) string {
	t.Helper()

	// 1. Prepare Signer Options
	signerOpts := jose.SignerOptions{}
	// Use WithHeader for standard protected headers not directly on options struct
	signerOpts.WithHeader("nonce", nonce)
	signerOpts.WithHeader("url", url)

	if includeJWK {
		if pubKey == nil {
			t.Fatal("pubKey cannot be nil when includeJWK is true")
		}
		// Signal library to embed the JWK (should go in protected header)
		signerOpts.EmbedJWK = true
	} else {
		t.Fatal("KID signing not implemented in this helper yet")
		// Example if using KID:
		// kid := "accountURL_string"
		// signerOpts.WithHeader(jose.HeaderKey("kid"), kid) // Add kid via WithHeader
	}

	// 2. Create Signer
	// Algorithm is implicitly taken from the signingKey
	// Using .WithType("JOSE+JSON") might be incorrect here, often used for JWE?
	// Let's try without it first, as the Content-Type header on the request sets the context.
	signer, err := jose.NewSigner(signingKey, &signerOpts)
	require.NoError(t, err, "Failed to create JWS signer")

	// 3. Sign the payload using the original Sign method
	// The library uses the key and options to build the correct protected header internally
	jwsObject, err := signer.Sign(payload)
	require.NoError(t, err, "Failed to sign JWS payload")

	// 4. Serialize to Flattened JSON using components from the signing result
	if len(jwsObject.Signatures) != 1 {
		t.Fatalf("Expected exactly one signature, got %d", len(jwsObject.Signatures))
	}
	signature := jwsObject.Signatures[0]

	// Marshal the *actual* protected header used by the library in the signature result
	// This *will* contain alg, nonce, url, jwk/kid correctly set by the library.
	rawProtectedBytes, err := json.Marshal(signature.Protected)
	require.NoError(t, err, "Failed to marshal signed protected header")
	b64Protected := base64.RawURLEncoding.EncodeToString(rawProtectedBytes)

	b64Payload := base64.RawURLEncoding.EncodeToString(payload)
	b64Signature := base64.RawURLEncoding.EncodeToString(signature.Signature)

	// Construct Flattened JWS JSON
	flattenedJWS := fmt.Sprintf(`{"protected": "%s", "payload": "%s", "signature": "%s"}`,
		b64Protected, b64Payload, b64Signature)

	t.Logf("Constructed JWS: %s", flattenedJWS)
	// Optional: Log decoded protected header to verify 'alg', 'nonce', 'url', 'jwk' are present
	decodedProtected, _ := base64.RawURLEncoding.DecodeString(b64Protected)
	t.Logf("Decoded Protected Header Used: %s", string(decodedProtected))

	return flattenedJWS
}

func TestHandleNewAccount_Success(t *testing.T) {
	// 1. Setup Test Environment
	dbConnStr, dbCleanup := testutils.SetupTestDB(t)
	defer dbCleanup()

	serverInstance, store := testutils.SetupTestServer(t, dbConnStr)
	testServer := httptest.NewServer(serverInstance)
	defer testServer.Close()

	// Get configured external URL for constructing target URLs
	cfgExternalURL := os.Getenv("CAFOUNDRY_EXTERNAL_URL")
	require.NotEmpty(t, cfgExternalURL, "CAFOUNDRY_EXTERNAL_URL env var should be set for test setup")

	// 2. Generate ACME Account Key Pair (ECDSA P-256)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	publicKey := &privateKey.PublicKey
	// Create JOSE keys
	pubJWK := &jose.JSONWebKey{Key: publicKey, Algorithm: string(jose.ES256)}
	signingKey := jose.SigningKey{Algorithm: jose.ES256, Key: privateKey}

	// 3. Get Nonce from Server
	nonceURL := testServer.URL + "/acme/new-nonce"
	nonceReq, _ := http.NewRequest(http.MethodHead, nonceURL, nil)
	nonceResp, err := testServer.Client().Do(nonceReq)
	require.NoError(t, err)
	nonce := nonceResp.Header.Get("Replay-Nonce")
	require.NotEmpty(t, nonce, "Failed to get nonce from server")
	nonceResp.Body.Close()

	// 4. Craft Payload
	contactEmail := "test-acct@example.org"
	newAccountReqPayload := acme.NewAccountPayload{ // Use exported type name if defined in acme package
		Contact:              []string{"mailto:" + contactEmail},
		TermsOfServiceAgreed: true,
	}
	payloadBytes, err := json.Marshal(newAccountReqPayload)
	require.NoError(t, err)

	// 5. Craft JWS Request Body (Flattened JSON)
	newAccountURL := cfgExternalURL + "/acme/new-account" // The URL protected header must match
	jwsBody := createTestJWS(t, newAccountURL, nonce, payloadBytes, signingKey, pubJWK, true)

	// 6. Make Request to New Account Endpoint
	client := testServer.Client()
	httpReq, err := http.NewRequest(http.MethodPost, testServer.URL+"/acme/new-account", strings.NewReader(jwsBody))
	require.NoError(t, err)
	httpReq.Header.Set("Content-Type", "application/jose+json")

	httpResp, err := client.Do(httpReq)
	require.NoError(t, err)
	defer httpResp.Body.Close()

	// 7. Assert Response
	respBodyBytes, _ := io.ReadAll(httpResp.Body) // Read body for potential error details
	assert.Equal(t, http.StatusCreated, httpResp.StatusCode, "Expected 201 Created, body: %s", string(respBodyBytes))

	// Check Headers
	assert.NotEmpty(t, httpResp.Header.Get("Replay-Nonce"), "Expected Replay-Nonce header")
	location := httpResp.Header.Get("Location")
	assert.NotEmpty(t, location, "Expected Location header")
	expectedLocationPrefix := cfgExternalURL + "/acme/account/"
	assert.True(t, strings.HasPrefix(location, expectedLocationPrefix), "Location header has wrong prefix. Got %s", location)

	// Check Response Body (ACME Account object)
	var accountResp model.Account
	err = json.Unmarshal(respBodyBytes, &accountResp)
	require.NoError(t, err, "Failed to unmarshal response body into Account struct")

	assert.NotEmpty(t, accountResp.ID, "Account ID should not be empty")
	assert.Equal(t, "valid", accountResp.Status, "Account status should be valid")
	require.Len(t, accountResp.Contact, 1, "Expected 1 contact email")
	assert.Equal(t, "mailto:"+contactEmail, accountResp.Contact[0])
	// PublicKeyJWK field is not included in response JSON body

	// 8. Assert Database State
	accountID := strings.TrimPrefix(location, expectedLocationPrefix)
	dbAccount, err := store.GetAccount(context.Background(), accountID) // Use background context for DB check
	require.NoError(t, err, "Error getting account from DB")
	require.NotNil(t, dbAccount, "Account should exist in DB")

	assert.Equal(t, accountID, dbAccount.ID)
	assert.Equal(t, "valid", dbAccount.Status)
	assert.Equal(t, newAccountReqPayload.Contact, dbAccount.Contact) // Compare slices

	// Compare stored JWK
	pubJWKBytes, _ := pubJWK.MarshalJSON()
	assert.JSONEq(t, string(pubJWKBytes), dbAccount.PublicKeyJWK, "Stored Public Key JWK does not match generated key")
}

// TODO: Add more tests for HandleNewAccount (e.g., existing account, bad nonce, bad signature, TOS failure)
