package acme_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/blockadesystems/cafoundry/internal/acme"
	"github.com/blockadesystems/cafoundry/internal/testutils" // Import test helpers
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleDirectory_Success(t *testing.T) {
	// 1. Setup Test Environment
	dbConnStr, dbCleanup := testutils.SetupTestDB(t)
	defer dbCleanup()

	// SetupTestServer now uses os.Setenv("CAFOUNDRY_EXTERNAL_URL", "https://test-ca.example.com")
	serverInstance, _ := testutils.SetupTestServer(t, dbConnStr)
	testServer := httptest.NewServer(serverInstance)
	defer testServer.Close()

	// --- CORRECTED URL EXPECTATIONS ---
	// Get the configured External URL used by the server setup
	// Ensure this matches what SetupTestServer sets via os.Setenv
	expectedExternalURL := os.Getenv("CAFOUNDRY_EXTERNAL_URL")
	require.NotEmpty(t, expectedExternalURL, "CAFOUNDRY_EXTERNAL_URL env var should be set for test setup")

	// Construct expected URLs based on the *configured* external URL
	expectedBaseURL := expectedExternalURL + "/acme"
	expectedIndexURL := expectedExternalURL + "/acme/directory"
	// --- END CORRECTION ---

	// 2. Make Request
	client := testServer.Client()
	// Use the test server's actual URL to make the request
	requestURL := testServer.URL + "/acme/directory"
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 3. Assert Response Status and Headers
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Expected status OK")
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/json", "Expected application/json content type")
	// Check Link header using the *expected* index URL
	expectedLink := fmt.Sprintf("<%s>;rel=\"index\"", expectedIndexURL)
	assert.Equal(t, expectedLink, resp.Header.Get("Link"), "Expected correct Link header")

	// 4. Assert Response Body
	bodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Failed to read response body")

	var dirResp acme.Directory
	err = json.Unmarshal(bodyBytes, &dirResp)
	require.NoError(t, err, "Failed to unmarshal response body: %s", string(bodyBytes))

	// Assert directory fields using the *expected* base URL
	assert.Equal(t, expectedBaseURL+"/new-nonce", dirResp.NewNonce)
	assert.Equal(t, expectedBaseURL+"/new-account", dirResp.NewAccount)
	assert.Equal(t, expectedBaseURL+"/new-order", dirResp.NewOrder)
	assert.Equal(t, expectedBaseURL+"/revoke-cert", dirResp.RevokeCert)
	require.NotNil(t, dirResp.Meta, "Meta field should not be nil")
	// Add assertions for Meta fields if needed, comparing against test config values
}
