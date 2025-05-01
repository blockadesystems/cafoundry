// In internal/acme/nonce_test.go
package acme_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os" // <-- Ensure 'os' is imported
	"testing"

	"github.com/blockadesystems/cafoundry/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleNewNonce_Success(t *testing.T) {
	// 1. Setup Test Environment
	dbConnStr, dbCleanup := testutils.SetupTestDB(t)
	defer dbCleanup()

	serverInstance, _ := testutils.SetupTestServer(t, dbConnStr)
	testServer := httptest.NewServer(serverInstance)
	defer testServer.Close()

	nonceURL := testServer.URL + "/acme/new-nonce"
	// --- CORRECTED URL EXPECTATION ---
	expectedExternalURL := os.Getenv("CAFOUNDRY_EXTERNAL_URL")
	require.NotEmpty(t, expectedExternalURL, "CAFOUNDRY_EXTERNAL_URL env var should be set for test setup")
	expectedDirURL := expectedExternalURL + "/acme/directory" // Base expectation on config
	expectedLink := fmt.Sprintf("<%s>;rel=\"index\"", expectedDirURL)
	// --- END CORRECTION ---
	client := testServer.Client()

	var firstNonce string

	// 2. Test HEAD Request
	t.Run("HEAD request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodHead, nonceURL, nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode, "HEAD: Expected 204 No Content")
		firstNonce = resp.Header.Get("Replay-Nonce")
		assert.NotEmpty(t, firstNonce, "HEAD: Replay-Nonce header should not be empty")
		assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"), "HEAD: Expected Cache-Control: no-store")
		assert.Equal(t, expectedLink, resp.Header.Get("Link"), "HEAD: Expected correct Link header") // Uses corrected link

		bodyBytes, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Empty(t, bodyBytes, "HEAD: Body should be empty")
	})

	// 3. Test POST Request
	t.Run("POST request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, nonceURL, nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Assertions now expect 200 OK and correct headers/body for POST
		assert.Equal(t, http.StatusOK, resp.StatusCode, "POST: Expected 200 OK")
		secondNonce := resp.Header.Get("Replay-Nonce")
		assert.NotEmpty(t, secondNonce, "POST: Replay-Nonce header should not be empty")
		assert.NotEqual(t, firstNonce, secondNonce, "POST: Nonce should be different from HEAD request")
		assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"), "POST: Expected Cache-Control: no-store")
		assert.Equal(t, expectedLink, resp.Header.Get("Link"), "POST: Expected correct Link header") // Uses corrected link

		assert.Equal(t, int64(0), resp.ContentLength, "POST: ContentLength should be 0")
		bodyBytes, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Empty(t, bodyBytes, "POST: Body should be empty")
	})
}
