// internal/testutils/server_test_helper.go
package testutils

import (
	"context"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	// Import necessary internal packages

	"github.com/blockadesystems/cafoundry/internal/ca"
	"github.com/blockadesystems/cafoundry/internal/config"
	"github.com/blockadesystems/cafoundry/internal/server"
	"github.com/blockadesystems/cafoundry/internal/storage"

	// "github.com/google/uuid"
	"github.com/labstack/echo/v4"
	// "github.com/labstack/echo/v4/middleware"

	"go.uber.org/zap/zaptest" // Use zaptest for testing logger
)

// SetupTestServer initializes all components needed to run the Echo app for testing.
// It uses the provided database connection string (DSN from SetupTestDB).
// Returns the configured Echo instance (for HTTPS routes) and the Storage instance.
func SetupTestServer(t *testing.T, dbConnStr string) (*echo.Echo, storage.Storage) {
	t.Helper()

	// Use zaptest logger which integrates with go test logging
	testLogger := zaptest.NewLogger(t)

	// 1. Load base config
	// Temporarily set env vars for config loading if needed, or construct cfg manually
	// Here we load defaults and override DB connection, assuming other defaults are okay for testing
	os.Clearenv() // Start with clean env for predictable config loading (optional)
	// Set minimal required env vars if LoadConfig relies heavily on them
	os.Setenv("CAFOUNDRY_EXTERNAL_URL", "https://test-ca.example.com") // Use a test URL

	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load base config for test: %v", err)
	}

	// 2. Override DB config with test container DSN
	parsedURL, err := url.Parse(dbConnStr)
	if err != nil {
		t.Fatalf("Failed to parse test DB connection string '%s': %v", dbConnStr, err)
	}
	cfg.DBHost = parsedURL.Hostname()
	portStr := parsedURL.Port()
	if portStr != "" {
		cfg.DBPort, _ = strconv.Atoi(portStr)
	} else {
		cfg.DBPort = 5432
	} // Should get port from testcontainers
	if parsedURL.User != nil {
		cfg.DBUser = parsedURL.User.Username()
		cfg.DBPassword, _ = parsedURL.User.Password()
	}
	cfg.DBName = strings.TrimPrefix(parsedURL.Path, "/")
	cfg.DBSSLMode = parsedURL.Query().Get("sslmode")

	// 3. Initialize Storage with test DB config
	// Use a shorter timeout context for storage init in tests
	// initCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	_, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Manually create data dir if storage relies on it for EnsureHTTPSCertificates
	if _, err := os.Stat(cfg.DataDir); os.IsNotExist(err) {
		os.MkdirAll(cfg.DataDir, 0750)
	}

	store, err := storage.NewStorage(
		cfg.StorageType, cfg.DataDir, cfg.DBHost, cfg.DBUser, cfg.DBPassword,
		cfg.DBName, cfg.DBPort, cfg.DBSSLMode, cfg.DBCert, cfg.DBKey, cfg.DBRootCert,
	)
	if err != nil {
		t.Fatalf("Failed to initialize storage for test: %v", err)
	}
	// NewStorage should have called ensureSchema

	// 4. Initialize CA Service
	// Ensure CA key/cert are generated/loaded into the test DB
	// Need to ensure test DB is clean if CA generation only happens once.
	// Relying on SetupTestDB providing a *fresh* DB container each time.
	caService, err := ca.New(cfg, store)
	if err != nil {
		t.Fatalf("Failed to initialize CA service for test: %v", err)
	}
	if !caService.IsInitialized() {
		t.Fatalf("CA service failed to initialize key/cert in test")
	}

	// 5. Create Echo instances (need both for routing)
	httpInstance := echo.New()
	httpsInstance := echo.New()

	// 6. Apply Common Middleware
	server.ApplyCommonMiddleware(httpInstance, store, cfg, caService, testLogger)
	server.ApplyCommonMiddleware(httpsInstance, store, cfg, caService, testLogger)

	// 7. Define Routes
	server.SetupRouter(httpInstance, httpsInstance, store, cfg, caService)

	// 8. Return the HTTPS instance (as it has most routes) and storage
	return httpsInstance, store
}
