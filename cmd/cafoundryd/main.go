package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/blockadesystems/cafoundry/internal/acme"
	"github.com/blockadesystems/cafoundry/internal/auth"
	"github.com/blockadesystems/cafoundry/internal/ca"
	"github.com/blockadesystems/cafoundry/internal/config"
	"github.com/blockadesystems/cafoundry/internal/management"
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
	logger = l.With(zap.String("package", "main"))
}

// Helper to apply common middleware
func applyCommonMiddleware(e *echo.Echo, store storage.Storage, cfg *config.Config, caService ca.CAService) {
	e.HideBanner = true
	e.Use(middleware.Recover())
	e.Use(middleware.RequestIDWithConfig(middleware.RequestIDConfig{
		Generator: func() string { return uuid.NewString() },
	}))

	// Middleware to set context values (logger, store, cfg, caService)
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			reqID := c.Response().Header().Get(echo.HeaderXRequestID)
			// Use the global 'logger' as the base for the request logger
			reqLogger := logger.With(zap.String("request_id", reqID))

			c.Set("caService", caService)
			c.Set("cfg", cfg)
			c.Set("store", store)
			c.Set("logger", reqLogger) // Set request-scoped logger
			return next(c)
		}
	})
	// Add Echo's logger *after* request ID and our logger are set, if desired
	e.Use(middleware.Logger())
}

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Fatal("failed to load configuration", zap.Error(err))
		os.Exit(1)
	}
	logger.Info("CA Foundry starting...", zap.Any("configuration", cfg))

	// Initialize storage
	store, err := storage.NewStorage(
		cfg.StorageType,
		cfg.DataDir,
		cfg.DBHost,
		cfg.DBUser,
		cfg.DBPassword,
		cfg.DBName,
		cfg.DBPort,
		cfg.DBSSLMode,
		cfg.DBCert,
		cfg.DBKey,
		cfg.DBRootCert,
	)
	if err != nil {
		logger.Fatal("failed to initialize storage", zap.Error(err), zap.String("storage_type", cfg.StorageType))
		os.Exit(1)
	}
	logger.Info("storage initialized")

	// Make sure the data directory exists
	if _, err := os.Stat(cfg.DataDir); os.IsNotExist(err) {
		err = os.MkdirAll(cfg.DataDir, 0755)
		if err != nil {
			logger.Fatal("failed to create data directory", zap.Error(err), zap.String("data_dir", cfg.DataDir))
			os.Exit(1)
		}
		logger.Info("created data directory", zap.String("data_dir", cfg.DataDir))
	} else {
		logger.Info("data directory exists", zap.String("data_dir", cfg.DataDir))
	}

	// Initialize CA
	caService, err := ca.New(cfg, store)
	if err != nil {
		logger.Fatal("failed to initialize CA service", zap.Error(err))
		os.Exit(1)
	}
	logger.Info("CA service initialized", zap.Bool("is_initialized", caService.IsInitialized()))

	// Ensure HTTPS certificates
	certFile, keyFile, err := ca.EnsureHTTPSCertificates(cfg)
	if err != nil {
		logger.Fatal("failed to ensure HTTPS certificates", zap.Error(err))
		os.Exit(1)
	}

	// --- Create Echo Instances ---
	httpInstance := echo.New()
	httpsInstance := echo.New()
	// --- Apply Common Middleware ---
	// Apply middleware providing context values (store, logger, cfg, caService) to BOTH instances
	applyCommonMiddleware(httpInstance, store, cfg, caService)
	applyCommonMiddleware(httpsInstance, store, cfg, caService)

	// --- Define HTTP Routes ---
	// Root handler (optional on HTTP)
	httpInstance.GET("/", func(c echo.Context) error {
		// Optional: Redirect to HTTPS?
		// return c.Redirect(http.StatusMovedPermanently, "https://"+c.Request().Host+c.Request().RequestURI)
		return c.String(http.StatusOK, "CA Foundry is running (HTTP)")
	})
	// ACME HTTP-01 Challenge Endpoint MUST be on HTTP instance
	httpInstance.GET("/.well-known/acme-challenge/:token", acme.HandleHTTP01Challenge)

	// --- Define HTTPS Routes ---
	// Root handler (optional on HTTPS)
	httpsInstance.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "CA Foundry is running (HTTPS)")
	})

	// ACME protocol endpoints MUST be on HTTPS instance
	acmeGroup := httpsInstance.Group("/acme")
	acmeGroup.GET("/directory", acme.HandleDirectory)
	acmeGroup.HEAD("/new-nonce", acme.HandleNewNonce) // HEAD before GET/POST usually
	acmeGroup.GET("/new-nonce", acme.HandleNewNonce)  // Also allow GET for nonce
	acmeGroup.POST("/new-account", acme.HandleNewAccount)
	acmeGroup.POST("/account/:accountID", acme.HandleAccount)
	acmeGroup.POST("/new-order", acme.HandleNewOrder)
	acmeGroup.POST("/order/:orderID", acme.HandleGetOrder)      // POST-as-GET
	acmeGroup.POST("/authz/:authzID", acme.HandleAuthorization) // POST-as-GET
	acmeGroup.POST("/chall/:challengeID", acme.HandleChallenge)
	acmeGroup.POST("/finalize/:orderID", acme.HandleFinalize)
	acmeGroup.POST("/cert/:certID", acme.HandleCertificate)
	acmeGroup.POST("/revoke-cert", acme.HandleRevokeCertificate)

	// --- Management API Endpoints (on httpsInstance) ---
	apiGroup := httpsInstance.Group("/api/v1")
	// Define required role for management actions
	// TODO: Make this role configurable?
	const policyAdminRole = "admin"

	// Create middleware instance requiring the admin role
	adminOnlyMiddleware := auth.APIKeyAuthMiddleware(store, policyAdminRole)

	// Apply auth middleware to the policy subgroup
	policyGroup := apiGroup.Group("/policy")
	policyGroup.Use(adminOnlyMiddleware)

	// Suffix management routes
	policyGroup.POST("/suffixes", management.HandleAddSuffix)
	policyGroup.GET("/suffixes", management.HandleListSuffixes)
	policyGroup.DELETE("/suffixes/:suffix", management.HandleDeleteSuffix)

	// Domain management routes
	policyGroup.POST("/domains", management.HandleAddDomain)
	policyGroup.GET("/domains", management.HandleListDomains)
	policyGroup.DELETE("/domains/:domain", management.HandleDeleteDomain)

	// TODO: Add endpoints for managing API keys themselves?

	// Start HTTP server and HTTPS server
	// --- Start Servers in Goroutines ---
	var wg sync.WaitGroup
	wg.Add(2) // Expect two servers to start

	go func() {
		defer wg.Done()
		logger.Info("Starting HTTP server", zap.String("address", cfg.HTTPAddress))
		if err := httpInstance.Start(cfg.HTTPAddress); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server failed to start or crashed", zap.Error(err))
			// Consider signaling main thread to exit instead of os.Exit here
		} else if err == http.ErrServerClosed {
			logger.Info("HTTP server shut down gracefully")
		}
	}()

	go func() {
		defer wg.Done()
		logger.Info("Starting HTTPS server", zap.String("address", cfg.HTTPSAddress))
		if err := httpsInstance.StartTLS(cfg.HTTPSAddress, certFile, keyFile); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTPS server failed to start or crashed", zap.Error(err))
			// Consider signaling main thread to exit
		} else if err == http.ErrServerClosed {
			logger.Info("HTTPS server shut down gracefully")
		}
	}()

	// --- Graceful Shutdown Handling ---
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit // Wait for interrupt signal

	logger.Info("Shutting down servers...")

	// Create context with timeout for shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // 10-second timeout
	defer cancel()

	// Shutdown servers
	shutdownErr := false
	if err := httpInstance.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP server shutdown failed", zap.Error(err))
		shutdownErr = true
	}
	if err := httpsInstance.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTPS server shutdown failed", zap.Error(err))
		shutdownErr = true
	}

	// Close storage connection pool
	if err := store.Close(); err != nil {
		logger.Error("Storage connection closing failed", zap.Error(err))
		shutdownErr = true
	}

	// Wait for server goroutines to finish (they should finish after Shutdown)
	// Add a timeout channel to prevent hanging indefinitely if wg.Done() isn't called
	waitChan := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitChan)
	}()

	select {
	case <-waitChan:
		logger.Info("All server goroutines finished.")
	case <-time.After(12 * time.Second): // Slightly longer than shutdown timeout
		logger.Warn("Timed out waiting for server goroutines to finish.")
		shutdownErr = true
	}

	if shutdownErr {
		logger.Warn("Shutdown completed with errors.")
		os.Exit(1)
	}
	logger.Info("Server shutdown completed successfully.")
}
