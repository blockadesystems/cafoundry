package main

import (
	"net/http"
	"os"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/blockadesystems/cafoundry/internal/acme"
	"github.com/blockadesystems/cafoundry/internal/ca"
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
	logger = l.With(zap.String("package", "main"))
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

	e := echo.New()
	e.HideBanner = true
	e.Use(middleware.Recover())

	// Middle to pass caService, cfg, and store to handlers
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set("caService", caService)
			c.Set("cfg", cfg)
			c.Set("store", store)
			return next(c)
		}
	})

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "CA Foundry is running!")
	})

	// ACME protocol endpoints
	acmeGroup := e.Group("/acme")
	acmeGroup.GET("/directory", acme.HandleDirectory)            // Directory endpoint
	acmeGroup.GET("/new-nonce", acme.HandleNewNonce)             // Nonce endpoint
	acmeGroup.HEAD("/new-nonce", acme.HandleNewNonce)            // Nonce endpoint (HEAD method)
	acmeGroup.POST("/new-account", acme.HandleNewAccount)        // Account creation
	acmeGroup.POST("/account/:accountID", acme.HandleAccount)    // Account management
	acmeGroup.POST("/new-order", acme.HandleNewOrder)            // Order creation
	acmeGroup.GET("/order/:orderID", acme.HandleGetOrder)        // Order status/management
	acmeGroup.POST("/authz/:authzID", acme.HandleAuthorization)  // Authorization objects
	acmeGroup.POST("/chall/:challengeID", acme.HandleChallenge)  // Challenge objects
	acmeGroup.POST("/finalize/:orderID", acme.HandleFinalize)    // Order finalization
	acmeGroup.GET("/cert/:certID", acme.HandleCertificate)       // Certificate download
	acmeGroup.POST("/revoke-cert", acme.HandleRevokeCertificate) // Certificate revocation

	// CA Foundry specific endpoints
	// apiGroup := e.Group("/api")
	// apiGroup.GET("/health", s.handleHealth)		// Health/status endpoint
	// apiGroup.GET("/ca-chain", s.handleCAChain)	// CA certificate chain endpoint
	// apiGroup.POST("/ocsp", s.handleOCSP)		// OCSP endpoint
	// apiGroup.GET("/crl", s.handleCRL)			// CRL distribution endpoint

	address := cfg.HTTPSAddress
	logger.Info("listening on address", zap.String("address", address))
	err = e.StartTLS(address, certFile, keyFile)
	if err != nil {
		logger.Fatal("error starting HTTPS server", zap.Error(err), zap.String("address", address))
		os.Exit(1)
	}
}
