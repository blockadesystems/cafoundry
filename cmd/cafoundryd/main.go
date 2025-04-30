package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/blockadesystems/cafoundry/internal/ca"
	"github.com/blockadesystems/cafoundry/internal/config"

	"github.com/blockadesystems/cafoundry/internal/server"
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

// Helper to generate secure API keys (e.g., 32 bytes -> 43 base64url chars)
func generateAPIKey(byteLength int) (string, error) {
	bytes := make([]byte, byteLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// Helper to generate random salt
func generateSalt(byteLength int) ([]byte, error) {
	salt := make([]byte, byteLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// Helper to hash API key with salt
func hashAPIKeyWithSaltBytes(saltBytes []byte, apiKeyPlaintext string) string {
	hashInput := append(saltBytes, []byte(apiKeyPlaintext)...)
	hashBytes := sha256.Sum256(hashInput)
	return hex.EncodeToString(hashBytes[:])
}

func main() {
	// --- Define Flags ---
	createAPIKey := flag.Bool("create-api-key", false, "Create a new API key, print it, and exit.")
	apiKeyRoles := flag.String("roles", "admin", "Comma-separated roles for new API key (e.g., admin,revoke)")
	apiKeyDesc := flag.String("description", "", "(Optional) Description for new API key")
	// configFilePath := flag.String("config", "", "(Optional) Path to config file (not implemented yet)")

	flag.Parse() // Parse flags early

	// --- Load Configuration ---
	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Fatal("failed to load configuration", zap.Error(err))
		os.Exit(1)
	}

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

	// --- Handle --create-api-key Flag ---
	if *createAPIKey {
		fmt.Println("Creating new API key...")
		defer store.Close() // Close store connection if we exit here

		rolesInput := strings.TrimSpace(*apiKeyRoles)
		if rolesInput == "" {
			fmt.Fprintln(os.Stderr, "Error: --roles flag cannot be empty.")
			os.Exit(1)
		}
		roles := make([]string, 0)
		for _, r := range strings.Split(rolesInput, ",") {
			trimmed := strings.TrimSpace(r)
			if trimmed != "" {
				roles = append(roles, trimmed)
			}
		}
		if len(roles) == 0 {
			fmt.Fprintln(os.Stderr, "Error: No valid roles specified.")
			os.Exit(1)
		}

		// Generate Key
		apiKeyPlaintext, err := generateAPIKey(32) // 32 bytes = 256 bits
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating API key: %v\n", err)
			os.Exit(1)
		}

		// Generate Salt (e.g., 16 bytes)
		saltBytes, err := generateSalt(16)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating salt: %v\n", err)
			os.Exit(1)
		}
		saltHex := hex.EncodeToString(saltBytes)

		// Hash Key with Salt
		keyHashHex := hashAPIKeyWithSaltBytes(saltBytes, apiKeyPlaintext)

		// Generate Prefix (first 8 chars)
		const keyPrefixLength = 8
		if len(apiKeyPlaintext) <= keyPrefixLength {
			fmt.Fprintf(os.Stderr, "Error: Generated key too short (this shouldn't happen)\n")
			os.Exit(1)
		}
		keyPrefix := apiKeyPlaintext[:keyPrefixLength]

		// Save Hashed Key, Salt, Prefix etc.
		err = store.SaveSaltedAPIKey(context.Background(), keyPrefix, saltHex, keyHashHex, *apiKeyDesc, roles)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error saving API key to storage: %v\n", err)
			os.Exit(1)
		}

		// Print details - IMPORTANT: Only time plaintext key is shown!
		fmt.Println("\n--- API Key Created Successfully ---")
		fmt.Printf("Key Prefix:   %s\n", keyPrefix)
		fmt.Printf("Description:  %s\n", *apiKeyDesc)
		fmt.Printf("Roles:        %v\n", roles)
		// fmt.Printf("Salt (Hex):   %s (Stored)\n", saltHex)       // Optional: Show salt?
		// fmt.Printf("Key Hash (Hex): %s (Stored)\n", keyHashHex) // Optional: Show hash?
		fmt.Printf("\nPLAINTEXT KEY (SAVE THIS NOW!): %s\n\n", apiKeyPlaintext)

		os.Exit(0) // Exit after creating key
	}

	defer store.Close() // Defer store close for normal server run
	logger.Info("CA Foundry starting...", zap.Any("configuration", cfg))

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
	server.ApplyCommonMiddleware(httpInstance, store, cfg, caService, logger)
	server.ApplyCommonMiddleware(httpsInstance, store, cfg, caService, logger)

	// --- Define HTTP Routes ---
	server.SetupRouter(httpInstance, httpsInstance, store, cfg, caService)

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
