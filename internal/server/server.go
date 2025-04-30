package server

import (
	"net/http" // Added for handlers

	"github.com/blockadesystems/cafoundry/internal/acme"
	"github.com/blockadesystems/cafoundry/internal/auth"
	"github.com/blockadesystems/cafoundry/internal/ca"
	"github.com/blockadesystems/cafoundry/internal/config"
	"github.com/blockadesystems/cafoundry/internal/management"
	"github.com/blockadesystems/cafoundry/internal/storage"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
)

// ApplyCommonMiddleware applies essential middleware to an Echo instance.
// It injects dependencies into the context.
func ApplyCommonMiddleware(e *echo.Echo, store storage.Storage, cfg *config.Config, caService ca.CAService, baseLogger *zap.Logger) {
	e.HideBanner = true
	e.Use(middleware.Recover())
	e.Use(middleware.RequestIDWithConfig(middleware.RequestIDConfig{
		Generator: func() string { return uuid.NewString() },
	}))

	// Middleware to set context values
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			reqID := c.Response().Header().Get(echo.HeaderXRequestID)
			reqLogger := baseLogger.With(zap.String("request_id", reqID))

			c.Set("caService", caService)
			c.Set("cfg", cfg)
			c.Set("store", store)
			c.Set("logger", reqLogger)
			return next(c)
		}
	})
	// Add Echo's logger *after* request ID and our logger are set, if desired for main app
	// e.Use(middleware.Logger()) // Keep commented out for test helper usage potentially
}

// SetupRouter defines all HTTP and HTTPS routes for the application.
func SetupRouter(httpInstance, httpsInstance *echo.Echo, store storage.Storage, cfg *config.Config, caService ca.CAService) {
	// --- Define HTTP Routes ---
	httpInstance.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "CA Foundry is running (HTTP - Unprotected Root)")
	})
	// ACME HTTP-01 Challenge Endpoint MUST be on HTTP instance
	// Note: Middleware added via ApplyCommonMiddleware provides store/logger here
	httpInstance.GET("/.well-known/acme-challenge/:token", acme.HandleHTTP01Challenge)

	// --- Define HTTPS Routes ---
	httpsInstance.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "CA Foundry is running (HTTPS - Unprotected Root)")
	})

	// ACME protocol endpoints MUST be on HTTPS instance
	acmeGroup := httpsInstance.Group("/acme")
	acmeGroup.GET("/directory", acme.HandleDirectory)
	acmeGroup.HEAD("/new-nonce", acme.HandleNewNonce)
	acmeGroup.GET("/new-nonce", acme.HandleNewNonce)
	acmeGroup.POST("/new-account", acme.HandleNewAccount)
	acmeGroup.POST("/account/:accountID", acme.HandleAccount)
	acmeGroup.POST("/new-order", acme.HandleNewOrder)
	acmeGroup.POST("/order/:orderID", acme.HandleGetOrder)
	acmeGroup.POST("/authz/:authzID", acme.HandleAuthorization)
	acmeGroup.POST("/chall/:challengeID", acme.HandleChallenge)
	acmeGroup.POST("/finalize/:orderID", acme.HandleFinalize)
	acmeGroup.POST("/cert/:certID", acme.HandleCertificate)
	acmeGroup.POST("/revoke-cert", acme.HandleRevokeCertificate)

	// Management API Endpoints (on httpsInstance)
	apiGroup := httpsInstance.Group("/api/v1")
	const policyAdminRole = "admin"                                          // Or make configurable
	adminOnlyMiddleware := auth.APIKeyAuthMiddleware(store, policyAdminRole) // Create auth middleware instance
	policyGroup := apiGroup.Group("/policy")
	policyGroup.Use(adminOnlyMiddleware) // Apply auth middleware to policy group

	// Suffix management routes
	policyGroup.POST("/suffixes", management.HandleAddSuffix)
	policyGroup.GET("/suffixes", management.HandleListSuffixes)
	policyGroup.DELETE("/suffixes/:suffix", management.HandleDeleteSuffix)
	// Domain management routes
	policyGroup.POST("/domains", management.HandleAddDomain)
	policyGroup.GET("/domains", management.HandleListDomains)
	policyGroup.DELETE("/domains/:domain", management.HandleDeleteDomain)

	// TODO: Add API Key management routes here later?
}
