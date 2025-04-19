package auth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/blockadesystems/cafoundry/internal/storage" // Import storage interface
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

var logger *zap.Logger

// Initialize package logger (assuming global logger exists or is passed)
// Note: Using zap.L() might have initialization order issues if not set early in main.
// It's generally better to pass loggers explicitly or via context deeper down.
// But for middleware setup, accessing it might be simpler if set globally early.
// Let's keep the original init pattern here for now.
func init() {
	// Attempt to get the already configured logger if possible
	// If zap.L() is used, ensure ReplaceGlobals was called in main's init or early on.
	logger = zap.L().With(zap.String("package", "auth"))
}

// APIKeyAuthMiddleware creates an Echo middleware function that authenticates requests
// based on a Bearer API key and checks for a required role.
func APIKeyAuthMiddleware(store storage.Storage, requiredRole string) echo.MiddlewareFunc {
	if store == nil {
		// Safety check, should not happen if setup correctly in main.go
		panic("auth: storage instance is nil in APIKeyAuthMiddleware")
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Get request-scoped logger from context if available, otherwise use package logger
			reqLogger := logger // Default to package logger
			if ctxLogger, ok := c.Get("logger").(*zap.Logger); ok && ctxLogger != nil {
				reqLogger = ctxLogger // Use request-scoped logger if present
			}

			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				reqLogger.Warn("Missing Authorization header")
				// Consider returning WWW-Authenticate header? Maybe not for API keys.
				return echo.NewHTTPError(http.StatusUnauthorized, "Authorization header is required")
			}

			// Expecting "Bearer <api-key>"
			headerParts := strings.SplitN(authHeader, " ", 2)
			if len(headerParts) != 2 || strings.ToLower(headerParts[0]) != "bearer" {
				reqLogger.Warn("Invalid Authorization header format")
				return echo.NewHTTPError(http.StatusUnauthorized, "Authorization header format must be Bearer <token>")
			}

			apiKey := headerParts[1]
			if apiKey == "" {
				reqLogger.Warn("Empty API key provided in Authorization header")
				return echo.NewHTTPError(http.StatusUnauthorized, "API key cannot be empty")
			}

			// Use request context for storage operations
			ctx := c.Request().Context()
			roles, err := store.GetAPIKey(ctx, apiKey)
			if err != nil {
				reqLogger.Error("Failed to retrieve API key from storage", zap.Error(err))
				// Mask internal error details
				return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify API key")
			}
			if roles == nil {
				// Key not found in storage
				reqLogger.Warn("Invalid API key presented")
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid API key")
			}

			// Check if the required role is present
			isAllowed := false
			for _, role := range roles {
				if role == requiredRole {
					isAllowed = true
					break
				}
			}

			if !isAllowed {
				reqLogger.Warn("API key lacks required role", zap.String("required_role", requiredRole), zap.Strings("key_roles", roles))
				return echo.NewHTTPError(http.StatusForbidden, fmt.Sprintf("API key does not have required role: %s", requiredRole))
			}

			// Key is valid and has the required role, proceed to the next handler
			reqLogger.Debug("API key authenticated successfully", zap.String("required_role", requiredRole))
			// Optional: Add authenticated user/roles to context?
			// c.Set("auth_roles", roles)
			return next(c)
		}
	}
}
