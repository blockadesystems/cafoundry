package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
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

// Helper function to hash API key with salt for verification
func hashAPIKeyWithSalt(saltHex string, apiKeyPlaintext string) (string, error) {
	saltBytes, err := hex.DecodeString(saltHex)
	if err != nil {
		return "", fmt.Errorf("invalid salt format: %w", err)
	}
	// Prepend salt to the key before hashing
	hashInput := append(saltBytes, []byte(apiKeyPlaintext)...)
	hashBytes := sha256.Sum256(hashInput)
	return hex.EncodeToString(hashBytes[:]), nil
}

// APIKeyAuthMiddleware creates an Echo middleware function that authenticates requests
// based on a Bearer API key (checking its salted hash) and checks for a required role.
func APIKeyAuthMiddleware(store storage.Storage, requiredRole string) echo.MiddlewareFunc {
	if store == nil {
		panic("auth: storage instance is nil in APIKeyAuthMiddleware")
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			reqLogger := logger
			if ctxLogger, ok := c.Get("logger").(*zap.Logger); ok && ctxLogger != nil {
				reqLogger = ctxLogger
			}

			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return echo.NewHTTPError(http.StatusUnauthorized, "Authorization header is required")
			}
			headerParts := strings.SplitN(authHeader, " ", 2)
			if len(headerParts) != 2 || strings.ToLower(headerParts[0]) != "bearer" {
				return echo.NewHTTPError(http.StatusUnauthorized, "Authorization header format must be Bearer <token>")
			}
			apiKeyPlaintext := headerParts[1]
			if apiKeyPlaintext == "" {
				return echo.NewHTTPError(http.StatusUnauthorized, "API key cannot be empty")
			}

			// --- Verification using Salted Hash ---
			// 1. Extract Key Prefix (assuming prefix length is known, e.g., 8)
			// TODO: Make prefix length configurable or store alongside hash? Let's use fixed 8.
			const keyPrefixLength = 8
			if len(apiKeyPlaintext) <= keyPrefixLength {
				reqLogger.Warn("API key presented is too short", zap.Int("length", len(apiKeyPlaintext)))
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid API key")
			}
			keyPrefix := apiKeyPlaintext[:keyPrefixLength]

			// 2. Fetch Salt, Hash, Roles by Prefix
			ctx := c.Request().Context()
			saltHex, storedHashHex, roles, _, _, err := store.GetAPIKeyInfoByPrefix(ctx, keyPrefix)
			if err != nil {
				reqLogger.Error("Failed to retrieve API key info by prefix", zap.String("prefix", keyPrefix), zap.Error(err))
				return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify API key")
			}
			if saltHex == "" || storedHashHex == "" {
				// Key prefix not found in storage
				reqLogger.Warn("Invalid API key presented (prefix not found)", zap.String("prefix", keyPrefix))
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid API key")
			}

			// 3. Compute Hash of incoming key using stored salt
			incomingHashHex, err := hashAPIKeyWithSalt(saltHex, apiKeyPlaintext)
			if err != nil {
				reqLogger.Error("Failed to compute hash for incoming key", zap.String("prefix", keyPrefix), zap.Error(err))
				return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify API key")
			}

			// 4. Compare Hashes (Constant Time)
			if subtle.ConstantTimeCompare([]byte(incomingHashHex), []byte(storedHashHex)) != 1 {
				// Hashes don't match
				reqLogger.Warn("Invalid API key presented (hash mismatch)", zap.String("prefix", keyPrefix))
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid API key")
			}

			// 5. Check Roles
			isAllowed := false
			for _, role := range roles {
				if role == requiredRole {
					isAllowed = true
					break
				}
			}
			if !isAllowed {
				reqLogger.Warn("API key lacks required role", zap.String("prefix", keyPrefix), zap.String("required_role", requiredRole), zap.Strings("key_roles", roles))
				return echo.NewHTTPError(http.StatusForbidden, fmt.Sprintf("API key does not have required role: %s", requiredRole))
			}

			// Key is valid and has the required role
			reqLogger.Debug("API key authenticated successfully via salted hash", zap.String("prefix", keyPrefix), zap.String("required_role", requiredRole))
			// Optional: Add context info
			// c.Set("auth_key_prefix", keyPrefix)
			// c.Set("auth_roles", roles)
			return next(c)
		}
	}
}
