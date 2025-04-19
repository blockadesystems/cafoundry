package management

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/blockadesystems/cafoundry/internal/storage" // Import storage interface
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// Package-level logger (alternative: pass via context if middleware adds it)
var logger *zap.Logger

func init() {
	// Attempt to get logger configured in main (requires ReplaceGlobals)
	logger = zap.L().Named("management")
}

// --- Suffix Management ---

// addSuffixRequest defines the expected JSON body for adding a suffix.
type addSuffixRequest struct {
	Suffix string `json:"suffix"`
}

// HandleAddSuffix handles POST requests to add a new allowed suffix.
func HandleAddSuffix(c echo.Context) error {
	store := c.Get("store").(storage.Storage)
	reqLogger := c.Get("logger").(*zap.Logger).With(zap.String("handler", "HandleAddSuffix"))
	ctx := c.Request().Context()

	var req addSuffixRequest
	if err := c.Bind(&req); err != nil {
		reqLogger.Warn("Failed to bind request body", zap.Error(err))
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
	}

	suffix := strings.TrimSpace(req.Suffix)
	if suffix == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Suffix cannot be empty")
	}

	// Storage layer handles normalization (lowercase, removing leading dot)
	err := store.AddAllowedSuffix(ctx, suffix)
	if err != nil {
		reqLogger.Error("Failed to add allowed suffix to storage", zap.String("suffix", suffix), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to save suffix")
	}

	reqLogger.Info("Successfully added allowed suffix", zap.String("suffix", suffix))
	// Return 201 Created or 204 No Content? 204 is simpler if not returning the object.
	return c.NoContent(http.StatusCreated)
}

// HandleListSuffixes handles GET requests to list all allowed suffixes.
func HandleListSuffixes(c echo.Context) error {
	store := c.Get("store").(storage.Storage)
	reqLogger := c.Get("logger").(*zap.Logger).With(zap.String("handler", "HandleListSuffixes"))
	ctx := c.Request().Context()

	suffixes, err := store.ListAllowedSuffixes(ctx)
	if err != nil {
		reqLogger.Error("Failed to list allowed suffixes from storage", zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve suffixes")
	}

	// Return as a simple JSON array
	return c.JSON(http.StatusOK, suffixes)
}

// HandleDeleteSuffix handles DELETE requests to remove an allowed suffix.
func HandleDeleteSuffix(c echo.Context) error {
	store := c.Get("store").(storage.Storage)
	reqLogger := c.Get("logger").(*zap.Logger).With(zap.String("handler", "HandleDeleteSuffix"))
	ctx := c.Request().Context()

	// Get suffix from path parameter and URL-decode it
	suffixParam := c.Param("suffix")
	suffix, err := url.PathUnescape(suffixParam)
	if err != nil {
		reqLogger.Warn("Failed to unescape suffix parameter", zap.String("param", suffixParam), zap.Error(err))
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid suffix parameter encoding: %v", err))
	}

	suffix = strings.TrimSpace(suffix)
	if suffix == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Suffix parameter cannot be empty")
	}

	// Storage layer handles normalization
	err = store.DeleteAllowedSuffix(ctx, suffix)
	if err != nil {
		reqLogger.Error("Failed to delete allowed suffix from storage", zap.String("suffix", suffix), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete suffix")
	}

	reqLogger.Info("Successfully deleted allowed suffix", zap.String("suffix", suffix))
	return c.NoContent(http.StatusNoContent)
}

// --- Domain Management ---

// addDomainRequest defines the expected JSON body for adding a domain.
type addDomainRequest struct {
	Domain string `json:"domain"`
}

// HandleAddDomain handles POST requests to add a new allowed domain.
func HandleAddDomain(c echo.Context) error {
	store := c.Get("store").(storage.Storage)
	reqLogger := c.Get("logger").(*zap.Logger).With(zap.String("handler", "HandleAddDomain"))
	ctx := c.Request().Context()

	var req addDomainRequest
	if err := c.Bind(&req); err != nil {
		reqLogger.Warn("Failed to bind request body", zap.Error(err))
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
	}

	domain := strings.TrimSpace(req.Domain)
	if domain == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Domain cannot be empty")
	}

	// Storage layer handles normalization (lowercase)
	err := store.AddAllowedDomain(ctx, domain)
	if err != nil {
		reqLogger.Error("Failed to add allowed domain to storage", zap.String("domain", domain), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to save domain")
	}

	reqLogger.Info("Successfully added allowed domain", zap.String("domain", domain))
	return c.NoContent(http.StatusCreated)
}

// HandleListDomains handles GET requests to list all allowed domains.
func HandleListDomains(c echo.Context) error {
	store := c.Get("store").(storage.Storage)
	reqLogger := c.Get("logger").(*zap.Logger).With(zap.String("handler", "HandleListDomains"))
	ctx := c.Request().Context()

	domains, err := store.ListAllowedDomains(ctx)
	if err != nil {
		reqLogger.Error("Failed to list allowed domains from storage", zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve domains")
	}

	// Return as a simple JSON array
	return c.JSON(http.StatusOK, domains)
}

// HandleDeleteDomain handles DELETE requests to remove an allowed domain.
func HandleDeleteDomain(c echo.Context) error {
	store := c.Get("store").(storage.Storage)
	reqLogger := c.Get("logger").(*zap.Logger).With(zap.String("handler", "HandleDeleteDomain"))
	ctx := c.Request().Context()

	// Get domain from path parameter and URL-decode it
	domainParam := c.Param("domain")
	domain, err := url.PathUnescape(domainParam)
	if err != nil {
		reqLogger.Warn("Failed to unescape domain parameter", zap.String("param", domainParam), zap.Error(err))
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid domain parameter encoding: %v", err))
	}

	domain = strings.TrimSpace(domain)
	if domain == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Domain parameter cannot be empty")
	}

	// Storage layer handles normalization
	err = store.DeleteAllowedDomain(ctx, domain)
	if err != nil {
		reqLogger.Error("Failed to delete allowed domain from storage", zap.String("domain", domain), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete domain")
	}

	reqLogger.Info("Successfully deleted allowed domain", zap.String("domain", domain))
	return c.NoContent(http.StatusNoContent)
}
