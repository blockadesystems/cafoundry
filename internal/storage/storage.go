package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blockadesystems/cafoundry/internal/model"
	"github.com/lib/pq" // Import the PostgreSQL driver AND helpers like pq.Array
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.Logger

// init initializes the package logger.
func init() {
	// Using NewProduction initially might be better, swap for Development config when debugging.
	cfg := zap.NewDevelopmentConfig() // Consider NewProductionConfig()
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	l, err := cfg.Build(zap.AddCallerSkip(1)) // Add caller skip for accurate line numbers
	if err != nil {
		panic(fmt.Sprintf("failed to initialize zap logger: %v", err))
	}
	logger = l.With(zap.String("package", "storage"))
}

// --- Interfaces ---

// Querier defines common methods implemented by *sql.DB and *sql.Tx.
// This allows storage methods to work with either a pool or a transaction.
type Querier interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

// Storage defines the interface for storing and retrieving CA and ACME data.
type Storage interface {
	// CA Data Methods
	SaveCRL(ctx context.Context, crlBytes []byte) error
	GetLatestCRL(ctx context.Context) ([]byte, error)
	SaveCAPrivateKey(ctx context.Context, keyBytes []byte) error
	GetCAPrivateKey(ctx context.Context) ([]byte, error)
	SaveCACertificate(ctx context.Context, certBytes []byte) error
	GetCACertificate(ctx context.Context) ([]byte, error)

	// Certificate Data Methods
	SaveCertificateData(ctx context.Context, certData *model.CertificateData) error
	GetCertificateData(ctx context.Context, serialNumber string) (*model.CertificateData, error)
	UpdateCertificateRevocation(ctx context.Context, serialNumber string, revoked bool, revokedAt time.Time, reasonCode int) error
	ListRevokedCertificates(ctx context.Context) ([]*model.CertificateData, error)

	// User/API Key Methods
	SaveUser(ctx context.Context, username string, password string, roles []string) error // UPSERT
	GetUser(ctx context.Context, username string) (string, []string, error)
	SaveAPIKey(ctx context.Context, apiKey string, roles []string) error // UPSERT
	GetAPIKey(ctx context.Context, apiKey string) ([]string, error)
	AddUser(ctx context.Context, username string, password string, roles []string) error    // INSERT only
	UpdateUser(ctx context.Context, username string, password string, roles []string) error // UPDATE only
	DeleteUser(ctx context.Context, username string) error
	ListUsers(ctx context.Context) (map[string][]string, error)

	// ACME Nonce Methods
	SaveNonce(ctx context.Context, nonce *model.Nonce) error
	ConsumeNonce(ctx context.Context, nonceValue string) (*model.Nonce, error)
	DeleteExpiredNonces(ctx context.Context) (int64, error)

	// ACME Account Methods
	SaveAccount(ctx context.Context, acc *model.Account) error
	GetAccount(ctx context.Context, id string) (*model.Account, error)
	GetAccountByKeyID(ctx context.Context, keyID string) (*model.Account, error)

	// ACME Order Methods
	SaveOrder(ctx context.Context, order *model.Order) error
	GetOrder(ctx context.Context, id string) (*model.Order, error)
	GetOrdersByAccountID(ctx context.Context, accountID string) ([]*model.Order, error)

	// ACME Authorization Methods
	SaveAuthorization(ctx context.Context, authz *model.Authorization) error
	GetAuthorization(ctx context.Context, id string) (*model.Authorization, error)
	GetAuthorizationsByOrderID(ctx context.Context, orderID string) ([]*model.Authorization, error)

	// ACME Challenge Methods
	SaveChallenge(ctx context.Context, chal *model.Challenge) error
	GetChallenge(ctx context.Context, id string) (*model.Challenge, error)
	GetChallengeByToken(ctx context.Context, token string) (*model.Challenge, error)
	GetChallengesByAuthorizationID(ctx context.Context, authzID string) ([]*model.Challenge, error)

	// --- Policy Methods ---
	AddAllowedDomain(ctx context.Context, domain string) error
	DeleteAllowedDomain(ctx context.Context, domain string) error
	ListAllowedDomains(ctx context.Context) ([]string, error)
	IsDomainAllowed(ctx context.Context, domain string) (bool, error) // Checks exact match OR suffix match

	AddAllowedSuffix(ctx context.Context, suffix string) error
	DeleteAllowedSuffix(ctx context.Context, suffix string) error
	ListAllowedSuffixes(ctx context.Context) ([]string, error)
	// IsSuffixAllowed helper might not be needed if IsDomainAllowed handles it

	// Transaction Helper (only implemented on PostgreSQLStorage)
	WithinTransaction(ctx context.Context, fn func(ctx context.Context, txStorage Storage) error) error

	Close() error // Close the underlying connection pool
}

// --- PostgreSQL Implementation ---

// PostgreSQLStorage holds the connection pool.
type PostgreSQLStorage struct {
	db *sql.DB
}

// postgresTxStore holds a transaction and implements the Storage interface.
type postgresTxStore struct {
	tx *sql.Tx
}

// Ensure PostgreSQLStorage implements Storage (compile-time check).
var _ Storage = (*PostgreSQLStorage)(nil)

// Ensure postgresTxStore implements Storage (compile-time check).
var _ Storage = (*postgresTxStore)(nil)

// NewStorage is the factory function.
func NewStorage(storageType string, dataDir string, dbHost string, dbUser string, dbPassword string, dbName string, dbPort int, dbSSLMode string, dbCert string, dbKey string, dbRootCert string) (Storage, error) {
	switch strings.ToLower(storageType) {
	case "postgres":
		return NewPostgreSQLStorage(dbHost, dbUser, dbPassword, dbName, dbPort, dbSSLMode, dbCert, dbKey, dbRootCert)
	default:
		logger.Error("Invalid storage type specified", zap.String("storage_type", storageType))
		return nil, fmt.Errorf("storage: invalid storage type: %s", storageType)
	}
}

// NewPostgreSQLStorage creates a new PostgreSQLStorage instance and ensures schema exists.
func NewPostgreSQLStorage(dbHost string, dbUser string, dbPassword string, dbName string, dbPort int, dbSSLMode string, dbCert string, dbKey string, dbRootCert string) (*PostgreSQLStorage, error) {
	connStr := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%d sslmode=%s",
		dbHost, dbUser, dbPassword, dbName, dbPort, dbSSLMode,
	)
	// Add optional SSL params
	if dbCert != "" {
		connStr += " sslcert=" + dbCert
	}
	if dbKey != "" {
		connStr += " sslkey=" + dbKey
	}
	if dbRootCert != "" {
		connStr += " sslrootcert=" + dbRootCert
	}

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		logger.Error("Failed to open PostgreSQL connection", zap.Error(err))
		return nil, fmt.Errorf("storage: failed to open PostgreSQL database: %w", err)
	}

	// Configure connection pool (tune as needed)
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Ping database to verify connection
	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = db.PingContext(pingCtx)
	if err != nil {
		db.Close() // Close pool if ping fails
		logger.Error("Failed to ping PostgreSQL database", zap.Error(err), zap.String("host", dbHost), zap.Int("port", dbPort), zap.String("dbname", dbName))
		return nil, fmt.Errorf("storage: failed to connect to PostgreSQL database: %w", err)
	}
	logger.Info("Successfully connected to PostgreSQL database", zap.String("host", dbHost), zap.Int("port", dbPort), zap.String("dbname", dbName))

	// --- Ensure Schema ---
	schemaCtx, schemaCancel := context.WithTimeout(context.Background(), 30*time.Second) // Longer timeout for DDL
	defer schemaCancel()
	if err := ensureSchema(schemaCtx, db); err != nil {
		db.Close()
		return nil, err // Error already logged in ensureSchema
	}

	s := &PostgreSQLStorage{
		db: db,
	}
	logger.Info("PostgreSQLStorage initialized")
	return s, nil
}

// ensureSchema creates tables and indexes if they don't exist.
func ensureSchema(ctx context.Context, db *sql.DB) error {
	// Phase 1: Create Tables and Indexes
	tableAndIndexStmts := []string{
		// CA Data Tables
		`CREATE TABLE IF NOT EXISTS crls ( id SERIAL PRIMARY KEY, crl_data BYTEA NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() );`,
		`CREATE TABLE IF NOT EXISTS ca_data ( id INTEGER PRIMARY KEY DEFAULT 1, key_data BYTEA, cert_data BYTEA, CONSTRAINT ca_data_single_row CHECK (id = 1) );`,
		// User/API Key Tables
		`CREATE TABLE IF NOT EXISTS users ( username TEXT PRIMARY KEY, password TEXT NOT NULL, roles TEXT[] NOT NULL );`,
		`CREATE TABLE IF NOT EXISTS api_keys ( api_key TEXT PRIMARY KEY, roles TEXT[] NOT NULL );`,
		// ACME Tables
		`CREATE TABLE IF NOT EXISTS acme_nonces ( value TEXT PRIMARY KEY, expires_at TIMESTAMP WITH TIME ZONE NOT NULL, issued_at TIMESTAMP WITH TIME ZONE NOT NULL );`,
		`CREATE INDEX IF NOT EXISTS idx_acme_nonces_expires_at ON acme_nonces (expires_at);`,
		`CREATE TABLE IF NOT EXISTS acme_accounts ( id TEXT PRIMARY KEY, public_key_jwk TEXT NOT NULL UNIQUE, contact TEXT[], status TEXT NOT NULL, tos_agreed BOOLEAN NOT NULL DEFAULT false, eab JSONB, created_at TIMESTAMP WITH TIME ZONE NOT NULL, last_modified_at TIMESTAMP WITH TIME ZONE NOT NULL );`,
		`CREATE TABLE IF NOT EXISTS certificates_data ( serial_number TEXT PRIMARY KEY, certificate_pem TEXT NOT NULL, chain_pem TEXT, issued_at TIMESTAMP WITH TIME ZONE NOT NULL, expires_at TIMESTAMP WITH TIME ZONE NOT NULL, account_id TEXT NOT NULL, order_id TEXT NOT NULL, revoked BOOLEAN NOT NULL DEFAULT false, revoked_at TIMESTAMP WITH TIME ZONE, revocation_reason INTEGER );`,
		`CREATE INDEX IF NOT EXISTS idx_certificates_data_account_id ON certificates_data (account_id);`,
		`CREATE INDEX IF NOT EXISTS idx_certificates_data_order_id ON certificates_data (order_id);`,
		`CREATE INDEX IF NOT EXISTS idx_certificates_data_revoked ON certificates_data (revoked);`,
		`CREATE TABLE IF NOT EXISTS acme_orders ( id TEXT PRIMARY KEY, account_id TEXT NOT NULL, status TEXT NOT NULL, expires_at TIMESTAMP WITH TIME ZONE NOT NULL, identifiers_json JSONB NOT NULL, not_before TIMESTAMP WITH TIME ZONE, not_after TIMESTAMP WITH TIME ZONE, error_json JSONB, certificate_serial TEXT, created_at TIMESTAMP WITH TIME ZONE NOT NULL, last_modified_at TIMESTAMP WITH TIME ZONE NOT NULL );`,
		`CREATE INDEX IF NOT EXISTS idx_acme_orders_account_id ON acme_orders (account_id);`,
		`CREATE INDEX IF NOT EXISTS idx_acme_orders_certificate_serial ON acme_orders (certificate_serial);`,
		`CREATE TABLE IF NOT EXISTS acme_authorizations ( id TEXT PRIMARY KEY, account_id TEXT NOT NULL, order_id TEXT NOT NULL, identifier_json JSONB NOT NULL, status TEXT NOT NULL, expires_at TIMESTAMP WITH TIME ZONE NOT NULL, wildcard BOOLEAN NOT NULL DEFAULT false, created_at TIMESTAMP WITH TIME ZONE NOT NULL );`,
		`CREATE INDEX IF NOT EXISTS idx_acme_authorizations_account_id ON acme_authorizations (account_id);`,
		`CREATE INDEX IF NOT EXISTS idx_acme_authorizations_order_id ON acme_authorizations (order_id);`,
		`CREATE TABLE IF NOT EXISTS acme_challenges ( id TEXT PRIMARY KEY, authorization_id TEXT NOT NULL, type TEXT NOT NULL, status TEXT NOT NULL, token TEXT NOT NULL UNIQUE, validated_at TIMESTAMP WITH TIME ZONE, error_json JSONB, created_at TIMESTAMP WITH TIME ZONE NOT NULL );`,
		`CREATE INDEX IF NOT EXISTS idx_acme_challenges_authorization_id ON acme_challenges (authorization_id);`,
		`CREATE TABLE IF NOT EXISTS policy_allowed_domains (domain TEXT PRIMARY KEY, added_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());`,
		`CREATE TABLE IF NOT EXISTS policy_allowed_suffixes (suffix TEXT PRIMARY KEY, added_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());`,
	}

	logger.Info("Executing CREATE TABLE IF NOT EXISTS and CREATE INDEX IF NOT EXISTS statements...")
	for i, stmt := range tableAndIndexStmts {
		_, err := db.ExecContext(ctx, stmt)
		if err != nil {
			// Log the specific failing statement
			logger.Error("Failed to execute schema statement (Table/Index Phase)", zap.Error(err), zap.Int("statement_index", i), zap.String("statement", stmt))
			return fmt.Errorf("storage: failed to initialize database schema (Table/Index Phase): %w", err)
		}
	}
	logger.Info("Table and index creation phase complete.")

	// Phase 2: Add Foreign Key Constraints
	fkStmt := `DO $$ BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_certificates_data_account_id') THEN
                ALTER TABLE certificates_data ADD CONSTRAINT fk_certificates_data_account_id FOREIGN KEY (account_id) REFERENCES acme_accounts(id) ON DELETE RESTRICT;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_certificates_data_order_id') THEN
                 ALTER TABLE certificates_data ADD CONSTRAINT fk_certificates_data_order_id FOREIGN KEY (order_id) REFERENCES acme_orders(id) ON DELETE RESTRICT;
             END IF;
             IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_acme_orders_account_id') THEN
                 ALTER TABLE acme_orders ADD CONSTRAINT fk_acme_orders_account_id FOREIGN KEY (account_id) REFERENCES acme_accounts(id) ON DELETE CASCADE;
             END IF;
             IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_acme_orders_certificate_serial') THEN
                 ALTER TABLE acme_orders ADD CONSTRAINT fk_acme_orders_certificate_serial FOREIGN KEY (certificate_serial) REFERENCES certificates_data(serial_number) ON DELETE SET NULL;
             END IF;
             IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_acme_authorizations_account_id') THEN
                 ALTER TABLE acme_authorizations ADD CONSTRAINT fk_acme_authorizations_account_id FOREIGN KEY (account_id) REFERENCES acme_accounts(id) ON DELETE CASCADE;
             END IF;
             IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_acme_authorizations_order_id') THEN
                 ALTER TABLE acme_authorizations ADD CONSTRAINT fk_acme_authorizations_order_id FOREIGN KEY (order_id) REFERENCES acme_orders(id) ON DELETE CASCADE;
             END IF;
             IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_acme_challenges_authorization_id') THEN
                 ALTER TABLE acme_challenges ADD CONSTRAINT fk_acme_challenges_authorization_id FOREIGN KEY (authorization_id) REFERENCES acme_authorizations(id) ON DELETE CASCADE;
             END IF;
        END $$;`

	logger.Info("Executing ALTER TABLE ADD CONSTRAINT statements...")
	_, err := db.ExecContext(ctx, fkStmt)
	if err != nil {
		// Log the specific underlying pq error if available
		if pqErr, ok := err.(*pq.Error); ok {
			logger.Error("Failed to add foreign key constraints", zap.Error(err),
				zap.String("severity", pqErr.Severity),
				zap.String("code", string(pqErr.Code)),
				zap.String("message", pqErr.Message),
				zap.String("detail", pqErr.Detail),
				zap.String("hint", pqErr.Hint),
				zap.String("constraint", pqErr.Constraint), // This might contain the failing constraint name
			)
		} else {
			logger.Error("Failed to execute schema statement (Foreign Key Phase)", zap.Error(err), zap.String("statement", "DO $$ ... $$"))
		}
		return fmt.Errorf("storage: failed to initialize database schema (Foreign Key Phase): %w", err)
	}

	logger.Info("Database schema initialization check complete.")
	return nil
}

// =============================================
// PostgreSQLStorage Method Implementations
// =============================================

// Close shuts down the database connection pool.
func (s *PostgreSQLStorage) Close() error {
	logger.Info("Closing database connection pool")
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// WithinTransaction executes the given function within a database transaction.
func (s *PostgreSQLStorage) WithinTransaction(ctx context.Context, fn func(ctx context.Context, txStorage Storage) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("storage: failed to begin transaction: %w", err)
	}
	txStore := &postgresTxStore{tx: tx}
	err = fn(ctx, txStore)
	if err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			logger.Error("Transaction function failed and rollback failed", zap.Error(err), zap.NamedError("rollback_error", rbErr))
			return fmt.Errorf("storage: transaction function failed (%w) and rollback failed (%v)", err, rbErr)
		}
		logger.Warn("Transaction rolled back due to error", zap.Error(err))
		return err
	}
	if err := tx.Commit(); err != nil {
		logger.Error("Failed to commit transaction", zap.Error(err))
		return fmt.Errorf("storage: failed to commit transaction: %w", err)
	}
	return nil
}

// --- CA Data ---
func (s *PostgreSQLStorage) SaveCRL(ctx context.Context, crlBytes []byte) error {
	return saveCRL(ctx, s.db, crlBytes)
}
func (s *PostgreSQLStorage) GetLatestCRL(ctx context.Context) ([]byte, error) {
	return getLatestCRL(ctx, s.db)
}
func (s *PostgreSQLStorage) SaveCAPrivateKey(ctx context.Context, keyBytes []byte) error {
	return saveCAPrivateKey(ctx, s.db, keyBytes)
}
func (s *PostgreSQLStorage) GetCAPrivateKey(ctx context.Context) ([]byte, error) {
	return getCAPrivateKey(ctx, s.db)
}
func (s *PostgreSQLStorage) SaveCACertificate(ctx context.Context, certBytes []byte) error {
	return saveCACertificate(ctx, s.db, certBytes)
}
func (s *PostgreSQLStorage) GetCACertificate(ctx context.Context) ([]byte, error) {
	return getCACertificate(ctx, s.db)
}

// --- Policy Methods ---
func (s *PostgreSQLStorage) AddAllowedDomain(ctx context.Context, domain string) error {
	return addAllowedDomain(ctx, s.db, domain)
}
func (s *PostgreSQLStorage) DeleteAllowedDomain(ctx context.Context, domain string) error {
	return deleteAllowedDomain(ctx, s.db, domain)
}
func (s *PostgreSQLStorage) ListAllowedDomains(ctx context.Context) ([]string, error) {
	return listAllowedDomains(ctx, s.db)
}
func (s *PostgreSQLStorage) IsDomainAllowed(ctx context.Context, domain string) (bool, error) {
	return isDomainAllowed(ctx, s.db, domain)
}
func (s *PostgreSQLStorage) AddAllowedSuffix(ctx context.Context, suffix string) error {
	return addAllowedSuffix(ctx, s.db, suffix)
}
func (s *PostgreSQLStorage) DeleteAllowedSuffix(ctx context.Context, suffix string) error {
	return deleteAllowedSuffix(ctx, s.db, suffix)
}
func (s *PostgreSQLStorage) ListAllowedSuffixes(ctx context.Context) ([]string, error) {
	return listAllowedSuffixes(ctx, s.db)
}

// =============================================
// postgresTxStore Method Implementations (Add Policy methods)
// =============================================
// ... (Implementations for CA, CertData, User/API, ACME resources) ...

// --- Policy Methods ---
func (s *postgresTxStore) AddAllowedDomain(ctx context.Context, domain string) error {
	return addAllowedDomain(ctx, s.tx, domain)
}
func (s *postgresTxStore) DeleteAllowedDomain(ctx context.Context, domain string) error {
	return deleteAllowedDomain(ctx, s.tx, domain)
}
func (s *postgresTxStore) ListAllowedDomains(ctx context.Context) ([]string, error) {
	return listAllowedDomains(ctx, s.tx)
}
func (s *postgresTxStore) IsDomainAllowed(ctx context.Context, domain string) (bool, error) {
	return isDomainAllowed(ctx, s.tx, domain)
}
func (s *postgresTxStore) AddAllowedSuffix(ctx context.Context, suffix string) error {
	return addAllowedSuffix(ctx, s.tx, suffix)
}
func (s *postgresTxStore) DeleteAllowedSuffix(ctx context.Context, suffix string) error {
	return deleteAllowedSuffix(ctx, s.tx, suffix)
}
func (s *postgresTxStore) ListAllowedSuffixes(ctx context.Context) ([]string, error) {
	return listAllowedSuffixes(ctx, s.tx)
}

// --- Certificate Data ---
func (s *PostgreSQLStorage) SaveCertificateData(ctx context.Context, certData *model.CertificateData) error {
	return saveCertificateData(ctx, s.db, certData)
}
func (s *PostgreSQLStorage) GetCertificateData(ctx context.Context, serialNumber string) (*model.CertificateData, error) {
	return getCertificateData(ctx, s.db, serialNumber)
}
func (s *PostgreSQLStorage) UpdateCertificateRevocation(ctx context.Context, serialNumber string, revoked bool, revokedAt time.Time, reasonCode int) error {
	return updateCertificateRevocation(ctx, s.db, serialNumber, revoked, revokedAt, reasonCode)
}
func (s *PostgreSQLStorage) ListRevokedCertificates(ctx context.Context) ([]*model.CertificateData, error) {
	return listRevokedCertificates(ctx, s.db)
}

// --- User/API Key ---
func (s *PostgreSQLStorage) SaveUser(ctx context.Context, username string, password string, roles []string) error {
	return saveUser(ctx, s.db, username, password, roles)
}
func (s *PostgreSQLStorage) GetUser(ctx context.Context, username string) (string, []string, error) {
	return getUser(ctx, s.db, username)
}
func (s *PostgreSQLStorage) SaveAPIKey(ctx context.Context, apiKey string, roles []string) error {
	return saveAPIKey(ctx, s.db, apiKey, roles)
}
func (s *PostgreSQLStorage) GetAPIKey(ctx context.Context, apiKey string) ([]string, error) {
	return getAPIKey(ctx, s.db, apiKey)
}
func (s *PostgreSQLStorage) AddUser(ctx context.Context, username string, password string, roles []string) error {
	return addUser(ctx, s.db, username, password, roles)
}
func (s *PostgreSQLStorage) UpdateUser(ctx context.Context, username string, password string, roles []string) error {
	return updateUser(ctx, s.db, username, password, roles)
}
func (s *PostgreSQLStorage) DeleteUser(ctx context.Context, username string) error {
	return deleteUser(ctx, s.db, username)
}
func (s *PostgreSQLStorage) ListUsers(ctx context.Context) (map[string][]string, error) {
	return listUsers(ctx, s.db)
}

// --- ACME Nonce ---
func (s *PostgreSQLStorage) SaveNonce(ctx context.Context, nonce *model.Nonce) error {
	return saveNonce(ctx, s.db, nonce)
}
func (s *PostgreSQLStorage) ConsumeNonce(ctx context.Context, nonceValue string) (*model.Nonce, error) {
	return consumeNonce(ctx, s.db, nonceValue)
}
func (s *PostgreSQLStorage) DeleteExpiredNonces(ctx context.Context) (int64, error) {
	return deleteExpiredNonces(ctx, s.db)
}

// --- ACME Account ---
func (s *PostgreSQLStorage) SaveAccount(ctx context.Context, acc *model.Account) error {
	return saveAccount(ctx, s.db, acc)
}
func (s *PostgreSQLStorage) GetAccount(ctx context.Context, id string) (*model.Account, error) {
	return getAccount(ctx, s.db, id)
}
func (s *PostgreSQLStorage) GetAccountByKeyID(ctx context.Context, keyID string) (*model.Account, error) {
	return getAccountByKeyID(ctx, s.db, keyID)
}

// --- ACME Order ---
func (s *PostgreSQLStorage) SaveOrder(ctx context.Context, order *model.Order) error {
	return saveOrder(ctx, s.db, order)
}
func (s *PostgreSQLStorage) GetOrder(ctx context.Context, id string) (*model.Order, error) {
	return getOrder(ctx, s.db, id)
}
func (s *PostgreSQLStorage) GetOrdersByAccountID(ctx context.Context, accountID string) ([]*model.Order, error) {
	return getOrdersByAccountID(ctx, s.db, accountID)
}

// --- ACME Authorization ---
func (s *PostgreSQLStorage) SaveAuthorization(ctx context.Context, authz *model.Authorization) error {
	return saveAuthorization(ctx, s.db, authz)
}
func (s *PostgreSQLStorage) GetAuthorization(ctx context.Context, id string) (*model.Authorization, error) {
	return getAuthorization(ctx, s.db, id)
}
func (s *PostgreSQLStorage) GetAuthorizationsByOrderID(ctx context.Context, orderID string) ([]*model.Authorization, error) {
	return getAuthorizationsByOrderID(ctx, s.db, orderID)
}

// --- ACME Challenge ---
func (s *PostgreSQLStorage) SaveChallenge(ctx context.Context, chal *model.Challenge) error {
	return saveChallenge(ctx, s.db, chal)
}
func (s *PostgreSQLStorage) GetChallenge(ctx context.Context, id string) (*model.Challenge, error) {
	return getChallenge(ctx, s.db, id)
}
func (s *PostgreSQLStorage) GetChallengeByToken(ctx context.Context, token string) (*model.Challenge, error) {
	return getChallengeByToken(ctx, s.db, token)
}
func (s *PostgreSQLStorage) GetChallengesByAuthorizationID(ctx context.Context, authzID string) ([]*model.Challenge, error) {
	return getChallengesByAuthorizationID(ctx, s.db, authzID)
}

// =============================================
// postgresTxStore Method Implementations
// =============================================

// Close is a no-op for a transaction store.
func (s *postgresTxStore) Close() error { return nil }

// WithinTransaction cannot be called on an already active transaction store.
func (s *postgresTxStore) WithinTransaction(ctx context.Context, fn func(ctx context.Context, txStorage Storage) error) error {
	return errors.New("storage: cannot start a transaction within an existing transaction")
}

// --- CA Data ---
func (s *postgresTxStore) SaveCRL(ctx context.Context, crlBytes []byte) error {
	return saveCRL(ctx, s.tx, crlBytes)
}
func (s *postgresTxStore) GetLatestCRL(ctx context.Context) ([]byte, error) {
	return getLatestCRL(ctx, s.tx)
}
func (s *postgresTxStore) SaveCAPrivateKey(ctx context.Context, keyBytes []byte) error {
	return saveCAPrivateKey(ctx, s.tx, keyBytes)
}
func (s *postgresTxStore) GetCAPrivateKey(ctx context.Context) ([]byte, error) {
	return getCAPrivateKey(ctx, s.tx)
}
func (s *postgresTxStore) SaveCACertificate(ctx context.Context, certBytes []byte) error {
	return saveCACertificate(ctx, s.tx, certBytes)
}
func (s *postgresTxStore) GetCACertificate(ctx context.Context) ([]byte, error) {
	return getCACertificate(ctx, s.tx)
}

// --- Certificate Data ---
func (s *postgresTxStore) SaveCertificateData(ctx context.Context, certData *model.CertificateData) error {
	return saveCertificateData(ctx, s.tx, certData)
}
func (s *postgresTxStore) GetCertificateData(ctx context.Context, serialNumber string) (*model.CertificateData, error) {
	return getCertificateData(ctx, s.tx, serialNumber)
}
func (s *postgresTxStore) UpdateCertificateRevocation(ctx context.Context, serialNumber string, revoked bool, revokedAt time.Time, reasonCode int) error {
	return updateCertificateRevocation(ctx, s.tx, serialNumber, revoked, revokedAt, reasonCode)
}
func (s *postgresTxStore) ListRevokedCertificates(ctx context.Context) ([]*model.CertificateData, error) {
	return listRevokedCertificates(ctx, s.tx)
}

// --- User/API Key ---
func (s *postgresTxStore) SaveUser(ctx context.Context, username string, password string, roles []string) error {
	return saveUser(ctx, s.tx, username, password, roles)
}
func (s *postgresTxStore) GetUser(ctx context.Context, username string) (string, []string, error) {
	return getUser(ctx, s.tx, username)
}
func (s *postgresTxStore) SaveAPIKey(ctx context.Context, apiKey string, roles []string) error {
	return saveAPIKey(ctx, s.tx, apiKey, roles)
}
func (s *postgresTxStore) GetAPIKey(ctx context.Context, apiKey string) ([]string, error) {
	return getAPIKey(ctx, s.tx, apiKey)
}
func (s *postgresTxStore) AddUser(ctx context.Context, username string, password string, roles []string) error {
	return addUser(ctx, s.tx, username, password, roles)
}
func (s *postgresTxStore) UpdateUser(ctx context.Context, username string, password string, roles []string) error {
	return updateUser(ctx, s.tx, username, password, roles)
}
func (s *postgresTxStore) DeleteUser(ctx context.Context, username string) error {
	return deleteUser(ctx, s.tx, username)
}
func (s *postgresTxStore) ListUsers(ctx context.Context) (map[string][]string, error) {
	return listUsers(ctx, s.tx)
}

// --- ACME Nonce ---
func (s *postgresTxStore) SaveNonce(ctx context.Context, nonce *model.Nonce) error {
	return saveNonce(ctx, s.tx, nonce)
}
func (s *postgresTxStore) ConsumeNonce(ctx context.Context, nonceValue string) (*model.Nonce, error) {
	return consumeNonce(ctx, s.tx, nonceValue)
}
func (s *postgresTxStore) DeleteExpiredNonces(ctx context.Context) (int64, error) {
	return deleteExpiredNonces(ctx, s.tx)
}

// --- ACME Account ---
func (s *postgresTxStore) SaveAccount(ctx context.Context, acc *model.Account) error {
	return saveAccount(ctx, s.tx, acc)
}
func (s *postgresTxStore) GetAccount(ctx context.Context, id string) (*model.Account, error) {
	return getAccount(ctx, s.tx, id)
}
func (s *postgresTxStore) GetAccountByKeyID(ctx context.Context, keyID string) (*model.Account, error) {
	return getAccountByKeyID(ctx, s.tx, keyID)
}

// --- ACME Order ---
func (s *postgresTxStore) SaveOrder(ctx context.Context, order *model.Order) error {
	return saveOrder(ctx, s.tx, order)
}
func (s *postgresTxStore) GetOrder(ctx context.Context, id string) (*model.Order, error) {
	return getOrder(ctx, s.tx, id)
}
func (s *postgresTxStore) GetOrdersByAccountID(ctx context.Context, accountID string) ([]*model.Order, error) {
	return getOrdersByAccountID(ctx, s.tx, accountID)
}

// --- ACME Authorization ---
func (s *postgresTxStore) SaveAuthorization(ctx context.Context, authz *model.Authorization) error {
	return saveAuthorization(ctx, s.tx, authz)
}
func (s *postgresTxStore) GetAuthorization(ctx context.Context, id string) (*model.Authorization, error) {
	return getAuthorization(ctx, s.tx, id)
}
func (s *postgresTxStore) GetAuthorizationsByOrderID(ctx context.Context, orderID string) ([]*model.Authorization, error) {
	return getAuthorizationsByOrderID(ctx, s.tx, orderID)
}

// --- ACME Challenge ---
func (s *postgresTxStore) SaveChallenge(ctx context.Context, chal *model.Challenge) error {
	return saveChallenge(ctx, s.tx, chal)
}
func (s *postgresTxStore) GetChallenge(ctx context.Context, id string) (*model.Challenge, error) {
	return getChallenge(ctx, s.tx, id)
}
func (s *postgresTxStore) GetChallengeByToken(ctx context.Context, token string) (*model.Challenge, error) {
	return getChallengeByToken(ctx, s.tx, token)
}
func (s *postgresTxStore) GetChallengesByAuthorizationID(ctx context.Context, authzID string) ([]*model.Challenge, error) {
	return getChallengesByAuthorizationID(ctx, s.tx, authzID)
}

// =============================================
// Unexported Helper Implementations
// =============================================

// --- CA Data Helpers ---
// saveCRL, getLatestCRL, saveCAPrivateKey, getCAPrivateKey, saveCACertificate, getCACertificate
func saveCRL(ctx context.Context, q Querier, crlBytes []byte) error {
	query := `INSERT INTO crls (crl_data, created_at) VALUES ($1, NOW())`
	_, err := q.ExecContext(ctx, query, crlBytes)
	if err != nil {
		return fmt.Errorf("storage: failed to save CRL: %w", err)
	}
	logger.Debug("CRL saved")
	return nil
}
func getLatestCRL(ctx context.Context, q Querier) ([]byte, error) {
	query := `SELECT crl_data FROM crls ORDER BY created_at DESC LIMIT 1`
	var crlBytes []byte
	err := q.QueryRowContext(ctx, query).Scan(&crlBytes)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("storage: failed to get latest CRL: %w", err)
	}
	return crlBytes, nil
}
func saveCAPrivateKey(ctx context.Context, q Querier, keyBytes []byte) error {
	query := `INSERT INTO ca_data (id, key_data) VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET key_data = EXCLUDED.key_data`
	_, err := q.ExecContext(ctx, query, keyBytes)
	if err != nil {
		return fmt.Errorf("storage: failed to save CA private key: %w", err)
	}
	logger.Debug("CA private key saved")
	return nil
}
func getCAPrivateKey(ctx context.Context, q Querier) ([]byte, error) {
	query := `SELECT key_data FROM ca_data WHERE id = 1`
	var keyBytes []byte
	err := q.QueryRowContext(ctx, query).Scan(&keyBytes)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("storage: failed to get CA private key: %w", err)
	}
	if keyBytes == nil {
		return nil, nil
	}
	return keyBytes, nil
}
func saveCACertificate(ctx context.Context, q Querier, certBytes []byte) error {
	query := `INSERT INTO ca_data (id, cert_data) VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET cert_data = EXCLUDED.cert_data`
	_, err := q.ExecContext(ctx, query, certBytes)
	if err != nil {
		return fmt.Errorf("storage: failed to save CA certificate: %w", err)
	}
	logger.Debug("CA certificate saved")
	return nil
}
func getCACertificate(ctx context.Context, q Querier) ([]byte, error) {
	query := `SELECT cert_data FROM ca_data WHERE id = 1`
	var certBytes []byte
	err := q.QueryRowContext(ctx, query).Scan(&certBytes)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("storage: failed to get CA certificate: %w", err)
	}
	if certBytes == nil {
		return nil, nil
	}
	return certBytes, nil
}

// --- Certificate Data Helpers ---
// saveCertificateData, getCertificateData, updateCertificateRevocation, listRevokedCertificates
func saveCertificateData(ctx context.Context, q Querier, certData *model.CertificateData) error {
	query := `
        INSERT INTO certificates_data
            (serial_number, certificate_pem, chain_pem, issued_at, expires_at, account_id, order_id, revoked, revoked_at, revocation_reason)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (serial_number) DO UPDATE SET
            certificate_pem = EXCLUDED.certificate_pem, chain_pem = EXCLUDED.chain_pem, issued_at = EXCLUDED.issued_at, expires_at = EXCLUDED.expires_at,
            account_id = EXCLUDED.account_id, order_id = EXCLUDED.order_id, revoked = EXCLUDED.revoked, revoked_at = EXCLUDED.revoked_at, revocation_reason = EXCLUDED.revocation_reason`
	var sqlChainPEM sql.NullString
	if certData.ChainPEM != "" {
		sqlChainPEM = sql.NullString{String: certData.ChainPEM, Valid: true}
	}
	var sqlRevokedAt sql.NullTime
	if certData.Revoked && !certData.RevokedAt.IsZero() {
		sqlRevokedAt = sql.NullTime{Time: certData.RevokedAt, Valid: true}
	}
	var sqlRevocationReason sql.NullInt32
	if certData.Revoked {
		sqlRevocationReason = sql.NullInt32{Int32: int32(certData.RevocationReason), Valid: true}
	}
	_, err := q.ExecContext(ctx, query, certData.SerialNumber, certData.CertificatePEM, sqlChainPEM, certData.IssuedAt, certData.ExpiresAt,
		certData.AccountID, certData.OrderID, certData.Revoked, sqlRevokedAt, sqlRevocationReason)
	if err != nil {
		return fmt.Errorf("storage: failed to save certificate data for serial '%s': %w", certData.SerialNumber, err)
	}
	logger.Debug("Certificate data saved", zap.String("serialNumber", certData.SerialNumber))
	return nil
}
func getCertificateData(ctx context.Context, q Querier, serialNumber string) (*model.CertificateData, error) {
	query := `SELECT serial_number, certificate_pem, chain_pem, issued_at, expires_at, account_id, order_id, revoked, revoked_at, revocation_reason FROM certificates_data WHERE serial_number = $1`
	var certData model.CertificateData
	var sqlChainPEM sql.NullString
	var sqlRevokedAt sql.NullTime
	var sqlRevocationReason sql.NullInt32
	err := q.QueryRowContext(ctx, query, serialNumber).Scan(&certData.SerialNumber, &certData.CertificatePEM, &sqlChainPEM, &certData.IssuedAt, &certData.ExpiresAt,
		&certData.AccountID, &certData.OrderID, &certData.Revoked, &sqlRevokedAt, &sqlRevocationReason)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("storage: failed to get certificate data for serial '%s': %w", serialNumber, err)
	}
	if sqlChainPEM.Valid {
		certData.ChainPEM = sqlChainPEM.String
	}
	if sqlRevokedAt.Valid {
		certData.RevokedAt = sqlRevokedAt.Time
	}
	if sqlRevocationReason.Valid {
		certData.RevocationReason = int(sqlRevocationReason.Int32)
	}
	return &certData, nil
}
func updateCertificateRevocation(ctx context.Context, q Querier, serialNumber string, revoked bool, revokedAt time.Time, reasonCode int) error {
	query := `UPDATE certificates_data SET revoked = $2, revoked_at = $3, revocation_reason = $4 WHERE serial_number = $1`
	var sqlRevokedAt sql.NullTime
	var sqlRevocationReason sql.NullInt32
	if revoked {
		if revokedAt.IsZero() {
			revokedAt = time.Now()
		}
		sqlRevokedAt = sql.NullTime{Time: revokedAt, Valid: true}
		sqlRevocationReason = sql.NullInt32{Int32: int32(reasonCode), Valid: true}
	}
	result, err := q.ExecContext(ctx, query, serialNumber, revoked, sqlRevokedAt, sqlRevocationReason)
	if err != nil {
		return fmt.Errorf("storage: failed to update revocation status for serial '%s': %w", serialNumber, err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		logger.Warn("Update revocation status affected 0 rows", zap.String("serialNumber", serialNumber))
	}
	logger.Debug("Certificate revocation updated", zap.String("serialNumber", serialNumber), zap.Bool("revoked", revoked))
	return nil
}
func listRevokedCertificates(ctx context.Context, q Querier) ([]*model.CertificateData, error) {
	query := `SELECT serial_number, certificate_pem, chain_pem, issued_at, expires_at, account_id, order_id, revoked, revoked_at, revocation_reason FROM certificates_data WHERE revoked = true ORDER BY revoked_at DESC`
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to query revoked certificates: %w", err)
	}
	defer rows.Close()
	revokedCerts := make([]*model.CertificateData, 0)
	for rows.Next() {
		var certData model.CertificateData
		var sqlChainPEM sql.NullString
		var sqlRevokedAt sql.NullTime
		var sqlRevocationReason sql.NullInt32
		err := rows.Scan(&certData.SerialNumber, &certData.CertificatePEM, &sqlChainPEM, &certData.IssuedAt, &certData.ExpiresAt,
			&certData.AccountID, &certData.OrderID, &certData.Revoked, &sqlRevokedAt, &sqlRevocationReason)
		if err != nil {
			return nil, fmt.Errorf("storage: failed to scan revoked certificate row: %w", err)
		}
		if sqlChainPEM.Valid {
			certData.ChainPEM = sqlChainPEM.String
		}
		if sqlRevokedAt.Valid {
			certData.RevokedAt = sqlRevokedAt.Time
		}
		if sqlRevocationReason.Valid {
			certData.RevocationReason = int(sqlRevocationReason.Int32)
		}
		revokedCerts = append(revokedCerts, &certData)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: error iterating revoked certificate rows: %w", err)
	}
	return revokedCerts, nil
}

// --- User/API Key Helpers ---
// saveUser, getUser, saveAPIKey, getAPIKey, addUser, updateUser, deleteUser, listUsers
func saveUser(ctx context.Context, q Querier, username string, password string, roles []string) error {
	query := `INSERT INTO users (username, password, roles) VALUES ($1, $2, $3) ON CONFLICT (username) DO UPDATE SET password = EXCLUDED.password, roles = EXCLUDED.roles`
	_, err := q.ExecContext(ctx, query, username, password, pq.Array(roles))
	if err != nil {
		return fmt.Errorf("storage: failed to save user '%s': %w", username, err)
	}
	logger.Debug("User saved/updated", zap.String("username", username))
	return nil
}
func getUser(ctx context.Context, q Querier, username string) (string, []string, error) {
	query := `SELECT password, roles FROM users WHERE username = $1`
	var password string
	var roles pq.StringArray
	err := q.QueryRowContext(ctx, query, username).Scan(&password, &roles)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil, nil
		}
		return "", nil, fmt.Errorf("storage: failed to get user '%s': %w", username, err)
	}
	return password, []string(roles), nil
}
func saveAPIKey(ctx context.Context, q Querier, apiKey string, roles []string) error {
	query := `INSERT INTO api_keys (api_key, roles) VALUES ($1, $2) ON CONFLICT (api_key) DO UPDATE SET roles = EXCLUDED.roles`
	_, err := q.ExecContext(ctx, query, apiKey, pq.Array(roles))
	if err != nil {
		apiKeyPrefix := apiKey[:min(8, len(apiKey))] + "..."
		return fmt.Errorf("storage: failed to save API key '%s': %w", apiKeyPrefix, err)
	}
	logger.Debug("API key saved/updated")
	return nil
}
func getAPIKey(ctx context.Context, q Querier, apiKey string) ([]string, error) {
	query := `SELECT roles FROM api_keys WHERE api_key = $1`
	var roles pq.StringArray
	err := q.QueryRowContext(ctx, query, apiKey).Scan(&roles)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		apiKeyPrefix := apiKey[:min(8, len(apiKey))] + "..."
		return nil, fmt.Errorf("storage: failed to get API key '%s': %w", apiKeyPrefix, err)
	}
	return []string(roles), nil
}
func addUser(ctx context.Context, q Querier, username string, password string, roles []string) error {
	query := `INSERT INTO users (username, password, roles) VALUES ($1, $2, $3)`
	_, err := q.ExecContext(ctx, query, username, password, pq.Array(roles))
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return fmt.Errorf("storage: user '%s' already exists", username)
		}
		return fmt.Errorf("storage: failed to add user '%s': %w", username, err)
	}
	logger.Info("User added", zap.String("username", username))
	return nil
}
func updateUser(ctx context.Context, q Querier, username string, password string, roles []string) error {
	query := `UPDATE users SET password = $2, roles = $3 WHERE username = $1`
	result, err := q.ExecContext(ctx, query, username, password, pq.Array(roles))
	if err != nil {
		return fmt.Errorf("storage: failed to update user '%s': %w", username, err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("storage: user '%s' not found for update", username)
	}
	logger.Info("User updated", zap.String("username", username))
	return nil
}
func deleteUser(ctx context.Context, q Querier, username string) error {
	query := `DELETE FROM users WHERE username = $1`
	result, err := q.ExecContext(ctx, query, username)
	if err != nil {
		return fmt.Errorf("storage: failed to delete user '%s': %w", username, err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		logger.Warn("DeleteUser affected 0 rows, user might not have existed", zap.String("username", username))
	}
	logger.Info("User delete attempted", zap.String("username", username), zap.Int64("rowsAffected", rowsAffected))
	return nil
}
func listUsers(ctx context.Context, q Querier) (map[string][]string, error) {
	query := `SELECT username, roles FROM users ORDER BY username`
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to list users: %w", err)
	}
	defer rows.Close()
	users := make(map[string][]string)
	for rows.Next() {
		var username string
		var roles pq.StringArray
		if err := rows.Scan(&username, &roles); err != nil {
			return nil, fmt.Errorf("storage: failed to scan user row during list: %w", err)
		}
		users[username] = []string(roles)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: error iterating user rows: %w", err)
	}
	logger.Debug("Users listed", zap.Int("count", len(users)))
	return users, nil
}

// --- ACME Nonce Helpers ---
// saveNonce, consumeNonce, deleteExpiredNonces
func saveNonce(ctx context.Context, q Querier, nonce *model.Nonce) error {
	query := `INSERT INTO acme_nonces (value, expires_at, issued_at) VALUES ($1, $2, $3)`
	_, err := q.ExecContext(ctx, query, nonce.Value, nonce.ExpiresAt, nonce.IssuedAt)
	if err != nil {
		return fmt.Errorf("storage: failed to save nonce '%s': %w", nonce.Value, err)
	}
	logger.Debug("Nonce saved", zap.String("nonce", nonce.Value))
	return nil
}
func consumeNonce(ctx context.Context, q Querier, nonceValue string) (*model.Nonce, error) {
	query := `DELETE FROM acme_nonces WHERE value = $1 AND expires_at > NOW() RETURNING value, expires_at, issued_at`
	var nonce model.Nonce
	err := q.QueryRowContext(ctx, query, nonceValue).Scan(&nonce.Value, &nonce.ExpiresAt, &nonce.IssuedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		} // Invalid/Used/Expired
		return nil, fmt.Errorf("storage: failed to consume nonce '%s': %w", nonceValue, err)
	}
	logger.Debug("Nonce consumed", zap.String("nonce", nonce.Value))
	return &nonce, nil
}
func deleteExpiredNonces(ctx context.Context, q Querier) (int64, error) {
	query := `DELETE FROM acme_nonces WHERE expires_at <= NOW()`
	res, err := q.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("storage: failed to delete expired nonces: %w", err)
	}
	rowsAffected, _ := res.RowsAffected()
	if rowsAffected > 0 {
		logger.Info("Deleted expired nonces", zap.Int64("count", rowsAffected))
	}
	return rowsAffected, nil
}

// --- ACME Account Helpers ---
// saveAccount, getAccount, getAccountByKeyID
func saveAccount(ctx context.Context, q Querier, acc *model.Account) error {
	now := time.Now()
	if acc.CreatedAt.IsZero() {
		acc.CreatedAt = now
	}
	acc.LastModifiedAt = now
	query := `
        INSERT INTO acme_accounts (id, public_key_jwk, contact, status, tos_agreed, eab, created_at, last_modified_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (id) DO UPDATE SET
            public_key_jwk = EXCLUDED.public_key_jwk, contact = EXCLUDED.contact, status = EXCLUDED.status,
            tos_agreed = EXCLUDED.tos_agreed, eab = EXCLUDED.eab, last_modified_at = EXCLUDED.last_modified_at`
	var eabArg interface{}                    // Use interface{} to allow passing nil for NULL
	if len(acc.ExternalAccountBinding) == 0 { // Check if nil or empty []byte
		eabArg = nil // Pass nil to let the driver handle SQL NULL
	} else {
		// Ensure the bytes are valid JSON before sending? Or rely on DB validation?
		// Let's pass the bytes directly, DB will validate JSONB syntax.
		eabArg = acc.ExternalAccountBinding
	}
	_, err := q.ExecContext(ctx, query,
		acc.ID,
		acc.PublicKeyJWK,
		pq.Array(acc.Contact),
		acc.Status,
		acc.TermsOfService,
		eabArg, // <-- Use the potentially nil argument here
		acc.CreatedAt,
		acc.LastModifiedAt,
	)

	if err != nil {
		return fmt.Errorf("storage: failed to save account '%s': %w", acc.ID, err)
	}
	logger.Debug("Account saved", zap.String("accountID", acc.ID))
	return nil
}
func getAccount(ctx context.Context, q Querier, id string) (*model.Account, error) {
	query := `SELECT id, public_key_jwk, contact, status, tos_agreed, eab, created_at, last_modified_at FROM acme_accounts WHERE id = $1`
	var acc model.Account
	var contacts pq.StringArray
	var eabJSON []byte
	err := q.QueryRowContext(ctx, query, id).Scan(&acc.ID, &acc.PublicKeyJWK, &contacts, &acc.Status, &acc.TermsOfService, &eabJSON, &acc.CreatedAt, &acc.LastModifiedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("storage: failed to get account '%s': %w", id, err)
	}
	acc.Contact = contacts
	if len(eabJSON) > 0 {
		acc.ExternalAccountBinding = json.RawMessage(eabJSON)
	}
	return &acc, nil
}
func getAccountByKeyID(ctx context.Context, q Querier, keyID string) (*model.Account, error) {
	// Assumes keyID is the public_key_jwk string
	query := `SELECT id, public_key_jwk, contact, status, tos_agreed, eab, created_at, last_modified_at FROM acme_accounts WHERE public_key_jwk = $1`
	var acc model.Account
	var contacts pq.StringArray
	var eabJSON []byte
	err := q.QueryRowContext(ctx, query, keyID).Scan(&acc.ID, &acc.PublicKeyJWK, &contacts, &acc.Status, &acc.TermsOfService, &eabJSON, &acc.CreatedAt, &acc.LastModifiedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("storage: failed to get account by keyID: %w", err)
	}
	acc.Contact = contacts
	if len(eabJSON) > 0 {
		acc.ExternalAccountBinding = json.RawMessage(eabJSON)
	}
	return &acc, nil
}

// --- ACME Order Helpers ---
// saveOrder, getOrder, getOrdersByAccountID
func saveOrder(ctx context.Context, q Querier, order *model.Order) error {
	now := time.Now()
	if order.CreatedAt.IsZero() {
		order.CreatedAt = now
	}
	order.LastModifiedAt = now
	identifiersBytes, err := json.Marshal(order.Identifiers)
	if err != nil {
		return fmt.Errorf("storage: failed to marshal order identifiers for '%s': %w", order.ID, err)
	}
	order.IdentifiersJSON = string(identifiersBytes)
	var errorBytes []byte
	if order.Error != nil {
		errorBytes, err = json.Marshal(order.Error)
		if err != nil {
			return fmt.Errorf("storage: failed to marshal order error for '%s': %w", order.ID, err)
		}
		order.ErrorJSON = string(errorBytes)
	} else {
		order.ErrorJSON = ""
	}
	query := `
        INSERT INTO acme_orders (id, account_id, status, expires_at, identifiers_json, not_before, not_after, error_json, certificate_serial, created_at, last_modified_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        ON CONFLICT (id) DO UPDATE SET account_id = EXCLUDED.account_id, status = EXCLUDED.status, expires_at = EXCLUDED.expires_at, identifiers_json = EXCLUDED.identifiers_json,
            not_before = EXCLUDED.not_before, not_after = EXCLUDED.not_after, error_json = EXCLUDED.error_json, certificate_serial = EXCLUDED.certificate_serial, last_modified_at = EXCLUDED.last_modified_at`
	var sqlNotBefore sql.NullTime
	if !order.NotBefore.IsZero() {
		sqlNotBefore = sql.NullTime{Time: order.NotBefore, Valid: true}
	}
	var sqlNotAfter sql.NullTime
	if !order.NotAfter.IsZero() {
		sqlNotAfter = sql.NullTime{Time: order.NotAfter, Valid: true}
	}
	var sqlErrorJSON sql.NullString
	if order.ErrorJSON != "" {
		sqlErrorJSON = sql.NullString{String: order.ErrorJSON, Valid: true}
	}
	var sqlCertSerial sql.NullString
	if order.CertificateSerial != "" {
		sqlCertSerial = sql.NullString{String: order.CertificateSerial, Valid: true}
	}
	_, err = q.ExecContext(ctx, query, order.ID, order.AccountID, order.Status, order.Expires, order.IdentifiersJSON, sqlNotBefore, sqlNotAfter, sqlErrorJSON, sqlCertSerial, order.CreatedAt, order.LastModifiedAt)
	if err != nil {
		return fmt.Errorf("storage: failed to save order '%s': %w", order.ID, err)
	}
	logger.Debug("Order saved", zap.String("orderID", order.ID), zap.String("status", order.Status))
	return nil
}
func getOrder(ctx context.Context, q Querier, id string) (*model.Order, error) {
	query := `SELECT id, account_id, status, expires_at, identifiers_json, not_before, not_after, error_json, certificate_serial, created_at, last_modified_at FROM acme_orders WHERE id = $1`
	var order model.Order
	var identifiersJSONBytes, errorJSONBytes []byte
	var sqlNotBefore, sqlNotAfter sql.NullTime
	var sqlCertSerial sql.NullString
	err := q.QueryRowContext(ctx, query, id).Scan(&order.ID, &order.AccountID, &order.Status, &order.Expires, &identifiersJSONBytes, &sqlNotBefore, &sqlNotAfter, &errorJSONBytes, &sqlCertSerial, &order.CreatedAt, &order.LastModifiedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("storage: failed to get order '%s': %w", id, err)
	}
	if len(identifiersJSONBytes) > 0 {
		if err := json.Unmarshal(identifiersJSONBytes, &order.Identifiers); err != nil {
			return nil, fmt.Errorf("storage: failed to unmarshal identifiers for order '%s': %w", order.ID, err)
		}
		order.IdentifiersJSON = string(identifiersJSONBytes)
	}
	if len(errorJSONBytes) > 0 {
		order.Error = &model.ProblemDetails{}
		if err := json.Unmarshal(errorJSONBytes, order.Error); err != nil {
			return nil, fmt.Errorf("storage: failed to unmarshal error for order '%s': %w", order.ID, err)
		}
		order.ErrorJSON = string(errorJSONBytes)
	}
	if sqlNotBefore.Valid {
		order.NotBefore = sqlNotBefore.Time
	}
	if sqlNotAfter.Valid {
		order.NotAfter = sqlNotAfter.Time
	}
	if sqlCertSerial.Valid {
		order.CertificateSerial = sqlCertSerial.String
	}
	return &order, nil
}
func getOrdersByAccountID(ctx context.Context, q Querier, accountID string) ([]*model.Order, error) {
	query := `SELECT id, account_id, status, expires_at, identifiers_json, not_before, not_after, error_json, certificate_serial, created_at, last_modified_at FROM acme_orders WHERE account_id = $1 ORDER BY created_at DESC`
	rows, err := q.QueryContext(ctx, query, accountID)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to query orders for account '%s': %w", accountID, err)
	}
	defer rows.Close()
	orders := make([]*model.Order, 0)
	for rows.Next() {
		var order model.Order
		var identifiersJSONBytes, errorJSONBytes []byte
		var sqlNotBefore, sqlNotAfter sql.NullTime
		var sqlCertSerial sql.NullString
		err := rows.Scan(&order.ID, &order.AccountID, &order.Status, &order.Expires, &identifiersJSONBytes, &sqlNotBefore, &sqlNotAfter, &errorJSONBytes, &sqlCertSerial, &order.CreatedAt, &order.LastModifiedAt)
		if err != nil {
			return nil, fmt.Errorf("storage: failed to scan order row for account '%s': %w", accountID, err)
		}
		if len(identifiersJSONBytes) > 0 {
			if err := json.Unmarshal(identifiersJSONBytes, &order.Identifiers); err != nil {
				return nil, fmt.Errorf("storage: failed to unmarshal identifiers for order '%s': %w", order.ID, err)
			}
			order.IdentifiersJSON = string(identifiersJSONBytes)
		}
		if len(errorJSONBytes) > 0 {
			order.Error = &model.ProblemDetails{}
			if err := json.Unmarshal(errorJSONBytes, order.Error); err != nil {
				return nil, fmt.Errorf("storage: failed to unmarshal error for order '%s': %w", order.ID, err)
			}
			order.ErrorJSON = string(errorJSONBytes)
		}
		if sqlNotBefore.Valid {
			order.NotBefore = sqlNotBefore.Time
		}
		if sqlNotAfter.Valid {
			order.NotAfter = sqlNotAfter.Time
		}
		if sqlCertSerial.Valid {
			order.CertificateSerial = sqlCertSerial.String
		}
		orders = append(orders, &order)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: error iterating order rows for account '%s': %w", accountID, err)
	}
	return orders, nil
}

// --- ACME Authorization Helpers ---
// saveAuthorization, getAuthorization, getAuthorizationsByOrderID
func saveAuthorization(ctx context.Context, q Querier, authz *model.Authorization) error {
	if authz.CreatedAt.IsZero() {
		authz.CreatedAt = time.Now()
	}
	identifierBytes, err := json.Marshal(authz.Identifier)
	if err != nil {
		return fmt.Errorf("storage: failed to marshal authz identifier for '%s': %w", authz.ID, err)
	}
	authz.IdentifierJSON = string(identifierBytes)
	query := `
        INSERT INTO acme_authorizations (id, account_id, order_id, identifier_json, status, expires_at, wildcard, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (id) DO UPDATE SET account_id = EXCLUDED.account_id, order_id = EXCLUDED.order_id, identifier_json = EXCLUDED.identifier_json,
            status = EXCLUDED.status, expires_at = EXCLUDED.expires_at, wildcard = EXCLUDED.wildcard`
	_, err = q.ExecContext(ctx, query, authz.ID, authz.AccountID, authz.OrderID, authz.IdentifierJSON, authz.Status, authz.Expires, authz.Wildcard, authz.CreatedAt)
	if err != nil {
		return fmt.Errorf("storage: failed to save authorization '%s': %w", authz.ID, err)
	}
	logger.Debug("Authorization saved", zap.String("authzID", authz.ID), zap.String("status", authz.Status))
	return nil
}
func getAuthorization(ctx context.Context, q Querier, id string) (*model.Authorization, error) {
	query := `SELECT id, account_id, order_id, identifier_json, status, expires_at, wildcard, created_at FROM acme_authorizations WHERE id = $1`
	var authz model.Authorization
	var identifierJSONBytes []byte
	err := q.QueryRowContext(ctx, query, id).Scan(&authz.ID, &authz.AccountID, &authz.OrderID, &identifierJSONBytes, &authz.Status, &authz.Expires, &authz.Wildcard, &authz.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("storage: failed to get authorization '%s': %w", id, err)
	}
	if len(identifierJSONBytes) > 0 {
		if err := json.Unmarshal(identifierJSONBytes, &authz.Identifier); err != nil {
			return nil, fmt.Errorf("storage: failed to unmarshal identifier for authorization '%s': %w", authz.ID, err)
		}
		authz.IdentifierJSON = string(identifierJSONBytes)
	} else {
		return nil, fmt.Errorf("storage: inconsistent data - identifier JSON is null/empty for authorization '%s'", authz.ID)
	}
	return &authz, nil
}
func getAuthorizationsByOrderID(ctx context.Context, q Querier, orderID string) ([]*model.Authorization, error) {
	query := `SELECT id, account_id, order_id, identifier_json, status, expires_at, wildcard, created_at FROM acme_authorizations WHERE order_id = $1 ORDER BY created_at ASC`
	rows, err := q.QueryContext(ctx, query, orderID)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to query authorizations for order '%s': %w", orderID, err)
	}
	defer rows.Close()
	authorizations := make([]*model.Authorization, 0)
	for rows.Next() {
		var authz model.Authorization
		var identifierJSONBytes []byte
		err := rows.Scan(&authz.ID, &authz.AccountID, &authz.OrderID, &identifierJSONBytes, &authz.Status, &authz.Expires, &authz.Wildcard, &authz.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("storage: failed to scan authorization row for order '%s': %w", orderID, err)
		}
		if len(identifierJSONBytes) > 0 {
			if err := json.Unmarshal(identifierJSONBytes, &authz.Identifier); err != nil {
				return nil, fmt.Errorf("storage: failed to unmarshal identifier for authorization '%s': %w", authz.ID, err)
			}
			authz.IdentifierJSON = string(identifierJSONBytes)
		} else {
			return nil, fmt.Errorf("storage: inconsistent data - identifier JSON is null/empty for authorization '%s'", authz.ID)
		}
		authorizations = append(authorizations, &authz)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: error iterating authorization rows for order '%s': %w", orderID, err)
	}
	return authorizations, nil
}

// --- ACME Challenge Helpers ---
// saveChallenge, getChallenge, getChallengeByToken, getChallengesByAuthorizationID
func saveChallenge(ctx context.Context, q Querier, chal *model.Challenge) error {
	if chal.CreatedAt.IsZero() {
		chal.CreatedAt = time.Now()
	}
	var errorBytes []byte
	var err error
	if chal.Error != nil {
		errorBytes, err = json.Marshal(chal.Error)
		if err != nil {
			return fmt.Errorf("storage: failed to marshal challenge error for '%s': %w", chal.ID, err)
		}
		chal.ErrorJSON = string(errorBytes)
	} else {
		chal.ErrorJSON = ""
	}
	query := `
        INSERT INTO acme_challenges (id, authorization_id, type, status, token, validated_at, error_json, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (id) DO UPDATE SET authorization_id = EXCLUDED.authorization_id, type = EXCLUDED.type, status = EXCLUDED.status, token = EXCLUDED.token,
            validated_at = EXCLUDED.validated_at, error_json = EXCLUDED.error_json`
	var sqlValidatedAt sql.NullTime
	if !chal.Validated.IsZero() {
		sqlValidatedAt = sql.NullTime{Time: chal.Validated, Valid: true}
	}
	var sqlErrorJSON sql.NullString
	if chal.ErrorJSON != "" {
		sqlErrorJSON = sql.NullString{String: chal.ErrorJSON, Valid: true}
	}
	_, err = q.ExecContext(ctx, query, chal.ID, chal.AuthorizationID, chal.Type, chal.Status, chal.Token, sqlValidatedAt, sqlErrorJSON, chal.CreatedAt)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			if strings.Contains(pqErr.Constraint, "acme_challenges_token_key") {
				return fmt.Errorf("storage: duplicate token constraint violation for challenge '%s', token '%s': %w", chal.ID, chal.Token, err)
			}
		}
		return fmt.Errorf("storage: failed to save challenge '%s': %w", chal.ID, err)
	}
	logger.Debug("Challenge saved", zap.String("challengeID", chal.ID), zap.String("status", chal.Status))
	return nil
}
func getChallenge(ctx context.Context, q Querier, id string) (*model.Challenge, error) {
	query := `SELECT id, authorization_id, type, status, token, validated_at, error_json, created_at FROM acme_challenges WHERE id = $1`
	var chal model.Challenge
	var errorJSONBytes []byte
	var sqlValidatedAt sql.NullTime
	err := q.QueryRowContext(ctx, query, id).Scan(&chal.ID, &chal.AuthorizationID, &chal.Type, &chal.Status, &chal.Token, &sqlValidatedAt, &errorJSONBytes, &chal.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("storage: failed to get challenge '%s': %w", id, err)
	}
	if len(errorJSONBytes) > 0 {
		chal.Error = &model.ProblemDetails{}
		if err := json.Unmarshal(errorJSONBytes, chal.Error); err != nil {
			return nil, fmt.Errorf("storage: failed to unmarshal error for challenge '%s': %w", chal.ID, err)
		}
		chal.ErrorJSON = string(errorJSONBytes)
	}
	if sqlValidatedAt.Valid {
		chal.Validated = sqlValidatedAt.Time
	}
	return &chal, nil
}
func getChallengeByToken(ctx context.Context, q Querier, token string) (*model.Challenge, error) {
	query := `SELECT id, authorization_id, type, status, token, validated_at, error_json, created_at FROM acme_challenges WHERE token = $1`
	var chal model.Challenge
	var errorJSONBytes []byte
	var sqlValidatedAt sql.NullTime
	err := q.QueryRowContext(ctx, query, token).Scan(&chal.ID, &chal.AuthorizationID, &chal.Type, &chal.Status, &chal.Token, &sqlValidatedAt, &errorJSONBytes, &chal.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("storage: failed to get challenge by token '%s': %w", token, err)
	}
	if len(errorJSONBytes) > 0 {
		chal.Error = &model.ProblemDetails{}
		if err := json.Unmarshal(errorJSONBytes, chal.Error); err != nil {
			return nil, fmt.Errorf("storage: failed to unmarshal error for challenge '%s': %w", chal.ID, err)
		}
		chal.ErrorJSON = string(errorJSONBytes)
	}
	if sqlValidatedAt.Valid {
		chal.Validated = sqlValidatedAt.Time
	}
	return &chal, nil
}
func getChallengesByAuthorizationID(ctx context.Context, q Querier, authzID string) ([]*model.Challenge, error) {
	query := `SELECT id, authorization_id, type, status, token, validated_at, error_json, created_at FROM acme_challenges WHERE authorization_id = $1 ORDER BY created_at ASC`
	rows, err := q.QueryContext(ctx, query, authzID)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to query challenges for authorization '%s': %w", authzID, err)
	}
	defer rows.Close()
	challenges := make([]*model.Challenge, 0)
	for rows.Next() {
		var chal model.Challenge
		var errorJSONBytes []byte
		var sqlValidatedAt sql.NullTime
		err := rows.Scan(&chal.ID, &chal.AuthorizationID, &chal.Type, &chal.Status, &chal.Token, &sqlValidatedAt, &errorJSONBytes, &chal.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("storage: failed to scan challenge row for authorization '%s': %w", authzID, err)
		}
		if len(errorJSONBytes) > 0 {
			chal.Error = &model.ProblemDetails{}
			if err := json.Unmarshal(errorJSONBytes, chal.Error); err != nil {
				return nil, fmt.Errorf("storage: failed to unmarshal error for challenge '%s': %w", chal.ID, err)
			}
			chal.ErrorJSON = string(errorJSONBytes)
		}
		if sqlValidatedAt.Valid {
			chal.Validated = sqlValidatedAt.Time
		}
		challenges = append(challenges, &chal)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: error iterating challenge rows for authorization '%s': %w", authzID, err)
	}
	return challenges, nil
}

// --- Policy Helpers ---

func addAllowedDomain(ctx context.Context, q Querier, domain string) error {
	normDomain := strings.ToLower(strings.TrimSpace(domain))
	if normDomain == "" {
		return errors.New("storage: allowed domain cannot be empty")
	}
	query := `INSERT INTO policy_allowed_domains (domain, added_at) VALUES ($1, NOW()) ON CONFLICT (domain) DO NOTHING`
	_, err := q.ExecContext(ctx, query, normDomain)
	if err != nil {
		return fmt.Errorf("storage: failed to add allowed domain '%s': %w", normDomain, err)
	}
	logger.Debug("Added/updated allowed domain", zap.String("domain", normDomain))
	return nil
}

func deleteAllowedDomain(ctx context.Context, q Querier, domain string) error {
	normDomain := strings.ToLower(strings.TrimSpace(domain))
	if normDomain == "" {
		return errors.New("storage: domain to delete cannot be empty")
	}
	query := `DELETE FROM policy_allowed_domains WHERE domain = $1`
	res, err := q.ExecContext(ctx, query, normDomain)
	if err != nil {
		return fmt.Errorf("storage: failed to delete allowed domain '%s': %w", normDomain, err)
	}
	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		logger.Warn("DeleteAllowedDomain affected 0 rows", zap.String("domain", normDomain))
	}
	logger.Info("Attempted to delete allowed domain", zap.String("domain", normDomain), zap.Int64("rowsAffected", rowsAffected))
	return nil
}

func listAllowedDomains(ctx context.Context, q Querier) ([]string, error) {
	query := `SELECT domain FROM policy_allowed_domains ORDER BY domain ASC`
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to query allowed domains: %w", err)
	}
	defer rows.Close()
	domains := make([]string, 0)
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, fmt.Errorf("storage: failed to scan allowed domain row: %w", err)
		}
		domains = append(domains, domain)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: error iterating allowed domain rows: %w", err)
	}
	return domains, nil
}

func addAllowedSuffix(ctx context.Context, q Querier, suffix string) error {
	// Normalize: lowercase, remove leading/trailing space, remove leading dot if present
	normSuffix := strings.ToLower(strings.TrimSpace(suffix))
	normSuffix = strings.TrimPrefix(normSuffix, ".")
	if normSuffix == "" {
		return errors.New("storage: allowed suffix cannot be empty")
	}

	query := `INSERT INTO policy_allowed_suffixes (suffix, added_at) VALUES ($1, NOW()) ON CONFLICT (suffix) DO NOTHING`
	_, err := q.ExecContext(ctx, query, normSuffix)
	if err != nil {
		return fmt.Errorf("storage: failed to add allowed suffix '%s': %w", normSuffix, err)
	}
	logger.Debug("Added/updated allowed suffix", zap.String("suffix", normSuffix))
	return nil
}

func deleteAllowedSuffix(ctx context.Context, q Querier, suffix string) error {
	normSuffix := strings.ToLower(strings.TrimSpace(suffix))
	normSuffix = strings.TrimPrefix(normSuffix, ".")
	if normSuffix == "" {
		return errors.New("storage: suffix to delete cannot be empty")
	}
	query := `DELETE FROM policy_allowed_suffixes WHERE suffix = $1`
	res, err := q.ExecContext(ctx, query, normSuffix)
	if err != nil {
		return fmt.Errorf("storage: failed to delete allowed suffix '%s': %w", normSuffix, err)
	}
	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		logger.Warn("DeleteAllowedSuffix affected 0 rows", zap.String("suffix", normSuffix))
	}
	logger.Info("Attempted to delete allowed suffix", zap.String("suffix", normSuffix), zap.Int64("rowsAffected", rowsAffected))
	return nil
}

func listAllowedSuffixes(ctx context.Context, q Querier) ([]string, error) {
	query := `SELECT suffix FROM policy_allowed_suffixes ORDER BY suffix ASC`
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to query allowed suffixes: %w", err)
	}
	defer rows.Close()
	suffixes := make([]string, 0)
	for rows.Next() {
		var suffix string
		if err := rows.Scan(&suffix); err != nil {
			return nil, fmt.Errorf("storage: failed to scan allowed suffix row: %w", err)
		}
		suffixes = append(suffixes, suffix)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: error iterating allowed suffix rows: %w", err)
	}
	return suffixes, nil
}

// isDomainAllowed checks if a domain exactly matches an allowed domain OR is a subdomain of an allowed suffix.
func isDomainAllowed(ctx context.Context, q Querier, domain string) (bool, error) {
	normDomain := strings.ToLower(strings.TrimSpace(domain))
	if normDomain == "" {
		return false, errors.New("domain cannot be empty")
	}

	// 1. Check for exact match
	queryExact := `SELECT 1 FROM policy_allowed_domains WHERE domain = $1 LIMIT 1`
	var dummy int
	err := q.QueryRowContext(ctx, queryExact, normDomain).Scan(&dummy)
	if err == nil {
		// Exact match found
		return true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		// Database error during exact match check
		return false, fmt.Errorf("storage: error checking exact domain match for '%s': %w", normDomain, err)
	}
	// No exact match found, continue to check suffixes...

	// 2. Fetch all allowed suffixes
	suffixes, err := listAllowedSuffixes(ctx, q)
	if err != nil {
		return false, fmt.Errorf("storage: failed to retrieve suffixes for domain check '%s': %w", normDomain, err)
	}

	// 3. Check if domain matches any suffix
	for _, suffix := range suffixes {
		// Check if domain is the suffix itself OR ends with ".suffix"
		if normDomain == suffix || strings.HasSuffix(normDomain, "."+suffix) {
			return true, nil
		}
	}

	// 4. No exact or suffix match found
	return false, nil
}

// --- Helper Functions ---
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
