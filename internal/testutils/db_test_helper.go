package testutils

import (
	"context"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// SetupTestDB starts a new PostgreSQL container for testing.
// It returns the connection string (DSN) for the test database
// and a cleanup function that should be deferred by the caller to terminate the container.
func SetupTestDB(t *testing.T) (string, func()) {
	t.Helper() // Mark this as a test helper function

	ctx := context.Background()
	dbName := "testdb"
	dbUser := "testuser"
	dbPassword := "testpass"
	dbPort := "5432/tcp"

	// Define the wait strategy
	waitStrategy := wait.ForAll( // Wait for ALL conditions
		wait.ForLog("database system is ready to accept connections").
			WithOccurrence(1).
			WithStartupTimeout(1*time.Minute),
		wait.ForListeningPort(nat.Port(dbPort)). // Also wait for the port to be listening
								WithStartupTimeout(1*time.Minute),
	).WithDeadline(2 * time.Minute) // Overall deadline for combined strategies

	// Run the container passing options directly
	postgresContainer, err := postgres.Run(ctx,
		"postgres:15-alpine",
		postgres.WithDatabase(dbName),
		postgres.WithUsername(dbUser),
		postgres.WithPassword(dbPassword),
		testcontainers.WithWaitStrategy(waitStrategy), // Use the combined wait strategy
	)
	if err != nil {
		t.Fatalf("Failed to start postgres container: %s", err)
	}

	// Define the cleanup function to terminate the container
	cleanup := func() {
		terminateCtx, terminateCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer terminateCancel()
		if err := postgresContainer.Terminate(terminateCtx); err != nil {
			// Log error but don't necessarily fail test run if cleanup fails minorly
			t.Logf("WARN: Failed to terminate postgres container: %s", err)
		} else {
			t.Log("Postgres container terminated")
		}
	}

	// Get the connection string (DSN) for the container
	// Explicitly disable SSL for simpler test connections.
	connStrCtx, connStrCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer connStrCancel()
	connStr, err := postgresContainer.ConnectionString(connStrCtx, "sslmode=disable")
	if err != nil {
		cleanup()
		t.Fatalf("Failed to get connection string: %s", err)
	}

	t.Logf("Postgres container started") // Don't log connection string with password

	return connStr, cleanup
}
