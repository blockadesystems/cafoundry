# CA Foundry 🛡️

CA Foundry is an ACME v2 protocol compatible Certificate Authority server written in Go. It's designed to issue TLS certificates automatically for internal networks, development environments, or testing purposes where using public CAs like Let's Encrypt is not feasible or desired.

**⚠️ Status: Development / Alpha ⚠️**

This project implements the core ACME v2 workflow and includes basic, database-driven policy management. However, it is still under active development. Important features like comprehensive policy enforcement (CAA, Key Types), advanced error handling, rate limiting, and CRL/OCSP serving endpoints are still missing or incomplete. It **should not be considered production-ready** without further hardening, comprehensive testing, and security audits.

## Features

* **ACME v2 Implementation:** Supports the core API endpoints required by ACME clients (Directory, Nonce, NewAccount, Account Info/Update, NewOrder, Order lookup, Authz lookup, Challenge trigger, Finalize, Certificate download, Revocation).
* **Challenge Validation:**
    * Implements server-side validation logic for `http-01` and `dns-01` challenges.
    * Serves `http-01` challenge responses over HTTP via `/.well-known/acme-challenge/:token`. (DNS resolver for validation is configurable).
* **Policy Management:**
    * Issuance policy (allowed exact domains, allowed suffixes) is stored in the database.
    * Protected REST API (`/api/v1/policy/...`) for managing allowed domains and suffixes.
* **API Key Management:**
    * Uses API keys for authenticating access to the management API.
    * Keys are stored securely using **Salted SHA-256** hashes.
    * Includes a command-line flag (`--create-api-key`) to bootstrap the initial admin key.
* **Persistence:** Uses PostgreSQL for storing ACME state, issued certificates, policy rules, hashed API keys, CA keypair, and CRLs.
* **Configuration:** Configurable via environment variables.
* **Transport:** Serves the ACME API over HTTPS and the HTTP-01 challenge endpoint over HTTP.
* **CA Management:** Automatically generates and stores a root CA keypair on first run if not found in the database. Issues certificates signed by this CA. Basic CRL generation included.
* **Graceful Shutdown:** Handles termination signals for cleaner shutdown.

## Architecture Overview

CA Foundry follows a standard Go project layout:

* `cmd/cafoundryd/main.go`: Main application entry point, server setup, routing, CLI flag handling.
* `internal/acme/`: Implements ACME protocol handlers and logic.
* `internal/ca/`: Implements the core Certificate Authority logic (signing, revocation, CRLs, basic policy checks).
* `internal/storage/`: Defines the storage interface and PostgreSQL implementation (including schema management).
* `internal/config/`: Handles loading configuration from environment variables.
* `internal/model/`: Defines data structures (ACME resources, DB models).
* `internal/auth/`: Implements authentication middleware (currently API Key auth).
* `internal/management/`: Implements HTTP handlers for the management API.

## Getting Started

### Prerequisites

* **Go:** Version 1.24 or later.
* **PostgreSQL:** A running PostgreSQL instance (v10+ recommended).
* **Git** (for cloning).

### Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/blockadesystems/cafoundry.git](https://github.com/blockadesystems/cafoundry.git)
    cd cafoundry
    ```
2.  **Build the binary:**
    ```bash
    go build -o cafoundryd ./cmd/cafoundryd/main.go #
    ```

### Database Setup

1.  Ensure your PostgreSQL server is running.
2.  Create a database and a user for CA Foundry.
    ```sql
    -- Example SQL commands:
    CREATE DATABASE cafoundry;
    CREATE USER cafoundry_user WITH PASSWORD 'your_secure_password';
    GRANT ALL PRIVILEGES ON DATABASE cafoundry TO cafoundry_user;
    ```
3.  CA Foundry will attempt to create/update the necessary tables (`api_keys`, `policy_allowed_domains`, `policy_allowed_suffixes`, `acme_accounts`, etc.) automatically when it first starts using the credentials provided via environment variables.
    * **Note:** If upgrading from a previous version, you may need to manually `DROP TABLE IF EXISTS api_keys;` before running the new version for the first time to ensure the correct schema for hashed keys is created.

### Configuration

Configuration is managed via environment variables. The application will use default values if variables are not set.

**Required:**

* `CAFOUNDRY_DB_HOST`: PostgreSQL host.
* `CAFOUNDRY_DB_PORT`: PostgreSQL port (default: `5432`).
* `CAFOUNDRY_DB_USER`: PostgreSQL user.
* `CAFOUNDRY_DB_PASSWORD`: PostgreSQL password.
* `CAFOUNDRY_DB_NAME`: PostgreSQL database name.
* `CAFOUNDRY_EXTERNAL_URL`: The **publicly accessible base URL** for the server, including the scheme (e.g., `https://cafoundry.example.com:8443`). **Do not include trailing slashes.** Crucial for ACME URLs.

**Optional (with defaults):**

* `CAFOUNDRY_HTTPS_ADDRESS`: Listen address for HTTPS ACME API (default: `:8443`).
* `CAFOUNDRY_HTTP_ADDRESS`: Listen address for HTTP (for HTTP-01) (default: `:8080`).
* `CAFOUNDRY_STORAGE_TYPE`: Storage backend (default: `postgres`).
* `CAFOUNDRY_DB_SSLMODE`: PostgreSQL SSL mode (default: `disable`).
* `CAFOUNDRY_DATA_DIR`: Directory for storing ephemeral data or generated certs (like the HTTPS cert) (default: `./data`).
* `CAFOUNDRY_HTTPS_CERT_FILE`: Path to HTTPS cert file (default: `./data/https.crt`, auto-generated if missing).
* `CAFOUNDRY_HTTPS_KEY_FILE`: Path to HTTPS key file (default: `./data/https.key`, auto-generated if missing).
* `CAFOUNDRY_DNS_RESOLVER`: Address (ip:port) of DNS resolver for ACME validation (default: "" - uses system default; set to `127.0.0.1:8053` when testing with local `pebble-challtestsrv`).
* **CA Subject:** (Defaults exist)
    * `CAFOUNDRY_ORGANIZATION`, `CAFOUNDRY_COUNTRY`, `CAFOUNDRY_PROVINCE`, `CAFOUNDRY_LOCALITY`, `CAFOUNDRY_COMMON_NAME`
* **Validity Periods:** (Defaults exist)
    * `CAFOUNDRY_CA_VALIDITY_YEARS` (default: 10)
    * `CAFOUNDRY_DEFAULT_CERT_VALIDITY_DAYS` (default: 365)
    * `CAFOUNDRY_CRL_VALIDITY_HOURS` (default: 24)
    * `CAFOUNDRY_NONCE_LIFETIME_SECONDS` (default: 3600)
    * `CAFOUNDRY_ORDER_LIFETIME_SECONDS` (default: 7 days)
    * `CAFOUNDRY_AUTHZ_LIFETIME_SECONDS` (default: 30 days)
* **ACME Directory Metadata:** (Defaults exist)
    * `CAFOUNDRY_ACME_TOS_URL`
    * `CAFOUNDRY_ACME_WEBSITE_URL`
    * `CAFOUNDRY_ACME_CAA_IDENTITIES` (comma-separated)
    * `CAFOUNDRY_ACME_EAB_REQUIRED` (default: false)
* **Certificate Extensions:** (Defaults exist)
    * `CAFOUNDRY_CRL_DP` (comma-separated)
    * `CAFOUNDRY_OCSP_URL` (comma-separated)
    * `CAFOUNDRY_ISSUER_URL` (comma-separated)

*(Note: Domain/Suffix policies are now managed via the API, not environment variables).*

### Bootstrapping: Creating the First API Key

The management API (`/api/v1/...`) requires authentication using an API key with appropriate roles (e.g., "admin"). To create the *first* key:

1.  Set the necessary **database connection environment variables**.
2.  Run the `cafoundryd` binary with the `--create-api-key` flag and specify roles (and optionally a description):
    ```bash
    # Example: Create a key with the 'admin' role
    export CAFOUNDRY_DB_PASSWORD=your_db_password
    # ... other DB vars ...

    ./cafoundryd --create-api-key --roles "admin" --description "Initial Admin Key"
    ```
3.  The command will generate a key, hash it, store the hash in the database, and print the details **including the plaintext key**.
4.  **SAVE THE PLAINTEXT KEY SECURELY!** This is the only time it will be shown.
5.  The program will then exit.

### Running the Server

Set all required environment variables (especially DB connection and `CAFOUNDRY_EXTERNAL_URL`) and run the binary *without* the `--create-api-key` flag:

```bash
./cafoundryd

Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.