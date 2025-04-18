# CA Foundry 🛡️

CA Foundry is an ACME v2 protocol compatible Certificate Authority server written in Go. It's designed to issue TLS certificates automatically for internal networks, development environments, or testing purposes where using public CAs like Let's Encrypt is not feasible or desired.

**⚠️ Status: Development / Alpha ⚠️**

This project implements the core ACME v2 workflow but is currently under active development. It **should not be considered production-ready** without further hardening, comprehensive testing, robust policy implementation, and security audits.

## Features

* **ACME v2 Implementation:** Supports the core API endpoints required by ACME clients:
    * `/directory`
    * `/new-nonce`
    * `/new-account`
    * `/account/:id` (Account lookup/update/deactivation)
    * `/new-order`
    * `/order/:id` (Order lookup)
    * `/authz/:id` (Authorization lookup)
    * `/chall/:id` (Challenge trigger)
    * `/finalize/:id` (Certificate issuance)
    * `/cert/:id` (Certificate download)
    * `/revoke-cert` (Certificate revocation)
* **Challenge Validation:**
    * Implements server-side validation logic for `http-01` and `dns-01` challenges.
    * Serves `http-01` challenge responses over HTTP via `/.well-known/acme-challenge/:token`.
* **Persistence:** Uses PostgreSQL for storing ACME state (accounts, orders, authz, challenges), issued certificates, CA keypair, and CRLs.
* **Configuration:** Configurable via environment variables.
* **Transport:** Serves the ACME API over HTTPS and the HTTP-01 challenge endpoint over HTTP.
* **CA Management:** Automatically generates and stores a root CA keypair on first run if not found in the database. Issues certificates signed by this CA. Basic CRL generation included.
* **Graceful Shutdown:** Handles termination signals for cleaner shutdown.

## Architecture Overview

CA Foundry follows a standard Go project layout:

* `cmd/cafoundryd/main.go`: Main application entry point, server setup, routing.
* `internal/acme/`: Implements ACME protocol handlers and logic.
* `internal/ca/`: Implements the core Certificate Authority logic (signing, revocation, CRLs).
* `internal/storage/`: Defines the storage interface and PostgreSQL implementation.
* `internal/config/`: Handles loading configuration from environment variables.
* `internal/model/`: Defines data structures (ACME resources, DB models).

## Getting Started

### Prerequisites

* **Go:** Version 1.23 or later.
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
    go build -o cafoundryd ./cmd/cafoundryd
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
3.  CA Foundry will attempt to create the necessary tables (`acme_accounts`, `acme_orders`, `certificates_data`, etc.) automatically when it first starts using the credentials provided via environment variables.

### Configuration

Configuration is managed via environment variables. The application will use default values if variables are not set.

**Required:**

* `CAFOUNDRY_DB_HOST`: PostgreSQL host.
* `CAFOUNDRY_DB_PORT`: PostgreSQL port (default: `5432`).
* `CAFOUNDRY_DB_USER`: PostgreSQL user.
* `CAFOUNDRY_DB_PASSWORD`: PostgreSQL password.
* `CAFOUNDRY_DB_NAME`: PostgreSQL database name.
* `CAFOUNDRY_EXTERNAL_URL`: The **publicly accessible base URL** for the server, including the scheme (e.g., `https://cafoundry.example.com:8443`). **Do not include trailing slashes.** This is crucial for generating correct ACME resource URLs.

**Optional (with defaults):**

* `CAFOUNDRY_HTTPS_ADDRESS`: Listen address for HTTPS ACME API (default: `:8443`).
* `CAFOUNDRY_HTTP_ADDRESS`: Listen address for HTTP (for HTTP-01) (default: `:8080`).
* `CAFOUNDRY_STORAGE_TYPE`: Storage backend (default: `postgres`).
* `CAFOUNDRY_DB_SSLMODE`: PostgreSQL SSL mode (default: `disable`; use `require`, `verify-ca`, or `verify-full` for production).
* `CAFOUNDRY_DATA_DIR`: Directory for storing ephemeral data or generated certs (like the HTTPS cert) (default: `./data`).
* `CAFOUNDRY_HTTPS_CERT_FILE`: Path to HTTPS cert file (default: `./data/https.crt`, auto-generated if missing).
* `CAFOUNDRY_HTTPS_KEY_FILE`: Path to HTTPS key file (default: `./data/https.key`, auto-generated if missing).
* **CA Subject:**
    * `CAFOUNDRY_ORGANIZATION` (default: "CA Foundry Authority")
    * `CAFOUNDRY_COUNTRY` (default: "US")
    * `CAFOUNDRY_PROVINCE` (default: "NC")
    * `CAFOUNDRY_LOCALITY` (default: "Raleigh")
    * `CAFOUNDry_COMMON_NAME` (default: "CA Foundry Root CA")
* **Validity Periods:**
    * `CAFOUNDRY_CA_VALIDITY_YEARS` (default: 10)
    * `CAFOUNDRY_DEFAULT_CERT_VALIDITY_DAYS` (default: 365)
    * `CAFOUNDRY_CRL_VALIDITY_HOURS` (default: 24)
    * `CAFOUNDRY_NONCE_LIFETIME_SECONDS` (default: 3600)
    * `CAFOUNDRY_ORDER_LIFETIME_SECONDS` (default: 604800 - 7 days)
    * `CAFOUNDRY_AUTHZ_LIFETIME_SECONDS` (default: 2592000 - 30 days)
* **ACME Directory Metadata:**
    * `CAFOUNDRY_ACME_TOS_URL` (default: "")
    * `CAFOUNDRY_ACME_WEBSITE_URL` (default: "")
    * `CAFOUNDRY_ACME_CAA_IDENTITIES` (default: "", comma-separated domains)
    * `CAFOUNDRY_ACME_EAB_REQUIRED` (default: false)
* **Certificate Extensions:**
    * `CAFOUNDRY_CRL_DP` (default: "", comma-separated CRL Distribution Point URLs)
    * `CAFOUNDRY_OCSP_URL` (default: "", comma-separated OCSP Server URLs)
    * `CAFOUNDRY_ISSUER_URL` (default: "", comma-separated Issuing Certificate URLs for AIA)

**Example Environment Setup (.env file or export):**

```bash
export CAFOUNDRY_DB_HOST="localhost"
export CAFOUNDRY_DB_PORT="5432"
export CAFOUNDRY_DB_USER="cafoundry_user"
export CAFOUNDRY_DB_PASSWORD="your_secure_password"
export CAFOUNDRY_DB_NAME="cafoundry"
export CAFOUNDRY_DB_SSLMODE="disable" # Or 'require', etc.
export CAFOUNDRY_EXTERNAL_URL="[https://your-host.example.com:8443](https://your-host.example.com:8443)"
export CAFOUNDRY_HTTPS_ADDRESS=":8443"
export CAFOUNDRY_HTTP_ADDRESS=":8080"
export CAFOUNDRY_COMMON_NAME="My Internal CA"
# Add others as needed
```

Running

Ensure all required environment variables are set, then run the compiled binary:
```Bash

./cafoundryd
```

The server will start listening on the configured HTTP and HTTPS addresses. Check the logs for confirmation and any errors.

Usage with ACME Clients

CA Foundry is designed to work with standard ACME v2 clients like Certbot, acme.sh, etc.

Important:

    Trust: The client machine (and any machine that needs to trust certificates issued by CA Foundry) must be configured to trust the CA Foundry root certificate. This certificate (ca.crt) is typically generated and stored in the location derived from CAFOUNDRY_DATA_DIR by the CA service on its first run if not found in the database, although the primary source is the database (GetCACertificate). You will need to retrieve this certificate and add it to the system or application trust stores.
    Server URL: Point your ACME client to the CA Foundry directory URL, which is {CAFOUNDRY_EXTERNAL_URL}/acme/directory.

Example using Certbot (Standalone mode, HTTP-01 challenge):


# 1. Make sure CA Foundry is running and accessible at CAFOUNDRY_EXTERNAL_URL.
# 2. Obtain the CA Foundry root certificate (e.g., ca.crt) and save it.
# 3. Run Certbot:

```bash
sudo certbot certonly \
    --standalone \
    --preferred-challenges http \
    --server [https://your-cafoundry-host.internal:8443/acme/directory](https://your-cafoundry-host.internal:8443/acme/directory) \
    --cert-path /tmp/cafoundry-cert.pem \
    --key-path /tmp/cafoundry-key.pem \
    --fullchain-path /tmp/cafoundry-fullchain.pem \
    -d myapp.yourdomain.internal \
    -d anotherapp.yourdomain.internal \
    --email your-admin@yourdomain.internal \
    --agree-tos \
    --non-interactive \
    --debug \
    --logs-dir /tmp/certbot-logs \
    --config-dir /tmp/certbot-config \
    --work-dir /tmp/certbot-work \
    --cacert /path/to/your/cafoundry-ca.crt # Tell certbot to trust your CA

# Check /tmp/ for the issued certificate files.
```

Adjust domains, email, server URL, and --cacert path accordingly.
Using --standalone requires ports 80/443 to be free or Certbot needs alternate ports configured.
You might need to use --no-verify-ssl initially if the HTTPS certificate for CA Foundry itself is self-signed.

TODO / Future Work

    Comprehensive Testing: Unit tests and integration tests (e.g., using Pebble).
    Policy Enforcement: Implement robust domain allow/block lists, key type restrictions in ca.SignCSR.
    CAA Checking: Add mandatory DNS CAA record checks.
    Rate Limiting: Implement ACME rate limits.
    CRL/OCSP Serving: Implement actual endpoints to serve CRLs and potentially OCSP responses. Add periodic CRL generation.
    ACME Edge Cases: Handle authorization deactivation, key change requests.
    Configuration: Support loading complex policies from a config file (YAML/TOML).
    Security Hardening: Input validation, dependency scanning, potential HSM/KMS support for CA key.
    Observability: Improve metrics and tracing.
    Documentation: Expand on advanced configuration and usage.

Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.