# certforge-akvconnector

Lightweight open-source connector that bridges **CertForge** certificate governance with **Azure Key Vault** for managed-identity key management.

Keys are generated inside AKV (HSM-backed, non-exportable by default). CertForge handles the CA signing workflow (ACME, DigiCert, self-signed). The connector is the glue: it receives key generation jobs from CertForge, executes them against AKV, and returns the CSR.

## How it works

```
CertForge approval pipeline
  → writes key_store_job (generate_key_csr)
  → connector polls GET /api/v1/connector/keystore/jobs
  → calls AKV: CreateCertificate (Unknown issuer → key generated, CSR returned)
  → posts CSR back to CertForge
  → CertForge CA backend signs the CSR (ACME / DigiCert / internal CA)
  → cert stored in CertForge; key stays in AKV
```

## Quick start

### 1. Create an API key in CertForge

Settings → API Keys → New Key → scope: `connector`

### 2. Register the connector in CertForge

CA Connectors → Add Connector → type: **Azure Key Vault — Key Management Connector**  
Enter your vault URL, save. Copy the **Connector ID** from the table.

### 3. Configure the connector

```bash
cp certforge-akvconnector.yaml.example certforge-akvconnector.yaml
# edit: certforge_url, api_key, connector_id, vault_url
```

### 4. Run

```bash
# Local (Azure CLI auth)
az login
./certforge-akvconnector

# Docker (managed identity)
docker run --rm \
  -e CERTFORGE_URL=https://app.certgovernance.app \
  -e CERTFORGE_API_KEY=cc_... \
  -e CONNECTOR_ID=... \
  -e AKV_VAULT_URL=https://myvault.vault.azure.net \
  ghcr.io/certforge-llc/certforge-akvconnector:latest

# Kubernetes (AKS with workload identity)
# See deploy/kubernetes/ for example manifests
```

## Authentication

Uses `DefaultAzureCredential` — tries in order:

| Method | When | Config needed |
|--------|------|---------------|
| Environment (SP) | CI/CD, legacy | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` |
| Workload Identity | AKS, GKE, EKS | `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_FEDERATED_TOKEN_FILE` |
| Managed Identity | Azure VMs, AKS, Container Apps | None (or `AZURE_CLIENT_ID` for user-assigned) |
| Azure CLI | Local dev | `az login` |

## Required Key Vault permissions

| Permission | Needed for |
|------------|-----------|
| Certificates: Get, List, Create, Delete | Key generation, deletion, ping |
| Secrets: Get | Exportable key export only |

## Operations

| Job operation | Description |
|--------------|-------------|
| `generate_key_csr` | Create key in AKV + return CSR PEM |
| `export_key` | Return private key PEM (exportable keys only) |
| `delete_key` | Delete AKV certificate + key |
| `ping` | Verify connectivity |

## Configuration

```yaml
certforge_url: https://app.certgovernance.app
api_key: cc_...
connector_id: ...
vault_url: https://myvault.vault.azure.net
poll_interval: 5s   # optional, default 5s
log_level: info     # optional: info | debug
```

All fields can be overridden with environment variables:
`CERTFORGE_URL`, `CERTFORGE_API_KEY`, `CONNECTOR_ID`, `AKV_VAULT_URL`

## Building

```bash
go build -ldflags "-X main.Version=v1.0.0" -o certforge-akvconnector .

# Cross-compile for Linux (for deployment)
GOOS=linux GOARCH=amd64 go build -ldflags "-X main.Version=v1.0.0" -o certforge-akvconnector-linux-amd64 .
```

## License

Apache 2.0
