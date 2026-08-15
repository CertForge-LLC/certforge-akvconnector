# certforge-akvconnector

Lightweight open-source connector that bridges **CertForge** certificate governance with **Azure Key Vault** for managed-identity key management.

Keys are generated inside AKV (HSM-backed, non-exportable by default). CertForge handles the CA signing workflow (ACME, DigiCert, self-signed, internal CA). The connector is the glue: it receives key generation jobs from CertForge, executes them against AKV, and returns the CSR.

## How it works

```
CertForge approval pipeline
  → writes keystore job (generate_key_csr)
  → connector polls GET /api/v1/connector/keystore/jobs
  → calls AKV: CreateCertificate (Unknown issuer → key generated inside AKV, CSR returned)
  → posts CSR back to CertForge
  → CertForge CA backend signs the CSR (ACME / DigiCert / internal CA)
  → cert stored in CertForge; key stays in AKV
  → (optional) CertForge sends merge_certificate job
  → connector merges signed cert into AKV to complete the certificate lifecycle
```

## Certificate lifecycle

The full lifecycle for a CertForge-signed certificate uses two jobs:

| Step | Job | What happens |
|------|-----|--------------|
| 1 | `generate_key_csr` | AKV generates the key pair and returns a CSR; key never leaves AKV |
| 2 | *(CertForge signs)* | CertForge routes the CSR to the configured CA for signing |
| 3 | `merge_certificate` | Signed cert is merged back into AKV, completing the certificate object |

After `merge_certificate`, AKV's expiry tracking, rotation policies, and Azure service integrations (App Service, API Management, etc.) activate. Without the merge, the AKV certificate stays in "pending" state — the key exists but AKV does not know the signed cert.

**When merge is optional:** if you only need the key and cert inside CertForge (e.g. for devices managed by certforge-connector), you can skip the merge. CertForge holds the cert; AKV holds the key.

For the `issue_with_ca` path (AKV integrated CAs such as DigiCert/GlobalSign), AKV handles the full lifecycle internally — no separate merge job is sent.

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
# See deploy/kubernetes/deployment.yaml
```

## Authentication

Uses `DefaultAzureCredential` — tries in order:

| Method | When | Config needed |
|--------|------|---------------|
| Environment (SP) | CI/CD, legacy | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` |
| Workload Identity | AKS, GKE with federated creds | `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_FEDERATED_TOKEN_FILE` |
| Managed Identity | Azure VMs, AKS, Container Apps | None (or `AZURE_CLIENT_ID` for user-assigned) |
| Azure CLI | Local dev | `az login` |

## Required Key Vault permissions

Assign these permissions to the managed identity / service principal the connector uses:

| Permission | Needed for |
|------------|-----------|
| Certificates: Get, List, Create, Delete | Key generation, listing, deletion, ping |
| Certificates: Purge | `purge_on_delete: true` only |
| Secrets: Get | `export_key` only — omit if you never use exportable keys |

Grant with least privilege: if your deployment does not use exportable keys, do not grant `Secrets: Get`.

## Operations

| Job operation | Description |
|--------------|-------------|
| `generate_key_csr` | Create key pair inside AKV + return CSR PEM for external signing |
| `merge_certificate` | Merge CA-signed certificate into AKV to complete the certificate lifecycle |
| `export_key` | ⚠️ Return private key PEM (exportable keys only — see Security below) |
| `delete_key` | Soft-delete AKV certificate + key; optionally purge immediately |
| `issue_with_ca` | Issue cert via a pre-configured AKV integrated CA (DigiCert, GlobalSign, etc.) |
| `list_issuers` | Return all AKV certificate issuers (used by CertForge UI) |
| `list_certs` | Return metadata for all certs in the vault (used by CertForge Discovery) |
| `ping` | Verify AKV connectivity and credential validity |

## Configuration

```yaml
certforge_url: https://app.certgovernance.app   # or https://eu.certgovernance.app
api_key: $CERTFORGE_API_KEY                     # connector-scoped key from CertForge Settings
connector_id: ...                               # from CA Connectors page in CertForge
vault_url: https://myvault.vault.azure.net      # must be a known, controlled vault — see Security

poll_interval: 5s    # optional, default 5s
log_level: info      # optional: info | debug

# Permanently purge soft-deleted certificates after delete_key.
# When false (default), deleted certs enter AKV soft-delete for the vault's
# retention period (default 90 days). Enable this if you need to re-create
# keys with the same name immediately after deletion (e.g. after revocation).
# Requires the Key Vault Certificate Purge permission.
purge_on_delete: false
```

All fields can be overridden with environment variables:  
`CERTFORGE_URL`, `CERTFORGE_API_KEY`, `CONNECTOR_ID`, `AKV_VAULT_URL`

## Security

### Exportable keys

> ⚠️ **`export_key` returns private key material.** This is the highest-risk operation the connector performs.

The `export_key` job is only dispatched by CertForge when a DTP explicitly allows exportable keys and the certificate was created with `exportable: true` in `generate_key_csr`. The private key is delivered to CertForge over TLS and stored encrypted.

**Recommendations:**

- Configure your Domain Trust Profiles to disallow exportable keys except where strictly required. Non-exportable is the default and the safer choice for most deployments.
- Do not grant `Secrets: Get` to the connector identity unless your deployment uses exportable keys.
- Review the CertForge audit log regularly for `export_key` events. The connector logs every export prominently with a `[SECURITY]` tag:

  ```
  [worker] [SECURITY] export_key: exporting private key "cf-abc123-example-com" from AKV (job ...)
  [worker] [SECURITY] export_key: private key "cf-abc123-example-com" exported and delivered to CertForge (job ...)
  ```

### Vault URL trust

The connector connects to whatever `vault_url` is configured. There are no SSRF-style request origin checks. Ensure:

- `vault_url` is set to your own, controlled Azure Key Vault.
- The connector config file (or environment) is only writable by trusted principals.
- In Kubernetes, use a read-only config source (ConfigMap or Secret projected as a volume).

### AKV soft-delete and `purge_on_delete`

AKV soft-delete is enabled by default on all vaults. When the connector runs `delete_key`, the certificate enters a recoverable state for the vault's retention period (default 90 days). During this window, a `generate_key_csr` job for the same domain will fail with:

```
certificate cf-... is soft-deleted in AKV and cannot be re-created until purged
```

To resolve: either set `purge_on_delete: true` in the connector config (requires `Certificates: Purge` permission), or purge the soft-deleted certificate manually:

```bash
az keyvault certificate purge --vault-name <vault> --name <cert-name>
```

`purge_on_delete: false` is the default — it preserves the recovery window, which may be required by your organization's data-protection policy.

### Required egress

The connector requires outbound HTTPS (port 443) only — no inbound ports.

| Destination | Purpose |
|-------------|---------|
| `app.certgovernance.app` (US) or `eu.certgovernance.app` (EU) | CertForge job polling and result delivery |
| `<your-vault>.vault.azure.net` | Azure Key Vault operations |
| `login.microsoftonline.com` | Azure AD token acquisition (SP / workload identity auth) |
| `<region>.oic.prod-aks.azure.com` | AKS OIDC token endpoint (workload identity only) |

## Building

```bash
go build -ldflags "-X main.Version=v1.0.0" -o certforge-akvconnector .

# Cross-compile for Linux (for deployment)
GOOS=linux GOARCH=amd64 go build -ldflags "-X main.Version=v1.0.0" -o certforge-akvconnector-linux-amd64 .
```

## Kubernetes deployment

See [`deploy/kubernetes/deployment.yaml`](deploy/kubernetes/deployment.yaml) for a complete example covering both AKS Workload Identity (recommended) and Service Principal authentication.

## License

Apache 2.0
