package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// akvClient wraps the Azure Key Vault SDK clients used by this connector.
type akvClient struct {
	certClient   *azcertificates.Client
	secretClient *azsecrets.Client
	vaultURL     string
}

// newAKVClient builds an AKV client using DefaultAzureCredential, which tries
// (in order): environment variables (SP), workload identity, managed identity,
// Azure CLI. This covers every deployment scenario without code changes.
func newAKVClient(vaultURL string) (*akvClient, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure credential: %w", err)
	}

	certClient, err := azcertificates.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azcertificates client: %w", err)
	}

	secretClient, err := azsecrets.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azsecrets client: %w", err)
	}

	return &akvClient{
		certClient:   certClient,
		secretClient: secretClient,
		vaultURL:     vaultURL,
	}, nil
}

// GenerateKeyCSRParams holds the decoded params for a generate_key_csr job.
type GenerateKeyCSRParams struct {
	Domains      []string `json:"domains"`
	KeyAlgorithm string   `json:"key_algorithm"`
	OrgID        string   `json:"org_id"`
	ApprovalID   string   `json:"approval_id"`
	Exportable   bool     `json:"exportable"`
}

// GenerateKeyCSR creates a key pair inside AKV under certName and returns the
// CSR PEM.  The key never leaves AKV — only the CSR is returned so CertForge
// can route it to the configured CA (ACME, DigiCert, self-signed, …) for signing.
//
// Uses the "Unknown" issuer policy so AKV generates the key and produces a CSR
// without attempting to sign it itself.  After CertForge signs the cert, callers
// may optionally call MergeCertificate to complete the AKV certificate lifecycle.
func (a *akvClient) GenerateKeyCSR(ctx context.Context, certName string, p GenerateKeyCSRParams) (csrPEM []byte, err error) {
	// Resolve key type and size from the CertForge key algorithm string.
	keyType := azcertificates.KeyTypeRSA
	var keySize *int32
	var curve *azcertificates.CurveName

	switch p.KeyAlgorithm {
	case "rsa-4096":
		keyType = azcertificates.KeyTypeRSA
		s := int32(4096)
		keySize = &s
	case "ecdsa-p256", "ec-256":
		keyType = azcertificates.KeyTypeEC
		c := azcertificates.CurveNameP256
		curve = &c
	case "ecdsa-p384", "ec-384":
		keyType = azcertificates.KeyTypeEC
		c := azcertificates.CurveNameP384
		curve = &c
	default: // "rsa-2048" or empty
		keyType = azcertificates.KeyTypeRSA
		s := int32(2048)
		keySize = &s
	}

	// Build Subject Alternative Names.
	domains := p.Domains
	if len(domains) == 0 {
		return nil, fmt.Errorf("generate_key_csr: no domains provided")
	}
	dnsSANs := make([]*string, len(domains))
	for i := range domains {
		s := domains[i]
		dnsSANs[i] = &s
	}
	cn := domains[0]
	subject := "CN=" + cn

	exportable := p.Exportable
	issuerName := "Unknown" // AKV: generate key + CSR, await external signing
	validity := int32(12)   // months; placeholder — CertForge controls actual validity
	contentType := "application/x-pem-file"

	_, err = a.certClient.CreateCertificate(ctx, certName, azcertificates.CreateCertificateParameters{
		CertificatePolicy: &azcertificates.CertificatePolicy{
			KeyProperties: &azcertificates.KeyProperties{
				KeyType:    &keyType,
				KeySize:    keySize,
				Curve:      curve,
				Exportable: &exportable,
			},
			SecretProperties: &azcertificates.SecretProperties{
				ContentType: &contentType,
			},
			X509CertificateProperties: &azcertificates.X509CertificateProperties{
				Subject: &subject,
				SubjectAlternativeNames: &azcertificates.SubjectAlternativeNames{
					DNSNames: dnsSANs,
				},
				ValidityInMonths: &validity,
			},
			IssuerParameters: &azcertificates.IssuerParameters{
				Name: &issuerName,
			},
		},
	}, nil)
	if err != nil && !isConflict(err) {
		return nil, fmt.Errorf("create certificate %s: %w", certName, err)
	}
	if isConflict(err) {
		// A previous generate_key_csr left a pending operation (e.g. the prior
		// attempt timed out before merge). Reuse the existing CSR so the retry
		// can proceed without needing to cancel and recreate the key.
		log.Printf("[akv] certificate %s already has an inProgress operation — reusing existing CSR", certName)
	}

	// Retrieve the pending operation to get the DER-encoded CSR.
	op, err := a.certClient.GetCertificateOperation(ctx, certName, nil)
	if err != nil {
		return nil, fmt.Errorf("get certificate operation %s: %w", certName, err)
	}
	if len(op.CSR) == 0 {
		return nil, fmt.Errorf("certificate operation %s: no CSR returned", certName)
	}

	// op.CSR is raw DER bytes; wrap in PEM for CertForge.
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: op.CSR})
	return csrPEM, nil
}

// MergeCertificate uploads the CA-signed certificate into AKV to complete the
// "Unknown issuer" certificate lifecycle.  After merge, the certificate is
// visible in AKV, expiry tracking and rotation policies activate, and the key
// can be used by Azure services that integrate with Key Vault.
//
// certPEM may contain the full chain (leaf + intermediates); AKV accepts it.
func (a *akvClient) MergeCertificate(ctx context.Context, certName string, certPEM []byte) error {
	// AKV MergeCertificate expects a slice of DER-encoded certificates.
	var certs [][]byte
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certs = append(certs, block.Bytes)
		}
	}
	if len(certs) == 0 {
		return fmt.Errorf("merge_certificate %s: no CERTIFICATE blocks in PEM", certName)
	}

	_, err := a.certClient.MergeCertificate(ctx, certName, azcertificates.MergeCertificateParameters{
		X509Certificates: certs,
	}, nil)
	if err != nil && isNotFound(err) {
		// Certificate may have already been deleted or merged — treat as OK.
		return nil
	}
	return err
}

// ExportKeyPEM retrieves the private key PEM for an exportable certificate.
// AKV stores the key as a secret whose name matches the certificate name.
// Returns an error if the key was created with a non-exportable policy.
func (a *akvClient) ExportKeyPEM(ctx context.Context, certName string) (keyPEM []byte, err error) {
	// The secret value for a PEM-content-type cert includes the full chain +
	// private key in PEM format.
	resp, err := a.secretClient.GetSecret(ctx, certName, "", nil)
	if err != nil {
		return nil, fmt.Errorf("get secret %s: %w (key may be non-exportable)", certName, err)
	}
	if resp.Value == nil || *resp.Value == "" {
		return nil, fmt.Errorf("secret %s: empty value", certName)
	}

	// Extract only the PRIVATE KEY block(s) from the PEM bundle.
	keyPEM = extractPrivateKeyPEM([]byte(*resp.Value))
	if len(keyPEM) == 0 {
		return nil, fmt.Errorf("secret %s: no private key block found (key may be non-exportable)", certName)
	}
	return keyPEM, nil
}

// DeleteCertificate deletes the AKV certificate (and its associated key).
// Best-effort: returns nil on 404.
func (a *akvClient) DeleteCertificate(ctx context.Context, certName string) error {
	_, err := a.certClient.DeleteCertificate(ctx, certName, nil)
	if err != nil && isNotFound(err) {
		return nil
	}
	return err
}

// Ping verifies connectivity and credential validity by listing one certificate page.
func (a *akvClient) Ping(ctx context.Context) error {
	pager := a.certClient.NewListCertificatePropertiesPager(nil)
	_, err := pager.NextPage(ctx)
	return err
}

// ─── integrated CA issuance ───────────────────────────────────────────────────

// AKVIssuer describes a certificate issuer configured in Azure Key Vault.
type AKVIssuer struct {
	Name     string `json:"name"`     // AKV issuer name (e.g. "DigiCert", "GlobalSign-Prod")
	Provider string `json:"provider"` // AKV provider type (e.g. "DigiCert", "GlobalSign")
}

// AKVCertInfo is the metadata for a certificate stored in Azure Key Vault.
type AKVCertInfo struct {
	Name       string    `json:"name"`        // AKV certificate name
	Subject    string    `json:"subject"`     // X.509 Subject DN
	Issuer     string    `json:"issuer"`      // X.509 Issuer DN
	SANs       []string  `json:"sans"`        // Subject Alternative Names
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	Serial     string    `json:"serial"`      // hex-encoded serial number
	IssuerName string    `json:"issuer_name"` // AKV issuer policy name ("Unknown", "DigiCert", …)
}

// IssueWithCAParams holds the decoded params for an issue_with_ca job.
type IssueWithCAParams struct {
	Domains        []string `json:"domains"`
	KeyAlgorithm   string   `json:"key_algorithm"`
	OrgID          string   `json:"org_id"`
	ApprovalID     string   `json:"approval_id"`
	Exportable     bool     `json:"exportable"`
	IssuerName     string   `json:"issuer_name"`     // AKV issuer name (must be pre-configured in vault)
	ValidityMonths int      `json:"validity_months"` // 0 → 12
}

// ListIssuers returns all certificate issuers configured in the vault.
func (a *akvClient) ListIssuers(ctx context.Context) ([]AKVIssuer, error) {
	pager := a.certClient.NewListIssuerPropertiesPager(nil)
	var issuers []AKVIssuer
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list_issuers: %w", err)
		}
		for _, item := range page.Value {
			if item == nil || item.ID == nil {
				continue
			}
			// ID is the full URI; extract the last path segment as the name.
			id := *item.ID
			parts := strings.Split(strings.TrimRight(id, "/"), "/")
			name := parts[len(parts)-1]
			provider := ""
			if item.Provider != nil {
				provider = *item.Provider
			}
			issuers = append(issuers, AKVIssuer{
				Name:     name,
				Provider: provider,
			})
		}
	}
	return issuers, nil
}

// ListCerts returns metadata for all certificates stored in the vault.
// It fetches the full certificate for each entry to extract X.509 fields.
func (a *akvClient) ListCerts(ctx context.Context) ([]AKVCertInfo, error) {
	pager := a.certClient.NewListCertificatePropertiesPager(nil)
	var out []AKVCertInfo
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list_certs: list page: %w", err)
		}
		for _, props := range page.Value {
			if props == nil || props.ID == nil {
				continue
			}
			name := props.ID.Name()
			info, err := a.fetchCertInfo(ctx, name)
			if err != nil {
				// Log and skip individual failures — don't abort the whole list.
				log.Printf("[akv] list_certs: skip %s: %v", name, err)
				continue
			}
			out = append(out, *info)
		}
	}
	return out, nil
}

// fetchCertInfo retrieves and parses a single certificate from AKV.
func (a *akvClient) fetchCertInfo(ctx context.Context, name string) (*AKVCertInfo, error) {
	resp, err := a.certClient.GetCertificate(ctx, name, "", nil)
	if err != nil {
		return nil, fmt.Errorf("get_certificate: %w", err)
	}
	if len(resp.CER) == 0 {
		return nil, fmt.Errorf("get_certificate: empty DER bytes")
	}

	cert, err := x509.ParseCertificate(resp.CER)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	info := &AKVCertInfo{
		Name:      name,
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		Serial:    hex.EncodeToString(cert.SerialNumber.Bytes()),
	}
	for _, san := range cert.DNSNames {
		info.SANs = append(info.SANs, san)
	}
	for _, ip := range cert.IPAddresses {
		info.SANs = append(info.SANs, ip.String())
	}

	// AKV issuer name from the certificate policy.
	if resp.Policy != nil && resp.Policy.IssuerParameters != nil && resp.Policy.IssuerParameters.Name != nil {
		info.IssuerName = *resp.Policy.IssuerParameters.Name
	}

	return info, nil
}

// IssueWithCA creates a certificate in AKV using a pre-configured external CA
// issuer (e.g. DigiCert, GlobalSign).  AKV coordinates with the CA and the
// connector polls until the operation completes.  Returns the signed cert PEM.
func (a *akvClient) IssueWithCA(ctx context.Context, certName string, p IssueWithCAParams) ([]byte, error) {
	if p.IssuerName == "" {
		return nil, fmt.Errorf("issue_with_ca: issuer_name is required")
	}

	keyType, keySize, curve := resolveKeyType(p.KeyAlgorithm)
	exportable := p.Exportable
	validity := int32(p.ValidityMonths)
	if validity == 0 {
		validity = 12
	}

	domains := p.Domains
	if len(domains) == 0 {
		return nil, fmt.Errorf("issue_with_ca: no domains provided")
	}
	dnsSANs := make([]*string, len(domains))
	for i := range domains {
		s := domains[i]
		dnsSANs[i] = &s
	}
	cn := domains[0]
	subject := "CN=" + cn
	contentType := "application/x-pem-file"
	issuerName := p.IssuerName

	_, err := a.certClient.CreateCertificate(ctx, certName, azcertificates.CreateCertificateParameters{
		CertificatePolicy: &azcertificates.CertificatePolicy{
			KeyProperties: &azcertificates.KeyProperties{
				KeyType:    &keyType,
				KeySize:    keySize,
				Curve:      curve,
				Exportable: &exportable,
			},
			SecretProperties: &azcertificates.SecretProperties{
				ContentType: &contentType,
			},
			X509CertificateProperties: &azcertificates.X509CertificateProperties{
				Subject: &subject,
				SubjectAlternativeNames: &azcertificates.SubjectAlternativeNames{
					DNSNames: dnsSANs,
				},
				ValidityInMonths: &validity,
			},
			IssuerParameters: &azcertificates.IssuerParameters{
				Name: &issuerName,
			},
		},
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("issue_with_ca create %s: %w", certName, err)
	}

	log.Printf("[akv] issue_with_ca: cert %q submitted to issuer %q, polling for completion", certName, p.IssuerName)

	// Poll until AKV+CA completes (can take minutes for external CAs).
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("issue_with_ca %s: context cancelled while waiting for CA: %w", certName, ctx.Err())
		case <-time.After(5 * time.Second):
		}

		op, err := a.certClient.GetCertificateOperation(ctx, certName, nil)
		if err != nil {
			return nil, fmt.Errorf("issue_with_ca get_operation %s: %w", certName, err)
		}
		if op.Status == nil {
			continue
		}
		switch *op.Status {
		case "completed":
			resp, err := a.certClient.GetCertificate(ctx, certName, "", nil)
			if err != nil {
				return nil, fmt.Errorf("issue_with_ca get_cert %s: %w", certName, err)
			}
			certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: resp.CER})
			log.Printf("[akv] issue_with_ca: cert %q issued by %q", certName, p.IssuerName)
			return certPEM, nil
		case "failed", "cancelled":
			errMsg := *op.Status
			if op.Error != nil {
				errMsg = op.Error.Error()
			}
			return nil, fmt.Errorf("issue_with_ca %s: CA returned %s: %s", certName, *op.Status, errMsg)
		default: // "inProgress" — keep polling
			log.Printf("[akv] issue_with_ca: cert %q status=%s, waiting…", certName, *op.Status)
		}
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// resolveKeyType maps a CertForge key algorithm string to AKV key parameters.
func resolveKeyType(keyAlgorithm string) (keyType azcertificates.KeyType, keySize *int32, curve *azcertificates.CurveName) {
	switch keyAlgorithm {
	case "rsa-4096":
		s := int32(4096)
		return azcertificates.KeyTypeRSA, &s, nil
	case "ecdsa-p256", "ec-256":
		c := azcertificates.CurveNameP256
		return azcertificates.KeyTypeEC, nil, &c
	case "ecdsa-p384", "ec-384":
		c := azcertificates.CurveNameP384
		return azcertificates.KeyTypeEC, nil, &c
	default: // "rsa-2048" or empty
		s := int32(2048)
		return azcertificates.KeyTypeRSA, &s, nil
	}
}

// extractPrivateKeyPEM scans a PEM bundle and returns only the private key blocks.
func extractPrivateKeyPEM(bundle []byte) []byte {
	var out []byte
	rest := bundle
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			out = append(out, pem.EncodeToMemory(block)...)
		}
	}
	return out
}

// isConflict reports whether an AKV error is a 409 Conflict (pending operation still inProgress).
func isConflict(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "409") ||
		strings.Contains(err.Error(), "Conflict")
}

// isNotFound reports whether an AKV error is a 404.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "404") ||
		strings.Contains(err.Error(), "CertificateNotFound") ||
		strings.Contains(err.Error(), "SecretNotFound")
}

// akvSanitize replaces any character not in [a-zA-Z0-9-] with a hyphen.
var akvSanitize = strings.NewReplacer(".", "-", "*", "wc", "_", "-")

// certNameFromParams produces a human-readable, AKV-safe certificate name.
// Format: cf-<8-char-approvalID>-<primary-domain>
// e.g. "cf-e91a66be-myapp-example-com"
// Falls back to cf-<full-approvalID> if no domains are provided.
// AKV names: [a-zA-Z0-9-], max 127 chars, must start with a letter.
func certNameFromParams(approvalID string, domains []string) string {
	id := approvalID
	if len(id) > 8 {
		id = id[:8]
	}
	if len(domains) > 0 {
		domain := akvSanitize.Replace(domains[0])
		// Strip any remaining non-AKV chars
		var b strings.Builder
		for _, r := range domain {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				b.WriteRune(r)
			}
		}
		domain = strings.Trim(b.String(), "-")
		if domain != "" {
			name := fmt.Sprintf("cf-%s-%s", id, domain)
			if len(name) > 127 {
				name = name[:127]
			}
			return name
		}
	}
	// Fallback: cf-<full-approvalID>
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, approvalID)
	name := "cf-" + safe
	if len(name) > 127 {
		name = name[:127]
	}
	return name
}
