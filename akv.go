package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"strings"

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
	if err != nil {
		return nil, fmt.Errorf("create certificate %s: %w", certName, err)
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

// ─── helpers ──────────────────────────────────────────────────────────────────

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

// isNotFound reports whether an AKV error is a 404.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "404") ||
		strings.Contains(err.Error(), "CertificateNotFound") ||
		strings.Contains(err.Error(), "SecretNotFound")
}

// certNameFromApprovalID produces an AKV-safe certificate name from a CertForge
// approval ID.  AKV names must start with a letter, contain only letters/digits/hyphens.
// UUID approval IDs satisfy the character set requirement; we add "cf-" prefix.
func certNameFromApprovalID(approvalID string) string {
	// Replace any non-alphanumeric, non-hyphen characters.
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
