package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// Worker is the main poll-process loop.
type Worker struct {
	cfg *Config
	cf  *certForgeClient
	akv *akvClient
}

// Run polls CertForge for pending keystore jobs until the context is cancelled.
func (w *Worker) Run(ctx context.Context) {
	log.Printf("[worker] polling every %s", w.cfg.PollInterval)
	ticker := time.NewTicker(w.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.pollOnce(ctx); err != nil {
				log.Printf("[worker] poll error: %v", err)
			}
		}
	}
}

func (w *Worker) pollOnce(ctx context.Context) error {
	jobs, err := w.cf.PollJobs(w.cfg.ConnectorID)
	if err != nil {
		return fmt.Errorf("poll: %w", err)
	}

	for _, job := range jobs {
		if err := w.processJob(ctx, job); err != nil {
			log.Printf("[worker] job %s (%s) error: %v", job.ID, job.Operation, err)
			// Fail the job so CertForge surfaces the error to the operator.
			_ = w.cf.FailJob(job.ID, err.Error())
		}
	}
	return nil
}

func (w *Worker) processJob(ctx context.Context, job Job) error {
	if w.cfg.LogLevel == "debug" {
		log.Printf("[worker] processing job %s op=%s", job.ID, job.Operation)
	}

	switch job.Operation {
	case "generate_key_csr":
		return w.handleGenerateKeyCSR(ctx, job)
	case "export_key":
		return w.handleExportKey(ctx, job)
	case "delete_key":
		return w.handleDeleteKey(ctx, job)
	case "merge_certificate":
		return w.handleMergeCertificate(ctx, job)
	case "ping":
		return w.handlePing(ctx, job)
	case "list_issuers":
		return w.handleListIssuers(ctx, job)
	case "list_certs":
		return w.handleListCerts(ctx, job)
	case "issue_with_ca":
		// Runs in a goroutine — external CA issuance can take minutes.
		go func(j Job) {
			issueCtx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()
			if err := w.handleIssueWithCA(issueCtx, j); err != nil {
				log.Printf("[worker] issue_with_ca job %s failed: %v", j.ID, err)
				_ = w.cf.FailJob(j.ID, err.Error())
			}
		}(job)
		return nil
	default:
		return fmt.Errorf("unknown operation %q", job.Operation)
	}
}

// ─── operation handlers ───────────────────────────────────────────────────────

func (w *Worker) handleGenerateKeyCSR(ctx context.Context, job Job) error {
	var params GenerateKeyCSRParams
	if err := json.Unmarshal(job.Params, &params); err != nil {
		return fmt.Errorf("parse params: %w", err)
	}

	// Derive a deterministic, AKV-safe key name from the approval ID.
	certName := certNameFromApprovalID(params.ApprovalID)
	if certName == "" || certName == "cf-" {
		return fmt.Errorf("generate_key_csr: approval_id is required to derive key name")
	}

	log.Printf("[worker] generate_key_csr: creating key %q in AKV (algo=%s exportable=%v domains=%v)",
		certName, params.KeyAlgorithm, params.Exportable, params.Domains)

	csrPEM, err := w.akv.GenerateKeyCSR(ctx, certName, params)
	if err != nil {
		return fmt.Errorf("generate_key_csr: %w", err)
	}

	result := map[string]string{
		"csr_pem": string(csrPEM),
		"key_ref": certName, // stored in issued_certificates.key_store_ref
	}
	if err := w.cf.CompleteJob(job.ID, result); err != nil {
		return fmt.Errorf("complete job: %w", err)
	}

	log.Printf("[worker] generate_key_csr: key %q created, CSR returned to CertForge", certName)
	return nil
}

func (w *Worker) handleExportKey(ctx context.Context, job Job) error {
	var params struct {
		KeyRef string `json:"key_ref"`
	}
	if err := json.Unmarshal(job.Params, &params); err != nil {
		return fmt.Errorf("parse params: %w", err)
	}
	if params.KeyRef == "" {
		return fmt.Errorf("export_key: key_ref is required")
	}

	log.Printf("[worker] export_key: exporting key %q from AKV", params.KeyRef)

	keyPEM, err := w.akv.ExportKeyPEM(ctx, params.KeyRef)
	if err != nil {
		return fmt.Errorf("export_key: %w", err)
	}

	result := map[string]string{
		"key_pem": string(keyPEM),
	}
	if err := w.cf.CompleteJob(job.ID, result); err != nil {
		return fmt.Errorf("complete job: %w", err)
	}

	log.Printf("[worker] export_key: key %q exported", params.KeyRef)
	return nil
}

func (w *Worker) handleDeleteKey(ctx context.Context, job Job) error {
	var params struct {
		KeyRef string `json:"key_ref"`
	}
	if err := json.Unmarshal(job.Params, &params); err != nil {
		return fmt.Errorf("parse params: %w", err)
	}
	if params.KeyRef == "" {
		// Nothing to delete — complete silently.
		return w.cf.CompleteJob(job.ID, map[string]bool{"ok": true})
	}

	log.Printf("[worker] delete_key: deleting %q from AKV", params.KeyRef)

	if err := w.akv.DeleteCertificate(ctx, params.KeyRef); err != nil {
		return fmt.Errorf("delete_key: %w", err)
	}

	if err := w.cf.CompleteJob(job.ID, map[string]bool{"ok": true}); err != nil {
		return fmt.Errorf("complete job: %w", err)
	}

	log.Printf("[worker] delete_key: %q deleted", params.KeyRef)
	return nil
}

func (w *Worker) handleMergeCertificate(ctx context.Context, job Job) error {
	var params struct {
		KeyRef  string `json:"key_ref"`
		CertPEM string `json:"cert_pem"`
	}
	if err := json.Unmarshal(job.Params, &params); err != nil {
		return fmt.Errorf("parse params: %w", err)
	}
	if params.KeyRef == "" || params.CertPEM == "" {
		return fmt.Errorf("merge_certificate: key_ref and cert_pem are required")
	}

	log.Printf("[worker] merge_certificate: merging signed cert into AKV key %q", params.KeyRef)

	if err := w.akv.MergeCertificate(ctx, params.KeyRef, []byte(params.CertPEM)); err != nil {
		return fmt.Errorf("merge_certificate: %w", err)
	}

	if err := w.cf.CompleteJob(job.ID, map[string]bool{"ok": true}); err != nil {
		return fmt.Errorf("complete job: %w", err)
	}

	log.Printf("[worker] merge_certificate: cert merged into AKV key %q", params.KeyRef)
	return nil
}

func (w *Worker) handlePing(ctx context.Context, job Job) error {
	if err := w.akv.Ping(ctx); err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	return w.cf.CompleteJob(job.ID, map[string]bool{"ok": true})
}

func (w *Worker) handleListIssuers(ctx context.Context, job Job) error {
	issuers, err := w.akv.ListIssuers(ctx)
	if err != nil {
		return fmt.Errorf("list_issuers: %w", err)
	}
	log.Printf("[worker] list_issuers: found %d issuers", len(issuers))
	return w.cf.CompleteJob(job.ID, map[string]any{"issuers": issuers})
}

func (w *Worker) handleListCerts(ctx context.Context, job Job) error {
	certs, err := w.akv.ListCerts(ctx)
	if err != nil {
		return fmt.Errorf("list_certs: %w", err)
	}
	log.Printf("[worker] list_certs: found %d certs", len(certs))
	return w.cf.CompleteJob(job.ID, map[string]any{"certs": certs})
}

func (w *Worker) handleIssueWithCA(ctx context.Context, job Job) error {
	var params IssueWithCAParams
	if err := json.Unmarshal(job.Params, &params); err != nil {
		return fmt.Errorf("parse params: %w", err)
	}
	if params.IssuerName == "" {
		return fmt.Errorf("issue_with_ca: issuer_name is required")
	}

	certName := certNameFromApprovalID(params.ApprovalID)
	if certName == "" || certName == "cf-" {
		return fmt.Errorf("issue_with_ca: approval_id is required to derive cert name")
	}

	log.Printf("[worker] issue_with_ca: cert %q via issuer %q (domains=%v)", certName, params.IssuerName, params.Domains)

	certPEM, err := w.akv.IssueWithCA(ctx, certName, params)
	if err != nil {
		return fmt.Errorf("issue_with_ca: %w", err)
	}

	result := map[string]string{
		"cert_pem": string(certPEM),
		"key_ref":  certName,
	}
	if err := w.cf.CompleteJob(job.ID, result); err != nil {
		return fmt.Errorf("complete job: %w", err)
	}

	log.Printf("[worker] issue_with_ca: cert %q issued and returned to CertForge", certName)
	return nil
}
