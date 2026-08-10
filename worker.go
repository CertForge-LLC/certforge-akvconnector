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
	case "ping":
		return w.handlePing(ctx, job)
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

func (w *Worker) handlePing(ctx context.Context, job Job) error {
	if err := w.akv.Ping(ctx); err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	return w.cf.CompleteJob(job.ID, map[string]bool{"ok": true})
}
