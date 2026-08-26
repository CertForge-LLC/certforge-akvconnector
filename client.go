package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// certForgeClient calls the CertForge keystore job API.
type certForgeClient struct {
	baseURL string
	apiKey  string
	version string // reported to CertForge on every poll via X-Connector-Version header
	http    *http.Client
}

func newCertForgeClient(baseURL, apiKey, version string) *certForgeClient {
	return &certForgeClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		version: version,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// newCertForgeClientMTLS creates a client that authenticates via mTLS client cert
// instead of a Bearer token. It connects directly to the mTLS port (bypassing
// Cloudflare) and pins the server certificate so no system trust store is needed.
//
// certFile, keyFile, and caFile are paths to PEM files written by "enroll".
func newCertForgeClientMTLS(baseURL, version, certFile, keyFile, caFile string) (*certForgeClient, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read mTLS cert %s: %w", certFile, err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read mTLS key %s: %w", keyFile, err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read mTLS server cert %s: %w", caFile, err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse mTLS client cert/key: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse mTLS server cert for pinning: no PEM block found")
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
			MinVersion:   tls.VersionTLS12,
		},
	}
	return &certForgeClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  "", // no bearer token — mTLS cert is the credential
		version: version,
		http:    &http.Client{Timeout: 30 * time.Second, Transport: transport},
	}, nil
}

// Job is a pending keystore operation delivered by the CertForge API.
type Job struct {
	ID        string          `json:"id"`
	Operation string          `json:"operation"`
	Params    json.RawMessage `json:"params"`
}

// PollJobs fetches pending keystore jobs for this connector.
// The X-Connector-Version header is included on every poll so CertForge can
// display the connector version without requiring a manual ping.
// pollInterval is sent as poll_interval_seconds so the server can display the
// configured poll cadence in the Agent Registry.
func (c *certForgeClient) PollJobs(connectorID string, pollInterval time.Duration) ([]Job, error) {
	secs := int(pollInterval.Seconds())
	if secs < 1 {
		secs = 1
	}
	url := fmt.Sprintf("%s/api/v1/connector/keystore/jobs?connector_id=%s&poll_interval_seconds=%d", c.baseURL, connectorID, secs)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	if c.version != "" {
		req.Header.Set("X-Connector-Version", c.version)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("poll: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("poll: API key rejected or connector disabled (403)")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("poll: unexpected %d: %s", resp.StatusCode, body)
	}

	var out struct {
		Jobs []Job `json:"jobs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("poll decode: %w", err)
	}
	return out.Jobs, nil
}

// CompleteJob marks a job as completed with the given result payload.
func (c *certForgeClient) CompleteJob(jobID string, result any) error {
	body, err := json.Marshal(map[string]any{"result": result})
	if err != nil {
		return err
	}
	return c.postJob(jobID, "complete", body)
}

// FailJob marks a job as failed with a human-readable error message.
func (c *certForgeClient) FailJob(jobID, errMsg string) error {
	body, err := json.Marshal(map[string]string{"error": errMsg})
	if err != nil {
		return err
	}
	return c.postJob(jobID, "fail", body)
}

func (c *certForgeClient) postJob(jobID, action string, body []byte) error {
	url := fmt.Sprintf("%s/api/v1/connector/keystore/jobs/%s/%s", c.baseURL, jobID, action)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s job %s: %w", action, jobID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s job %s: %d %s", action, jobID, resp.StatusCode, b)
	}
	log.Printf("[client] job %s %sd", jobID, action)
	return nil
}
