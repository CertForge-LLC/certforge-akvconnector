package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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

// Job is a pending keystore operation delivered by the CertForge API.
type Job struct {
	ID        string          `json:"id"`
	Operation string          `json:"operation"`
	Params    json.RawMessage `json:"params"`
}

// PollJobs fetches pending keystore jobs for this connector.
// The X-Connector-Version header is included on every poll so CertForge can
// display the connector version without requiring a manual ping.
func (c *certForgeClient) PollJobs(connectorID string) ([]Job, error) {
	url := fmt.Sprintf("%s/api/v1/connector/keystore/jobs?connector_id=%s", c.baseURL, connectorID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
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
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
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
