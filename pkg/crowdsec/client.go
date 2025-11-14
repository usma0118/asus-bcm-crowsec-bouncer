package crowdsec

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

type Decision struct {
	IP       string
	Duration string
	Scenario string
}

type rawDecision struct {
	Value    string `json:"value"`
	Duration string `json:"duration"`
	Scenario string `json:"scenario"`
}

type Client struct {
	baseURL string
	apiKey  string
	client  *http.Client
	log     *zap.Logger
}

func NewClient(baseURL, apiKey string, insecure bool, log *zap.Logger) *Client {
	tr := &http.Transport{}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: tr,
		},
		log: log,
	}
}

func (c *Client) ListIPv4Bans(ctx context.Context) ([]Decision, error) {
	url := c.baseURL + "/v1/decisions?type=ban&scope=Ip"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, errors.New(string(b))
	}

	var raw []rawDecision
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}

	out := make([]Decision, 0, len(raw))
	for _, r := range raw {
		ip := strings.TrimSpace(r.Value)
		if ip == "" {
			continue
		}
		// IPv6 skip
		if strings.Contains(ip, ":") {
			continue
		}
		dur := strings.TrimSpace(r.Duration)
		if dur == "" {
			dur = "0"
		}
		sc := strings.TrimSpace(r.Scenario)
		if sc == "" {
			sc = "unknown"
		}
		out = append(out, Decision{
			IP:       ip,
			Duration: dur,
			Scenario: sc,
		})
	}

	return out, nil
}
