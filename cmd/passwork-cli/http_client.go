package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var apiHTTPClient = &http.Client{
	Timeout: 15 * time.Second,
}

func configureHTTPClient(noSSLVerify bool) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{}
	}
	tr.TLSClientConfig.InsecureSkipVerify = noSSLVerify
	apiHTTPClient.Transport = tr
}

func joinAPIURL(baseURL, endpoint string) string {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if endpoint == "" {
		return base
	}
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}
	return base + endpoint
}

func doAPIRequest(method, baseURL, endpoint, accessToken, mph string, body []byte) (int, string, error) {
	url := joinAPIURL(baseURL, endpoint)
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return 0, "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("X-Response-Format", "raw")
	req.Header.Set("Accept", "application/json")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if mph != "" {
		req.Header.Set("Passwork-MasterKeyHash", mph)
	}
	resp, err := apiHTTPClient.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", fmt.Errorf("read response: %w", err)
	}
	return resp.StatusCode, string(respBody), nil
}

func apiErrorMessage(body string) string {
	var out struct {
		Errors []struct {
			Message string `json:"message"`
			Code    string `json:"code"`
		} `json:"errors"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || len(out.Errors) == 0 {
		if len(body) > 200 {
			return body[:200] + "..."
		}
		return body
	}
	e := out.Errors[0]
	if e.Code != "" {
		return e.Message + " (" + e.Code + ")"
	}
	return e.Message
}
