package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ramaadi/keevault/apps/env-client/internal/run"
)

// projectConfig contains only shareable settings. Credentials stay outside it.
type projectConfig struct {
	VaultURL        string   `json:"vaultUrl"`
	EnvironmentID   string   `json:"environmentId"`
	RequiredSecrets []string `json:"requiredSecrets"`
	Command         []string `json:"command"`
}

func loadProjectConfig(path string) (projectConfig, error) {
	var config projectConfig
	if path == "" {
		path = "keevault.json"
	}
	file, err := os.Open(path)
	if err != nil {
		return config, fmt.Errorf("configuration file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return config, fmt.Errorf("configuration file: %w", err)
	}
	if info.Size() > 1024*1024 {
		return config, fmt.Errorf("configuration file exceeds 1 MiB")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 1024*1024+1))
	decoder.DisallowUnknownFields()
	var value *projectConfig
	if err := decoder.Decode(&value); err != nil {
		return config, fmt.Errorf("configuration file: %w", err)
	}
	if value == nil {
		return config, fmt.Errorf("configuration file must be a JSON object")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return config, fmt.Errorf("configuration file must contain exactly one JSON object")
	}
	config = *value
	if strings.TrimSpace(config.EnvironmentID) != config.EnvironmentID || strings.ContainsRune(config.EnvironmentID, '\x00') {
		return config, fmt.Errorf("environmentId must not contain surrounding whitespace or NUL")
	}
	if len(config.Command) == 0 || strings.TrimSpace(config.Command[0]) == "" {
		return config, fmt.Errorf("command must be a nonempty argv array")
	}
	for _, arg := range config.Command {
		if strings.ContainsRune(arg, '\x00') {
			return config, fmt.Errorf("command arguments must not contain NUL")
		}
	}
	seen := map[string]bool{}
	for _, name := range config.RequiredSecrets {
		if !run.ValidName(name) || seen[name] {
			return config, fmt.Errorf("requiredSecrets must contain unique valid environment variable names")
		}
		seen[name] = true
	}
	return config, nil
}
