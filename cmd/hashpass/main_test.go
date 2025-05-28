package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashpassCLI(t *testing.T) {
	// Build the binary
	cmd := exec.Command("go", "build", "-o", "hashpass_test", ".")
	err := cmd.Run()
	require.NoError(t, err)
	defer os.Remove("hashpass_test")

	tests := []struct {
		name        string
		args        []string
		wantErr     bool
		wantOutput  string
		wantExitCode int
	}{
		{
			name:        "No arguments",
			args:        []string{},
			wantErr:     true,
			wantOutput:  "Usage: go run cmd/hashpass/main.go <password>",
			wantExitCode: 1,
		},
		{
			name:        "Too many arguments",
			args:        []string{"password1", "password2"},
			wantErr:     true,
			wantOutput:  "Usage: go run cmd/hashpass/main.go <password>",
			wantExitCode: 1,
		},
		{
			name:        "Valid password",
			args:        []string{"testpassword123"},
			wantErr:     false,
			wantOutput:  "Password hash: ",
			wantExitCode: 0,
		},
		{
			name:        "Empty password",
			args:        []string{""},
			wantErr:     false,
			wantOutput:  "Password hash: ",
			wantExitCode: 0,
		},
		{
			name:        "Special characters password",
			args:        []string{"p@ssw0rd!#$%"},
			wantErr:     false,
			wantOutput:  "Password hash: ",
			wantExitCode: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command("./hashpass_test", tt.args...)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			
			if tt.wantErr {
				assert.Error(t, err)
				// Check exit code
				if exitErr, ok := err.(*exec.ExitError); ok {
					assert.Equal(t, tt.wantExitCode, exitErr.ExitCode())
				}
			} else {
				assert.NoError(t, err)
			}

			output := stdout.String() + stderr.String()
			assert.Contains(t, output, tt.wantOutput)

			// For successful password hashing, verify the hash format
			if !tt.wantErr && strings.Contains(output, "Password hash: ") {
				// argon2 hashes start with $argon2id$
				hash := strings.TrimPrefix(output, "Password hash: ")
				hash = strings.TrimSpace(hash)
				assert.True(t, strings.HasPrefix(hash, "$argon2id$"),
					"Hash should be in argon2id format")
				// Verify hash has reasonable length
				assert.Greater(t, len(hash), 50, "argon2id hash should be reasonably long")
			}
		})
	}
}

func TestHashpassIntegration(t *testing.T) {
	// Test that the generated hash can be verified
	cmd := exec.Command("go", "run", ".", "testpassword")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err)
	
	// Extract the hash
	outputStr := string(output)
	require.Contains(t, outputStr, "Password hash: ")
	
	hash := strings.TrimPrefix(outputStr, "Password hash: ")
	hash = strings.TrimSpace(hash)
	
	// Verify it's a valid argon2id hash by checking format
	assert.True(t, strings.HasPrefix(hash, "$argon2id$"))
	assert.Greater(t, len(hash), 50)
}