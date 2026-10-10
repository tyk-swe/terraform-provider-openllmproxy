//go:build integration

package acceptance

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyk-swe/olp/sdk/management"
)

func TestKeyLifecycleAndPrivateOneTimeOutput(t *testing.T) {
	for _, name := range []string{"OLP_TEST_TERRAFORM_BINARY", "OLP_TEST_TOFU_BINARY"} {
		t.Run(name, func(t *testing.T) {
			instance := newInstallation(t)
			dir := t.TempDir()
			tool := required(t, name)
			configFile := privateFile(t, dir, "cli.tfrc", `provider_installation { dev_overrides { "registry.terraform.io/tyk-swe/openllmproxy" = "`+filepath.Dir(required(t, "OLP_TEST_PROVIDER_BINARY"))+`" } direct {} }`)
			env := append(os.Environ(), "TF_CLI_CONFIG_FILE="+configFile, "OLP_MANAGEMENT_URL="+instance.endpoint, "OLP_MANAGEMENT_TOKEN_FILE="+instance.tokenFile, "TF_IN_AUTOMATION=1")
			run := func(arguments ...string) []byte {
				t.Helper()
				command := exec.CommandContext(t.Context(), tool, arguments...)
				command.Dir = dir
				command.Env = env
				output, err := command.CombinedOutput()
				if err != nil {
					t.Fatalf("%s %v: %v\n%s", name, arguments, err, output)
				}
				return output
			}
			secretPath := filepath.Join(dir, "client.key")
			write := func(keyName, limit string, capture bool) {
				t.Helper()
				definition, _ := json.Marshal(map[string]any{"name": keyName, "daily_cost_limit": limit, "scopes": []string{"models_read"}, "requests_per_minute": 10})
				key := map[string]any{"definition": string(definition)}
				if capture {
					key["secret_file"] = secretPath
				}
				configuration := map[string]any{"terraform": map[string]any{"required_providers": map[string]any{"openllmproxy": map[string]string{"source": "registry.terraform.io/tyk-swe/openllmproxy"}}}, "provider": map[string]any{"openllmproxy": map[string]any{}}, "resource": map[string]any{"openllmproxy_key": map[string]any{"test": key}}}
				encoded, _ := json.Marshal(configuration)
				if err := os.WriteFile(filepath.Join(dir, "main.tf.json"), encoded, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			write("Managed key", "10", true)
			run("plan", "-input=false", "-out=create.tfplan")
			run("apply", "-input=false", "create.tfplan")
			secret, err := os.ReadFile(secretPath)
			if err != nil || !strings.HasPrefix(string(secret), "olp_") {
				t.Fatal("one-time key was not captured in its private destination")
			}
			info, err := os.Stat(secretPath)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatal("captured key output is not owner-only")
			}
			stateJSON := run("show", "-json")
			if strings.Contains(string(stateJSON), strings.TrimSpace(string(secret))) {
				t.Fatal("generated API key entered Terraform state")
			}
			clear(secret)
			var state struct {
				Values struct {
					RootModule struct {
						Resources []struct {
							Values struct {
								ID string `json:"id"`
							} `json:"values"`
						} `json:"resources"`
					} `json:"root_module"`
				} `json:"values"`
			}
			if json.Unmarshal(stateJSON, &state) != nil || len(state.Values.RootModule.Resources) != 1 {
				t.Fatal("key identity missing from state")
			}
			id := state.Values.RootModule.Resources[0].Values.ID
			write("Updated key", "20", true)
			run("apply", "-auto-approve", "-input=false")
			run("plan", "-input=false", "-detailed-exitcode")
			// Imported metadata cannot recover a one-time secret. Remove the
			// creation-only output choice before adopting an existing key.
			write("Updated key", "20", false)
			run("state", "rm", "openllmproxy_key.test")
			run("import", "-input=false", "openllmproxy_key.test", id)
			run("apply", "-auto-approve", "-input=false")
			run("plan", "-input=false", "-detailed-exitcode")
			run("destroy", "-auto-approve", "-input=false")
			client, err := management.NewClient(instance.endpoint, instance.tokenFile)
			if err != nil {
				t.Fatal(err)
			}
			read, _ := management.Lookup("get_api_key")
			result, err := client.Call(t.Context(), read, management.Arguments{Path: map[string]string{"api_key_id": id}})
			var key map[string]json.RawMessage
			if err != nil || json.Unmarshal(result.Body, &key) != nil || string(key["revoked_at"]) == "null" {
				t.Fatal("destroy did not revoke the retained key authority")
			}

			// A local output failure must retain the created UUID in state;
			// otherwise retrying would orphan an active key on every attempt.
			secretPath = dir
			write("Capture failure", "20", true)
			command := exec.CommandContext(t.Context(), tool, "apply", "-auto-approve", "-input=false")
			command.Dir = dir
			command.Env = env
			failed, applyErr := command.CombinedOutput()
			if applyErr == nil || !strings.Contains(string(failed), "Cannot capture API key") {
				t.Fatal("expected a private-output failure")
			}
			if json.Unmarshal(run("show", "-json"), &state) != nil || len(state.Values.RootModule.Resources) != 1 || state.Values.RootModule.Resources[0].Values.ID == "" {
				t.Fatal("output failure orphaned the created key identity")
			}
			run("destroy", "-auto-approve", "-input=false")
		})
	}
}
