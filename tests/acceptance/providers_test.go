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

func TestProviderAndCredentialSlotLifecyclesWithWriteOnlyRotation(t *testing.T) {
	for _, engine := range []string{"OLP_TEST_TERRAFORM_BINARY", "OLP_TEST_TOFU_BINARY"} {
		t.Run(engine, func(t *testing.T) {
			privateValue := "provider-private-credential-one"
			upstream := compatibleUpstream(t)
			defer upstream.Close()
			instance := newInstallation(t, "OLP_PROVIDER_EGRESS_ALLOW_CIDRS=127.0.0.0/8", "OLP_PROVIDER_EGRESS_ALLOW_HTTP_HOSTS=127.0.0.1")
			dir := t.TempDir()
			configFile := privateFile(t, dir, "cli.tfrc", `provider_installation { dev_overrides { "registry.terraform.io/tyk-swe/openllmproxy" = "`+filepath.Dir(required(t, "OLP_TEST_PROVIDER_BINARY"))+`" } direct {} }`)
			run := func(arguments ...string) []byte {
				t.Helper()
				command := exec.CommandContext(t.Context(), required(t, engine), arguments...)
				command.Dir = dir
				command.Env = append(os.Environ(), "TF_CLI_CONFIG_FILE="+configFile, "OLP_MANAGEMENT_URL="+instance.endpoint, "OLP_MANAGEMENT_TOKEN_FILE="+instance.tokenFile, "TF_VAR_credential="+privateValue, "TF_IN_AUTOMATION=1")
				output, err := command.CombinedOutput()
				if err != nil {
					t.Fatalf("%s %v: %v\n%s", engine, arguments, err, strings.ReplaceAll(string(output), privateValue, "[redacted]"))
				}
				return output
			}
			write := func(phase int) {
				t.Helper()
				definition := func(fields map[string]any) string { b, _ := json.Marshal(fields); return string(b) }
				name, limit := "Initial", "10"
				if phase > 1 {
					name, limit = "Updated", "20"
				}
				if phase == 3 {
					name = "Retained after invalid credential"
				}
				configuration := map[string]any{
					"terraform": map[string]any{"required_providers": map[string]any{"openllmproxy": map[string]string{"source": "registry.terraform.io/tyk-swe/openllmproxy"}}},
					"provider":  map[string]any{"openllmproxy": map[string]any{}},
					"variable":  map[string]any{"credential": map[string]any{"type": "string", "sensitive": true, "ephemeral": true}},
					"resource": map[string]any{
						"openllmproxy_provider":        map[string]any{"test": map[string]any{"definition": definition(map[string]any{"name": name + " provider", "configuration": map[string]any{"kind": "openai_compatible", "auth_mode": "api_key", "endpoint": upstream.URL + "/v1", "options": map[string]any{"parameter_defaults": map[string]any{}}}, "model": "managed-model"}), "secret": "${var.credential}", "secret_version": phase}},
						"openllmproxy_credential_slot": map[string]any{},
					},
				}
				resources := configuration["resource"].(map[string]any)
				for _, slot := range []string{"first", "second"} {
					resources["openllmproxy_credential_slot"].(map[string]any)[slot] = map[string]any{"provider_id": "${openllmproxy_provider.test.id}", "definition": definition(map[string]any{"name": name + " " + slot, "priority": 0, "weight": 1, "daily_cost_limit": limit}), "secret": "${var.credential}", "secret_version": phase}
				}
				b, _ := json.Marshal(configuration)
				if err := os.WriteFile(filepath.Join(dir, "main.tf.json"), b, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			assertPrivate := func(data []byte) {
				t.Helper()
				for _, secret := range []string{"provider-private-credential-one", "provider-private-credential-two"} {
					if strings.Contains(string(data), secret) {
						t.Fatal("write-only provider/slot credential entered plan or state")
					}
				}
			}
			write(1)
			run("plan", "-input=false", "-out=create.tfplan")
			assertPrivate(run("show", "-json", "create.tfplan"))
			run("apply", "-input=false", "create.tfplan")
			run("plan", "-input=false", "-detailed-exitcode")
			privateValue = "provider-private-credential-two"
			write(2)
			run("plan", "-input=false", "-out=update.tfplan")
			assertPrivate(run("show", "-json", "update.tfplan"))
			run("apply", "-input=false", "update.tfplan")
			stateJSON := run("show", "-json")
			assertPrivate(stateJSON)
			var state struct {
				Values struct {
					RootModule struct {
						Resources []struct {
							Address string `json:"address"`
							Values  struct {
								ID         string `json:"id"`
								ProviderID string `json:"provider_id"`
							} `json:"values"`
						} `json:"resources"`
					} `json:"root_module"`
				} `json:"values"`
			}
			if json.Unmarshal(stateJSON, &state) != nil || len(state.Values.RootModule.Resources) != 3 {
				t.Fatal("missing provider or independent slots")
			}
			client, err := management.NewClient(instance.endpoint, instance.tokenFile)
			if err != nil {
				t.Fatal(err)
			}
			operation, _ := management.Lookup("get_provider")
			for _, item := range state.Values.RootModule.Resources {
				if item.Address == "openllmproxy_provider.test" {
					result, err := client.Call(t.Context(), operation, management.Arguments{Path: map[string]string{"provider_id": item.Values.ID}})
					var remote struct {
						Version int `json:"draft_credential_version"`
					}
					if err != nil || json.Unmarshal(result.Body, &remote) != nil || remote.Version < 2 {
						t.Fatal("replacement provider credential was not validated and staged")
					}
				}
			}
			// A configuration write can commit before credential validation fails.
			// Retain that public change and the prior successful secret counter.
			privateValue = "unusable-provider-private-credential"
			write(3)
			failed := exec.CommandContext(t.Context(), required(t, engine), "apply", "-auto-approve", "-input=false")
			failed.Dir = dir
			failed.Env = append(os.Environ(), "TF_CLI_CONFIG_FILE="+configFile, "OLP_MANAGEMENT_URL="+instance.endpoint, "OLP_MANAGEMENT_TOKEN_FILE="+instance.tokenFile, "TF_VAR_credential="+privateValue, "TF_IN_AUTOMATION=1")
			failedOutput, failedError := failed.CombinedOutput()
			if failedError == nil || !strings.Contains(string(failedOutput), "Credential validation failed") {
				t.Fatalf("invalid credential was accepted: %v\n%s", failedError, strings.ReplaceAll(string(failedOutput), privateValue, "[redacted]"))
			}
			partial := run("show", "-json")
			if strings.Contains(string(partial), privateValue) {
				t.Fatal("failed write-only credential entered state")
			}
			var partialState struct {
				Values struct {
					RootModule struct {
						Resources []struct {
							Address string `json:"address"`
							Values  struct {
								Definition string `json:"definition"`
								Version    int    `json:"secret_version"`
							} `json:"values"`
						} `json:"resources"`
					} `json:"root_module"`
				} `json:"values"`
			}
			if json.Unmarshal(partial, &partialState) != nil {
				t.Fatal("invalid partial state")
			}
			for _, item := range partialState.Values.RootModule.Resources {
				if item.Address == "openllmproxy_provider.test" && (item.Values.Version != 2 || !strings.Contains(item.Values.Definition, "Retained after invalid credential")) {
					t.Fatal("committed configuration or prior secret counter was lost")
				}
			}
			privateValue = "provider-private-credential-two"
			run("apply", "-auto-approve", "-input=false")
			for _, item := range state.Values.RootModule.Resources {
				id := item.Values.ID
				if item.Values.ProviderID != "" {
					id = item.Values.ProviderID + "/" + id
				}
				run("state", "rm", item.Address)
				run("import", "-input=false", item.Address, id)
			}
			// Seed fields describe creation rather than mutable inventory. Omit them
			// when adopting an existing provider, whose inventory remains untouched.
			configBytes, _ := os.ReadFile(filepath.Join(dir, "main.tf.json"))
			var configuration map[string]any
			json.Unmarshal(configBytes, &configuration)
			provider := configuration["resource"].(map[string]any)["openllmproxy_provider"].(map[string]any)["test"].(map[string]any)
			var definition map[string]any
			json.Unmarshal([]byte(provider["definition"].(string)), &definition)
			delete(definition, "model")
			b, _ := json.Marshal(definition)
			provider["definition"] = string(b)
			b, _ = json.Marshal(configuration)
			os.WriteFile(filepath.Join(dir, "main.tf.json"), b, 0o600)
			run("apply", "-auto-approve", "-input=false")
			run("plan", "-input=false", "-detailed-exitcode")
			// A saved destruction plan must retain a provider edited by someone
			// else, even when this apply legitimately removes its own slots.
			run("plan", "-destroy", "-input=false", "-out=destroy.tfplan")
			var providerID string
			for _, item := range state.Values.RootModule.Resources {
				if item.Address == "openllmproxy_provider.test" {
					providerID = item.Values.ID
				}
			}
			current, err := client.Call(t.Context(), operation, management.Arguments{Path: map[string]string{"provider_id": providerID}})
			if err != nil {
				t.Fatal(err)
			}
			var remote map[string]json.RawMessage
			json.Unmarshal(current.Body, &remote)
			patch, _ := json.Marshal(map[string]any{"name": "External protected edit", "configuration": remote["configuration"]})
			update, _ := management.Lookup("update_provider")
			if _, err = client.Call(t.Context(), update, management.Arguments{Path: map[string]string{"provider_id": providerID}, IfMatch: current.ETag, Body: patch}); err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(t.Context(), required(t, engine), "apply", "-input=false", "destroy.tfplan")
			command.Dir = dir
			command.Env = append(os.Environ(), "TF_CLI_CONFIG_FILE="+configFile, "OLP_MANAGEMENT_URL="+instance.endpoint, "OLP_MANAGEMENT_TOKEN_FILE="+instance.tokenFile, "TF_VAR_credential="+privateValue, "TF_IN_AUTOMATION=1")
			output, err := command.CombinedOutput()
			if err == nil || (!strings.Contains(string(output), "412") && !strings.Contains(string(output), "Resource changed while planning")) {
				t.Fatalf("external edit was not protected: %v\n%s", err, strings.ReplaceAll(string(output), privateValue, "[redacted]"))
			}
			current, err = client.Call(t.Context(), operation, management.Arguments{Path: map[string]string{"provider_id": providerID}})
			if err != nil || !strings.Contains(string(current.Body), "External protected edit") {
				t.Fatal("child changes authorized destruction of an externally edited provider")
			}
			run("destroy", "-auto-approve", "-input=false")
		})
	}
}
