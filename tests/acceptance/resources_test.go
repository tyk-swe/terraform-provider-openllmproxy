//go:build integration

package acceptance

import (
	"encoding/json"
	"fmt"
	"github.com/tyk-swe/olp/sdk/management"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBudgetAndNotificationLifecyclesWithWriteOnlySecrets(t *testing.T) {
	for _, name := range []string{"OLP_TEST_TERRAFORM_BINARY", "OLP_TEST_TOFU_BINARY"} {
		t.Run(name, func(t *testing.T) {
			instance := newInstallation(t)
			tool := required(t, name)
			dir := t.TempDir()
			configFile := privateFile(t, dir, "cli.tfrc", `provider_installation { dev_overrides { "registry.terraform.io/tyk-swe/openllmproxy" = "`+filepath.Dir(required(t, "OLP_TEST_PROVIDER_BINARY"))+`" } direct {} }`)
			privateValue := "ephemeral-private-signature-one"
			run := func(arguments ...string) []byte {
				t.Helper()
				command := exec.CommandContext(t.Context(), tool, arguments...)
				command.Dir = dir
				command.Env = append(os.Environ(), "TF_CLI_CONFIG_FILE="+configFile, "OLP_MANAGEMENT_URL="+instance.endpoint, "OLP_MANAGEMENT_TOKEN_FILE="+instance.tokenFile, "TF_VAR_signing_secret="+privateValue, "TF_IN_AUTOMATION=1")
				output, err := command.CombinedOutput()
				if err != nil {
					t.Fatalf("%s %v: %v\n%s", name, arguments, err, strings.ReplaceAll(string(output), privateValue, "[redacted]"))
				}
				return output
			}
			write := func(phase int) {
				t.Helper()
				suffix, limit, threshold := "Initial", "10", 80
				if phase >= 2 {
					suffix, limit, threshold = "Updated", "20", 90
				}
				definition := func(fields map[string]any) string { encoded, _ := json.Marshal(fields); return string(encoded) }
				project := "${openllmproxy_project.test.id}"
				budget := map[string]any{"name": suffix + " budget", "project_id": project, "monthly_cost_limit": limit}
				if phase == 3 {
					delete(budget, "monthly_cost_limit")
					budget["daily_cost_limit"] = "25"
				}
				configuration := map[string]any{
					"terraform": map[string]any{"required_providers": map[string]any{"openllmproxy": map[string]string{"source": "registry.terraform.io/tyk-swe/openllmproxy"}}},
					"provider":  map[string]any{"openllmproxy": map[string]any{}},
					"variable":  map[string]any{"signing_secret": map[string]any{"type": "string", "sensitive": true, "ephemeral": true}},
					"resource": map[string]any{
						"openllmproxy_project":                  map[string]any{"test": map[string]any{"definition": definition(map[string]any{"name": "Acceptance project"})}},
						"openllmproxy_budget_group":             map[string]any{"test": map[string]any{"definition": definition(budget)}},
						"openllmproxy_notification_destination": map[string]any{"test": map[string]any{"definition": definition(map[string]any{"name": suffix + " destination", "project_id": project, "url": "https://notifications.example.com/hooks", "enabled": false}), "secret": "${var.signing_secret}", "secret_version": phase}},
						"openllmproxy_notification_rule":        map[string]any{"test": map[string]any{"definition": definition(map[string]any{"name": suffix + " rule", "project_id": project, "event": "budget.threshold", "subject_kind": "budget_group", "subject_id": "${openllmproxy_budget_group.test.id}", "window_kind": "month", "threshold_percent": threshold, "destination_id": "${openllmproxy_notification_destination.test.id}", "enabled": false})}},
					},
				}
				encoded, _ := json.Marshal(configuration)
				if err := os.WriteFile(filepath.Join(dir, "main.tf.json"), encoded, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			write(1)
			run("plan", "-input=false", "-out=create.tfplan")
			plan := run("show", "-json", "create.tfplan")
			if strings.Contains(string(plan), privateValue) {
				t.Fatal("ephemeral write-only signing secret appeared in saved plan")
			}
			run("apply", "-input=false", "create.tfplan")
			privateValue = "ephemeral-private-signature-two"
			write(2)
			run("plan", "-input=false", "-out=update.tfplan")
			run("apply", "-input=false", "update.tfplan")
			stateJSON := run("show", "-json")
			if strings.Contains(string(stateJSON), privateValue) || strings.Contains(string(stateJSON), "ephemeral-private-signature-one") {
				t.Fatal("write-only signing value appeared in resource state")
			}
			var state struct {
				Values struct {
					RootModule struct {
						Resources []struct {
							Address string `json:"address"`
							Values  struct {
								ID string `json:"id"`
							} `json:"values"`
						} `json:"resources"`
					} `json:"root_module"`
				} `json:"values"`
			}
			if err := json.Unmarshal(stateJSON, &state); err != nil {
				t.Fatal(err)
			}
			if len(state.Values.RootModule.Resources) != 4 {
				t.Fatal("missing created resource")
			}
			for _, resource := range state.Values.RootModule.Resources {
				run("state", "rm", resource.Address)
				run("import", "-input=false", resource.Address, resource.Values.ID)
			}
			// Import discovers the server's definition. Apply adopts the chosen JSON
			// fields/counter, then a second plan must be empty rather than loop on
			// PostgreSQL's fixed monetary scale or immutable project placement.
			run("apply", "-auto-approve", "-input=false")
			run("plan", "-input=false", "-detailed-exitcode")
			write(3)
			run("apply", "-auto-approve", "-input=false")
			client, err := management.NewClient(instance.endpoint, instance.tokenFile)
			if err != nil {
				t.Fatal(err)
			}
			read, _ := management.Lookup("get_budget_group")
			for _, resource := range state.Values.RootModule.Resources {
				if resource.Address != "openllmproxy_budget_group.test" {
					continue
				}
				result, err := client.Call(t.Context(), read, management.Arguments{Path: map[string]string{"budget_group_id": resource.Values.ID}})
				var group map[string]json.RawMessage
				if err != nil || json.Unmarshal(result.Body, &group) != nil || string(group["monthly_cost_limit"]) != "null" {
					t.Fatal("removed monthly ceiling still limits the remotely managed budget")
				}
			}
			run("destroy", "-auto-approve", "-input=false")
			for _, resource := range state.Values.RootModule.Resources {
				if resource.Values.ID == "" {
					t.Fatal(fmt.Sprintf("missing imported identity for %s", resource.Address))
				}
			}
		})
	}
}
