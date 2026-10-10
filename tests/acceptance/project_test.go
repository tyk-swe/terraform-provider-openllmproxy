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

func TestProjectLifecycleWithTerraformAndOpenTofu(t *testing.T) {
	for _, name := range []string{"OLP_TEST_TERRAFORM_BINARY", "OLP_TEST_TOFU_BINARY"} {
		t.Run(name, func(t *testing.T) {
			instance := newInstallation(t)
			tool := required(t, name)
			providerBinary := required(t, "OLP_TEST_PROVIDER_BINARY")
			dir := t.TempDir()
			configFile := privateFile(t, dir, "cli.tfrc", `provider_installation { dev_overrides { "registry.terraform.io/tyk-swe/openllmproxy" = "`+filepath.Dir(providerBinary)+`" } direct {} }`)
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
			write := func(projectName string) {
				t.Helper()
				configuration := map[string]any{"terraform": map[string]any{"required_providers": map[string]any{"openllmproxy": map[string]string{"source": "registry.terraform.io/tyk-swe/openllmproxy"}}}, "provider": map[string]any{"openllmproxy": map[string]any{}}, "resource": map[string]any{"openllmproxy_project": map[string]any{"test": map[string]string{"definition": `{"name":"` + projectName + `"}`}}}}
				encoded, _ := json.Marshal(configuration)
				if err := os.WriteFile(filepath.Join(dir, "main.tf.json"), encoded, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			write("Terraform project")
			run("plan", "-input=false", "-out=create.tfplan")
			run("apply", "-input=false", "create.tfplan")
			var state struct {
				Values struct {
					RootModule struct {
						Resources []struct {
							Values struct {
								ID   string `json:"id"`
								ETag string `json:"etag"`
							} `json:"values"`
						} `json:"resources"`
					} `json:"root_module"`
				} `json:"values"`
			}
			if err := json.Unmarshal(run("show", "-json"), &state); err != nil {
				t.Fatal(err)
			}
			if len(state.Values.RootModule.Resources) != 1 || state.Values.RootModule.Resources[0].Values.ID == "" || state.Values.RootModule.Resources[0].Values.ETag == "" {
				t.Fatal("creation did not preserve resource identity and observed ETag")
			}
			id := state.Values.RootModule.Resources[0].Values.ID
			write("Renamed Terraform project")
			run("plan", "-input=false", "-out=update.tfplan")
			run("apply", "-input=false", "update.tfplan")
			run("state", "rm", "openllmproxy_project.test")
			run("import", "-input=false", "openllmproxy_project.test", id)
			run("plan", "-input=false", "-detailed-exitcode")
			// Applying an already reviewed plan must not overwrite an external
			// edit committed after that plan observed the resource ETag.
			write("Reviewed project change")
			run("plan", "-input=false", "-out=stale.tfplan")
			client, err := management.NewClient(instance.endpoint, instance.tokenFile)
			if err != nil {
				t.Fatal(err)
			}
			read, _ := management.Lookup("get_project")
			current, err := client.Call(t.Context(), read, management.Arguments{Path: map[string]string{"project_id": id}})
			if err != nil {
				t.Fatal(err)
			}
			update, _ := management.Lookup("update_project")
			if _, err = client.Call(t.Context(), update, management.Arguments{Path: map[string]string{"project_id": id}, IfMatch: current.ETag, Body: json.RawMessage(`{"name":"Concurrent external change"}`)}); err != nil {
				t.Fatal(err)
			}
			apply := exec.CommandContext(t.Context(), tool, "apply", "-input=false", "stale.tfplan")
			apply.Dir = dir
			apply.Env = env
			output, err := apply.CombinedOutput()
			if err == nil || (!strings.Contains(string(output), "412") && !strings.Contains(string(output), "Resource changed while planning")) {
				t.Fatalf("stale plan was not rejected by its observed ETag: %v\n%s", err, output)
			}
			current, err = client.Call(t.Context(), read, management.Arguments{Path: map[string]string{"project_id": id}})
			if err != nil || !strings.Contains(string(current.Body), "Concurrent external change") {
				t.Fatal("stale plan overwrote the external update")
			}
			run("destroy", "-auto-approve", "-input=false")
		})
	}
}
