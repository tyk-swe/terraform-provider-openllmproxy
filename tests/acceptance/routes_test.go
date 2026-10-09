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

func qualifiedProviderModel(t *testing.T, client *management.Client, endpoint string) string {
	t.Helper()
	call := func(name string, paths map[string]string, etag string, body any) management.Response {
		t.Helper()
		operation, exists := management.Lookup(name)
		if !exists {
			t.Fatalf("missing generated fixture operation %s", name)
		}
		var encoded json.RawMessage
		if body != nil {
			encoded, _ = json.Marshal(body)
		}
		defer clear(encoded)
		result, err := client.Call(t.Context(), operation, management.Arguments{Path: paths, IfMatch: etag, Body: encoded})
		if err != nil {
			t.Fatalf("qualification %s: %v", name, err)
		}
		return result
	}
	created := call("create_provider", nil, "", map[string]any{"name": "Route fixture", "configuration": map[string]any{"kind": "openai_compatible", "auth_mode": "api_key", "endpoint": endpoint + "/v1"}, "credential": "provider-private-credential-one", "model": "managed-model"})
	var provider map[string]any
	if err := json.Unmarshal(created.Body, &provider); err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{"provider_id": provider["id"].(string)}
	call("probe_provider", paths, created.ETag, nil)
	models := call("list_provider_models", paths, "", nil)
	var inventory struct {
		Items []struct {
			ID   string `json:"id"`
			ETag string `json:"etag"`
		} `json:"items"`
	}
	if err := json.Unmarshal(models.Body, &inventory); err != nil || len(inventory.Items) != 1 {
		t.Fatal("fixture model inventory unavailable")
	}
	paths["model_id"] = inventory.Items[0].ID
	providerPaths := map[string]string{"provider_id": provider["id"].(string)}
	observed := call("get_provider", providerPaths, "", nil)
	call("set_provider_model", paths, observed.ETag, map[string]any{"enabled": true, "capabilities": []any{map[string]any{"operation": "generation", "surface": "openai", "mode": "unary"}, map[string]any{"operation": "generation", "surface": "openai", "mode": "streaming"}}})
	observed = call("get_provider", providerPaths, "", nil)
	call("certify_provider_model", paths, observed.ETag, nil)
	delete(paths, "model_id")
	current := call("get_provider", paths, "", nil)
	call("activate_provider", paths, current.ETag, nil)
	return inventory.Items[0].ID
}

func TestPublishedRouteLifecycleWithTerraformAndOpenTofu(t *testing.T) {
	for _, engine := range []string{"OLP_TEST_TERRAFORM_BINARY", "OLP_TEST_TOFU_BINARY"} {
		t.Run(engine, func(t *testing.T) {
			upstream := compatibleUpstream(t)
			defer upstream.Close()
			instance := newInstallation(t, "OLP_PROVIDER_EGRESS_ALLOW_CIDRS=127.0.0.0/8", "OLP_PROVIDER_EGRESS_ALLOW_HTTP_HOSTS=127.0.0.1")
			client, err := management.NewClient(instance.endpoint, instance.tokenFile)
			if err != nil {
				t.Fatal(err)
			}
			modelID := qualifiedProviderModel(t, client, upstream.URL)
			dir := t.TempDir()
			configFile := privateFile(t, dir, "cli.tfrc", `provider_installation { dev_overrides { "registry.terraform.io/tyk-swe/openllmproxy" = "`+filepath.Dir(required(t, "OLP_TEST_PROVIDER_BINARY"))+`" } direct {} }`)
			tool := required(t, engine)
			env := append(os.Environ(), "TF_CLI_CONFIG_FILE="+configFile, "OLP_MANAGEMENT_URL="+instance.endpoint, "OLP_MANAGEMENT_TOKEN_FILE="+instance.tokenFile)
			run := func(args ...string) []byte {
				t.Helper()
				command := exec.CommandContext(t.Context(), tool, args...)
				command.Dir, command.Env = dir, env
				output, err := command.CombinedOutput()
				if err != nil {
					t.Fatalf("%s: %v\n%s", args[0], err, output)
				}
				return output
			}
			projectBoundary := ""
			write := func(timeout int) {
				t.Helper()
				declaration := map[string]any{"slug": "managed-route", "operations": []string{"generation"}, "overall_timeout_ms": timeout, "max_attempts": 1, "fidelity": map[string]any{"mode": "transformed"}, "targets": []any{map[string]any{"provider_model_id": modelID, "priority": 0, "weight": 1, "timeout_ms": 2000}}}
				if projectBoundary != "" {
					declaration["project_id"] = projectBoundary
				}
				definition, _ := json.Marshal(declaration)
				configuration := map[string]any{"terraform": map[string]any{"required_providers": map[string]any{"openllmproxy": map[string]any{"source": "registry.terraform.io/tyk-swe/openllmproxy"}}}, "provider": map[string]any{"openllmproxy": map[string]any{}}, "resource": map[string]any{"openllmproxy_route": map[string]any{"test": map[string]any{"definition": string(definition)}}}}
				encoded, _ := json.Marshal(configuration)
				if err := os.WriteFile(filepath.Join(dir, "main.tf.json"), encoded, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			write(30000)
			run("plan", "-input=false", "-out=create.tfplan")
			run("apply", "-input=false", "create.tfplan")
			var state struct {
				Values struct {
					RootModule struct {
						Resources []struct {
							Values struct{ ID, ETag string }
						}
					} `json:"root_module"`
				}
			}
			if err := json.Unmarshal(run("show", "-json"), &state); err != nil || len(state.Values.RootModule.Resources) != 1 {
				t.Fatal("published resource identity unavailable")
			}
			id := state.Values.RootModule.Resources[0].Values.ID
			createProject, _ := management.Lookup("create_project")
			projectResult, err := client.Call(t.Context(), createProject, management.Arguments{Body: json.RawMessage(`{"name":"Replacement boundary"}`)})
			if err != nil {
				t.Fatal(err)
			}
			var project struct{ ID string }
			if err := json.Unmarshal(projectResult.Body, &project); err != nil {
				t.Fatal(err)
			}
			projectBoundary = project.ID
			write(30000)
			invalid := exec.CommandContext(t.Context(), tool, "plan", "-input=false")
			invalid.Dir, invalid.Env = dir, env
			invalidOutput, invalidErr := invalid.CombinedOutput()
			if invalidErr == nil || !strings.Contains(string(invalidOutput), "Invalid route replacement") {
				t.Fatalf("project transfer was not refused before destruction: %v\n%s", invalidErr, invalidOutput)
			}
			projectBoundary = ""
			write(40000)
			run("plan", "-input=false", "-out=update.tfplan")
			run("apply", "-input=false", "update.tfplan")
			run("plan", "-input=false", "-detailed-exitcode")
			run("state", "rm", "openllmproxy_route.test")
			run("import", "-input=false", "openllmproxy_route.test", id)
			run("apply", "-auto-approve", "-input=false")
			run("plan", "-input=false", "-detailed-exitcode")
			write(45000)
			run("plan", "-input=false", "-out=stale.tfplan")
			read, _ := management.Lookup("get_route")
			current, err := client.Call(t.Context(), read, management.Arguments{Path: map[string]string{"route_id": id}})
			if err != nil {
				t.Fatal(err)
			}
			update, _ := management.Lookup("update_route")
			changed, _ := json.Marshal(map[string]any{"slug": "managed-route", "operations": []string{"generation"}, "overall_timeout_ms": 50000, "max_attempts": 1, "fidelity": map[string]any{"mode": "transformed"}, "targets": []any{map[string]any{"provider_model_id": modelID, "priority": 0, "weight": 1, "timeout_ms": 2000}}})
			if _, err = client.Call(t.Context(), update, management.Arguments{Path: map[string]string{"route_id": id}, IfMatch: current.ETag, Body: changed}); err != nil {
				t.Fatal(err)
			}
			stale := exec.CommandContext(t.Context(), tool, "apply", "-input=false", "stale.tfplan")
			stale.Dir, stale.Env = dir, env
			output, applyErr := stale.CombinedOutput()
			if applyErr == nil || (!strings.Contains(string(output), "412") && !strings.Contains(string(output), "Resource changed while planning")) {
				t.Fatalf("stale publication plan was accepted: %v\n%s", applyErr, output)
			}
			current, err = client.Call(t.Context(), read, management.Arguments{Path: map[string]string{"route_id": id}})
			if err != nil || !strings.Contains(string(current.Body), `"overall_timeout_ms":50000`) {
				t.Fatal("stale plan overwrote an external publication")
			}
			run("destroy", "-auto-approve", "-input=false")
			result, err := client.Call(t.Context(), read, management.Arguments{Path: map[string]string{"route_id": id}})
			var retired struct {
				State         string
				RevisionCount int `json:"revision_count"`
			}
			decodeErr := json.Unmarshal(result.Body, &retired)
			if err != nil || decodeErr != nil || retired.State != "retired" || retired.RevisionCount < 2 {
				t.Fatalf("destruction lost retirement/history: %v %s", err, result.Body)
			}
		})
	}
}
