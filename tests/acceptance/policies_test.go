//go:build integration

package acceptance

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tyk-swe/olp/sdk/management"
)

func TestRoutingPolicyLifecyclesWithTerraformAndOpenTofu(t *testing.T) {
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
			createDraft, _ := management.Lookup("create_route_draft")
			body, _ := json.Marshal(map[string]any{"slug": "policy-draft", "operations": []any{"generation"}, "overall_timeout_ms": 30000, "max_attempts": 1, "fidelity": map[string]any{"mode": "transformed"}, "targets": []any{map[string]any{"provider_model_id": modelID, "priority": 0, "weight": 1, "timeout_ms": 2000}}})
			draft, err := client.Call(t.Context(), createDraft, management.Arguments{Body: body})
			if err != nil {
				t.Fatal(err)
			}
			var created struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(draft.Body, &created) != nil || created.ID == "" {
				t.Fatal("fixture draft identity missing")
			}
			dir := t.TempDir()
			config := privateFile(t, dir, "cli.tfrc", `provider_installation { dev_overrides { "registry.terraform.io/tyk-swe/openllmproxy" = "`+filepath.Dir(required(t, "OLP_TEST_PROVIDER_BINARY"))+`" } direct {} }`)
			tool := required(t, engine)
			env := append(os.Environ(), "TF_CLI_CONFIG_FILE="+config, "OLP_MANAGEMENT_URL="+instance.endpoint, "OLP_MANAGEMENT_TOKEN_FILE="+instance.tokenFile)
			run := func(args ...string) []byte {
				command := exec.CommandContext(t.Context(), tool, args...)
				command.Dir, command.Env = dir, env
				output, err := command.CombinedOutput()
				if err != nil {
					t.Fatalf("%s %v: %v\n%s", engine, args, err, output)
				}
				return output
			}
			write := func(phase int) {
				policy := map[string]any{"allowed_strategies": []any{"weighted"}}
				if phase == 2 || phase == 4 {
					policy["constraints"] = map[string]any{"regions": []any{"west"}}
				}
				encoded, _ := json.Marshal(policy)
				definitions := map[string]any{
					"installation": map[string]any{"scope": "installation", "scope_id": uuid.Nil.String(), "definition": string(encoded)},
					"key":          map[string]any{"scope": "api-key", "scope_id": "${openllmproxy_key.client.id}", "definition": string(encoded)},
					"draft":        map[string]any{"scope": "route-draft", "scope_id": created.ID, "definition": string(encoded)},
				}
				key, _ := json.Marshal(map[string]any{"name": fmt.Sprintf("Policy client phase %d", phase), "scopes": []any{"models_read"}})
				document := map[string]any{"terraform": map[string]any{"required_providers": map[string]any{"openllmproxy": map[string]any{"source": "registry.terraform.io/tyk-swe/openllmproxy"}}}, "provider": map[string]any{"openllmproxy": map[string]any{}}, "resource": map[string]any{"openllmproxy_key": map[string]any{"client": map[string]any{"definition": string(key)}}, "openllmproxy_routing_policy": definitions}}
				data, _ := json.Marshal(document)
				if err := os.WriteFile(filepath.Join(dir, "main.tf.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			write(1)
			run("plan", "-input=false", "-out=create.tfplan")
			run("apply", "-input=false", "create.tfplan")
			write(2)
			run("plan", "-input=false", "-out=update.tfplan")
			run("apply", "-input=false", "update.tfplan")
			var state struct {
				Values struct {
					Root struct {
						Resources []struct {
							Address string         `json:"address"`
							Values  map[string]any `json:"values"`
						} `json:"resources"`
					} `json:"root_module"`
				} `json:"values"`
			}
			if err := json.Unmarshal(run("show", "-json"), &state); err != nil {
				t.Fatal(err)
			}
			identities := map[string]map[string]any{}
			for _, resource := range state.Values.Root.Resources {
				if resource.Values["scope"] != nil {
					identities[resource.Address] = resource.Values
				}
			}
			if len(identities) != 3 {
				t.Fatal("missing scoped policy identities")
			}
			for address, values := range identities {
				run("state", "rm", address)
				run("import", "-input=false", address, values["scope"].(string)+"/"+values["scope_id"].(string))
			}
			run("apply", "-input=false", "-auto-approve")
			run("plan", "-input=false", "-detailed-exitcode")
			write(3)
			run("apply", "-input=false", "-auto-approve")
			get, _ := management.Lookup("get_routing_policy")
			for _, values := range identities {
				result, err := client.Call(t.Context(), get, management.Arguments{Path: map[string]string{"scope": values["scope"].(string), "id": values["scope_id"].(string)}})
				if err != nil {
					t.Fatal(err)
				}
				var value struct {
					Policy struct {
						Constraints struct {
							Regions []string `json:"regions"`
						} `json:"constraints"`
					} `json:"policy"`
				}
				if json.Unmarshal(result.Body, &value) != nil || len(value.Policy.Constraints.Regions) != 0 {
					t.Fatal("policy replacement retained removed region constraints")
				}
			}
			write(4)
			run("plan", "-input=false", "-out=foreign.tfplan")
			values := identities["openllmproxy_routing_policy.key"]
			paths := map[string]string{"scope": "api-key", "id": values["scope_id"].(string)}
			observed, err := client.Call(t.Context(), get, management.Arguments{Path: paths})
			if err != nil {
				t.Fatal(err)
			}
			put, _ := management.Lookup("put_routing_policy")
			external := json.RawMessage(`{"allowed_strategies":["weighted"],"constraints":{"regions":["east"]}}`)
			if _, err := client.Call(t.Context(), put, management.Arguments{Path: paths, IfMatch: observed.ETag, Body: external}); err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(t.Context(), tool, "apply", "-input=false", "foreign.tfplan")
			command.Dir, command.Env = dir, env
			output, err := command.CombinedOutput()
			if err == nil || (!strings.Contains(string(output), "412") && !strings.Contains(string(output), "Resource changed while planning")) {
				t.Fatalf("saved plan did not refuse the foreign policy transition: %v\n%s", err, output)
			}
			preserved, err := client.Call(t.Context(), get, management.Arguments{Path: paths})
			if err != nil {
				t.Fatal(err)
			}
			var foreign struct {
				Policy struct {
					Constraints struct {
						Regions []string `json:"regions"`
					} `json:"constraints"`
				} `json:"policy"`
			}
			if json.Unmarshal(preserved.Body, &foreign) != nil || len(foreign.Policy.Constraints.Regions) != 1 || foreign.Policy.Constraints.Regions[0] != "east" {
				t.Fatal("saved plan overwrote the foreign policy")
			}
			run("apply", "-input=false", "-auto-approve")
			run("destroy", "-input=false", "-auto-approve")
			for _, values := range identities {
				result, err := client.Call(t.Context(), get, management.Arguments{Path: map[string]string{"scope": values["scope"].(string), "id": values["scope_id"].(string)}})
				if err != nil {
					t.Fatal(err)
				}
				var value struct {
					Configured bool `json:"configured"`
				}
				if json.Unmarshal(result.Body, &value) != nil || value.Configured {
					t.Fatal("destroy retained an explicit policy")
				}
			}
		})
	}
}
