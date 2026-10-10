//go:build integration

package acceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyk-swe/olp/sdk/management"
)

func TestGuardrailAndCopiedRoutePoliciesWithTerraformAndOpenTofu(t *testing.T) {
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
			call := func(name string, paths map[string]string, etag string, body any) management.Response {
				operation, ok := management.Lookup(name)
				if !ok {
					t.Fatalf("missing operation %s", name)
				}
				var encoded json.RawMessage
				if body != nil {
					encoded, _ = json.Marshal(body)
				}
				value, err := client.Call(context.Background(), operation, management.Arguments{Path: paths, IfMatch: etag, Body: encoded})
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				return value
			}
			project := call("create_project", nil, "", map[string]any{"name": "Guardrail fixture"})
			var projectBody struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(project.Body, &projectBody); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			configFile := privateFile(t, dir, "cli.tfrc", `provider_installation { dev_overrides { "registry.terraform.io/tyk-swe/openllmproxy" = "`+filepath.Dir(required(t, "OLP_TEST_PROVIDER_BINARY"))+`" } direct {} }`)
			tool := required(t, engine)
			env := append(os.Environ(), "TF_CLI_CONFIG_FILE="+configFile, "OLP_MANAGEMENT_URL="+instance.endpoint, "OLP_MANAGEMENT_TOKEN_FILE="+instance.tokenFile)
			cli := func(args ...string) []byte {
				cmd := exec.CommandContext(t.Context(), tool, args...)
				cmd.Dir, cmd.Env = dir, env
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("%s %v: %v\n%s", tool, args, err, out)
				}
				return out
			}
			policy := func(pattern string) map[string]any {
				return map[string]any{"rules": []any{map[string]any{"id": "account", "phase": "input", "action": "block", "pattern": pattern}}}
			}
			write := func(phase int) {
				guardrail, _ := json.Marshal(map[string]any{"name": fmt.Sprintf("Account filter %d", phase), "type": "builtin.regex", "project_id": projectBody.ID, "policy": policy(fmt.Sprintf("ACCOUNT-[0-9]{%d}", phase+7))})
				route, _ := json.Marshal(map[string]any{"slug": "guarded-route", "operations": []string{"generation"}, "overall_timeout_ms": 30000, "max_attempts": 1, "fidelity": map[string]any{"mode": "transformed"}, "targets": []any{map[string]any{"provider_model_id": modelID, "priority": 0, "weight": 1, "timeout_ms": 2000}}})
				configuration := map[string]any{"terraform": map[string]any{"required_providers": map[string]any{"openllmproxy": map[string]any{"source": "registry.terraform.io/tyk-swe/openllmproxy"}}}, "provider": map[string]any{"openllmproxy": map[string]any{}}, "resource": map[string]any{
					"openllmproxy_guardrail": map[string]any{"filter": map[string]any{"definition": string(guardrail)}},
					"openllmproxy_route":     map[string]any{"guarded": map[string]any{"definition": "${jsonencode(merge(jsondecode(" + fmt.Sprintf("%q", string(route)) + "), {content_policy = jsondecode(openllmproxy_guardrail.filter.definition).policy}))}"}},
				}}
				encoded, _ := json.Marshal(configuration)
				if err := os.WriteFile(filepath.Join(dir, "main.tf.json"), encoded, 0600); err != nil {
					t.Fatal(err)
				}
			}
			write(1)
			cli("plan", "-input=false", "-out=create.tfplan")
			cli("apply", "-input=false", "create.tfplan")
			var state struct {
				Values struct {
					Root struct {
						Resources []struct {
							Address string `json:"address"`
							Values  struct {
								ID string `json:"id"`
							} `json:"values"`
						} `json:"resources"`
					} `json:"root_module"`
				} `json:"values"`
			}
			if err := json.Unmarshal(cli("show", "-json"), &state); err != nil {
				t.Fatal(err)
			}
			identities := map[string]string{}
			for _, value := range state.Values.Root.Resources {
				identities[value.Address] = value.Values.ID
			}
			guardrailID, routeID := identities["openllmproxy_guardrail.filter"], identities["openllmproxy_route.guarded"]
			if guardrailID == "" || routeID == "" {
				t.Fatal("managed graph has no identities")
			}
			paths := map[string]string{"guardrail_id": guardrailID}
			created := call("get_guardrail", paths, "", nil)
			var original struct {
				RevisionID string `json:"revision_id"`
			}
			if err := json.Unmarshal(created.Body, &original); err != nil {
				t.Fatal(err)
			}
			write(2)
			cli("plan", "-input=false", "-out=update.tfplan")
			cli("apply", "-input=false", "update.tfplan")
			observedRoute := call("get_route", map[string]string{"route_id": routeID}, "", nil)
			if !strings.Contains(string(observedRoute.Body), "ACCOUNT-[0-9]{9}") {
				t.Fatal("route did not publish the selected copied policy")
			}
			old := call("get_guardrail_revision", map[string]string{"guardrail_id": guardrailID, "revision_id": original.RevisionID}, "", nil)
			if !strings.Contains(string(old.Body), "ACCOUNT-[0-9]{8}") {
				t.Fatal("old policy changed")
			}
			for address, id := range identities {
				cli("state", "rm", address)
				cli("import", "-input=false", address, id)
			}
			cli("apply", "-input=false", "-auto-approve")
			cli("plan", "-input=false", "-detailed-exitcode")
			write(3)
			cli("plan", "-input=false", "-out=foreign.tfplan")
			observed := call("get_guardrail", paths, "", nil)
			call("update_guardrail", paths, observed.ETag, map[string]any{"name": "External protected filter", "policy": policy("EXTERNAL")})
			cmd := exec.CommandContext(t.Context(), tool, "apply", "-input=false", "foreign.tfplan")
			cmd.Dir, cmd.Env = dir, env
			out, err := cmd.CombinedOutput()
			if err == nil || (!strings.Contains(string(out), "412") && !strings.Contains(string(out), "Resource changed while planning")) {
				t.Fatalf("foreign update was not refused: %v\n%s", err, out)
			}
			if current := call("get_guardrail", paths, "", nil); !strings.Contains(string(current.Body), "EXTERNAL") {
				t.Fatal("external policy was overwritten")
			}
			if current := call("get_route", map[string]string{"route_id": routeID}, "", nil); !strings.Contains(string(current.Body), "ACCOUNT-[0-9]{9}") {
				t.Fatal("failed guardrail update changed the published copy")
			}
			write(2)
			cli("apply", "-input=false", "-auto-approve")
			cli("destroy", "-input=false", "-auto-approve")
			var retired struct {
				RetiredAt *string `json:"retired_at"`
			}
			if err := json.Unmarshal(call("get_guardrail", paths, "", nil).Body, &retired); err != nil || retired.RetiredAt == nil {
				t.Fatal("definition history was not retained")
			}
			call("get_guardrail_revision", map[string]string{"guardrail_id": guardrailID, "revision_id": original.RevisionID}, "", nil)
		})
	}
}
