//go:build integration

package acceptance

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tyk-swe/olp/sdk/management"
)

func TestCertifiedMCPServerLifecyclesWithTerraformAndOpenTofu(t *testing.T) {
	for _, engine := range []string{"OLP_TEST_TERRAFORM_BINARY", "OLP_TEST_TOFU_BINARY"} {
		t.Run(engine, func(t *testing.T) {
			const first = "mcp-first-ephemeral"
			const second = "mcp-second-ephemeral"
			var description atomic.Value
			description.Store("Reviewed original catalog")
			var calls atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method == "DELETE" {
					w.WriteHeader(204)
					return
				}
				bearer := r.Header.Get("Authorization")
				if bearer != "Bearer "+first && bearer != "Bearer "+second {
					w.WriteHeader(401)
					return
				}
				var request struct {
					ID     int    `json:"id"`
					Method string `json:"method"`
				}
				if json.NewDecoder(r.Body).Decode(&request) != nil {
					w.WriteHeader(400)
					return
				}
				if request.ID == 0 {
					w.WriteHeader(202)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				var result any
				switch request.Method {
				case "initialize":
					result = map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{"tools": map[string]any{}}}
				case "tools/list":
					result = map[string]any{"tools": []any{map[string]any{"name": "lookup", "description": description.Load(), "inputSchema": map[string]any{"type": "object"}}}}
				default:
					t.Errorf("certification invoked %s", request.Method)
					w.WriteHeader(400)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
			}))
			defer upstream.Close()
			instance := newInstallation(t, "OLP_PROVIDER_EGRESS_ALLOW_CIDRS=127.0.0.0/8", "OLP_PROVIDER_EGRESS_ALLOW_HTTP_HOSTS=127.0.0.1")
			client, err := management.NewClient(instance.endpoint, instance.tokenFile)
			if err != nil {
				t.Fatal(err)
			}
			call := func(name string, paths map[string]string, etag string, body any) management.Response {
				op, ok := management.Lookup(name)
				if !ok {
					t.Fatalf("missing generated operation %s", name)
				}
				var raw json.RawMessage
				if body != nil {
					raw, _ = json.Marshal(body)
				}
				response, err := client.Call(t.Context(), op, management.Arguments{Path: paths, IfMatch: etag, Body: raw})
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				return response
			}
			project := call("create_project", nil, "", map[string]any{"name": "MCP fixture"})
			var owning struct {
				ID string `json:"id"`
			}
			json.Unmarshal(project.Body, &owning)
			dir := t.TempDir()
			configFile := privateFile(t, dir, "cli.tfrc", `provider_installation { dev_overrides { "registry.terraform.io/tyk-swe/openllmproxy" = "`+filepath.Dir(required(t, "OLP_TEST_PROVIDER_BINARY"))+`" } direct {} }`)
			tool := required(t, engine)
			env := append(os.Environ(), "TF_CLI_CONFIG_FILE="+configFile, "OLP_MANAGEMENT_URL="+instance.endpoint, "OLP_MANAGEMENT_TOKEN_FILE="+instance.tokenFile)
			cli := func(args ...string) []byte {
				cmd := exec.CommandContext(t.Context(), tool, args...)
				cmd.Dir, cmd.Env = dir, env
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("%v: %v\n%s", args, err, out)
				}
				return out
			}
			write := func(version int) {
				secret := first
				name := "Lookup"
				if version > 1 {
					secret = second
					name = "Lookup updated"
				}
				if version > 2 {
					name = "Lookup reviewed"
				}
				env = append(env, "TF_VAR_bearer="+secret)
				definition, _ := json.Marshal(map[string]any{"name": name, "project_id": owning.ID, "transport": "streamable_http", "endpoint": upstream.URL, "enabled": true})
				config := map[string]any{"terraform": map[string]any{"required_providers": map[string]any{"openllmproxy": map[string]any{"source": "registry.terraform.io/tyk-swe/openllmproxy"}}}, "provider": map[string]any{"openllmproxy": map[string]any{}}, "variable": map[string]any{"bearer": map[string]any{"type": "string", "sensitive": true, "ephemeral": true}}, "resource": map[string]any{"openllmproxy_mcp_server": map[string]any{"lookup": map[string]any{"definition": string(definition), "secret": "${var.bearer}", "secret_version": version}}}}
				raw, _ := json.Marshal(config)
				privateFile(t, dir, "main.tf.json", string(raw))
			}
			write(1)
			cli("plan", "-input=false", "-out=create.tfplan")
			if raw := cli("show", "-json", "create.tfplan"); bytes.Contains(raw, []byte(first)) {
				t.Fatal("ephemeral bearer entered saved plan")
			}
			cli("apply", "-input=false", "-auto-approve", "create.tfplan")
			state := cli("show", "-json")
			var root struct {
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
			if json.Unmarshal(state, &root) != nil || len(root.Values.RootModule.Resources) != 1 {
				t.Fatal("created identity missing")
			}
			id := root.Values.RootModule.Resources[0].Values.ID
			paths := map[string]string{"server_id": id}
			initial := call("get_mcp_server", paths, "", nil)
			var original map[string]any
			json.Unmarshal(initial.Body, &original)
			revision := original["revision_id"].(string)
			description.Store("Reviewed changed catalog")
			write(2)
			cli("plan", "-input=false", "-out=update.tfplan")
			cli("apply", "-input=false", "-auto-approve", "update.tfplan")
			state = cli("show", "-json")
			for _, secret := range []string{first, second} {
				if bytes.Contains(state, []byte(secret)) || bytes.Contains(cli("show", "-json", "update.tfplan"), []byte(secret)) {
					t.Fatal("rotated bearer persisted in state/plan")
				}
			}
			old := call("get_mcp_server_revision", map[string]string{"server_id": id, "revision_id": revision}, "", nil)
			if !bytes.Contains(old.Body, []byte("Reviewed original catalog")) {
				t.Fatal("immutable old catalog changed")
			}
			cli("state", "rm", "openllmproxy_mcp_server.lookup")
			cli("import", "-input=false", "openllmproxy_mcp_server.lookup", id)
			cli("apply", "-input=false", "-auto-approve")
			cmd := exec.CommandContext(t.Context(), tool, "plan", "-input=false", "-detailed-exitcode")
			cmd.Dir, cmd.Env = dir, env
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("imported definition drift: %v\n%s", err, out)
			}
			before := calls.Load()
			description.Store("Unapproved live drift")
			current := call("get_mcp_server", paths, "", nil)
			if calls.Load() != before || !bytes.Contains(current.Body, []byte("Reviewed changed catalog")) {
				t.Fatal("read adopted live upstream drift")
			}
			write(3)
			cli("plan", "-input=false", "-out=foreign.tfplan")
			call("update_mcp_server", paths, current.ETag, map[string]any{"name": "External protected edit", "endpoint": upstream.URL, "enabled": true})
			cmd = exec.CommandContext(t.Context(), tool, "apply", "-input=false", "-auto-approve", "foreign.tfplan")
			cmd.Dir, cmd.Env = dir, env
			out, err := cmd.CombinedOutput()
			if err == nil || (!strings.Contains(string(out), "412") && !strings.Contains(string(out), "Resource changed while planning")) {
				t.Fatalf("foreign change not refused: %v %s", err, out)
			}
			preserved := call("get_mcp_server", paths, "", nil)
			if !bytes.Contains(preserved.Body, []byte("External protected edit")) {
				t.Fatal("foreign edit overwritten")
			}
			cli("destroy", "-input=false", "-auto-approve")
			retired := call("get_mcp_server", paths, "", nil)
			var metadata struct {
				RetiredAt     *string `json:"retired_at"`
				HasCredential bool    `json:"has_credential"`
			}
			if json.Unmarshal(retired.Body, &metadata) != nil || metadata.RetiredAt == nil || metadata.HasCredential {
				t.Fatal("retirement failed to remove bearer/preserve history")
			}
			call("get_mcp_server_revision", map[string]string{"server_id": id, "revision_id": revision}, "", nil)
		})
	}
}
