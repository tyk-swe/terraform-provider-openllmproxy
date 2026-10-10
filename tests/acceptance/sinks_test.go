//go:build integration

package acceptance

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tyk-swe/olp/sdk/management"
)

func TestSignedExportSinkLifecyclesWithTerraformAndOpenTofu(t *testing.T) {
	for _, engine := range []string{"OLP_TEST_TERRAFORM_BINARY", "OLP_TEST_TOFU_BINARY"} {
		t.Run(engine, func(t *testing.T) {
			const first = "sink-ephemeral-first"
			const rotated = "sink-ephemeral-rotated"
			var delivered atomic.Int64
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(io.LimitReader(r.Body, 1<<17))
				if err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				var event struct {
					ID     string `json:"id"`
					Stream string `json:"stream"`
				}
				if json.Unmarshal(body, &event) != nil || event.ID == "" || event.Stream != "audit" || r.Header.Get("Idempotency-Key") != event.ID {
					t.Error("invalid export envelope")
					w.WriteHeader(400)
					return
				}
				valid := false
				for _, key := range []string{first, rotated} {
					sum := hmac.New(sha256.New, []byte(key))
					sum.Write(body)
					valid = valid || r.Header.Get("X-OLP-Signature") == "sha256="+hex.EncodeToString(sum.Sum(nil))
				}
				if !valid {
					t.Error("signature does not bind request bytes")
					w.WriteHeader(403)
					return
				}
				delivered.Add(1)
				w.WriteHeader(204)
			}))
			defer receiver.Close()
			instance := newInstallation(t, "OLP_PROVIDER_EGRESS_ALLOW_CIDRS=127.0.0.0/8", "OLP_PROVIDER_EGRESS_ALLOW_HTTP_HOSTS=127.0.0.1")
			client, err := management.NewClient(instance.endpoint, instance.tokenFile)
			if err != nil {
				t.Fatal(err)
			}
			call := func(name string, paths map[string]string, etag string, body any) management.Response {
				op, ok := management.Lookup(name)
				if !ok {
					t.Fatalf("missing %s", name)
				}
				var encoded json.RawMessage
				if body != nil {
					encoded, _ = json.Marshal(body)
				}
				result, err := client.Call(t.Context(), op, management.Arguments{Path: paths, IfMatch: etag, Body: encoded})
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				return result
			}
			project := call("create_project", nil, "", map[string]any{"name": "Export fixture"})
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
					t.Fatalf("%s %v: %v\n%s", tool, args, err, out)
				}
				return out
			}
			write := func(version int) {
				secret := first
				if version > 1 {
					secret = rotated
				}
				env = append(env, "TF_VAR_signing="+secret)
				resources := map[string]any{}
				for _, name := range []string{"installation", "project"} {
					definition := map[string]any{"name": name + " facts", "type": "https", "destination": receiver.URL, "streams": []string{"audit"}, "enabled": true}
					if name == "project" {
						definition["project_id"] = owning.ID
						definition["streams"] = []string{"requests"}
						definition["enabled"] = false
					}
					if version > 1 {
						definition["name"] = name + " updated"
					}
					encoded, _ := json.Marshal(definition)
					resources[name] = map[string]any{"definition": string(encoded), "secret": "${var.signing}", "secret_version": version}
				}
				config := map[string]any{"terraform": map[string]any{"required_providers": map[string]any{"openllmproxy": map[string]any{"source": "registry.terraform.io/tyk-swe/openllmproxy"}}}, "provider": map[string]any{"openllmproxy": map[string]any{}}, "variable": map[string]any{"signing": map[string]any{"type": "string", "ephemeral": true, "sensitive": true}}, "resource": map[string]any{"openllmproxy_sink": resources}}
				encoded, _ := json.Marshal(config)
				privateFile(t, dir, "main.tf.json", string(encoded))
			}
			for _, version := range []int{1, 2} {
				write(version)
				plan := "create.tfplan"
				if version == 2 {
					plan = "update.tfplan"
				}
				cli("plan", "-input=false", "-out="+plan)
				raw, _ := os.ReadFile(filepath.Join(dir, plan))
				if bytes.Contains(raw, []byte(first)) || bytes.Contains(raw, []byte(rotated)) {
					t.Fatal("write-only value persisted in plan")
				}
				plainPlan := cli("show", "-json", plan)
				if bytes.Contains(plainPlan, []byte(first)) || bytes.Contains(plainPlan, []byte(rotated)) {
					t.Fatal("write-only value persisted in decoded saved plan")
				}
				cli("apply", "-input=false", "-auto-approve", plan)
			}
			state := cli("show", "-json")
			if bytes.Contains(state, []byte(first)) || bytes.Contains(state, []byte(rotated)) {
				t.Fatal("write-only value persisted in state")
			}
			var root struct {
				Values struct {
					Root struct {
						Resources []struct {
							Address string
							Values  struct {
								ID string `json:"id"`
							}
						} `json:"resources"`
					} `json:"root_module"`
				} `json:"values"`
			}
			if err = json.Unmarshal(state, &root); err != nil || len(root.Values.Root.Resources) != 2 {
				t.Fatal("missing sink identities")
			}
			for _, r := range root.Values.Root.Resources {
				cli("state", "rm", r.Address)
				cli("import", "-input=false", r.Address, r.Values.ID)
			}
			cli("apply", "-input=false", "-auto-approve")
			cli("plan", "-input=false", "-detailed-exitcode")
			deadline := time.Now().Add(15 * time.Second)
			for delivered.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			if delivered.Load() == 0 {
				t.Fatal("built installation worker did not deliver signed audit facts")
			}
			write(3)
			cli("plan", "-input=false", "-out=foreign.tfplan")
			selected := root.Values.Root.Resources[0]
			if strings.HasSuffix(selected.Address, ".project") {
				selected = root.Values.Root.Resources[1]
			}
			paths := map[string]string{"sink_id": selected.Values.ID}
			current := call("get_sink", paths, "", nil)
			var desired map[string]any
			json.Unmarshal(current.Body, &desired)
			call("update_sink", paths, current.ETag, map[string]any{"name": "External protected edit", "destination": receiver.URL, "streams": desired["streams"], "enabled": desired["enabled"]})
			cmd := exec.CommandContext(t.Context(), tool, "apply", "-input=false", "-auto-approve", "foreign.tfplan")
			cmd.Dir, cmd.Env = dir, env
			out, err := cmd.CombinedOutput()
			if err == nil || (!strings.Contains(string(out), "412") && !strings.Contains(string(out), "Resource changed while planning")) {
				t.Fatal("saved sink plan did not refuse external edit")
			}
			protected := call("get_sink", paths, "", nil)
			if !bytes.Contains(protected.Body, []byte("External protected edit")) {
				t.Fatal("external edit was overwritten")
			}
			cli("destroy", "-input=false", "-auto-approve")
			for _, r := range root.Values.Root.Resources {
				retired := call("get_sink", map[string]string{"sink_id": r.Values.ID}, "", nil)
				var body struct {
					Retired *string `json:"retired_at"`
					Has     bool    `json:"has_credential"`
				}
				if json.Unmarshal(retired.Body, &body) != nil || body.Retired == nil || body.Has {
					t.Fatal("retirement did not retain identity and remove signing credential")
				}
			}
		})
	}
}
