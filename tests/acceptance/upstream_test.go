//go:build integration

package acceptance

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func compatibleUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("credential fixture request: %s %s", r.Method, r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer provider-private-credential-one" && r.Header.Get("Authorization") != "Bearer provider-private-credential-two" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" && r.URL.Path == "/v1/models" {
			w.Write([]byte(`{"object":"list","data":[{"id":"managed-model","object":"model","created":1,"owned_by":"fixture"}]}`))
			return
		}
		if r.Method == "POST" && r.URL.Path == "/v1/chat/completions" {
			var body struct {
				Stream bool `json:"stream"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			if body.Stream {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Write([]byte("data: {\"id\":\"chunk\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"managed-model\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"OK\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"chunk\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"managed-model\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}\n\ndata: [DONE]\n\n"))
				return
			}

			w.Write([]byte(`{"id":"fixture","object":"chat.completion","model":"managed-model","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
			return
		}
		if r.Method == "POST" && r.URL.Path == "/v1/responses" {
			var body struct {
				Stream bool `json:"stream"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			if body.Stream {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Write([]byte("event: response.created\ndata: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":{\"id\":\"resp-fixture\",\"object\":\"response\",\"status\":\"in_progress\",\"model\":\"managed-model\",\"output\":[]}}\n\nevent: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"sequence_number\":1,\"item_id\":\"msg-fixture\",\"output_index\":0,\"content_index\":0,\"delta\":\"OK\"}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"sequence_number\":2,\"response\":{\"id\":\"resp-fixture\",\"object\":\"response\",\"status\":\"completed\",\"model\":\"managed-model\",\"output\":[{\"id\":\"msg-fixture\",\"type\":\"message\",\"role\":\"assistant\",\"status\":\"completed\",\"content\":[{\"type\":\"output_text\",\"text\":\"OK\",\"annotations\":[]}]}],\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n"))
				return
			}

			w.Write([]byte(`{"id":"resp-fixture","object":"response","status":"completed","model":"managed-model","output":[{"id":"msg-fixture","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"OK","annotations":[]}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`))
			return
		}
		w.WriteHeader(404)
	}))
}
