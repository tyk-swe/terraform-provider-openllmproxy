//go:build integration

package acceptance

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type installation struct{ endpoint, tokenFile string }

func required(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required for explicitly selected acceptance tests", name)
	}
	return value
}
func privateFile(t *testing.T, dir, name, value string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
func address(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	value := listener.Addr().String()
	listener.Close()
	return value
}

// Each test owns a fresh database, encryption/authentication keys and process;
// only the disposable PostgreSQL/Valkey services are shared.
func newInstallation(t *testing.T, environment ...string) installation {
	t.Helper()
	raw := required(t, "OLP_TEST_DATABASE_URL")
	admin, err := pgx.Connect(t.Context(), raw)
	if err != nil {
		t.Fatal("connect disposable PostgreSQL:", err)
	}
	name := "tf_" + strings.ReplaceAll(rand.Text(), "-", "")
	identifier := pgx.Identifier{name}.Sanitize()
	if _, err = admin.Exec(t.Context(), "CREATE DATABASE "+identifier); err != nil {
		admin.Close(t.Context())
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		admin.Exec(ctx, "DROP DATABASE "+identifier+" WITH (FORCE)")
		admin.Close(ctx)
	})
	databaseURL, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	databaseURL.Path = "/" + name
	dir := t.TempDir()
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		t.Fatal(err)
	}
	master := privateFile(t, dir, "master.json", fmt.Sprintf(`{"active_version":1,"keys":[{"version":1,"key":"%x"}]}`, key))
	if _, err = rand.Read(key); err != nil {
		t.Fatal(err)
	}
	auth := privateFile(t, dir, "auth.key", fmt.Sprintf("%x", key))
	clear(key)
	bootstrap := rand.Text() + rand.Text()
	bootFile := privateFile(t, dir, "bootstrap.token", bootstrap)
	endpoint := "http://" + address(t)
	env := append(os.Environ(), "OLP_DATABASE_URL="+databaseURL.String(), "OLP_VALKEY_URL="+required(t, "OLP_TEST_VALKEY_URL"), "OLP_AUTH_HMAC_KEY_FILE="+auth, "OLP_MASTER_KEY_FILE="+master, "OLP_BOOTSTRAP_TOKEN_FILE="+bootFile, "OLP_LISTEN_ADDR="+strings.TrimPrefix(endpoint, "http://"), "OLP_OBSERVABILITY_LISTEN_ADDR="+address(t), "OLP_PUBLIC_ORIGIN="+endpoint, "OLP_DATABASE_MAX_CONNECTIONS=5")
	env = append(env, environment...)
	binary := required(t, "OLP_TEST_BINARY")
	migrate := exec.CommandContext(t.Context(), binary, "migrate")
	migrate.Env = env
	if output, err := migrate.CombinedOutput(); err != nil {
		t.Fatalf("migrate: %v\n%s", err, output)
	}
	logPath := filepath.Join(dir, "process.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	process := exec.Command(binary, "all")
	process.Env = env
	process.Stdout = logFile
	process.Stderr = logFile
	if err = process.Start(); err != nil {
		logFile.Close()
		t.Fatal(err)
	}
	done := make(chan struct{})
	var exitErr error
	go func() { exitErr = process.Wait(); close(done) }()
	t.Cleanup(func() {
		process.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			process.Process.Kill()
			<-done
		}
		logFile.Close()
		if t.Failed() {
			output, _ := os.ReadFile(logPath)
			t.Logf("installation process:\n%s", output)
		}
	})
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(20 * time.Second)
	for {
		response, err := client.Get(endpoint + "/api/v1/setup/status")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("installation did not become available")
		}
		select {
		case <-done:
			t.Fatalf("installation exited: %v", exitErr)
		case <-time.After(50 * time.Millisecond):
		}
	}
	call := func(path string, body any, headers map[string]string) (map[string]any, *http.Response) {
		encoded, _ := json.Marshal(body)
		request, _ := http.NewRequestWithContext(t.Context(), "POST", endpoint+path, bytes.NewReader(encoded))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", endpoint)
		for name, value := range headers {
			request.Header.Set(name, value)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var result map[string]any
		if json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result) != nil {
			t.Fatal("invalid installation response")
		}
		if response.StatusCode != 201 {
			t.Fatalf("%s status %d, problem %v", path, response.StatusCode, result["type"])
		}
		return result, response
	}
	session, response := call("/api/v1/setup", map[string]string{"email": "owner@example.com", "display_name": "Acceptance owner", "password": "A long acceptance password 42!"}, map[string]string{"X-OLP-Setup-Token": bootstrap})
	cookies := []string{}
	for _, cookie := range response.Cookies() {
		cookies = append(cookies, cookie.Name+"="+cookie.Value)
	}
	created, _ := call("/api/v1/management-tokens", map[string]any{"name": "Infrastructure acceptance", "scopes": []string{"manage_projects", "read", "configure", "keys", "settings", "access"}, "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}, map[string]string{"Cookie": strings.Join(cookies, "; "), "X-CSRF-Token": session["csrf_token"].(string), "Idempotency-Key": rand.Text()})
	return installation{endpoint: endpoint, tokenFile: privateFile(t, dir, "management.token", created["secret"].(string))}
}
