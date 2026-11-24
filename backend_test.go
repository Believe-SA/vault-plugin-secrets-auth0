package auth0

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

const (
	mgmtID     = "mgmt-id"
	mgmtSecret = "mgmt-secret"
	mgmtToken  = "mgmt-token"
	failAud    = "https://fail"
)

// fakeAuth0 serves the Management API token and the client endpoints used.
type fakeAuth0 struct {
	*httptest.Server

	mu      sync.Mutex
	clients map[string]string   // client_id -> secret
	grants  map[string][]string // client_id -> audiences
	meta    map[string]map[string]string
	names   map[string]string
	next    int
}

func newFakeAuth0(t *testing.T) *fakeAuth0 {
	t.Helper()

	f := &fakeAuth0{
		clients: map[string]string{"app-1": "app-1-secret"},
		grants:  map[string][]string{},
		meta:    map[string]map[string]string{},
		names:   map[string]string{},
	}
	f.Server = httptest.NewTLSServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.Close)

	return f
}

func (f *fakeAuth0) domain() string { return strings.TrimPrefix(f.URL, "https://") }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	err := json.NewEncoder(w).Encode(v)
	if err != nil {
		panic(err)
	}
}

func (f *fakeAuth0) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if r.URL.Path == "/oauth/token" {
		f.handleToken(w, r)

		return
	}

	if r.Header.Get("Authorization") != "Bearer "+mgmtToken {
		writeJSON(w, 401, map[string]any{"statusCode": 401, "message": "bad token"})

		return
	}

	f.handleManagement(w, r)
}

// handleToken issues the Management API token.
func (f *fakeAuth0) handleToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()

	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}

	if id != mgmtID || secret != mgmtSecret || r.PostForm.Get("audience") != f.URL+"/api/v2/" {
		writeJSON(w, 401, map[string]string{"error": "access_denied", "error_description": "Unauthorized"})

		return
	}

	writeJSON(w, 200, map[string]any{"access_token": mgmtToken, "token_type": "Bearer", "expires_in": 3600})
}

func (f *fakeAuth0) handleManagement(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/v2/clients":
		var c struct {
			Name     string            `json:"name"`
			Metadata map[string]string `json:"client_metadata"`
		}

		_ = json.NewDecoder(r.Body).Decode(&c)
		f.next++
		id := fmt.Sprintf("dyn-%d", f.next)
		f.clients[id] = id + "-secret"
		f.meta[id] = c.Metadata
		f.names[id] = c.Name
		writeJSON(w, 201, map[string]string{"client_id": id, "client_secret": f.clients[id]})
	case r.Method == http.MethodPost && r.URL.Path == "/api/v2/client-grants":
		var g struct {
			ClientID string `json:"client_id"`
			Audience string `json:"audience"`
		}

		_ = json.NewDecoder(r.Body).Decode(&g)
		if g.Audience == failAud {
			writeJSON(w, 404, map[string]any{"statusCode": 404, "message": "no such API"})

			return
		}

		f.grants[g.ClientID] = append(f.grants[g.ClientID], g.Audience)
		writeJSON(w, 201, map[string]string{"id": "grant", "client_id": g.ClientID, "audience": g.Audience})
	case strings.HasPrefix(r.URL.Path, "/api/v2/clients/"):
		id := strings.TrimPrefix(r.URL.Path, "/api/v2/clients/")
		if _, ok := f.clients[id]; !ok {
			writeJSON(w, 404, map[string]any{"statusCode": 404, "message": "not found"})

			return
		}

		if r.Method == http.MethodDelete {
			delete(f.clients, id)
			delete(f.grants, id)
			w.WriteHeader(http.StatusNoContent)
		}
	default:
		writeJSON(w, 404, map[string]any{"statusCode": 404, "message": "unknown route"})
	}
}

func (f *fakeAuth0) hasClient(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	_, ok := f.clients[id]

	return ok
}

func setup(t *testing.T) (*backend, *logical.InmemStorage, *fakeAuth0) {
	t.Helper()

	f := newFakeAuth0(t)
	s := &logical.InmemStorage{}
	conf := logical.TestBackendConfig()
	conf.StorageView = s

	b := newBackend(f.Client())

	err := b.Setup(context.Background(), conf)
	if err != nil {
		t.Fatal(err)
	}

	return b, s, f
}

func request(t *testing.T, b *backend, s logical.Storage, op logical.Operation, path string, data map[string]any) *logical.Response {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: op, Path: path, Storage: s, Data: data,
	})
	if err != nil {
		t.Fatalf("%s %s: %v", op, path, err)
	}

	return resp
}

func mustOK(t *testing.T, resp *logical.Response) *logical.Response {
	t.Helper()

	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp.Error())
	}

	return resp
}

func mustErr(t *testing.T, resp *logical.Response) {
	t.Helper()

	if resp == nil || !resp.IsError() {
		t.Fatalf("expected an error response, got %#v", resp)
	}
}

func writeTenant(t *testing.T, b *backend, s logical.Storage, f *fakeAuth0) {
	t.Helper()
	mustOK(t, request(t, b, s, logical.UpdateOperation, "example/config", map[string]any{
		"domain": f.domain(), "client_id": mgmtID, "client_secret": mgmtSecret,
	}))
}

func TestTenants(t *testing.T) {
	b, s, f := setup(t)

	mustErr(t, request(t, b, s, logical.UpdateOperation, "example/config", map[string]any{"domain": "x"}))
	mustErr(t, request(t, b, s, logical.UpdateOperation, "tenants/config", map[string]any{
		"domain": "x", "client_id": "a", "client_secret": "b",
	}))
	writeTenant(t, b, s, f)

	resp := mustOK(t, request(t, b, s, logical.ReadOperation, "example/config", nil))
	if _, ok := resp.Data["client_secret"]; ok {
		t.Fatal("client_secret must not be returned")
	}

	if resp.Data["client_id"] != mgmtID {
		t.Fatalf("unexpected client_id %v", resp.Data["client_id"])
	}

	resp = mustOK(t, request(t, b, s, logical.ListOperation, "tenants/", nil))
	if keys := resp.Data["keys"].([]string); len(keys) != 1 || keys[0] != "example" {
		t.Fatalf("unexpected tenants %v", keys)
	}

	mustOK(t, request(t, b, s, logical.UpdateOperation, "example/roles/app", map[string]any{
		"grants": map[string]any{"https://api.example.com/api": "read:x"},
	}))
	mustErr(t, request(t, b, s, logical.DeleteOperation, "example/config", nil))
	mustOK(t, request(t, b, s, logical.DeleteOperation, "example/roles/app", nil))
	mustOK(t, request(t, b, s, logical.DeleteOperation, "example/config", nil))
}

func TestRoles(t *testing.T) {
	b, s, f := setup(t)

	grants := map[string]any{"https://api.example.com/api": "read:x write:x"}
	mustErr(t, request(t, b, s, logical.UpdateOperation, "example/roles/dyn", map[string]any{"grants": grants}))
	writeTenant(t, b, s, f)

	mustErr(t, request(t, b, s, logical.UpdateOperation, "example/roles/dyn", map[string]any{"ttl": 60}))
	mustErr(t, request(t, b, s, logical.UpdateOperation, "example/roles/dyn", map[string]any{
		"grants": grants, "ttl": 600, "max_ttl": 60,
	}))
	mustOK(t, request(t, b, s, logical.UpdateOperation, "example/roles/dyn", map[string]any{
		"grants": grants, "ttl": 60, "client_metadata": map[string]any{"ratelimit_tier": "gold"},
	}))

	resp := mustOK(t, request(t, b, s, logical.ReadOperation, "example/roles/dyn", nil))
	got := resp.Data["grants"].(map[string]string)

	meta := resp.Data["client_metadata"].(map[string]string)
	if got["https://api.example.com/api"] != "read:x write:x" || resp.Data["name_template"] != defaultNameTemplate ||
		resp.Data["ttl"] != int64(60) || meta["ratelimit_tier"] != "gold" {
		t.Fatalf("unexpected role %v", resp.Data)
	}

	mustErr(t, request(t, b, s, logical.UpdateOperation, "example/roles/dyn", map[string]any{
		"name_template": "{{ .Unknown",
	}))

	resp = mustOK(t, request(t, b, s, logical.ListOperation, "example/roles/", nil))
	if keys := resp.Data["keys"].([]string); len(keys) != 1 || keys[0] != "dyn" {
		t.Fatalf("unexpected roles %v", keys)
	}
}

func TestCredsAndRevoke(t *testing.T) {
	b, s, f := setup(t)
	writeTenant(t, b, s, f)
	mustOK(t, request(t, b, s, logical.UpdateOperation, "example/roles/dyn", map[string]any{
		"grants": map[string]any{"https://api.example.com/a": "read:x", "https://api.example.com/b": "read:y"}, "ttl": 60,
		"client_metadata": "ratelimit_tier=gold",
	}))

	resp := mustOK(t, request(t, b, s, logical.ReadOperation, "example/creds/dyn", nil))

	id := resp.Data["client_id"].(string)
	if !f.hasClient(id) || resp.Data["client_secret"] != id+"-secret" || len(f.grants[id]) != 2 ||
		f.meta[id]["ratelimit_tier"] != "gold" {
		t.Fatalf("client not created as expected: %v, grants %v", resp.Data, f.grants[id])
	}

	if resp.Secret == nil || resp.Secret.TTL.Seconds() != 60 {
		t.Fatalf("expected a 60s lease, got %#v", resp.Secret)
	}

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation, Storage: s, Secret: resp.Secret,
		Data: map[string]any{"secret_type": secretClientType},
	})
	if err != nil {
		t.Fatal(err)
	}

	if f.hasClient(id) {
		t.Fatal("client should be deleted on revoke")
	}
}

func TestCredsGrantFailureCleansUp(t *testing.T) {
	b, s, f := setup(t)
	writeTenant(t, b, s, f)
	mustOK(t, request(t, b, s, logical.UpdateOperation, "example/roles/dyn", map[string]any{
		"grants": map[string]any{failAud: "read:x"},
	}))

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "example/creds/dyn", Storage: s,
	})
	if err == nil {
		t.Fatal("expected an error")
	}

	if f.hasClient("dyn-1") {
		t.Fatal("half-created client should be deleted")
	}
}

func TestWALRollback(t *testing.T) {
	b, s, f := setup(t)
	writeTenant(t, b, s, f)

	err := b.walRollback(context.Background(), &logical.Request{Storage: s}, walTypeClient,
		map[string]any{"tenant": "example", "client_id": "app-1"})
	if err != nil {
		t.Fatal(err)
	}

	if f.hasClient("app-1") {
		t.Fatal("client should be deleted by rollback")
	}
	// Idempotent once the client is gone.
	err = b.walRollback(context.Background(), &logical.Request{Storage: s}, walTypeClient,
		map[string]any{"tenant": "example", "client_id": "app-1"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNameTemplate(t *testing.T) {
	b, s, f := setup(t)
	writeTenant(t, b, s, f)

	tmpl := `{{ if eq (.DisplayName | truncate 11) "kubernetes-" }}{{ printf "vault-kube-%s" .RoleName }}` +
		`{{ else }}{{ printf "vault-%s-%s" .RoleName (.DisplayName | replace "oidc-" "" | replace "@example.com" "") }}{{ end }}`
	mustOK(t, request(t, b, s, logical.UpdateOperation, "example/roles/dyn", map[string]any{
		"grants": map[string]any{"https://api.example.com/api": "read:x"}, "name_template": tmpl,
	}))

	for display, want := range map[string]string{
		"kubernetes-myns-vault":     "vault-kube-dyn",
		"oidc-john.doe@example.com": "vault-dyn-john.doe",
	} {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation, Path: "example/creds/dyn", Storage: s, DisplayName: display,
		})
		if err != nil || resp.IsError() {
			t.Fatalf("creds read: %v %v", err, resp)
		}

		if got := f.names[resp.Data["client_id"].(string)]; got != want || resp.Data["client_name"] != want {
			t.Fatalf("%s: got name %q, want %q", display, got, want)
		}
	}
}
