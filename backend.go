// Package auth0 implements a Vault secrets engine creating short-lived Auth0 M2M clients.
package auth0

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const backendHelp = `
The Auth0 secrets engine creates dynamic M2M clients, deleted when their
lease ends, across several tenants.
`

type backend struct {
	*framework.Backend

	lock    sync.RWMutex
	clients map[string]*auth0Client

	// httpClient is used for all Auth0 calls; nil means http.DefaultClient.
	httpClient *http.Client
}

// Factory returns a configured Auth0 secrets backend.
//
//nolint:ireturn // signature imposed by logical.Factory
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend(nil)

	err := b.Setup(ctx, conf)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func newBackend(httpClient *http.Client) *backend {
	b := &backend{
		clients:    map[string]*auth0Client{},
		httpClient: httpClient,
	}
	b.Backend = &framework.Backend{
		Help:           strings.TrimSpace(backendHelp),
		BackendType:    logical.TypeLogical,
		RunningVersion: "v" + Version,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{"tenant/"},
		},
		Paths: framework.PathAppend(
			pathTenants(b),
			pathRoles(b),
			pathCreds(b),
		),
		Secrets:     []*framework.Secret{secretClient(b)},
		WALRollback: b.walRollback,
		Invalidate:  b.invalidate,
		Clean:       b.reset,
	}

	return b
}

func (b *backend) reset(context.Context) {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.clients = map[string]*auth0Client{}
}

func (b *backend) invalidate(_ context.Context, key string) {
	if t, ok := strings.CutPrefix(key, "tenant/"); ok && strings.HasSuffix(t, "/config") {
		b.resetTenant(strings.TrimSuffix(t, "/config"))
	}
}

func (b *backend) resetTenant(tenant string) {
	b.lock.Lock()
	defer b.lock.Unlock()

	delete(b.clients, tenant)
}

// getClient returns the cached Auth0 client of a tenant, building it on first use.
func (b *backend) getClient(ctx context.Context, s logical.Storage, tenant string) (*auth0Client, error) {
	b.lock.RLock()
	c, ok := b.clients[tenant]
	b.lock.RUnlock()

	if ok {
		return c, nil
	}

	b.lock.Lock()
	defer b.lock.Unlock()

	if c, ok := b.clients[tenant]; ok {
		return c, nil
	}

	cfg, err := getTenantConfig(ctx, s, tenant)
	if err != nil {
		return nil, err
	}

	if cfg == nil {
		return nil, fmt.Errorf("tenant %q is not configured", tenant)
	}

	// The Management API token source outlives the request context.
	c, err = newAuth0Client(cfg, b.httpClient) //nolint:contextcheck
	if err != nil {
		return nil, err
	}

	b.clients[tenant] = c

	return c, nil
}
