package auth0

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/auth0/go-auth0/management"
	"golang.org/x/oauth2"
)

// auth0Client wraps the Management API of one tenant.
type auth0Client struct {
	mgmt *management.Management
}

func newAuth0Client(cfg *tenantConfig, httpClient *http.Client) (*auth0Client, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	// Long-lived context: the token source refreshes the Management API token.
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)

	mgmt, err := management.New(cfg.Domain,
		management.WithClientCredentials(ctx, cfg.ClientID, cfg.ClientSecret),
		management.WithClient(httpClient),
	)
	if err != nil {
		return nil, err
	}

	return &auth0Client{mgmt: mgmt}, nil
}

func (c *auth0Client) createClient(ctx context.Context, name, description string, metadata map[string]string) (string, string, error) {
	cl := &management.Client{
		Name:        new(name),
		Description: new(description),
		AppType:     new("non_interactive"),
		GrantTypes:  &[]string{"client_credentials"},
	}

	if len(metadata) > 0 {
		m := map[string]any{}
		for k, v := range metadata {
			m[k] = v
		}

		cl.ClientMetadata = &m
	}

	err := c.mgmt.Client.Create(ctx, cl)
	if err != nil {
		return "", "", fmt.Errorf("creating client: %w", err)
	}

	return cl.GetClientID(), cl.GetClientSecret(), nil
}

func (c *auth0Client) createGrant(ctx context.Context, clientID, audience string, scopes []string) error {
	g := &management.ClientGrant{
		ClientID: new(clientID),
		Audience: new(audience),
		Scope:    &scopes,
	}

	err := c.mgmt.ClientGrant.Create(ctx, g)
	if err != nil {
		return fmt.Errorf("creating grant for %s: %w", audience, err)
	}

	return nil
}

// deleteClient is idempotent: an already deleted client is not an error.
func (c *auth0Client) deleteClient(ctx context.Context, clientID string) error {
	err := c.mgmt.Client.Delete(ctx, clientID)

	var mErr management.Error
	if errors.As(err, &mErr) && mErr.Status() == http.StatusNotFound {
		return nil
	}

	if err != nil {
		return fmt.Errorf("deleting client %s: %w", clientID, err)
	}

	return nil
}
