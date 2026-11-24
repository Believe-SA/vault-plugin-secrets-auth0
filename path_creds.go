package auth0

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const walTypeClient = "client"

type walClient struct {
	Tenant   string `json:"tenant" mapstructure:"tenant"`
	ClientID string `json:"client_id" mapstructure:"client_id"`
}

func pathCreds(b *backend) []*framework.Path {
	return []*framework.Path{{
		Pattern: framework.GenericNameRegex("tenant") + "/creds/" + framework.GenericNameRegex("role") + "$",
		Fields: map[string]*framework.FieldSchema{
			"tenant": tenantField(),
			"role":   {Type: framework.TypeString, Description: "Role name."},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.pathCredsRead},
		},
		HelpSynopsis: "Create a dynamic M2M client, deleted when the lease ends.",
	}}
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tenant := getString(d, "tenant")
	name := getString(d, "role")

	r, err := getRole(ctx, req.Storage, tenant, name)
	if err != nil {
		return nil, err
	}

	if r == nil {
		return logical.ErrorResponse("role %q not found in tenant %q", name, tenant), nil
	}

	c, err := b.getClient(ctx, req.Storage, tenant)
	if err != nil {
		return nil, err
	}

	appName, err := clientName(r.NameTemplate, name, req.DisplayName)
	if err != nil {
		return nil, err
	}

	clientID, clientSecret, err := c.createClient(ctx, appName,
		fmt.Sprintf("Managed by Vault role %s/%s for %s", tenant, name, req.DisplayName), r.ClientMetadata)
	if err != nil {
		return nil, err
	}

	// The WAL deletes the client if Vault dies before the lease exists.
	walID, err := framework.PutWAL(ctx, req.Storage, walTypeClient, &walClient{Tenant: tenant, ClientID: clientID})
	if err != nil {
		return nil, b.cleanup(ctx, c, clientID, fmt.Errorf("writing WAL: %w", err))
	}

	err = createGrants(ctx, c, clientID, r.Grants)
	if err != nil {
		return nil, b.cleanup(ctx, c, clientID, err)
	}

	resp := b.Secret(secretClientType).Response(
		map[string]any{
			"client_id":     clientID,
			"client_secret": clientSecret,
			"client_name":   appName,
		},
		map[string]any{
			"tenant":    tenant,
			"role":      name,
			"client_id": clientID,
		},
	)
	resp.Secret.TTL = r.TTL
	resp.Secret.MaxTTL = r.MaxTTL

	err = framework.DeleteWAL(ctx, req.Storage, walID)
	if err != nil {
		return nil, fmt.Errorf("deleting WAL: %w", err)
	}

	return resp, nil
}

// createGrants creates the grants of a client, in a stable order.
func createGrants(ctx context.Context, c *auth0Client, clientID string, grants map[string][]string) error {
	for _, aud := range slices.Sorted(maps.Keys(grants)) {
		err := c.createGrant(ctx, clientID, aud, grants[aud])
		if err != nil {
			return err
		}
	}

	return nil
}

// cleanup deletes a half-created client; on failure the WAL retries later.
func (b *backend) cleanup(ctx context.Context, c *auth0Client, clientID string, cause error) error {
	err := c.deleteClient(ctx, clientID)
	if err != nil {
		b.Logger().Warn("failed to delete client, WAL will retry", "client_id", clientID, "error", err)
	}

	return cause
}

func (b *backend) walRollback(ctx context.Context, req *logical.Request, kind string, data any) error {
	if kind != walTypeClient {
		return fmt.Errorf("unknown WAL type %q", kind)
	}

	entry, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("unexpected WAL data %T", data)
	}

	tenant, _ := entry["tenant"].(string)
	clientID, _ := entry["client_id"].(string)

	c, err := b.getClient(ctx, req.Storage, tenant)
	if err != nil {
		return err
	}

	return c.deleteClient(ctx, clientID)
}
