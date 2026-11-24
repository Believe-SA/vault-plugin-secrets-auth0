package auth0

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const secretClientType = "auth0_client" //nolint:gosec // secret type name, not a credential

func secretClient(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: secretClientType,
		Fields: map[string]*framework.FieldSchema{
			"client_id":     {Type: framework.TypeString, Description: "Auth0 client ID."},
			"client_secret": {Type: framework.TypeString, Description: "Auth0 client secret."},
		},
		Renew:  b.secretClientRenew,
		Revoke: b.secretClientRevoke,
	}
}

func (b *backend) secretClientRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	tenant, _ := req.Secret.InternalData["tenant"].(string)
	name, _ := req.Secret.InternalData["role"].(string)

	r, err := getRole(ctx, req.Storage, tenant, name)
	if err != nil {
		return nil, err
	}

	if r == nil {
		return nil, fmt.Errorf("role %s/%s no longer exists", tenant, name)
	}

	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = r.TTL
	resp.Secret.MaxTTL = r.MaxTTL

	return resp, nil
}

func (b *backend) secretClientRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	tenant, _ := req.Secret.InternalData["tenant"].(string)

	clientID, _ := req.Secret.InternalData["client_id"].(string)
	if tenant == "" || clientID == "" {
		return nil, errors.New("secret is missing tenant or client_id")
	}

	c, err := b.getClient(ctx, req.Storage, tenant)
	if err != nil {
		return nil, err
	}

	return nil, c.deleteClient(ctx, clientID)
}
