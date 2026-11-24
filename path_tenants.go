package auth0

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// reservedTenant is the path segment listing tenants, so it can't be a tenant name.
const reservedTenant = "tenants"

type tenantConfig struct {
	Domain       string `json:"domain"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func tenantPrefix(tenant string) string    { return "tenant/" + tenant + "/" }
func tenantConfigKey(tenant string) string { return tenantPrefix(tenant) + "config" }

// getString returns a string field; the framework guarantees its type.
func getString(d *framework.FieldData, key string) string {
	v, _ := d.Get(key).(string)

	return v
}

func tenantField() *framework.FieldSchema {
	return &framework.FieldSchema{Type: framework.TypeString, Description: "Auth0 tenant name, e.g. example."}
}

func pathTenants(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "tenants/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathTenantList},
			},
			HelpSynopsis: "List configured tenants.",
		},
		{
			Pattern: framework.GenericNameRegex("tenant") + "/config$",
			Fields: map[string]*framework.FieldSchema{
				"tenant": tenantField(),
				"domain": {
					Type:        framework.TypeString,
					Description: "Auth0 tenant domain, e.g. example.eu.auth0.com.",
				},
				"client_id": {
					Type:        framework.TypeString,
					Description: "Client ID of the Management API M2M client.",
				},
				"client_secret": {
					Type:        framework.TypeString,
					Description: "Client secret of the Management API M2M client. Never returned.",
					DisplayAttrs: &framework.DisplayAttributes{
						Sensitive: true,
					},
				},
			},
			ExistenceCheck: b.tenantExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.pathTenantWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathTenantWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathTenantRead},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathTenantDelete},
			},
			HelpSynopsis: "Configure the Management API credentials of an Auth0 tenant.",
		},
	}
}

func getTenantConfig(ctx context.Context, s logical.Storage, tenant string) (*tenantConfig, error) {
	entry, err := s.Get(ctx, tenantConfigKey(tenant))
	if err != nil || entry == nil {
		return nil, err
	}

	cfg := &tenantConfig{}

	err = entry.DecodeJSON(cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func (b *backend) tenantExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	cfg, err := getTenantConfig(ctx, req.Storage, getString(d, "tenant"))

	return cfg != nil, err
}

func (b *backend) pathTenantList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, "tenant/")
	if err != nil {
		return nil, err
	}

	for i, k := range keys {
		keys[i] = strings.TrimSuffix(k, "/")
	}

	return logical.ListResponse(keys), nil
}

func (b *backend) pathTenantWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tenant := getString(d, "tenant")
	if tenant == reservedTenant {
		return logical.ErrorResponse("%q is a reserved name", reservedTenant), nil
	}

	cfg, err := getTenantConfig(ctx, req.Storage, tenant)
	if err != nil {
		return nil, err
	}

	if cfg == nil {
		cfg = &tenantConfig{}
	}

	if v, ok := d.GetOk("domain"); ok {
		cfg.Domain, _ = v.(string)
	}

	if v, ok := d.GetOk("client_id"); ok {
		cfg.ClientID, _ = v.(string)
	}

	if v, ok := d.GetOk("client_secret"); ok {
		cfg.ClientSecret, _ = v.(string)
	}

	if cfg.Domain == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return logical.ErrorResponse("domain, client_id and client_secret are required"), nil
	}

	entry, err := logical.StorageEntryJSON(tenantConfigKey(tenant), cfg)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	b.resetTenant(tenant)

	return nil, nil
}

func (b *backend) pathTenantRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := getTenantConfig(ctx, req.Storage, getString(d, "tenant"))
	if err != nil || cfg == nil {
		return nil, err
	}

	return &logical.Response{Data: map[string]any{
		"domain":    cfg.Domain,
		"client_id": cfg.ClientID,
	}}, nil
}

func (b *backend) pathTenantDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tenant := getString(d, "tenant")

	roles, err := req.Storage.List(ctx, rolePrefix(tenant))
	if err != nil {
		return nil, err
	}

	if len(roles) > 0 {
		return logical.ErrorResponse("tenant %q still has %d role(s)", tenant, len(roles)), nil
	}

	err = req.Storage.Delete(ctx, tenantConfigKey(tenant))
	if err != nil {
		return nil, fmt.Errorf("deleting tenant config: %w", err)
	}

	b.resetTenant(tenant)

	return nil, nil
}
