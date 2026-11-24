package auth0

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/template"
	"github.com/hashicorp/vault/sdk/logical"
)

// Same syntax and fields as the database engines' username_template.
const defaultNameTemplate = `{{ printf "vault-%s-%s" .RoleName (random 8) }}`

type role struct {
	// audience -> scopes
	Grants       map[string][]string `json:"grants,omitempty"`
	NameTemplate string              `json:"name_template,omitempty"`
	// Copied to the created clients, e.g. ratelimit_tier
	ClientMetadata map[string]string `json:"client_metadata,omitempty"`
	TTL            time.Duration     `json:"ttl,omitempty"`
	MaxTTL         time.Duration     `json:"max_ttl,omitempty"`
}

func rolePrefix(tenant string) string    { return tenantPrefix(tenant) + "roles/" }
func roleKey(tenant, name string) string { return rolePrefix(tenant) + name }

func pathRoles(b *backend) []*framework.Path {
	tenant := framework.GenericNameRegex("tenant")

	return []*framework.Path{
		{
			Pattern: tenant + "/roles/?$",
			Fields:  map[string]*framework.FieldSchema{"tenant": tenantField()},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathRoleList},
			},
			HelpSynopsis: "List the roles of a tenant.",
		},
		{
			Pattern: tenant + "/roles/" + framework.GenericNameRegex("name") + "$",
			Fields: map[string]*framework.FieldSchema{
				"tenant": tenantField(),
				"name": {
					Type:        framework.TypeString,
					Description: "Role name.",
				},
				"grants": {
					Type:        framework.TypeKVPairs,
					Description: "audience=space-separated scopes, one entry per API.",
				},
				"client_metadata": {
					Type:        framework.TypeKVPairs,
					Description: "Metadata set on the created clients, e.g. ratelimit_tier=gold.",
				},
				"name_template": {
					Type:        framework.TypeString,
					Description: "Template of the created client name, with .RoleName and .DisplayName.",
					Default:     defaultNameTemplate,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease TTL.",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum lease TTL.",
				},
			},
			ExistenceCheck: b.roleExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRoleRead},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRoleDelete},
			},
			HelpSynopsis: "Manage dynamic client roles.",
		},
	}
}

func getRole(ctx context.Context, s logical.Storage, tenant, name string) (*role, error) {
	entry, err := s.Get(ctx, roleKey(tenant, name))
	if err != nil || entry == nil {
		return nil, err
	}

	r := &role{}

	err = entry.DecodeJSON(r)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func (b *backend) roleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	r, err := getRole(ctx, req.Storage, getString(d, "tenant"), getString(d, "name"))

	return r != nil, err
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, rolePrefix(getString(d, "tenant")))
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(keys), nil
}

func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tenant := getString(d, "tenant")
	name := getString(d, "name")

	cfg, err := getTenantConfig(ctx, req.Storage, tenant)
	if err != nil {
		return nil, err
	}

	if cfg == nil {
		return logical.ErrorResponse("tenant %q is not configured", tenant), nil
	}

	r, err := getRole(ctx, req.Storage, tenant, name)
	if err != nil {
		return nil, err
	}

	if r == nil {
		r = &role{}
	}

	r.update(d)

	msg := r.validate(name)
	if msg != "" {
		return logical.ErrorResponse(msg), nil
	}

	entry, err := logical.StorageEntryJSON(roleKey(tenant, name), r)
	if err != nil {
		return nil, err
	}

	return nil, req.Storage.Put(ctx, entry)
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	r, err := getRole(ctx, req.Storage, getString(d, "tenant"), getString(d, "name"))
	if err != nil || r == nil {
		return nil, err
	}

	grants := map[string]string{}
	for aud, scopes := range r.Grants {
		grants[aud] = strings.Join(scopes, " ")
	}

	return &logical.Response{Data: map[string]any{
		"grants":          grants,
		"client_metadata": r.ClientMetadata,
		"name_template":   r.NameTemplate,
		"ttl":             int64(r.TTL.Seconds()),
		"max_ttl":         int64(r.MaxTTL.Seconds()),
	}}, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, req.Storage.Delete(ctx, roleKey(getString(d, "tenant"), getString(d, "name")))
}

// update sets the role fields present in the request.
func (r *role) update(d *framework.FieldData) {
	if v, ok := d.GetOk("grants"); ok {
		grants, _ := v.(map[string]string)

		r.Grants = map[string][]string{}
		for aud, scopes := range grants {
			r.Grants[aud] = strings.Fields(scopes)
		}
	}

	if v, ok := d.GetOk("client_metadata"); ok {
		r.ClientMetadata, _ = v.(map[string]string)
	}

	if v, ok := d.GetOk("ttl"); ok {
		ttl, _ := v.(int)
		r.TTL = time.Duration(ttl) * time.Second
	}

	if v, ok := d.GetOk("max_ttl"); ok {
		maxTTL, _ := v.(int)
		r.MaxTTL = time.Duration(maxTTL) * time.Second
	}

	if v, ok := d.GetOk("name_template"); ok {
		r.NameTemplate, _ = v.(string)
	} else if r.NameTemplate == "" {
		r.NameTemplate = defaultNameTemplate
	}
}

// validate returns an error message, or "" when the role is valid.
func (r *role) validate(name string) string {
	_, err := clientName(r.NameTemplate, name, "oidc-john.doe@example.com")
	if err != nil {
		return "invalid name_template: " + err.Error()
	}

	if len(r.Grants) == 0 {
		return "grants is required"
	}

	if r.MaxTTL > 0 && r.TTL > r.MaxTTL {
		return "ttl can't be greater than max_ttl"
	}

	return ""
}

type nameData struct {
	RoleName    string
	DisplayName string
}

// clientName renders the role's name template for the requesting token.
func clientName(tmpl, roleName, displayName string) (string, error) {
	t, err := template.NewTemplate(template.Template(tmpl))
	if err != nil {
		return "", err
	}

	name, err := t.Generate(nameData{RoleName: roleName, DisplayName: displayName})
	if err != nil {
		return "", err
	}

	if name == "" {
		return "", errors.New("template renders an empty name")
	}

	return name, nil
}
