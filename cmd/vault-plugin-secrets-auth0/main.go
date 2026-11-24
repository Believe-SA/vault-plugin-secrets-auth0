// Command vault-plugin-secrets-auth0 serves the Auth0 secrets engine plugin.
package main

import (
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/plugin"

	auth0 "github.com/Believe-SA/vault-plugin-secrets-auth0"
)

func main() {
	err := plugin.ServeMultiplex(&plugin.ServeOpts{BackendFactoryFunc: auth0.Factory})
	if err != nil {
		hclog.New(&hclog.LoggerOptions{}).Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
