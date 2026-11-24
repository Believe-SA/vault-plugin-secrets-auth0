#!/usr/bin/env python3
"""Integration tests of the plugin in a real Vault dev server (see make test-vault).

Registers the built binary with its sha256 and version, mounts it pinned and
exercises every path. Auth0 is never reached: creds reads must fail cleanly.
"""

import hashlib
import http.client
import json
import os
import sys
from urllib.parse import urlsplit

ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
TOKEN = os.environ.get("VAULT_TOKEN", "root")
BINARY = os.environ.get("PLUGIN_BINARY", "bin/linux/vault-plugin-secrets-auth0")
VERSION = os.environ["PLUGIN_VERSION"]


def call(method, path, data=None):
    # http.client only speaks HTTP(S), unlike urllib (file://...).
    url = urlsplit(ADDR)
    conn_class = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
    conn = conn_class(url.netloc, timeout=30)
    try:
        conn.request(
            method,
            f"/v1/{path}",
            body=json.dumps(data) if data is not None else None,
            headers={"X-Vault-Token": TOKEN},
        )
        resp = conn.getresponse()
        body = resp.read()
        return resp.status, json.loads(body) if body else {}
    finally:
        conn.close()


def ok(method, path, data=None):
    status, body = call(method, path, data)
    assert status < 300, f"{method} {path}: HTTP {status} {body}"
    return body


def fails(method, path, data=None, contains=""):
    status, body = call(method, path, data)
    assert status >= 400, f"{method} {path}: expected an error, got HTTP {status}"
    errors = " ".join(body.get("errors", []))
    assert contains in errors, f"{method} {path}: {contains!r} not in {errors!r}"


def main():
    with open(BINARY, "rb") as f:
        sha256 = hashlib.sha256(f.read()).hexdigest()

    # Catalog registration: Vault checks the sha256 and the reported version.
    plugin = {"sha256": sha256, "command": "vault-plugin-secrets-auth0", "version": f"v{VERSION}"}
    ok("PUT", "sys/plugins/catalog/secret/auth0", plugin)
    fails("PUT", "sys/plugins/catalog/secret/auth0-bad", {**plugin, "version": "v9.9.9"}, "version")
    ok("PUT", "sys/plugins/pins/secret/auth0", {"version": f"v{VERSION}"})
    ok("POST", "sys/mounts/auth0", {"type": "auth0"})
    mount = ok("GET", "sys/mounts/auth0")
    running = mount.get("running_plugin_version") or mount.get("data", {}).get("running_plugin_version")
    assert running == f"v{VERSION}", f"running version {running}"

    # Tenants: the secret is write-only, "tenants" is reserved.
    fails("PUT", "auth0/example/config", {"domain": "x"}, "required")
    fails("PUT", "auth0/tenants/config", {"domain": "x", "client_id": "a", "client_secret": "b"}, "reserved")
    # Unreachable domain: creds reads fail fast without reaching Auth0.
    ok("PUT", "auth0/example/config", {"domain": "127.0.0.1:1", "client_id": "a", "client_secret": "b"})
    config = ok("GET", "auth0/example/config")["data"]
    assert "client_secret" not in config, config
    assert ok("LIST", "auth0/tenants")["data"]["keys"] == ["example"]

    # Roles.
    role = {
        "grants": {"https://api.example.com/api": "read:x write:x"},
        "client_metadata": {"ratelimit_tier": "gold"},
        "name_template": '{{ printf "vault-%s-%s" .RoleName (random 4) }}',
        "ttl": 600,
        "max_ttl": 3600,
    }
    fails("PUT", "auth0/example/roles/ci", {"ttl": 60}, "grants is required")
    fails("PUT", "auth0/example/roles/ci", {**role, "name_template": "{{ .Oops"}, "invalid name_template")
    fails("PUT", "auth0/example/roles/ci", {**role, "ttl": 7200}, "max_ttl")
    ok("PUT", "auth0/example/roles/ci", role)
    read = ok("GET", "auth0/example/roles/ci")["data"]
    assert read["grants"] == role["grants"] and read["client_metadata"] == role["client_metadata"], read
    assert read["ttl"] == 600 and read["max_ttl"] == 3600, read
    assert ok("LIST", "auth0/example/roles")["data"]["keys"] == ["ci"]

    # Plugin reload keeps the mount working.
    ok("PUT", "sys/plugins/reload/backend", {"mounts": ["auth0/"]})
    ok("GET", "auth0/example/roles/ci")

    fails("GET", "auth0/example/creds/missing", contains="not found")
    fails("GET", "auth0/example/creds/ci", contains="creating client")

    # Cleanup order: roles first.
    fails("DELETE", "auth0/example/config", contains="still has")
    ok("DELETE", "auth0/example/roles/ci")
    ok("DELETE", "auth0/example/config")
    ok("DELETE", "sys/mounts/auth0")

    print(f"OK: plugin v{VERSION} on Vault {ok('GET', 'sys/seal-status')['version']}")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as e:
        sys.exit(f"FAIL: {e}")
