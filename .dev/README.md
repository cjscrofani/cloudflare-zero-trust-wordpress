# Local test environment

A disposable WordPress install for working on this plugin. Requires Docker
(OrbStack, Docker Desktop or Colima). The plugin is bind-mounted from the repo
root, so edits on the host are live — no rebuild, no reinstall.

```bash
.dev/bin/dev up
```

That starts MariaDB and WordPress, installs WordPress, activates the plugin and
prints the URL. Then open the settings page it gives you and log in with
`admin` / `admin`.

```
.dev/bin/dev up              start and install
.dev/bin/dev down            stop, keep data
.dev/bin/dev destroy         stop and delete all data
.dev/bin/dev wp <args>       run WP-CLI (e.g. .dev/bin/dev wp option list)
.dev/bin/dev state           print the plugin's stored settings
.dev/bin/dev reset           settings back to fresh-install
.dev/bin/dev seed-saml       fake a pre-2.0.0 SAML install (migration test)
.dev/bin/dev logs [service]  tail logs
.dev/bin/dev tunnel          expose the site publicly via cloudflared
```

## HTTPS

The plugin requires HTTPS: `is_ssl()` gates several warnings, and Cloudflare
will not accept an `http://` redirect URI.

On **OrbStack** this is free. The `dev.orbstack.domains` label publishes the
container at `https://cfzt.local` with OrbStack's own CA, which it installs into
the macOS keychain — so the certificate is already trusted by your browser and
by `curl`, with nothing to configure.

On **Docker Desktop or Colima** that label does nothing. Either use the
cloudflared tunnel below, or put your own TLS proxy in front and set `SITE_URL`
to match.

TLS terminates at the proxy, so `wp-config.php` promotes
`X-Forwarded-Proto: https` into `$_SERVER['HTTPS']`. Without that WordPress
redirect-loops and `is_ssl()` returns false.

## Testing the migration from 1.x

The riskiest path in 2.0.0 is the SAML removal: a site running SAML in
**primary** login mode has the WordPress login form disabled, and the only
other way in was just deleted. If the migration misbehaves, that site is
unreachable.

```bash
.dev/bin/dev seed-saml                  # pre-2.0.0 state: SAML + primary mode
open https://cfzt.local/wp-admin/       # loading any admin page runs the migration
.dev/bin/dev state                      # inspect the result
```

Expect all of:

- `auth_method` is `oauth2`, `login_mode` is `secondary`
- the `saml_*` keys are gone, `cfzt_version` is `2.0.0`
- a "SAML support has been removed" notice that says the login mode was changed
- **`/wp-login.php` still shows a normal login form** — the actual anti-lockout check

## Testing against real Cloudflare

Provisioning only makes **outbound** calls, so the local site does not need to
be publicly reachable for the wizard to work: Cloudflare redirects the
*browser* back, not the server. A locally-trusted hostname is enough to test
the wizard, the API client and every error path.

What it is *not* enough for is confirming that Cloudflare accepts the redirect
URI, since it may reject a non-public hostname — which would be
indistinguishable from it rejecting the `?cfzt_callback=1` query string. For
that, get a real public hostname:

1. In Cloudflare Zero Trust → Networks → Tunnels, create a tunnel, add a public
   hostname on a domain in your account, and point it at `http://wordpress:80`.
2. Put the tunnel token in `.dev/.env` (copy `.dev/.env.example`), and set
   `SITE_URL` and `DEV_DOMAIN` to that hostname.
3. `.dev/bin/dev down && .dev/bin/dev up && .dev/bin/dev tunnel`

`SITE_URL` is baked into the database at install time, so change it *before*
the first `up`, or run `.dev/bin/dev destroy` first.

## Checks that need no Cloudflare account

```bash
# PHP syntax, all files
docker run --rm -v "$PWD":/app -w /app php:8.2-cli \
  sh -c 'for f in includes/*.php templates/*.php *.php; do php -l "$f"; done'

# AJAX guards: nonce, capability, token shape
# (grab the nonce from the settings page HTML: cfztSetupNonce = "...")
curl -sS -b cookies.txt -X POST https://cfzt.local/wp-admin/admin-ajax.php \
  -d "action=cfzt_connect_cloudflare&token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
# -> cfzt_bad_nonce
```

A well-formed but invalid token is a useful test on its own: it exercises the
real API round-trip and the error mapping without needing valid credentials.
It should come back as `cfzt_api_unauthorized` with a readable message.

## Note on the plugin writing to the repo

The plugin regenerates `assets/js/cfzt-admin.js` at runtime, so the bind mount
is read-write and the container can modify that tracked file. If it shows up
dirty in `git status` after running the env, that is why.
