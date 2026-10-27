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

## Testing activation and upgrade paths

`CFZT_Plugin::get_instance()` runs `run_upgrades()` on every load and re-stamps `cfzt_version`,
so a version set with one WP-CLI call is already overwritten by the next call or page view.
To exercise the activation hook the way WordPress runs it (plugins_loaded already passed, only
`CFZT_Plugin` loaded), do everything in one process with the plugin skipped:

```bash
.dev/bin/dev wp --skip-plugins eval '
  update_option("cfzt_version", "1.0.4");
  include WP_PLUGIN_DIR . "/zero-trust-login-for-cloudflare/cloudflare-zero-trust-login.php";
  CFZT_Plugin::activate();
  echo "ok ", get_option("cfzt_version"), "\n";'
```

This is the path that fataled before 2.1.2. `wp plugin deactivate` / `activate` does not
reproduce it, because the surrounding WP-CLI calls load the plugin and run the migration first.

## Fetching admin pages from the shell

Port 80 is not published to the host; Chrome reaches the site through the tunnel. For curl,
run inside the container and mint a session for user 1 instead of logging in:

```bash
dcx() { docker compose -f .dev/docker-compose.yml exec -T wordpress "$@"; }
COOKIE=$(.dev/bin/dev wp eval 'echo "wordpress_sec_" . COOKIEHASH . "=" . wp_generate_auth_cookie(1, time()+1800, "secure_auth")
  . "; wordpress_logged_in_" . COOKIEHASH . "=" . wp_generate_auth_cookie(1, time()+1800, "logged_in");' 2>/dev/null | tail -1)
dcx curl -s -H 'Host: cfzt.local' -H 'X-Forwarded-Proto: https' -H "Cookie: $COOKIE" \
  'http://localhost/wp-admin/options-general.php?page=cf-zero-trust' | grep -o 'assets/[a-z/.-]*'
```

The admin account is the one `.dev/bin/dev up` creates (`ADMIN_USER`/`ADMIN_PASS` in `.env`,
or the defaults at the top of `.dev/bin/dev`). The site's stored client ID is a placeholder,
so the "Login with Cloudflare Zero Trust" button always fails with `invalid_client`; use the
WordPress form, or re-provision through the settings wizard with a real API token.

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

## Plugin Check

Plugin Check is installed in the test site (`wp plugin install plugin-check --activate` if it
is ever missing). Run it the way WordPress.org will see the package:

```bash
.dev/bin/dev wp plugin check zero-trust-login-for-cloudflare \
  --exclude-directories=.dev,.github,.wordpress-org,dist \
  --exclude-files=.gitattributes,.gitignore,README.md,CHANGELOG.md,SECURITY.md,class-github-updater.php
```

Expected: no findings. Drop the `class-github-updater.php` exclusion to see the GitHub
package's view, which reports only the updater itself. The CSV output (`--format=csv`) is
grouped by `FILE:` headers rather than being one flat table.

The plugin is mounted at `wp-content/plugins/zero-trust-login-for-cloudflare`, which matters:
Plugin Check derives the slug from the folder name and checks every text domain against it.

## Note on the bind mount

The mount is read-write so WordPress can write `debug.log` and so that
Plugin Check can be installed next to the plugin. Since 2.0.0 the plugin
itself no longer writes to its own folder (the on-disk JS/CSS generators were
removed), so a dirty `git status` after running the env is not expected.
