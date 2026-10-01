# 2.0.0 pre-release verification

Status as of 2026-10-01. 2.0.0 is code-complete on
`feat/auto-provisioning-and-saml-removal`. **Two checks remain, and both need a real
Cloudflare account.** Everything testable without one has been done.

## Release gate

The plugin self-updates from GitHub releases. Tagging 2.0.0 offers it to existing 1.0.4
installs immediately, and that upgrade runs a migration that can change a site's login
mode — so finish the two outstanding checks before tagging. If you want to release other
work sooner, hold the version bump back rather than shipping an unverified 2.0.0.

## Outstanding — needs your Cloudflare account

### 1. Token deep link preselects the permissions

Open the wizard's **Create a token on Cloudflare** link and confirm the Cloudflare token
screen arrives with permissions already selected, rather than showing an "unresolved
permission key" notice.

The short keys are **inferred, not confirmed**:

```
access_apps_write          (edit)
access_organizations_write (read)
```

If either is wrong, correct it via the `cfzt_token_permission_keys` filter, or read the
real keys from `GET /accounts/{id}/tokens/permission_groups`. The wizard already lists the
permissions in prose as a fallback, so a wrong key degrades to a manual step rather than a
broken token.

### 2. Cloudflare accepts the redirect URI

Run a real provision and watch for a validation error on `redirect_uris`. The URI contains
a query string:

```
https://<host>/wp-login.php?cfzt_callback=1
```

**If it is rejected, the fix is a real decision, not a detail.** The `cfzt_redirect_uri`
filter is a one-liner but leaves every install needing it. Moving to a rewrite path is the
correct fix, but it changes the callback URL and breaks existing 1.0.x installs whose
Cloudflare applications point at the old one — that needs a migration and a release note.

Note that `cfzt.local` may not be a hostname Cloudflare will accept, and a rejection there
is **indistinguishable** from a rejection of the query string. To get an unambiguous
answer, use the cloudflared tunnel (see `.dev/README.md`) so the site has a genuine public
hostname.

### 3. Then: actually log in

Provisioning succeeding does not prove the application works. A wrong scope or a missing
identity provider only shows up at login. Complete a full round trip.

## Verified

Done in the local environment on 2026-09-30/10-01.

| Check | Result |
|---|---|
| PHP 8.2 syntax, all files | pass |
| Both JS bundles via `node --check` | pass |
| Settings page renders, no PHP notices | pass |
| Provisioning panel present and wired | pass |
| Wizard is 3 tabs / 3 panels, correctly labelled | pass |
| Token deep link round-trips to valid JSON | pass (was broken, fixed in `cf606ec`) |
| HTTPS with a trusted cert, `is_ssl()` true | pass |
| AJAX: missing nonce rejected | `cfzt_bad_nonce` |
| AJAX: unauthenticated rejected | `0` |
| AJAX: malformed token rejected | `cfzt_malformed_token` |
| Live Cloudflare API error mapping, invalid token | `cfzt_api_unauthorized`, readable message |

### SAML migration, including the lockout path

The riskiest code in the release, verified end to end with `.dev/bin/dev seed-saml` —
seeding SAML **plus primary login mode**, where the WordPress login form is disabled and
the only other way in has been removed:

- `auth_method` → `oauth2`, `login_mode` → `secondary`
- `saml_*` keys dropped, `cfzt_version` → `2.0.0`
- notice shown, stating the login mode was changed
- **`/wp-login.php` still serves a working login form** — the actual anti-lockout check
- no PHP errors

## Known gaps

- No automated test suite. Everything above is manual or ad hoc.
- `CFZT_Cloudflare_API::API_BASE` is a hard constant, so API error paths cannot be
  exercised against a mock. Reading an optional `CFZT_CLOUDFLARE_API_BASE` constant would
  make offline testing of 403/404/duplicate-app/missing-secret paths possible. Prefer a
  constant over a filter: wp-config access is already trusted, whereas a filter widens the
  SSRF surface.
- `CFZT_Security::encrypt_data()` derives its IV from a salt, so every value encrypts under
  the same IV and identical secrets produce identical ciphertext. Pre-existing, unchanged
  here, worth fixing now that setup writes secrets automatically.
