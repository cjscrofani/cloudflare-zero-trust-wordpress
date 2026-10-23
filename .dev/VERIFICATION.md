# 2.0.0 pre-release verification

Status as of 2026-10-23. 2.0.0 is code-complete on
`feat/auto-provisioning-and-saml-removal`. **All three release-gate checks have passed** against a real Cloudflare account on a public
hostname. The remaining items are the two known gaps below and a release decision.

## Release gate

The plugin self-updates from GitHub releases. Tagging 2.0.0 offers it to existing 1.0.4
installs immediately, and that upgrade runs a migration that can change a site's login
mode — so finish the two outstanding checks before tagging. If you want to release other
work sooner, hold the version bump back rather than shipping an unverified 2.0.0.

## Outstanding — needs your Cloudflare account

### 1. Token deep link preselects the permissions — DONE 2026-10-23

Confirmed against the live dashboard. The original keys (`access_apps_write`,
`access_organizations_write`) were wrong: the dashboard filled in the token name but left
Permissions empty. The permission-group `label` values (`access_write`, `access_acct_read`)
were wrong too. The template URL wants the keys from Cloudflare's [API token template
URLs](https://developers.cloudflare.com/fundamentals/api/how-to/account-owned-token-template/)
reference, which are the labels without their read/write suffix:

```
access       (edit)  → Account · Access: Apps and Policies · Edit
access_acct  (read)  → Account · Access: Organizations, Identity Providers, and Groups · Read
```

With those, both rows preselect and Account Resources defaults to "All accounts". Fixed in
`class-cfzt-provisioner.php`.

### 2. Cloudflare accepts the redirect URI — DONE 2026-10-23

Provisioned for real against a public hostname (the GDWS Sandbox on Cloudways,
`https://wordpress-1180674-6746829.cloudwaysapps.com`). Cloudflare accepted

```
https://<host>/wp-login.php?cfzt_callback=1
```

without complaint, created the SaaS OIDC application and policy, and the plugin saved the
team domain, client ID and secret. No rewrite-path migration is needed.

Three bugs surfaced on the way and are fixed on the branch:

- With only the two Access permissions, `GET /accounts` returns an empty list and the wizard
  stops at "This token cannot see any Cloudflare accounts." Adding **Account Settings: Read**
  to the token fixed it; the deep link, prose and error message now include it.
- The saved client secret was encrypted twice (provisioner + settings sanitizer), so login
  would have failed at the token exchange.
- The provenance keys were dropped on a first provision for the same sanitizer reason.

### 3. Then: actually log in — DONE 2026-10-23

Full round trip completed on the sandbox: login button → Cloudflare Access (the client's
team, Google IdP) → callback with `code` and `state` → WordPress session. The plugin created
the user from the IdP identity with `cfzt_user`, `cfzt_auth_method=oidc`, `cfzt_sub` and
`cfzt_last_login` meta, as a subscriber (the default role). One wrinkle: the wizard's policy
defaulted to the WordPress admin email's domain (`gdws.co`), which did not match the identity
provider's domain, so Access denied the first attempt until the policy was widened. Worth a
clearer hint in the wizard about which email domains the IdP actually issues.

Also found and fixed on the sandbox: **ordinary password logins were rejected in secondary
mode** by the backup-code handler (shipped in 1.0.4; see CHANGELOG).

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


## 2026-10-23 (later): post-audit fixes

Three independent reviewers audited the branch (see `AUDIT-2026-10-23.md`). All findings
were fixed the same day. Automated checks run against the local dev site are listed in
the audit file's Resolution note. On the sandbox:

- Deployed the fixed tree; set `cfzt_version` back to `1.0.4` and loaded a page: the
  upgrade ran on `init`, re-encoded the stored secret with the `cfzt-enc:v1:` marker,
  and it still decrypts.
- `GET wp-login.php?cfzt_action=login` redirects to the Cloudflare authorization URL with
  a fresh `state` and `nonce`, scope `openid email profile groups`, and sets the
  `cfzt_oidc_flow` cookie (HttpOnly, Secure, SameSite=Lax, 10 minutes).
- Real login round trip through Cloudflare (2026-10-23 23:40 UTC): clicked "Login with
  Cloudflare Zero Trust" on the sandbox, signed in through a Google Workspace identity,
  and landed in wp-admin (profile page, as a Subscriber).
  Server side: `cfzt_last_login` updated, `cfzt_auth_method=oidc`, role unchanged. This
  exercised the per-browser state cookie, the state check, the ID-token nonce/audience/
  issuer check and the `groups` scope against live Cloudflare Access.

## 2026-10-23 (release path)

- Built `dist/cloudflare-zero-trust-login-1.0.5.zip` from tag `v1.0.5` and
  `dist/cloudflare-zero-trust-login-2.0.0.zip` from the `release/2.0.0` merge, both with
  `git archive --prefix=cloudflare-zero-trust-login/`. Neither contains `.dev/`, `.github/`
  or Markdown; the 2.0.0 package carries `LICENSE`.
- Sandbox downgraded to 1.0.5 (secret rewritten to the unprefixed 1.x form), then upgraded
  to 2.0.0 by handing the 2.0.0 zip to the WordPress installer (`wp plugin install --force`,
  the same upgrader code path the self-updater uses). Result: one plugin folder, plugin
  active, `cfzt_version` 2.0.0, secret re-encoded with the `cfzt-enc:v1:` marker and still
  decrypting, front page 200, login start redirect requesting `openid email profile groups`.
- 1.0.5 itself was smoke-tested on the sandbox before the upgrade: per-browser state cookie
  set, callback refused without the cookie, password login yields a password error again.
