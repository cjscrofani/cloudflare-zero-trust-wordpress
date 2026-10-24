=== Zero Trust Login for Cloudflare ===
Contributors: cjscrofani
Tags: cloudflare, zero trust, sso, oidc, login
Requires at least: 5.0
Tested up to: 7.1
Requires PHP: 7.2
Stable tag: 2.1.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Sign in to WordPress with your Cloudflare Zero Trust identity over OpenID Connect. One-token setup, role mapping, backup codes, audit log.

== Description ==

Zero Trust Login for Cloudflare turns a Cloudflare Access application into a WordPress login. Your users sign in with whatever identity provider you have connected to Cloudflare Zero Trust (Google Workspace, Microsoft Entra, Okta, GitHub, one-time PIN and so on), and WordPress trusts the result.

**Set up in minutes.** Paste a scoped Cloudflare API token and the setup wizard discovers your account, creates the Access application with the right redirect URL and scopes, attaches an allow policy, and stores the credentials. The token is used once and never saved. Manual setup with an existing application is also supported.

**Cloudflare-only or side by side.** Primary mode makes Cloudflare the only way in: WordPress passwords never grant access and the password-reset and registration screens are refused. Secondary mode adds a "Login with Cloudflare Zero Trust" button next to the normal form.

**Users and roles follow your identity provider.** Accounts can be created on first login with the email address as the username. Identity-provider groups map to WordPress roles and are re-applied on every login, and email-domain restrictions are enforced every time.

**Built for the failure cases.** Per-browser login state, a rate limiter that trusts forwarding headers only from Cloudflare's own IP ranges, ten one-time backup codes per account for the day your identity provider is down, encrypted write-only client secrets, and an audit log with CSV export.

= Features =

* OpenID Connect sign-in against Cloudflare Access SaaS or self-hosted applications
* Automatic provisioning of the Access application from inside wp-admin
* Primary (Cloudflare only) and secondary (side by side) login modes
* Automatic user creation with a configurable default role
* Identity-provider group to WordPress role mapping
* Email-domain restrictions checked on every login
* One-time backup codes usable in either login mode
* Client secret encrypted at rest (AES-256-CBC when OpenSSL is available) and never shown again
* Credentials may be supplied through constants or environment variables instead of the database
* Rate limiting of failed attempts per IP
* Security headers on the login screen
* Dashboard, filterable authentication log and CSV export
* Settings import and export (everything except the client secret)
* Actions and filters for extending the login flow

= Requirements =

* A Cloudflare account with Zero Trust enabled (the free plan is sufficient)
* HTTPS on your WordPress site. Cloudflare will not accept a plain-HTTP redirect URL.
* The OpenSSL PHP extension is recommended so the client secret can be encrypted at rest

= External services =

This plugin connects to Cloudflare. No other third-party service is contacted.

**Cloudflare Access (your team domain, for example `yourteam.cloudflareaccess.com`)**
Used on every sign-in. The browser is redirected there to authenticate, and the plugin then calls the OpenID Connect token and userinfo endpoints on that domain server-to-server, sending the authorization code, your application's client ID and client secret, and receiving the signed-in user's email, name, subject identifier and group memberships. The plugin also fetches the OpenID discovery document from that domain when you use "Test Connection".

**Cloudflare API (`api.cloudflare.com`)**
Used only while you run the setup wizard, and only if you choose automatic setup. The API token you paste is sent with each request to verify the token, list the accounts it can reach, and create or update the Access application and its policy. Along with the token, the plugin sends your site's hostname, the redirect URL and the application name you entered. The token is held in memory for the duration of the request and is never stored.

Both services are provided by Cloudflare, Inc. and are governed by the Cloudflare [Terms of Service](https://www.cloudflare.com/terms/) and [Privacy Policy](https://www.cloudflare.com/privacypolicy/).

= Data stored by this plugin =

For each user who signs in through Cloudflare the plugin stores user meta: the Cloudflare subject identifier and issuer, the last login time, the authentication method, and hashed backup codes if any were generated. When logging is enabled, a custom table records authentication events with a timestamp, the email or username involved, outcome, IP address and user agent. All of this is removed when the plugin is uninstalled.

== Installation ==

1. Install the plugin from the WordPress plugin directory, or upload the zip under Plugins > Add New > Upload Plugin, then activate it.
2. Go to Settings > CF Zero Trust.
3. Choose **Automatic setup**, create a Cloudflare API token using the link in the wizard (it preselects the required permissions), paste it, and follow the steps. The wizard creates the Access application and saves its credentials.
4. Or choose **Manual setup**: create a SaaS application of type OIDC in Zero Trust > Access > Applications, set its redirect URL to `https://your-site/wp-login.php?cfzt_callback=1`, and copy the client ID and client secret into the plugin.
5. Log out and use the "Login with Cloudflare Zero Trust" button. Leave the login mode on **secondary** until you have confirmed a successful sign-in, then switch to **primary** if you want Cloudflare to be the only way in.

For a hardened install you can define `CFZT_CLIENT_ID` and `CFZT_CLIENT_SECRET` in `wp-config.php` or as environment variables so that the credentials never live in the database.

== Frequently Asked Questions ==

= What happens if my identity provider goes down and the site is in primary mode? =

Every account created through Cloudflare receives ten one-time backup codes, shown once on the user's profile. A backup code can be entered on the login screen in either mode. An administrator with server access can also switch the login mode back to secondary with WP-CLI: `wp option patch update cfzt_settings login_mode secondary`.

= Does this plugin store my Cloudflare API token? =

No. The token is used by the setup wizard for the requests needed to create the Access application and is then discarded. Only the resulting client ID and client secret are stored, and the secret is encrypted.

= Can existing WordPress users sign in with Cloudflare? =

Yes. Users are matched by email address. If a WordPress account with the same email exists, the Cloudflare identity is linked to it on first sign-in.

= Does it work with a self-hosted Access application instead of a SaaS one? =

Yes. Choose the self-hosted application type in the settings. The plugin uses the `get-identity` endpoint on your team domain for that type.

= Does the plugin phone home? =

No. The only network connections are to Cloudflare, as described under External services.

= Where is the audit log? =

Tools > CF Zero Trust Logs. It can be filtered by level, date, method and outcome, exported as CSV, or cleared.

== Screenshots ==

1. The WordPress login form with the "Login with Cloudflare Zero Trust" button and the backup-code link.

== Changelog ==

= 2.1.1 =
* Fixed the advanced settings page showing no fields in 2.1.0. The wizard, the login flow and saved settings were not affected.
* Removed the unused `Domain Path` plugin header.

= 2.1.0 =
* Renamed to Zero Trust Login for Cloudflare, with a matching text domain, for distribution through the WordPress plugin directory. Existing installs keep their settings and folder.
* All output is escaped and all request input is unslashed and sanitized according to the WordPress coding standards.
* Translator comments added to every string with a placeholder; two strings now use numbered placeholders.
* Token and userinfo failures are written to the plugin's own log instead of the PHP error log; the PHP error log is used only when `WP_DEBUG` is on.
* The WordPress.org package no longer contains the GitHub update checker.

= 2.0.0 =
* Automatic provisioning of the Cloudflare Access application from inside wp-admin.
* Removed SAML support; the implementation did not validate signatures. Sites using SAML are moved to OIDC on upgrade, and sites that were in primary mode are moved back to secondary so nobody is locked out.
* Client secret is now write-only and never included in settings exports.
* Per-browser OIDC state and nonce, forwarding headers trusted only from Cloudflare's IP ranges, and a number of smaller audit fixes.

= 1.0.5 =
* Security: fixed a primary-mode bypass. All 1.0.x sites should update.

The complete changelog is in the plugin's GitHub repository.

== Upgrade Notice ==

= 2.1.1 =
Fixes the blank advanced settings page in 2.1.0. No settings changes required.

= 2.1.0 =
Rename and coding-standards release ahead of WordPress.org listing. No settings changes required.

= 2.0.0 =
SAML has been removed and the client secret is stored differently. Read the upgrade notes before updating from 1.x.
