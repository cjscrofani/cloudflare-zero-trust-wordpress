# Changelog

All notable changes to the Zero Trust Login for Cloudflare plugin (formerly Cloudflare Zero Trust Login for WordPress) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Removed the `Domain Path` plugin header. It pointed at an empty `languages/` folder that is
  not in release packages, which the WordPress.org submission scanner flagged. Translations
  are loaded by WordPress itself, so the header served no purpose.

## [2.1.0] - 2026-10-24

### Changed
- **Renamed to "Zero Trust Login for Cloudflare"** ahead of submission to the WordPress plugin
  directory, whose trademark rule does not allow a plugin name to begin with "Cloudflare".
  The text domain is now `zero-trust-login-for-cloudflare` to match the directory slug. The
  main plugin file keeps its name, so existing installs update in place and keep their
  settings; the GitHub updater renames new packages to whatever folder the site already uses.
- Every string with a placeholder now carries a translators comment, and two strings with
  more than one placeholder use numbered placeholders.
- Token and userinfo failures are recorded through the plugin's own logger (and so appear in
  the log viewer) instead of going straight to the PHP error log. The error log is now only
  written to when `WP_DEBUG` is on.
- `load_plugin_textdomain()` is no longer called; WordPress loads translations itself.

### Fixed
- Every echoed string is escaped for its context, and every request value is unslashed and
  sanitized before use, as the WordPress coding standards require. Plugin Check reports no
  errors on the WordPress.org package.
- Log queries always go through `$wpdb->prepare()`.
- Export filenames use `gmdate()` so they do not depend on the runtime timezone.

### Added
- `readme.txt` in the WordPress.org format, including the external-services disclosure.
- `.dev/bin/build-release --wporg` builds the WordPress.org package, which is the GitHub
  package without the GitHub update checker (directory guideline 8).
- Directory listing assets (icon, banners, screenshot) under `.wordpress-org/`.

## [2.0.0] - 2026-10-23

### Removed
- **BREAKING: SAML authentication has been removed.** The implementation never performed
  cryptographic signature validation, leaving it open to response tampering and replay, and
  it provided no capability the OIDC path lacks — both terminate at the same Cloudflare
  Access application. Rather than ship a known-vulnerable authentication path, it is gone:
  `class-cfzt-saml.php`, its settings, its rewrite endpoints and the PHP DOM requirement.
- The wizard's "Choose Method" step, which now had only one option, along with the
  SAML fields, warnings and health checks throughout the admin UI.
- The automatic dark-mode CSS, the one-option authentication-method selector, rewrite-rule
  flushing (nothing registers rewrite rules any more), the PHP-session "fingerprint" code
  (it was never called), and the on-disk JS/CSS generators, which duplicated the files in
  `assets/`.

### Migration
- Sites configured for SAML are switched to OIDC automatically on upgrade.
- **Sites using SAML in "Cloudflare only" login mode are moved back to "Cloudflare alongside
  WordPress login."** Without this they would have had no working way in: WordPress login was
  disabled and the only other path has been removed.
- The stored SAML settings are discarded, and a persistent admin notice explains what changed
  and links to OIDC setup.
- Migrations run on `init` and from the activation hook, so they cover background updates
  through the WordPress updater and manual reinstalls (deactivate, delete, upload, activate)
  alike.
- Client secrets saved by 1.x are re-encoded with the new encryption marker (see Fixed).

### Added
- **Automatic Cloudflare provisioning.** The setup wizard can now create the Zero Trust
  Access application for you. Paste a scoped API token once and the plugin discovers your
  account, reads your team domain, creates a SaaS OIDC application pointed at this site's
  callback URL, attaches an Access policy named "WordPress login (<host>)", and saves the
  credentials. The page then locks and reloads so stale form values cannot overwrite them.
  The manual instructions remain available as a fallback.
- Once the plugin has created an application the wizard shows a **Connected to Cloudflare**
  summary with a **Run automatic setup again** button. If an application already points at
  this site, **Replace the existing application** deletes it in Cloudflare before creating a
  new one, so no orphaned app with a lost secret is left behind.
- **Pre-filled API token link.** The wizard links to Cloudflare with the three required
  permissions already selected (Access: Apps and Policies → Edit; Access: Organizations,
  Identity Providers, and Groups → Read; Account Settings → Read), so the token can be
  created in a few clicks.
- The wizard's policy step explains that the identity-provider domain may differ from the
  WordPress admin email's domain, and the "everyone" option warns that, combined with
  auto-create, any identity the identity provider accepts gets a WordPress account.
- **`CFZT_Cloudflare_API`** — a minimal Cloudflare API v4 client covering the endpoints
  needed for provisioning.
- **`CFZT_Provisioner`** — provisioning logic that accepts any bearer token, so the
  credential source can change (for example to OAuth) without rewriting it.
- **`CFZT_Setup`** — admin-AJAX endpoints for the guided setup flow.
- **`CFZT_Plugin::get_redirect_uri()`** — single source of truth for the OIDC callback URL,
  filterable via `cfzt_redirect_uri`.
- **Local test environment** in `.dev/` — WordPress over HTTPS with the plugin
  bind-mounted, WP-CLI wired up, an optional cloudflared tunnel, and `dev seed-saml` to
  reproduce a pre-2.0.0 SAML install so the upgrade migration can be tested deliberately.
  `.dev/VERIFICATION.md` records the release-gate checks, all of which passed against a
  real Cloudflare account on 2026-10-23.

### Changed
- **New accounts use the full email address as the WordPress username** (for example
  `jane@example.com` rather than `jane`), so people from different domains are far less
  likely to collide or be renamed with a numeric suffix. Existing accounts are untouched.
  Filterable via `cfzt_new_username`.
- The login request now asks Cloudflare for the `groups` scope, so the groups claim that
  role mapping reads is actually sent. Provisioned applications already granted it.
- **Role mapping is re-applied on every login** for accounts the plugin created, whenever
  Cloudflare sends a group claim. Accounts made by hand keep their role. Disable with the
  `cfzt_sync_role_on_login` filter.
- **Email domain restrictions are checked on every Cloudflare login**, not only when an
  account is created.
- **The client secret is never displayed.** The settings field is always empty; leave it
  blank to keep the saved secret. Settings exports no longer contain it either, so enter it
  by hand after importing. Imports from 1.x exports, which carried it, still restore it.
- Login starts at a local endpoint (`wp-login.php?cfzt_action=login`) rather than a
  Cloudflare URL rendered into the page. The login button and primary-mode redirects point
  there; `CFZT_Auth::get_auth_url()` still works and returns it.
- A `redirect_to` on the login URL is now preserved through the Cloudflare round trip.
- Only failed attempts count towards the rate limit, so repeated successful logins never
  lock anyone out.
- Log retention raised from 1,000 to 10,000 rows (filterable via `cfzt_log_retention_rows`).
- Automatic setup is refused while `CFZT_CLIENT_ID` or `CFZT_CLIENT_SECRET` is defined in
  `wp-config.php`, instead of creating an application whose secret could never be stored.
- The plugin header now declares `Requires at least: 5.0` and `Requires PHP: 7.2`, so the
  WordPress updater enforces them instead of the activation hook alone.

### Security
All of the following were present in 1.0.4.
- **Primary ("Cloudflare only") mode could be bypassed.** Adding `?cfzt_callback=1` to
  `wp-login.php` switched the redirect off while WordPress's password check still ran, so a
  password login worked. The lost-password and registration screens were only hidden with
  CSS. A password now never grants access in primary mode, and the lost-password, reset and
  registration actions are refused server-side (filter `cfzt_primary_mode_blocked_actions`).
- **The OIDC `state` was a WordPress nonce shared by every logged-out visitor** for up to
  12 hours, and the ID token's `nonce` was never checked. An attacker could complete a login
  in a victim's browser and leave them signed into the attacker's account (login CSRF), and
  two people logging in at once broke each other's attempts. Every login now mints a random
  state and nonce, binds them to the browser with a short-lived HttpOnly `SameSite=Lax`
  cookie, and verifies the returned state and the ID token's nonce, audience and issuer.
- **The rate limiter believed `CF-Connecting-IP`, `X-Forwarded-For` and `X-Real-IP` from
  anyone.** A client that could reach the origin directly could rotate the header for
  unlimited backup-code guesses, or spoof a victim's address to lock them out. Forwarding
  headers are now trusted only when the connecting peer is in Cloudflare's published IP
  ranges, or in ranges added with the new `cfzt_trusted_proxies` filter.
- **Any user with the `edit_users` capability could generate backup codes for any
  plugin-created account**, including administrators, and receive them in plaintext. The
  handler now requires `edit_user` for the specific target.
- **The client secret was written in plaintext into the settings page HTML and into settings
  exports.** Encryption at rest only protected against database readers. It is no longer
  rendered or exported.
- **Failed-login usernames were logged unaltered and exported to CSV as-is.** Control
  characters could forge log lines, a leading `=`, `+`, `-` or `@` would run as a formula
  in a spreadsheet, and 1,000 junk failures evicted every real record. Identifiers are now
  stripped of control characters, CSV cells are neutralised, and retention is 10,000 rows.
- Unchanged from the first 2.0.0 work: the Cloudflare API token is used only for the
  duration of setup and is **never written to the database**, and the provisioned client
  secret is saved server-side and not sent back to the browser. Provisioning warns when no
  identity provider is configured, when OpenSSL is unavailable, and when the site is not
  served over HTTPS.

### Fixed
- **Ordinary WordPress password logins were rejected in "alongside WordPress login" mode.**
  The hidden "Use a backup code" field is always present in the login form, and the
  backup-code handler engaged whenever the field existed rather than when it held a value,
  so every password login failed with "Please enter both username and backup code." Shipped in
  1.0.4, which introduced backup codes; found while testing on a hosted sandbox.
- **Saving the Advanced settings form silently deleted role mapping, email domain
  restrictions and the custom redirect URLs.** The sanitizer only kept those fields when the
  submitted form contained them, and the Advanced form does not render them. Fields a form
  does not render are now carried over from the stored settings.
- **Importing settings double-encrypted the client secret**, so every Cloudflare login
  failed at the token exchange afterwards while "Test Connection" still passed. Programmatic
  writes now go through `CFZT_Plugin::save_settings()`, which bypasses the form sanitizer,
  and encrypted values carry a marker so they are never encrypted twice.
- **Role mapping could never match.** The login request did not ask for the `groups` scope,
  so Cloudflare never sent the claim the mapping reads, and existing users were never
  re-evaluated despite the settings tooltip saying they were. Both are addressed (see
  Changed).
- **Backup codes were unreachable in primary mode.** The redirect to Cloudflare fired before
  the backup-code handler ran, so the emergency path only worked when the password form was
  available anyway. A submitted backup code now bypasses the redirect.
- **The settings page was unreadable for anyone whose OS is in dark mode.** A
  `prefers-color-scheme: dark` block darkened the plugin's card while WordPress core kept its
  near-black headings and labels, since the WordPress admin has no dark theme to follow. The
  automatic dark mode is removed from the settings page and the login-form divider.
- The setup checklist notice rendered its item titles in white on white, because WordPress
  relocates admin notices to just under the page's first heading, which here sits inside the
  orange header. The notice now sets its own text colour.
- Pressing Escape on the settings page clicked every dismiss button on the page, permanently
  dismissing admin notices. It now only closes tooltips.
- Declared the `$backup_codes` property on `CFZT_Plugin` to avoid a PHP 8.2 dynamic property
  deprecation notice.
- The OIDC callback URL is no longer duplicated across `class-cfzt-auth.php` and the admin
  template, so the URL registered with Cloudflare cannot drift from the one sent during
  authentication.

### Developer
- New filters: `cfzt_new_username`, `cfzt_sync_role_on_login`,
  `cfzt_primary_mode_blocked_actions`, `cfzt_trusted_proxies`, `cfzt_log_retention_rows`,
  `cfzt_redirect_uri`, `cfzt_provision_app_body` and `cfzt_token_permission_keys`. The
  README documents each with its signature. `cfzt_default_role` and `cfzt_user_data`, which
  the README previously listed, never existed.
- **`CFZT_Plugin::save_settings( array $options )`** writes `cfzt_settings` without running
  the form sanitizer. Use it for any programmatic write; `update_option()` expects plaintext
  from an admin form.
- `CFZT_Security::encrypt_data()` prefixes its output with `cfzt-enc:v1:` and returns
  already-marked values unchanged; `is_encrypted()` tests for the marker. `decrypt_data()`
  still reads unprefixed 1.x values.
- `CFZT_Security::is_rate_limited()` / `record_failed_attempt()` replace the old
  `check_rate_limit()`, which counted every call.
- `CFZT_Logger::sanitize_identifier()` for anything attacker-supplied that ends up in a log.
- The GitHub updater prefers a `.zip` release asset and, when falling back to the tag
  zipball, renames its `<repo>-<version>/` folder to the plugin slug on install
  (`upgrader_source_selection`). `.dev/bin/build-release` builds
  `dist/cloudflare-zero-trust-login-<version>.zip` via `git archive`, and `.gitattributes`
  export-ignores `.dev/` and Markdown so neither ships.

## [1.0.5] - 2026-10-23

Security hotfix for every 1.0.x install. No settings changes; update and carry on.

### Security
- **Primary login mode could be bypassed.** Adding `?cfzt_callback=1` to the login URL
  switched off the redirect to Cloudflare while leaving WordPress password login fully
  working. In primary mode a password now never grants access, and the lost-password,
  reset and registration screens are refused server-side instead of merely hidden. A
  submitted backup code is the one deliberate exception; 2.0.0 makes that path reachable
  from the primary-mode login screen.
- **The OIDC `state` was shared by every visitor.** It was a WordPress nonce for user 0,
  identical for all logged-out visitors for up to 12 hours and visible in the login
  button, so a login started by one person could be completed in another person's browser
  (login CSRF), and two people logging in at once broke each other. Each login now starts
  at `wp-login.php?cfzt_action=login`, which mints a random state per attempt, binds it to
  the browser with a short-lived HttpOnly `SameSite=Lax` cookie, and consumes it once.

### Fixed
- Every WordPress password login in secondary mode was rejected with "Please enter both
  username and backup code", because the backup-code handler fired whenever its (always
  present, hidden) field existed rather than when it held a value.
- `redirect_to` now survives the Cloudflare round trip.
- The login button no longer constructs a second authentication handler on every render,
  which registered duplicate hooks.

### Developer
- New filter `cfzt_primary_mode_blocked_actions`.

## [1.0.4] - 2025-10-23

### Added

#### Phase 1: Quick Wins
- **Copy-to-clipboard functionality** for sensitive data (Team Domain, Client ID, URLs)
- **Enhanced success messages** with visual toast notifications and animations
- **Keyboard shortcuts**: Ctrl/Cmd+S to save settings from anywhere
- **Mobile-responsive admin interface** with optimized layouts for small screens
- **Dark mode support** with automatic system preference detection

#### Phase 2: Testing & Validation
- **Test Connection feature** with detailed diagnostics and troubleshooting guidance
- **Live validation** for Team Domain and Client ID format checking
- **Enhanced error messages** with formatted display, troubleshooting steps, and direct action links

#### Phase 3: Enhanced Monitoring
- **Dashboard overview page** showing real-time authentication statistics and recent activity
- **Visual log viewer** with filtering, searching, sorting, CSV export, and pagination
- **Users list integration** with CF Zero Trust column, filter views, and sortable columns

#### Phase 4: Configuration Enhancements
- **Setup progress indicator** showing configuration completion percentage with task breakdown
- **Contextual help tooltips** with click-to-show hints for all critical settings
- **Settings import/export** as JSON with encryption handling and validation
- **Role mapping system** for assigning WordPress roles based on Cloudflare groups
- **Email domain restrictions** for controlling which domains can authenticate

#### Phase 5: Advanced Features
- **Custom redirect URLs** for post-login and post-logout destinations
- **Backup codes system** with 10 one-time emergency access codes per user
  - User profile integration for code generation
  - Login form toggle for backup code entry
  - Copy and print functionality
  - Automatic expiration after use
- **Onboarding checklist** with dismissible admin notice guiding initial setup

#### New Pages & Templates
- `templates/dashboard-page.php`: Complete dashboard with statistics and charts
- `templates/logs-page.php`: Dedicated logs viewer interface
- `includes/class-cfzt-backup-codes.php`: Backup codes management system

### Changed
- Admin settings page completely redesigned with tabbed interface
- Improved visual hierarchy and modern UI design
- Enhanced form layouts with better grouping and spacing
- Login UI now shows backup code option when available
- All AJAX responses now properly escaped to prevent XSS
- Uninstall process now includes complete data cleanup

### Fixed

#### Critical Security Fixes
- **Open redirect vulnerability**: Added `wp_validate_redirect()` to all redirect handlers (OIDC and SAML)
- **Brute force vulnerability**: Implemented rate limiting for backup code authentication
- **XSS vulnerability**: HTML-escaped all test connection error messages and warnings
- **Import injection**: Added proper sanitization for role mappings in settings import
- **Redirect consistency**: Standardized SAML logout to use `wp_safe_redirect()`

#### Code Quality Improvements
- Added null checks in backup code count calculation to prevent warnings
- Fixed missing redirect URL fields in import/export functionality
- Improved array structure validation throughout
- Enhanced error handling in all AJAX endpoints

### Security
- **5 critical security vulnerabilities patched** (see Fixed section above)
- All user inputs now validated and sanitized
- All outputs properly escaped with context-aware functions
- Rate limiting prevents brute force attacks on emergency access codes
- Backup codes stored using WordPress password hashing (bcrypt)
- Complete CSRF protection with nonce verification on all AJAX calls
- Proper capability checks on all administrative functions

### Performance
- Added options caching to reduce database queries
- Optimized JavaScript with event delegation
- Efficient DOM manipulation with minimal reflows
- Reduced redundant API calls through smart caching

### Developer Experience
- Comprehensive inline documentation with examples
- Consistent coding standards across all files
- Proper use of WordPress hooks and filters
- Clean separation of concerns (MVC-like structure)
- Extensive logging for debugging and monitoring

### Database
- New table columns handled automatically on update
- Proper cleanup of all data on uninstall including:
  - Backup codes metadata
  - Onboarding state
  - Complete logs table removal
  - All transients and options

### Accessibility
- Proper ARIA labels on dynamic content
- Keyboard navigation support throughout
- Screen reader friendly notifications
- Focus management in modals and tooltips

### Internationalization
- All new strings properly wrapped with translation functions
- Consistent text domain usage throughout
- Support for pluralization where appropriate

## [1.0.3] - 2025-10-23

### Added
- Centralized logging system with CFZT_Logger class
- User helper class for consolidated user management
- Type hints for improved code quality and IDE support
- Class constants for magic strings (auth methods, app types, etc.)
- Options caching to reduce database queries
- PHP and WordPress version checking on activation
- Activation timestamp tracking
- Improved GitHub update checker with configurable cache duration (6→12 hours)
- Comprehensive CHANGELOG.md file

### Changed
- Improved code organization by extracting duplicate user creation logic
- Enhanced activation/deactivation hooks with proper cleanup
- Better error handling with structured logging context
- Moved SAML class file to includes/ directory for consistency
- Enhanced inline documentation with PHPDoc examples

### Fixed
- **CRITICAL**: Fatal error on plugin activation (CFZT_Logger not found)
- **CRITICAL**: SAML file path mismatch causing load failures
- Version mismatch between plugin header and constant (1.0.0→1.0.2→1.0.3)
- Encryption nonce now uses truly random values instead of wp_create_nonce()
- All $_SERVER superglobal access now properly sanitized
- Uninstall cleanup now removes all plugin data including user meta
- Internationalization completed for all user-facing error messages

### Security
- **CRITICAL**: Documented SAML signature validation limitation (NOT production-ready)
- Added security warnings to SAML implementation throughout codebase and README
- Improved sanitization across all components
- Enhanced rate limiting and session protection

## [1.0.2] - 2025-10-23

### Changed
- Manual update feature improvements
- Updated .gitignore

## [1.0.1] - 2025-10-20

### Changed
- Initial public release refinements

## [1.0.0] - 2025-10-15

### Added
- Initial release
- OIDC (OpenID Connect) authentication with Cloudflare Zero Trust
- Experimental SAML authentication support
- Support for both SaaS and Self-hosted Cloudflare applications
- Dual login modes (Primary and Secondary)
- Automatic user creation with configurable roles
- AES-256-CBC encryption for credentials (with fallback)
- Rate limiting (10 attempts per 5 minutes)
- Session protection with fingerprinting
- Security headers on login pages
- GitHub-based auto-update system
- Environment variable support for credentials
- Comprehensive admin settings interface
- Authentication logging capability
- SAML endpoints (ACS, SLS, metadata)
- Login page UI modifications

### Security
- Client secret encryption using WordPress salts
- Rate limiting to prevent brute force attacks
- Session ID regeneration after login
- Security headers (CSP, X-Frame-Options, etc.)
- Nonce verification for state parameters
- CSRF protection

---

## Version History Summary

- **2.0.0**: SAML removed, automatic Cloudflare provisioning, six pre-existing security fixes
- **1.0.5**: Security hotfix for 1.0.x: primary-mode bypass, shared OIDC state, password login rejection
- **1.0.4**: Major usability and security update - 19 new features, 5 critical security fixes
- **1.0.3**: Code quality improvements and comprehensive logging
- **1.0.2**: Manual update feature improvements
- **1.0.1**: Initial public release refinements
- **1.0.0**: Initial release with OIDC and experimental SAML support

---

## Upgrade Notes

### Upgrading to 2.0.0

**Important**: SAML support is removed, and the login flow, rate limiter and settings
handling have changed in ways that are visible to administrators.

**What's New:**
- Automatic Cloudflare provisioning from the setup wizard
- Six security fixes to code that shipped in 1.0.4 (see the 2.0.0 Security section)
- Role mapping works, and is re-applied on every login for plugin-created accounts

**After Upgrading:**
1. If the site used SAML, it is now on OIDC and (if it was in "Cloudflare only" mode) back
   on "alongside WordPress login". Run the setup wizard, then restore the login mode.
2. The client secret is no longer displayed. Nothing to do; leave the field blank on saves.
3. If you rely on settings import/export, new exports omit the client secret: re-enter it
   after importing.
4. If a non-Cloudflare proxy or load balancer sits in front of the site, add its ranges with
   the `cfzt_trusted_proxies` filter, otherwise all visitors share one rate-limit counter.
5. Review role mapping: mappings configured in 1.x never matched before and will start to
   apply at users' next logins.
6. Generate backup codes for at least one administrator before enabling primary mode.

**Breaking Changes:**
- SAML authentication and its settings are gone.
- New accounts are created with the full email address as their username. Existing accounts
  are not renamed.
- Generating backup codes requires `edit_user` on the target account, not `edit_users`.
- `CFZT_Security::check_rate_limit()` was replaced by `is_rate_limited()` and
  `record_failed_attempt()`.

### Upgrading to 1.0.4

**Important**: This is a major update with significant UI changes and new features.

**What's New:**
- Completely redesigned admin interface with modern tabbed layout
- 19 new usability features including dashboard, logs viewer, and backup codes
- 5 critical security vulnerabilities patched

**After Upgrading:**
1. Review the new Dashboard page (Tools → CF Zero Trust)
2. Check out the new Logs viewer (Tools → CF Zero Trust Logs)
3. Consider generating backup codes for your CF Zero Trust users
4. Explore the new settings import/export feature
5. Set up role mapping if you use Cloudflare groups
6. Configure custom redirect URLs if desired

**No Breaking Changes:**
- All existing settings are preserved
- Users remain authenticated
- No configuration changes required
- Backward compatible with 1.0.0-1.0.3

### Upgrading to Future Versions

When upgrading, the plugin will:
- Preserve your existing settings
- Run any pending data migrations on the first request after the update
- Clear cached transients
- Not delete any user data or metadata

### Important Notes

- **SAML Support**: Removed in 2.0.0. Sites that used it are migrated to OIDC automatically.
- **PHP Requirements**: Requires PHP 7.2+ and WordPress 5.0+
- **OpenSSL Recommended**: For proper credential encryption

---

## Links

- [GitHub Repository](https://github.com/cjscrofani/cloudflare-zero-trust-wordpress)
- [Issue Tracker](https://github.com/cjscrofani/cloudflare-zero-trust-wordpress/issues)
- [Cloudflare Zero Trust Documentation](https://developers.cloudflare.com/cloudflare-one/)

