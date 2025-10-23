# Changelog

All notable changes to the Cloudflare Zero Trust Login for WordPress plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

- **1.0.2**: Current release with manual update improvements
- **1.0.1**: Initial public release refinements
- **1.0.0**: Initial release with OIDC and experimental SAML support

---

## Upgrade Notes

### Upgrading to Future Versions

When upgrading, the plugin will:
- Preserve your existing settings
- Automatically flush rewrite rules
- Clear cached transients
- Not delete any user data or metadata

### Important Notes

- **SAML Support**: SAML authentication does not perform cryptographic signature validation and should NOT be used in production. Use OIDC for production deployments.
- **PHP Requirements**: Requires PHP 7.2+ and WordPress 5.0+
- **OpenSSL Recommended**: For proper credential encryption

---

## Links

- [GitHub Repository](https://github.com/cjscrofani/cloudflare-zero-trust-wordpress)
- [Issue Tracker](https://github.com/cjscrofani/cloudflare-zero-trust-wordpress/issues)
- [Cloudflare Zero Trust Documentation](https://developers.cloudflare.com/cloudflare-one/)

