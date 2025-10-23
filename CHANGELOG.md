# Changelog

All notable changes to the Cloudflare Zero Trust Login for WordPress plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

- **1.0.4**: Major usability and security update - 19 new features, 5 critical security fixes
- **1.0.3**: Code quality improvements and comprehensive logging
- **1.0.2**: Manual update feature improvements
- **1.0.1**: Initial public release refinements
- **1.0.0**: Initial release with OIDC and experimental SAML support

---

## Upgrade Notes

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

