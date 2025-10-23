# Cloudflare Zero Trust Login for WordPress

A secure WordPress authentication plugin that integrates Cloudflare Zero Trust OIDC (OpenID Connect) into your WordPress login system. Supports both SaaS and Self-hosted applications with enterprise-grade security features.

## ⚠️ IMPORTANT SECURITY NOTICE

**SAML Authentication Limitation:**
This plugin includes experimental SAML support that **does NOT perform proper cryptographic signature validation**. The SAML implementation should **NOT be used in production environments** as it is vulnerable to response tampering and replay attacks.

**Recommendations:**
- ✅ **Use OIDC authentication** (fully implemented and secure)
- ❌ **Do not use SAML** in production without additional security measures
- 📖 See `class-cfzt-saml.php` for detailed security documentation

If SAML is absolutely required, consider using a production-ready SAML library like SimpleSAMLphp, LightSAML, or OneLogin PHP SAML.

## 🚀 Features

### Authentication
- **OIDC Integration**: Seamless authentication using Cloudflare Zero Trust OpenID Connect ✅ **Secure & Production-Ready**
- **SAML Support**: Experimental SAML authentication ⚠️ **Not production-ready** (see security notice above)
- **Dual Application Support**: Works with both SaaS and Self-hosted Cloudflare applications
- **Flexible Login Modes**:
  - Secondary mode: Traditional WordPress login alongside Cloudflare login
  - Primary mode: Cloudflare-only authentication (disables WordPress login)

### User Management
- **Automatic User Creation**: Optionally create WordPress users on first login
- **Role Assignment**: Configure default roles for new users
- **User Metadata**: Stores Cloudflare identity information securely

### Security
- **Encrypted Credentials**: Client secrets encrypted using AES-256-CBC (when OpenSSL available)
- **Environment Variables**: Support for storing credentials outside the database
- **Rate Limiting**: Built-in protection against brute force attempts (10 attempts per 5 minutes)
- **Session Protection**: Enhanced session security with fingerprinting
- **Security Headers**: Automatic security headers on login pages (CSP, X-Frame-Options, etc.)

### Developer-Friendly
- **Auto-Updates**: GitHub-based update system - no manual downloads needed
- **Clean Architecture**: Well-organized, object-oriented codebase
- **Hooks & Filters**: Extensible with WordPress actions and filters
- **Comprehensive Logging**: Optional authentication event logging

## 📋 Requirements

- WordPress 5.0 or higher
- PHP 7.2 or higher
- A Cloudflare account with Zero Trust enabled
- SSL/HTTPS enabled on your WordPress site
- OpenSSL PHP extension (recommended for encryption)
- PHP DOM extension (required only if using SAML - not recommended for production)

## 🔧 Installation

### Method 1: Direct Download
1. Download the latest release from the [Releases page](https://github.com/cjscrofani/cloudflare-zero-trust-wordpress/releases)
2. Upload to your `/wp-content/plugins/` directory
3. Activate the plugin through the 'Plugins' menu in WordPress

### Method 2: Git Clone
```bash
cd wp-content/plugins/
git clone https://github.com/cjscrofani/cloudflare-zero-trust-wordpress.git cloudflare-zero-trust-login
```

## ⚙️ Configuration

### Step 1: Cloudflare Zero Trust Setup

1. Log in to your [Cloudflare Zero Trust dashboard](https://one.dash.cloudflare.com/)
2. Navigate to **Access** → **Applications**
3. Click **Add an application**
4. Choose application type:
   - **SaaS** (Recommended): For standard OIDC integration
   - **Self-hosted**: For custom applications
5. Configure the application:
   - **Application name**: Your WordPress site name
   - **Session duration**: As desired
   - **Application domain**: Your WordPress URL
6. Configure OIDC settings:
   - **Redirect URL**: `https://yoursite.com/wp-login.php?cfzt_callback=1`
   - **Grant type**: Authorization code
   - **Scopes**: openid, email, profile
7. Save and note your:
   - Client ID
   - Client Secret
   - Team Domain (from Issuer URL, e.g., `yourteam.cloudflareaccess.com`)

### Step 2: WordPress Plugin Configuration

1. Go to **Settings** → **CF Zero Trust** in WordPress admin
2. Enter your Cloudflare credentials:
   - **Team Domain**: Your Cloudflare team domain
   - **Client ID**: From Cloudflare application
   - **Client Secret**: From Cloudflare application
3. Configure options:
   - **Application Type**: Match what you created in Cloudflare
   - **Login Mode**: Secondary (both) or Primary (Cloudflare only)
   - **Auto-create Users**: Enable to create users on first login
   - **Default Role**: Role for new users
4. Save settings

### Step 3: Security Hardening (Recommended)

Add to your `wp-config.php`:

```php
// Method 1: Direct constants
define('CFZT_CLIENT_ID', 'your-client-id-here');
define('CFZT_CLIENT_SECRET', 'your-client-secret-here');

// Method 2: Environment variables
define('CFZT_CLIENT_ID', getenv('CFZT_CLIENT_ID'));
define('CFZT_CLIENT_SECRET', getenv('CFZT_CLIENT_SECRET'));
```

Or use `.env` file:
```
CFZT_CLIENT_ID=your-client-id-here
CFZT_CLIENT_SECRET=your-client-secret-here
```

## 🎯 Usage

### For End Users

1. Navigate to your WordPress login page
2. Click "Login with Cloudflare Zero Trust"
3. Authenticate with your Cloudflare identity provider
4. You'll be redirected back and logged into WordPress

### For Administrators

- **Monitor Authentication**: Enable logging to track login attempts
- **User Management**: View Cloudflare-authenticated users via user meta `cfzt_user`
- **Access Control**: Use Cloudflare policies to control who can access your site

## 🔐 Security Considerations

- **Use OIDC, not SAML**: The OIDC implementation is production-ready and secure. SAML is experimental only.
- **Always use HTTPS** for your WordPress site
- **Keep WordPress salts configured** properly in `wp-config.php` (affects encryption)
- **Use environment variables** for credentials when possible (see Step 3 in Configuration)
- **Regularly update the plugin** for security patches via the built-in GitHub updater
- **Monitor authentication logs** for suspicious activity (enable in settings)
- **Implement IP restrictions** in Cloudflare Zero Trust policies for additional security
- **Use strong authentication** in your Cloudflare identity provider (MFA recommended)

## 🛠️ Development

### Project Structure
```
cloudflare-zero-trust-login/
├── assets/
│   └── css/
│       └── cfzt-login.css
├── includes/
│   ├── class-cfzt-admin.php
│   ├── class-cfzt-auth.php
│   ├── class-cfzt-login-ui.php
│   ├── class-cfzt-plugin.php
│   ├── class-cfzt-security.php
│   └── class-github-updater.php
├── templates/
│   ├── admin-page.php
│   └── login-button.php
├── cloudflare-zero-trust-login.php
└── uninstall.php
```

### Hooks and Filters

#### Actions
- `cfzt_user_authenticated` - Fired after successful authentication
- `cfzt_user_created` - Fired after new user creation
- `cfzt_authentication_attempt` - Fired on any authentication attempt

#### Filters
- `cfzt_default_role` - Modify default role for new users
- `cfzt_user_data` - Modify user data before creation

## 🐛 Troubleshooting

### Common Issues

**Login button not appearing**
- Verify Team Domain and Client ID are configured
- Check browser console for JavaScript errors

**Authentication fails**
- Ensure redirect URL matches exactly in Cloudflare
- Verify Client Secret is correct
- Check WordPress error logs with logging enabled

**Users cannot be created**
- Enable "Auto-create Users" in settings
- Verify default role is valid
- Check user email isn't already registered

**Rate limit errors**
- Wait 5 minutes before trying again
- Check for automated/bot login attempts

### Debug Mode

Add to `wp-config.php`:
```php
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
define('WP_DEBUG_DISPLAY', false);
```

Then enable authentication logging in plugin settings.

## 📄 License

This project is licensed under the GPL v2 or later - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- [Plugin Website](https://github.com/cjscrofani/cloudflare-zero-trust-wordpress)
- [Report Issues](https://github.com/cjscrofani/cloudflare-zero-trust-wordpress/issues)
- [Cloudflare Zero Trust Documentation](https://developers.cloudflare.com/cloudflare-one/)
- [WordPress Plugin Handbook](https://developer.wordpress.org/plugins/)
