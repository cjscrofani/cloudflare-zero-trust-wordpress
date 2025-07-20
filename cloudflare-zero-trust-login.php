<?php
/**
 * Plugin Name: Cloudflare Zero Trust Login
 * Plugin URI: https://your-website.com/
 * Description: Secure WordPress authentication using Cloudflare Zero Trust OIDC (OpenID Connect). Supports both SaaS and Self-hosted applications with built-in security features.
 * Version: 1.0.0
 * Author: Your Name
 * License: GPL v2 or later
 * Text Domain: cf-zero-trust
 * 
 * This plugin integrates Cloudflare Zero Trust as a login provider for WordPress,
 * supporting both SaaS and Self-hosted application types with enterprise-grade
 * security features including rate limiting, encryption, and session protection.
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('CFZT_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('CFZT_PLUGIN_URL', plugin_dir_url(__FILE__));
define('CFZT_PLUGIN_BASENAME', plugin_basename(__FILE__));

// Check for environment variables or wp-config constants
if (!defined('CFZT_CLIENT_ID')) {
    define('CFZT_CLIENT_ID', getenv('CFZT_CLIENT_ID') ?: '');
}
if (!defined('CFZT_CLIENT_SECRET')) {
    define('CFZT_CLIENT_SECRET', getenv('CFZT_CLIENT_SECRET') ?: '');
}

// Main plugin class
class CloudflareZeroTrustLogin {
    
    private static $instance = null;
    
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        $this->init_hooks();
    }
    
    private function init_hooks() {
        // Admin hooks
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('admin_notices', array($this, 'admin_notices'));
        
        // Login hooks
        add_action('login_form', array($this, 'add_login_button'));
        add_action('init', array($this, 'handle_callback'));
        add_filter('authenticate', array($this, 'maybe_disable_wp_login'), 30, 3);
        add_action('login_enqueue_scripts', array($this, 'enqueue_login_styles'));
        
        // Security hooks
        add_action('init', array($this, 'rate_limiting'), 1);
        add_action('login_init', array($this, 'add_security_headers'));
        add_action('wp_login', array($this, 'session_protection'), 10, 2);
        add_action('wp_login_failed', array($this, 'log_failed_login'));
        add_filter('option_cfzt_settings', array($this, 'override_with_constants'));
        add_filter('pre_update_option_cfzt_settings', array($this, 'protect_constants'), 10, 2);
        
        // Activation/Deactivation hooks
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
        register_uninstall_hook(__FILE__, array(__CLASS__, 'uninstall'));
    }
    
    public function activate() {
        // Create necessary database tables or options
        add_option('cfzt_settings', array(
            'auth_method' => 'oauth2', // This is OIDC in Cloudflare's terminology
            'app_type' => 'saas', // SaaS is recommended for new installations
            'team_domain' => '',
            'client_id' => '',
            'client_secret' => '',
            'login_mode' => 'secondary',
            'auto_create_users' => 'yes',
            'default_role' => 'subscriber',
            'enable_logging' => 'no'
        ));
    }
    
    public function deactivate() {
        // Cleanup if needed
    }
    
    public function admin_notices() {
        // Show encryption status on settings page
        $screen = get_current_screen();
        if ($screen && $screen->id === 'settings_page_cf-zero-trust') {
            if (!$this->is_encryption_available()) {
                ?>
                <div class="notice notice-warning">
                    <p><?php _e('OpenSSL is not available on your server. Client secrets will be stored with basic obfuscation instead of strong encryption. Consider enabling OpenSSL for better security.', 'cf-zero-trust'); ?></p>
                </div>
                <?php
            }
        }
    }
    
    public function add_admin_menu() {
        add_options_page(
            'Cloudflare Zero Trust Settings',
            'CF Zero Trust',
            'manage_options',
            'cf-zero-trust',
            array($this, 'settings_page')
        );
    }
    
    public function register_settings() {
        register_setting('cfzt_settings_group', 'cfzt_settings', array($this, 'sanitize_settings'));
        
        add_settings_section(
            'cfzt_main_section',
            'Cloudflare Zero Trust Configuration',
            array($this, 'section_callback'),
            'cf-zero-trust'
        );
        
        // Add settings fields
        $fields = array(
            'auth_method' => 'Authentication Method',
            'app_type' => 'Application Type',
            'team_domain' => 'Team Domain',
            'client_id' => 'Client ID',
            'client_secret' => 'Client Secret',
            'login_mode' => 'Login Mode',
            'auto_create_users' => 'Auto-create Users',
            'default_role' => 'Default User Role',
            'enable_logging' => 'Enable Authentication Logging'
        );
        
        foreach ($fields as $field => $label) {
            add_settings_field(
                'cfzt_' . $field,
                $label,
                array($this, 'field_callback_' . $field),
                'cf-zero-trust',
                'cfzt_main_section'
            );
        }
    }
    
    public function sanitize_settings($input) {
        $sanitized = array();
        
        $sanitized['auth_method'] = sanitize_text_field($input['auth_method']);
        $sanitized['app_type'] = sanitize_text_field($input['app_type']);
        $sanitized['team_domain'] = sanitize_text_field($input['team_domain']);
        $sanitized['client_id'] = sanitize_text_field($input['client_id']);
        
        // Encrypt sensitive data
        $sanitized['client_secret'] = $this->encrypt_data(sanitize_text_field($input['client_secret']));
        
        $sanitized['login_mode'] = sanitize_text_field($input['login_mode']);
        $sanitized['auto_create_users'] = sanitize_text_field($input['auto_create_users']);
        $sanitized['default_role'] = sanitize_text_field($input['default_role']);
        $sanitized['enable_logging'] = sanitize_text_field($input['enable_logging']);
        
        return $sanitized;
    }
    
    public function section_callback() {
        echo '<p>Configure your Cloudflare Zero Trust integration settings below.</p>';
    }
    
    public function field_callback_auth_method() {
        $options = get_option('cfzt_settings');
        $value = isset($options['auth_method']) ? $options['auth_method'] : 'oauth2';
        ?>
        <select name="cfzt_settings[auth_method]">
            <option value="oauth2" <?php selected($value, 'oauth2'); ?>>OIDC (OpenID Connect)</option>
            <option value="saml" <?php selected($value, 'saml'); ?>>SAML (Coming Soon)</option>
        </select>
        <p class="description">OIDC (OpenID Connect) is the authentication protocol used by Cloudflare Zero Trust.</p>
        <?php
    }
    
    public function field_callback_app_type() {
        $options = get_option('cfzt_settings');
        $value = isset($options['app_type']) ? $options['app_type'] : 'self-hosted'; // Default to self-hosted for backward compatibility
        ?>
        <select name="cfzt_settings[app_type]">
            <option value="saas" <?php selected($value, 'saas'); ?>>SaaS (Recommended)</option>
            <option value="self-hosted" <?php selected($value, 'self-hosted'); ?>>Self-hosted</option>
        </select>
        <p class="description">Choose the application type you created in Cloudflare Zero Trust. SaaS apps provide standard OIDC endpoints.</p>
        <?php
    }
    
    public function field_callback_team_domain() {
        $options = get_option('cfzt_settings');
        $value = isset($options['team_domain']) ? $options['team_domain'] : '';
        ?>
        <input type="text" name="cfzt_settings[team_domain]" value="<?php echo esc_attr($value); ?>" class="regular-text" />
        <p class="description">Your Cloudflare Zero Trust team domain (e.g., <code>yourteam.cloudflareaccess.com</code>)<br>
        This is the hostname from your Issuer URL, without https://</p>
        <?php
    }
    
    public function field_callback_client_id() {
        $options = get_option('cfzt_settings');
        $value = isset($options['client_id']) ? $options['client_id'] : '';
        $from_constant = defined('CFZT_CLIENT_ID') && CFZT_CLIENT_ID;
        ?>
        <input type="text" name="cfzt_settings[client_id]" value="<?php echo esc_attr($value); ?>" class="regular-text" <?php echo $from_constant ? 'readonly' : ''; ?> />
        <?php if ($from_constant): ?>
            <p class="description"><strong>Value set via constant/environment variable</strong></p>
        <?php else: ?>
            <p class="description">Client ID from your Cloudflare Zero Trust OIDC application.</p>
        <?php endif; ?>
        <?php
    }
    
    public function field_callback_client_secret() {
        $options = get_option('cfzt_settings');
        $from_constant = defined('CFZT_CLIENT_SECRET') && CFZT_CLIENT_SECRET;
        
        if ($from_constant) {
            $value = '[SET VIA CONSTANT]';
        } else {
            $value = isset($options['client_secret']) ? $this->decrypt_data($options['client_secret']) : '';
        }
        ?>
        <input type="password" name="cfzt_settings[client_secret]" value="<?php echo esc_attr($value); ?>" class="regular-text" <?php echo $from_constant ? 'readonly' : ''; ?> />
        <?php if ($from_constant): ?>
            <p class="description"><strong>Value set via constant/environment variable (hidden for security)</strong></p>
        <?php else: ?>
            <p class="description">Client Secret from your Cloudflare Zero Trust OIDC application.</p>
        <?php endif; ?>
        <?php
    }
    
    public function field_callback_login_mode() {
        $options = get_option('cfzt_settings');
        $value = isset($options['login_mode']) ? $options['login_mode'] : 'secondary';
        ?>
        <select name="cfzt_settings[login_mode]">
            <option value="secondary" <?php selected($value, 'secondary'); ?>>Secondary (Show both login options)</option>
            <option value="primary" <?php selected($value, 'primary'); ?>>Primary (Disable WordPress login)</option>
        </select>
        <p class="description">Choose whether to use Cloudflare Zero Trust as the only login method or alongside WordPress login.</p>
        <?php
    }
    
    public function field_callback_auto_create_users() {
        $options = get_option('cfzt_settings');
        $value = isset($options['auto_create_users']) ? $options['auto_create_users'] : 'yes';
        ?>
        <select name="cfzt_settings[auto_create_users]">
            <option value="yes" <?php selected($value, 'yes'); ?>>Yes</option>
            <option value="no" <?php selected($value, 'no'); ?>>No</option>
        </select>
        <p class="description">Automatically create WordPress users for authenticated Cloudflare Zero Trust users.</p>
        <?php
    }
    
    public function field_callback_default_role() {
        $options = get_option('cfzt_settings');
        $value = isset($options['default_role']) ? $options['default_role'] : 'subscriber';
        ?>
        <select name="cfzt_settings[default_role]">
            <?php wp_dropdown_roles($value); ?>
        </select>
        <p class="description">Default role for auto-created users.</p>
        <?php
    }
    
    public function field_callback_enable_logging() {
        $options = get_option('cfzt_settings');
        $value = isset($options['enable_logging']) ? $options['enable_logging'] : 'no';
        ?>
        <select name="cfzt_settings[enable_logging]">
            <option value="yes" <?php selected($value, 'yes'); ?>>Yes</option>
            <option value="no" <?php selected($value, 'no'); ?>>No</option>
        </select>
        <p class="description">Log authentication attempts to the WordPress error log.</p>
        <?php
    }
    
    public function settings_page() {
        ?>
        <div class="wrap">
            <h1>Cloudflare Zero Trust Settings</h1>
            <form method="post" action="options.php">
                <?php
                settings_fields('cfzt_settings_group');
                do_settings_sections('cf-zero-trust');
                submit_button();
                ?>
            </form>
            
            <h2>Setup Instructions</h2>
            <ol>
                <li>In Cloudflare Zero Trust, go to Access > Applications</li>
                <li>Add a new application and choose type:
                    <ul>
                        <li><strong>SaaS</strong> (Recommended) - Provides standard OIDC endpoints</li>
                        <li><strong>Self-hosted</strong> - For custom applications</li>
                    </ul>
                </li>
                <li>Configure OIDC settings with redirect URL: <code><?php echo esc_url(home_url('/wp-login.php?cfzt_callback=1')); ?></code></li>
                <li>Copy the provided credentials:
                    <ul>
                        <li><strong>Client ID</strong> - The unique identifier</li>
                        <li><strong>Client Secret</strong> - The authentication secret</li>
                        <li><strong>Team Domain</strong> - From the Issuer URL (e.g., <code>yourteam.cloudflareaccess.com</code>)</li>
                    </ul>
                </li>
                <li>Enter these values above and save</li>
            </ol>
            
            <h3>For SaaS Applications</h3>
            <p>If you created a SaaS application, Cloudflare provides these endpoints:</p>
            <ul>
                <li><strong>Authorization:</strong> <code>/cdn-cgi/access/sso/oidc/{client_id}/authorization</code></li>
                <li><strong>Token:</strong> <code>/cdn-cgi/access/sso/oidc/{client_id}/token</code></li>
                <li><strong>Userinfo:</strong> <code>/cdn-cgi/access/sso/oidc/{client_id}/userinfo</code></li>
            </ul>
            <p>The plugin automatically uses the correct endpoints based on your Application Type setting.</p>
            
            <h2>Security Status</h2>
            <table class="widefat">
                <tr>
                    <td><strong>Encryption Method:</strong></td>
                    <td><?php echo $this->is_encryption_available() ? '✓ AES-256-CBC (OpenSSL)' : '⚠ Basic Obfuscation (Install OpenSSL for better security)'; ?></td>
                </tr>
                <tr>
                    <td><strong>Auth Salt:</strong></td>
                    <td><?php echo defined('AUTH_SALT') && AUTH_SALT !== 'put your unique phrase here' ? '✓ Configured' : '✗ Using default (insecure)'; ?></td>
                </tr>
                <tr>
                    <td><strong>Secure Auth Salt:</strong></td>
                    <td><?php echo defined('SECURE_AUTH_SALT') && SECURE_AUTH_SALT !== 'put your unique phrase here' ? '✓ Configured' : '✗ Using default (insecure)'; ?></td>
                </tr>
                <tr>
                    <td><strong>Client ID Source:</strong></td>
                    <td><?php echo defined('CFZT_CLIENT_ID') && CFZT_CLIENT_ID ? '✓ Set via constant/environment' : '⚠ Stored in database'; ?></td>
                </tr>
                <tr>
                    <td><strong>Client Secret Source:</strong></td>
                    <td><?php echo defined('CFZT_CLIENT_SECRET') && CFZT_CLIENT_SECRET ? '✓ Set via constant/environment' : '⚠ Stored in database (encrypted)'; ?></td>
                </tr>
                <tr>
                    <td><strong>Rate Limiting:</strong></td>
                    <td>✓ Active (10 attempts per 5 minutes)</td>
                </tr>
                <tr>
                    <td><strong>Security Headers:</strong></td>
                    <td>✓ Active on login page</td>
                </tr>
            </table>
            
            <?php if (!defined('AUTH_SALT') || AUTH_SALT === 'put your unique phrase here'): ?>
            <div class="notice notice-error inline">
                <p>Your WordPress salts are not properly configured. Please update your <code>wp-config.php</code> file with unique salts from <a href="https://api.wordpress.org/secret-key/1.1/salt/" target="_blank">WordPress.org</a></p>
            </div>
            <?php endif; ?>
            
            <h2>Using Environment Variables (Recommended)</h2>
            <p>For better security, you can set credentials via environment variables or constants in <code>wp-config.php</code>:</p>
            <pre style="background: #f0f0f0; padding: 10px; overflow-x: auto;">
// Method 1: Environment variables (add to .env or server config)
CFZT_CLIENT_ID=your-client-id-here
CFZT_CLIENT_SECRET=your-client-secret-here

// Method 2: wp-config.php constants
define('CFZT_CLIENT_ID', 'your-client-id-here');
define('CFZT_CLIENT_SECRET', 'your-client-secret-here');

// Method 3: wp-config.php with environment variables
define('CFZT_CLIENT_ID', getenv('CFZT_CLIENT_ID'));
define('CFZT_CLIENT_SECRET', getenv('CFZT_CLIENT_SECRET'));</pre>
        </div>
        <?php
    }
    
    public function add_login_button() {
        $options = get_option('cfzt_settings');
        
        if (empty($options['team_domain']) || empty($options['client_id'])) {
            return;
        }
        
        $auth_url = $this->get_auth_url();
        ?>
        <div class="cfzt-login-wrapper">
            <div class="cfzt-divider">
                <span>OR</span>
            </div>
            <a href="<?php echo esc_url($auth_url); ?>" class="cfzt-login-button">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
                </svg>
                Login with Cloudflare Zero Trust
            </a>
        </div>
        <?php
    }
    
    public function enqueue_login_styles() {
        ?>
        <style>
            .cfzt-login-wrapper {
                margin: 20px 0;
            }
            
            .cfzt-divider {
                text-align: center;
                margin: 20px 0;
                position: relative;
            }
            
            .cfzt-divider span {
                background: #fff;
                padding: 0 10px;
                position: relative;
                color: #72777c;
                font-size: 14px;
            }
            
            .cfzt-divider:before {
                content: '';
                position: absolute;
                top: 50%;
                left: 0;
                right: 0;
                height: 1px;
                background: #ddd;
            }
            
            .cfzt-login-button {
                display: flex;
                align-items: center;
                justify-content: center;
                width: 100%;
                padding: 12px;
                background: #f38020;
                color: #fff;
                text-decoration: none;
                border-radius: 4px;
                font-size: 14px;
                font-weight: 500;
                transition: background 0.2s;
            }
            
            .cfzt-login-button:hover {
                background: #e56f0e;
                color: #fff;
            }
            
            .cfzt-login-button svg {
                margin-right: 8px;
            }
            
            <?php
            $options = get_option('cfzt_settings');
            if (isset($options['login_mode']) && $options['login_mode'] === 'primary') {
                ?>
                #loginform,
                #lostpasswordform,
                #registerform {
                    display: none !important;
                }
                
                .cfzt-divider {
                    display: none;
                }
                <?php
            }
            ?>
        </style>
        <?php
    }
    
    private function get_auth_url() {
        $options = get_option('cfzt_settings');
        $state = wp_create_nonce('cfzt_auth');
        set_transient('cfzt_auth_state_' . $state, true, 300); // 5 minutes
        
        // Build authorization endpoint based on app type
        $app_type = isset($options['app_type']) ? $options['app_type'] : 'self-hosted'; // Default to self-hosted for backward compatibility
        
        if ($app_type === 'saas') {
            // SaaS apps use /cdn-cgi/access/sso/oidc/{client_id}/authorization
            $auth_endpoint = 'https://' . $options['team_domain'] . '/cdn-cgi/access/sso/oidc/' . $options['client_id'] . '/authorization';
        } else {
            // Self-hosted apps use the simpler endpoint
            $auth_endpoint = 'https://' . $options['team_domain'] . '/cdn-cgi/access/authorize';
        }
        
        $params = array(
            'client_id' => $options['client_id'],
            'redirect_uri' => home_url('/wp-login.php?cfzt_callback=1'),
            'response_type' => 'code',
            'scope' => 'openid email profile',
            'state' => $state
        );
        
        return $auth_endpoint . '?' . http_build_query($params);
    }
    
    public function handle_callback() {
        if (!isset($_GET['cfzt_callback']) || !isset($_GET['code']) || !isset($_GET['state'])) {
            return;
        }
        
        // Verify state
        $state = sanitize_text_field($_GET['state']);
        if (!get_transient('cfzt_auth_state_' . $state)) {
            wp_die('Invalid state parameter');
        }
        delete_transient('cfzt_auth_state_' . $state);
        
        // Exchange code for token
        $options = get_option('cfzt_settings');
        
        // Build token endpoint based on app type
        $app_type = isset($options['app_type']) ? $options['app_type'] : 'self-hosted'; // Default to self-hosted for backward compatibility
        
        if ($app_type === 'saas') {
            // SaaS apps use /cdn-cgi/access/sso/oidc/{client_id}/token
            $token_url = 'https://' . $options['team_domain'] . '/cdn-cgi/access/sso/oidc/' . $options['client_id'] . '/token';
        } else {
            // Self-hosted apps use the simpler endpoint
            $token_url = 'https://' . $options['team_domain'] . '/cdn-cgi/access/token';
        }
        
        // Decrypt client secret before use (unless it's from a constant)
        if (isset($options['client_secret_is_constant']) && $options['client_secret_is_constant']) {
            $client_secret = $options['client_secret'];
        } else {
            $client_secret = $this->decrypt_data($options['client_secret']);
        }
        
        $response = wp_remote_post($token_url, array(
            'body' => array(
                'grant_type' => 'authorization_code',
                'client_id' => $options['client_id'],
                'client_secret' => $client_secret,
                'code' => sanitize_text_field($_GET['code']),
                'redirect_uri' => home_url('/wp-login.php?cfzt_callback=1')
            )
        ));
        
        if (is_wp_error($response)) {
            $error_message = $response->get_error_message();
            error_log('[CF Zero Trust] Token exchange failed: ' . $error_message);
            wp_die('Failed to exchange authorization code: ' . esc_html($error_message));
        }
        
        $http_code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        $token_data = json_decode($body, true);
        
        if ($http_code !== 200 || !isset($token_data['access_token'])) {
            error_log('[CF Zero Trust] Token response error. HTTP Code: ' . $http_code . ', Body: ' . $body);
            wp_die('Invalid token response. Please check your Cloudflare Zero Trust configuration.');
        }
        
        // Get user info
        $user_info = $this->get_user_info($token_data['access_token'], $options);
        
        if (!$user_info) {
            error_log('[CF Zero Trust] Failed to retrieve user information from token');
            wp_die('Failed to retrieve user information. Check your error logs for details.');
        }
        
        // Authenticate user
        $this->authenticate_user($user_info);
    }
    
    private function get_user_info($access_token, $options) {
        // Build userinfo endpoint based on app type
        $app_type = isset($options['app_type']) ? $options['app_type'] : 'self-hosted'; // Default to self-hosted for backward compatibility
        
        if ($app_type === 'saas') {
            // SaaS apps use the standard OIDC userinfo endpoint
            $user_url = 'https://' . $options['team_domain'] . '/cdn-cgi/access/sso/oidc/' . $options['client_id'] . '/userinfo';
        } else {
            // Self-hosted apps use the Cloudflare-specific endpoint
            $user_url = 'https://' . $options['team_domain'] . '/cdn-cgi/access/get-identity';
        }
        
        $response = wp_remote_get($user_url, array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $access_token
            )
        ));
        
        if (is_wp_error($response)) {
            error_log('[CF Zero Trust] Failed to get user info: ' . $response->get_error_message());
            return false;
        }
        
        $http_code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        
        if ($http_code !== 200) {
            error_log('[CF Zero Trust] User info request failed. HTTP Code: ' . $http_code . ', Body: ' . $body);
            return false;
        }
        
        $user_data = json_decode($body, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log('[CF Zero Trust] Failed to parse user info JSON: ' . json_last_error_msg());
            return false;
        }
        
        return $user_data;
    }
    
    private function authenticate_user($user_info) {
        $options = get_option('cfzt_settings');
        
        // Get email from user info (handle different response formats)
        $email = isset($user_info['email']) ? $user_info['email'] : '';
        if (empty($email) && isset($user_info['preferred_username'])) {
            $email = $user_info['preferred_username'];
        }
        
        if (empty($email)) {
            $this->log_authentication('unknown', false);
            wp_die('No email address provided by Cloudflare Zero Trust.');
        }
        
        // Check if user exists
        $user = get_user_by('email', $email);
        
        if (!$user && $options['auto_create_users'] === 'yes') {
            // Create new user
            $username = sanitize_user(current(explode('@', $email)));
            $username = $this->ensure_unique_username($username);
            
            $user_id = wp_create_user(
                $username,
                wp_generate_password(),
                $email
            );
            
            if (!is_wp_error($user_id)) {
                $user = get_user_by('id', $user_id);
                
                // Set user role
                $user->set_role($options['default_role']);
                
                // Update user meta
                update_user_meta($user_id, 'cfzt_user', true);
                
                // Store the unique identifier (sub)
                $sub = isset($user_info['sub']) ? $user_info['sub'] : $email;
                update_user_meta($user_id, 'cfzt_sub', $sub);
                
                // Store additional OIDC claims if available
                if (isset($user_info['iss'])) {
                    update_user_meta($user_id, 'cfzt_issuer', $user_info['iss']);
                }
                
                // Update display name if available
                if (isset($user_info['name'])) {
                    wp_update_user(array(
                        'ID' => $user_id,
                        'display_name' => $user_info['name']
                    ));
                } elseif (isset($user_info['given_name']) || isset($user_info['family_name'])) {
                    $display_name = trim($user_info['given_name'] . ' ' . $user_info['family_name']);
                    if (!empty($display_name)) {
                        wp_update_user(array(
                            'ID' => $user_id,
                            'display_name' => $display_name
                        ));
                    }
                }
            }
        }
        
        if ($user) {
            // Log the user in
            wp_set_current_user($user->ID);
            wp_set_auth_cookie($user->ID, true);
            
            // Log successful authentication
            $this->log_authentication($email, true);
            
            // Redirect to admin or specified URL
            $redirect_to = isset($_REQUEST['redirect_to']) ? $_REQUEST['redirect_to'] : admin_url();
            wp_safe_redirect($redirect_to);
            exit;
        } else {
            $this->log_authentication($email, false);
            wp_die('User authentication failed. Auto-creation may be disabled or you may not have permission to access this site. Please contact the administrator.');
        }
    }
    
    private function ensure_unique_username($username) {
        $original = $username;
        $counter = 1;
        
        while (username_exists($username)) {
            $username = $original . $counter;
            $counter++;
        }
        
        return $username;
    }
    
    public function maybe_disable_wp_login($user, $username, $password) {
        $options = get_option('cfzt_settings');
        
        if (isset($options['login_mode']) && $options['login_mode'] === 'primary') {
            // Check if this is a cfzt callback
            if (!isset($_GET['cfzt_callback'])) {
                // Redirect to CF Zero Trust login
                $auth_url = $this->get_auth_url();
                wp_redirect($auth_url);
                exit;
            }
        }
        
        return $user;
    }
    
    /**
     * Encrypt sensitive data using WordPress's built-in functions
     */
    private function encrypt_data($data) {
        if (empty($data)) {
            return '';
        }
        
        // Use WordPress salts for encryption
        $key = wp_salt('auth');
        $salt = wp_salt('secure_auth');
        
        // Create a unique nonce for this encryption
        $nonce = wp_create_nonce('cfzt_encrypt');
        
        // Combine data with nonce for added security
        $data_with_nonce = $nonce . '::' . $data;
        
        // Use WordPress's built-in password hashing for a simple obfuscation
        // For more secure encryption, consider using OpenSSL if available
        if (function_exists('openssl_encrypt')) {
            $method = 'AES-256-CBC';
            $iv = substr(hash('sha256', $salt), 0, 16);
            $encrypted = openssl_encrypt($data_with_nonce, $method, $key, 0, $iv);
            return base64_encode($encrypted);
        } else {
            // Fallback to a simpler obfuscation method
            return base64_encode($data_with_nonce . '::' . hash_hmac('sha256', $data, $key));
        }
    }
    
    /**
     * Decrypt sensitive data
     */
    private function decrypt_data($encrypted_data) {
        if (empty($encrypted_data)) {
            return '';
        }
        
        $key = wp_salt('auth');
        $salt = wp_salt('secure_auth');
        
        if (function_exists('openssl_decrypt')) {
            $method = 'AES-256-CBC';
            $iv = substr(hash('sha256', $salt), 0, 16);
            $decrypted = openssl_decrypt(base64_decode($encrypted_data), $method, $key, 0, $iv);
            
            if ($decrypted !== false) {
                // Extract the original data without the nonce
                $parts = explode('::', $decrypted, 2);
                return isset($parts[1]) ? $parts[1] : '';
            }
        } else {
            // Fallback for simple obfuscation
            $decoded = base64_decode($encrypted_data);
            $parts = explode('::', $decoded, 3);
            return isset($parts[1]) ? $parts[1] : '';
        }
        
        return '';
    }
    
    /**
     * Get encryption status for admin notice
     */
    public function is_encryption_available() {
        return function_exists('openssl_encrypt') && function_exists('openssl_decrypt');
    }
    
    /**
     * Rate limiting for OAuth callback endpoint
     */
    public function rate_limiting() {
        if (!isset($_GET['cfzt_callback'])) {
            return;
        }
        
        $ip = $_SERVER['REMOTE_ADDR'];
        $attempts_key = 'cfzt_attempts_' . $ip;
        $attempts = get_transient($attempts_key) ?: 0;
        
        if ($attempts > 10) {
            wp_die('Too many authentication attempts. Please try again in 5 minutes.', 'Rate Limit Exceeded', array('response' => 429));
        }
        
        set_transient($attempts_key, $attempts + 1, 300); // 5 minutes
    }
    
    /**
     * Add security headers to login page
     */
    public function add_security_headers() {
        // Prevent clickjacking
        header('X-Frame-Options: DENY');
        
        // Prevent MIME type sniffing
        header('X-Content-Type-Options: nosniff');
        
        // Enable XSS protection
        header('X-XSS-Protection: 1; mode=block');
        
        // Referrer policy
        header('Referrer-Policy: strict-origin-when-cross-origin');
        
        // Content Security Policy
        $csp = "default-src 'self'; ";
        $csp .= "script-src 'self' 'unsafe-inline' https://*.cloudflareaccess.com; ";
        $csp .= "style-src 'self' 'unsafe-inline'; ";
        $csp .= "img-src 'self' data: https://*.cloudflareaccess.com; ";
        $csp .= "connect-src 'self' https://*.cloudflareaccess.com; ";
        $csp .= "frame-ancestors 'none';";
        
        header("Content-Security-Policy: $csp");
    }
    
    /**
     * Session protection after login
     */
    public function session_protection($user_login, $user) {
        if (get_user_meta($user->ID, 'cfzt_user', true)) {
            // Regenerate session ID after CF Zero Trust login
            if (function_exists('session_regenerate_id') && session_status() === PHP_SESSION_ACTIVE) {
                session_regenerate_id(true);
            }
            
            // Log successful authentication
            $this->log_authentication($user->user_email, true);
        }
    }
    
    /**
     * Log failed login attempts
     */
    public function log_failed_login($username) {
        $options = get_option('cfzt_settings');
        if (isset($options['enable_logging']) && $options['enable_logging'] === 'yes') {
            error_log(sprintf(
                '[CF Zero Trust] Failed login attempt for username: %s from IP: %s',
                $username,
                $_SERVER['REMOTE_ADDR']
            ));
        }
    }
    
    /**
     * Log authentication attempts
     */
    private function log_authentication($email, $success) {
        $options = get_option('cfzt_settings');
        if (isset($options['enable_logging']) && $options['enable_logging'] === 'yes') {
            $status = $success ? 'SUCCESS' : 'FAILED';
            error_log(sprintf(
                '[CF Zero Trust] Authentication %s for email: %s from IP: %s',
                $status,
                $email,
                $_SERVER['REMOTE_ADDR']
            ));
        }
        
        // Trigger action for other plugins to hook into
        do_action('cfzt_authentication_attempt', $email, $success);
    }
    
    /**
     * Override database settings with constants if defined
     */
    public function override_with_constants($settings) {
        if (defined('CFZT_CLIENT_ID') && CFZT_CLIENT_ID) {
            $settings['client_id'] = CFZT_CLIENT_ID;
        }
        if (defined('CFZT_CLIENT_SECRET') && CFZT_CLIENT_SECRET) {
            // Don't decrypt if it's from a constant
            $settings['client_secret'] = CFZT_CLIENT_SECRET;
            $settings['client_secret_is_constant'] = true;
        }
        return $settings;
    }
    
    /**
     * Prevent overwriting constants in database
     */
    public function protect_constants($new_value, $old_value) {
        if (defined('CFZT_CLIENT_ID') && CFZT_CLIENT_ID) {
            $new_value['client_id'] = $old_value['client_id'] ?? '';
        }
        if (defined('CFZT_CLIENT_SECRET') && CFZT_CLIENT_SECRET) {
            $new_value['client_secret'] = $old_value['client_secret'] ?? '';
        }
        return $new_value;
    }
    
    /**
     * Uninstall cleanup
     */
    public static function uninstall() {
        // Only run if not a multisite or if network admin
        if (!is_multisite() || is_super_admin()) {
            // Remove plugin options
            delete_option('cfzt_settings');
            
            // Remove user meta
            $users = get_users(array(
                'meta_key' => 'cfzt_user',
                'meta_value' => true
            ));
            
            foreach ($users as $user) {
                delete_user_meta($user->ID, 'cfzt_user');
                delete_user_meta($user->ID, 'cfzt_sub');
                delete_user_meta($user->ID, 'cfzt_issuer');
            }
            
            // Clean up transients
            global $wpdb;
            $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_cfzt_%'");
            $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_cfzt_%'");
        }
    }
}

// Initialize the plugin
CloudflareZeroTrustLogin::get_instance();