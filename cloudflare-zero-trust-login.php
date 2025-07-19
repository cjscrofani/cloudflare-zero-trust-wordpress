<?php
/**
 * Plugin Name: Cloudflare Zero Trust Login
 * Plugin URI: https://your-website.com/
 * Description: Adds Cloudflare Zero Trust as a login method for WordPress
 * Version: 1.0.0
 * Author: Your Name
 * License: GPL v2 or later
 * Text Domain: cf-zero-trust
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('CFZT_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('CFZT_PLUGIN_URL', plugin_dir_url(__FILE__));
define('CFZT_PLUGIN_BASENAME', plugin_basename(__FILE__));

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
        
        // Login hooks
        add_action('login_form', array($this, 'add_login_button'));
        add_action('init', array($this, 'handle_callback'));
        add_filter('authenticate', array($this, 'maybe_disable_wp_login'), 30, 3);
        add_action('login_enqueue_scripts', array($this, 'enqueue_login_styles'));
        
        // Activation/Deactivation hooks
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
    }
    
    public function activate() {
        // Create necessary database tables or options
        add_option('cfzt_settings', array(
            'auth_method' => 'oauth2',
            'team_domain' => '',
            'client_id' => '',
            'client_secret' => '',
            'login_mode' => 'secondary',
            'auto_create_users' => 'yes',
            'default_role' => 'subscriber'
        ));
    }
    
    public function deactivate() {
        // Cleanup if needed
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
            'team_domain' => 'Team Domain',
            'client_id' => 'Client ID',
            'client_secret' => 'Client Secret',
            'login_mode' => 'Login Mode',
            'auto_create_users' => 'Auto-create Users',
            'default_role' => 'Default User Role'
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
        $sanitized['team_domain'] = sanitize_text_field($input['team_domain']);
        $sanitized['client_id'] = sanitize_text_field($input['client_id']);
        $sanitized['client_secret'] = sanitize_text_field($input['client_secret']);
        $sanitized['login_mode'] = sanitize_text_field($input['login_mode']);
        $sanitized['auto_create_users'] = sanitize_text_field($input['auto_create_users']);
        $sanitized['default_role'] = sanitize_text_field($input['default_role']);
        
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
            <option value="oauth2" <?php selected($value, 'oauth2'); ?>>OAuth 2.0</option>
            <option value="saml" <?php selected($value, 'saml'); ?>>SAML (Coming Soon)</option>
        </select>
        <p class="description">Select the authentication method to use with Cloudflare Zero Trust.</p>
        <?php
    }
    
    public function field_callback_team_domain() {
        $options = get_option('cfzt_settings');
        $value = isset($options['team_domain']) ? $options['team_domain'] : '';
        ?>
        <input type="text" name="cfzt_settings[team_domain]" value="<?php echo esc_attr($value); ?>" class="regular-text" />
        <p class="description">Your Cloudflare Zero Trust team domain (e.g., yourteam.cloudflareaccess.com)</p>
        <?php
    }
    
    public function field_callback_client_id() {
        $options = get_option('cfzt_settings');
        $value = isset($options['client_id']) ? $options['client_id'] : '';
        ?>
        <input type="text" name="cfzt_settings[client_id]" value="<?php echo esc_attr($value); ?>" class="regular-text" />
        <p class="description">OAuth 2.0 Client ID from your Cloudflare Zero Trust application.</p>
        <?php
    }
    
    public function field_callback_client_secret() {
        $options = get_option('cfzt_settings');
        $value = isset($options['client_secret']) ? $options['client_secret'] : '';
        ?>
        <input type="password" name="cfzt_settings[client_secret]" value="<?php echo esc_attr($value); ?>" class="regular-text" />
        <p class="description">OAuth 2.0 Client Secret from your Cloudflare Zero Trust application.</p>
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
                <li>Create an OAuth application in your Cloudflare Zero Trust dashboard</li>
                <li>Set the redirect URL to: <code><?php echo esc_url(home_url('/wp-login.php?cfzt_callback=1')); ?></code></li>
                <li>Copy the Client ID and Client Secret to the fields above</li>
                <li>Enter your team domain (found in your Zero Trust dashboard)</li>
                <li>Save the settings and test the login</li>
            </ol>
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
        
        $params = array(
            'client_id' => $options['client_id'],
            'redirect_uri' => home_url('/wp-login.php?cfzt_callback=1'),
            'response_type' => 'code',
            'scope' => 'openid email profile',
            'state' => $state
        );
        
        return 'https://' . $options['team_domain'] . '/cdn-cgi/access/authorize?' . http_build_query($params);
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
        $token_url = 'https://' . $options['team_domain'] . '/cdn-cgi/access/token';
        
        $response = wp_remote_post($token_url, array(
            'body' => array(
                'grant_type' => 'authorization_code',
                'client_id' => $options['client_id'],
                'client_secret' => $options['client_secret'],
                'code' => sanitize_text_field($_GET['code']),
                'redirect_uri' => home_url('/wp-login.php?cfzt_callback=1')
            )
        ));
        
        if (is_wp_error($response)) {
            wp_die('Failed to exchange authorization code');
        }
        
        $body = wp_remote_retrieve_body($response);
        $token_data = json_decode($body, true);
        
        if (!isset($token_data['access_token'])) {
            wp_die('Invalid token response');
        }
        
        // Get user info
        $user_info = $this->get_user_info($token_data['access_token'], $options['team_domain']);
        
        if (!$user_info) {
            wp_die('Failed to retrieve user information');
        }
        
        // Authenticate user
        $this->authenticate_user($user_info);
    }
    
    private function get_user_info($access_token, $team_domain) {
        $user_url = 'https://' . $team_domain . '/cdn-cgi/access/get-identity';
        
        $response = wp_remote_get($user_url, array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $access_token
            )
        ));
        
        if (is_wp_error($response)) {
            return false;
        }
        
        $body = wp_remote_retrieve_body($response);
        return json_decode($body, true);
    }
    
    private function authenticate_user($user_info) {
        $options = get_option('cfzt_settings');
        $email = $user_info['email'];
        
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
                update_user_meta($user_id, 'cfzt_sub', $user_info['sub']);
                
                // Update display name if available
                if (isset($user_info['name'])) {
                    wp_update_user(array(
                        'ID' => $user_id,
                        'display_name' => $user_info['name']
                    ));
                }
            }
        }
        
        if ($user) {
            // Log the user in
            wp_set_current_user($user->ID);
            wp_set_auth_cookie($user->ID, true);
            
            // Redirect to admin or specified URL
            $redirect_to = isset($_REQUEST['redirect_to']) ? $_REQUEST['redirect_to'] : admin_url();
            wp_safe_redirect($redirect_to);
            exit;
        } else {
            wp_die('User authentication failed. Please contact the administrator.');
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
}

// Initialize the plugin
CloudflareZeroTrustLogin::get_instance();