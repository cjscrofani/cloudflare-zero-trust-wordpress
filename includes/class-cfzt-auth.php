<?php
/**
 * Authentication handler for Cloudflare Zero Trust
 *
 * @package CloudflareZeroTrustLogin
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class CFZT_Auth {
    
    /**
     * Security instance
     * @var CFZT_Security
     */
    private $security;
    
    /**
     * SAML handler instance
     * @var CFZT_SAML
     */
    private $saml_handler;
    
    /**
     * Constructor
     * 
     * @param CFZT_Security $security Security instance
     */
    public function __construct($security) {
        $this->security = $security;
        $this->init_hooks();
        
        // Initialize SAML handler if needed
        $this->init_saml_if_needed();
    }
    
    /**
     * Initialize hooks
     */
    private function init_hooks() {
        add_action('init', array($this, 'handle_callback'));
        add_filter('authenticate', array($this, 'maybe_disable_wp_login'), 30, 3);
        add_action('wp_login', array($this, 'on_user_login'), 10, 2);
        add_action('wp_login_failed', array($this, 'on_login_failed'));
    }
    
    /**
     * Initialize SAML handler if needed
     */
    private function init_saml_if_needed() {
        $options = CFZT_Plugin::get_option();
        if (isset($options['auth_method']) && $options['auth_method'] === 'saml' && !$this->saml_handler) {
            require_once CFZT_PLUGIN_DIR . 'includes/class-cfzt-saml.php';
            $this->saml_handler = new CFZT_SAML($this->security);
        }
    }
    
    /**
     * Get authorization URL based on auth method
     *
     * @return string Authorization URL
     */
    public function get_auth_url() {
        $options = CFZT_Plugin::get_option();
        $auth_method = isset($options['auth_method']) ? $options['auth_method'] : CFZT_Plugin::AUTH_METHOD_OIDC;

        if ($auth_method === CFZT_Plugin::AUTH_METHOD_SAML && $this->saml_handler) {
            return $this->saml_handler->get_auth_url();
        } else {
            return $this->get_oidc_auth_url();
        }
    }
    
    /**
     * Get OIDC authorization URL
     * 
     * @return string Authorization URL
     */
    private function get_oidc_auth_url() {
        $options = CFZT_Plugin::get_option();
        
        if (empty($options['team_domain']) || empty($options['client_id'])) {
            return '';
        }
        
        $state = wp_create_nonce('cfzt_auth');
        set_transient('cfzt_auth_state_' . $state, true, 300); // 5 minutes
        
        // Build authorization endpoint based on app type
        $app_type = isset($options['app_type']) ? $options['app_type'] : 'self-hosted';
        
        if ($app_type === 'saas') {
            $auth_endpoint = 'https://' . $options['team_domain'] . '/cdn-cgi/access/sso/oidc/' . $options['client_id'] . '/authorization';
        } else {
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
    
    /**
     * Handle OAuth callback (for OIDC only)
     */
    public function handle_callback() {
        // Only handle OIDC callbacks here
        // SAML is handled through its own endpoints
        if (!isset($_GET['cfzt_callback']) || !isset($_GET['code']) || !isset($_GET['state'])) {
            return;
        }
        
        $options = CFZT_Plugin::get_option();
        $auth_method = isset($options['auth_method']) ? $options['auth_method'] : CFZT_Plugin::AUTH_METHOD_OIDC;

        // Only process if using OIDC
        if ($auth_method !== CFZT_Plugin::AUTH_METHOD_OIDC) {
            return;
        }
        
        // Rate limiting
        if (!$this->security->check_rate_limit()) {
            wp_die(
                __('Too many authentication attempts. Please try again in 5 minutes.', 'cf-zero-trust'),
                __('Rate Limit Exceeded', 'cf-zero-trust'),
                array('response' => 429)
            );
        }

        // Verify state
        $state = sanitize_text_field($_GET['state']);
        if (!get_transient('cfzt_auth_state_' . $state)) {
            $this->log_authentication('unknown', false, 'Invalid state parameter');
            wp_die(__('Invalid state parameter', 'cf-zero-trust'));
        }
        delete_transient('cfzt_auth_state_' . $state);

        // Exchange code for token
        $token_data = $this->exchange_code_for_token(sanitize_text_field($_GET['code']));

        if (!$token_data || !isset($token_data['access_token'])) {
            $this->log_authentication('unknown', false, 'Token exchange failed');
            wp_die(__('Failed to exchange authorization code. Please check your Cloudflare Zero Trust configuration.', 'cf-zero-trust'));
        }

        // Get user info
        $user_info = $this->get_user_info($token_data['access_token']);

        if (!$user_info) {
            $this->log_authentication('unknown', false, 'Failed to retrieve user info');
            wp_die(__('Failed to retrieve user information. Check your error logs for details.', 'cf-zero-trust'));
        }
        
        // Authenticate user
        $this->authenticate_user($user_info);
    }
    
    /**
     * Exchange authorization code for access token
     * 
     * @param string $code Authorization code
     * @return array|false Token data or false on failure
     */
    private function exchange_code_for_token($code) {
        $options = CFZT_Plugin::get_option();
        
        // Build token endpoint based on app type
        $app_type = isset($options['app_type']) ? $options['app_type'] : 'self-hosted';
        
        if ($app_type === 'saas') {
            $token_url = 'https://' . $options['team_domain'] . '/cdn-cgi/access/sso/oidc/' . $options['client_id'] . '/token';
        } else {
            $token_url = 'https://' . $options['team_domain'] . '/cdn-cgi/access/token';
        }
        
        // Get client secret
        $client_secret = $this->security->get_client_secret();
        
        $response = wp_remote_post($token_url, array(
            'timeout' => 30,
            'body' => array(
                'grant_type' => 'authorization_code',
                'client_id' => $options['client_id'],
                'client_secret' => $client_secret,
                'code' => $code,
                'redirect_uri' => home_url('/wp-login.php?cfzt_callback=1')
            )
        ));
        
        if (is_wp_error($response)) {
            error_log('[CF Zero Trust] Token exchange failed: ' . $response->get_error_message());
            return false;
        }
        
        $http_code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        
        if ($http_code !== 200) {
            error_log('[CF Zero Trust] Token response error. HTTP Code: ' . $http_code . ', Body: ' . $body);
            return false;
        }
        
        $token_data = json_decode($body, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log('[CF Zero Trust] Failed to parse token response: ' . json_last_error_msg());
            return false;
        }
        
        return $token_data;
    }
    
    /**
     * Get user information from access token
     * 
     * @param string $access_token Access token
     * @return array|false User info or false on failure
     */
    private function get_user_info($access_token) {
        $options = CFZT_Plugin::get_option();
        
        // Build userinfo endpoint based on app type
        $app_type = isset($options['app_type']) ? $options['app_type'] : 'self-hosted';
        
        if ($app_type === 'saas') {
            $user_url = 'https://' . $options['team_domain'] . '/cdn-cgi/access/sso/oidc/' . $options['client_id'] . '/userinfo';
        } else {
            $user_url = 'https://' . $options['team_domain'] . '/cdn-cgi/access/get-identity';
        }
        
        $response = wp_remote_get($user_url, array(
            'timeout' => 30,
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
    
    /**
     * Authenticate user with WordPress
     * 
     * @param array $user_info User information from Cloudflare
     */
    private function authenticate_user($user_info) {
        $options = CFZT_Plugin::get_option();
        
        // Get email from user info
        $email = isset($user_info['email']) ? $user_info['email'] : '';
        if (empty($email) && isset($user_info['preferred_username'])) {
            $email = $user_info['preferred_username'];
        }
        
        if (empty($email)) {
            $this->log_authentication('unknown', false, 'No email provided');
            wp_die(__('No email address provided by Cloudflare Zero Trust.', 'cf-zero-trust'));
        }
        
        // Check if user exists
        $user = get_user_by('email', $email);
        
        if (!$user && $options['auto_create_users'] === CFZT_Plugin::OPTION_YES) {
            $user = CFZT_User_Helper::create_user($email, $user_info, 'oidc');
        }

        if ($user) {
            // Log the user in
            wp_set_current_user($user->ID);
            wp_set_auth_cookie($user->ID, true);

            // Update last login meta
            CFZT_User_Helper::update_last_login($user->ID, 'oidc');
            
            // Protect session
            $this->security->protect_session();
            
            // Log successful authentication
            $this->log_authentication($email, true);
            
            // Trigger action for other plugins
            do_action('cfzt_user_authenticated', $user, $user_info);
            
            // Redirect to admin or specified URL
            $redirect_to = isset($_REQUEST['redirect_to']) ? $_REQUEST['redirect_to'] : admin_url();
            wp_safe_redirect($redirect_to);
            exit;
        } else {
            $this->log_authentication($email, false, 'User creation disabled or failed');
            wp_die(__('User authentication failed. Auto-creation may be disabled or you may not have permission to access this site.', 'cf-zero-trust'));
        }
    }
    
    /**
     * Maybe disable WordPress login
     * 
     * @param WP_User|WP_Error|null $user
     * @param string $username
     * @param string $password
     * @return WP_User|WP_Error|null
     */
    public function maybe_disable_wp_login($user, $username, $password) {
        $options = CFZT_Plugin::get_option();
        
        if (isset($options['login_mode']) && $options['login_mode'] === 'primary') {
            // Check if this is a cfzt callback
            if (!isset($_GET['cfzt_callback'])) {
                // Allow programmatic authentication
                if (defined('DOING_AJAX') || defined('DOING_CRON') || defined('WP_CLI')) {
                    return $user;
                }
                
                // Redirect to CF Zero Trust login
                $auth_url = $this->get_auth_url();
                if (!empty($auth_url)) {
                    wp_redirect($auth_url);
                    exit;
                }
            }
        }
        
        return $user;
    }
    
    /**
     * Handle user login event
     * 
     * @param string $user_login Username
     * @param WP_User $user User object
     */
    public function on_user_login($user_login, $user) {
        if (get_user_meta($user->ID, 'cfzt_user', true)) {
            // Session protection for CF Zero Trust users
            $this->security->protect_session();
            
            // Log successful authentication
            $this->log_authentication($user->user_email, true);
        }
    }
    
    /**
     * Handle failed login
     * 
     * @param string $username Username
     */
    public function on_login_failed($username) {
        $this->log_authentication($username, false, 'WordPress login failed');
    }
    
    /**
     * Log authentication attempts
     *
     * @param string $identifier Email or username
     * @param bool $success Success status
     * @param string $message Optional message
     */
    private function log_authentication($identifier, $success, $message = '') {
        CFZT_Logger::auth_attempt($identifier, $success, 'oidc', $message);
    }
    
    /**
     * Get SAML metadata URL if using SAML
     * 
     * @return string|null Metadata URL or null if not using SAML
     */
    public function get_saml_metadata_url() {
        if ($this->saml_handler) {
            return $this->saml_handler->get_metadata_url();
        }
        return null;
    }
}