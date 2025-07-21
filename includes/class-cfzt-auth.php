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
     * Constructor
     * 
     * @param CFZT_Security $security Security instance
     */
    public function __construct($security) {
        $this->security = $security;
        $this->init_hooks();
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
     * Get authorization URL
     * 
     * @return string Authorization URL
     */
    public function get_auth_url() {
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
     * Handle OAuth callback
     */
    public function handle_callback() {
        if (!isset($_GET['cfzt_callback']) || !isset($_GET['code']) || !isset($_GET['state'])) {
            return;
        }
        
        // Rate limiting
        if (!$this->security->check_rate_limit()) {
            wp_die('Too many authentication attempts. Please try again in 5 minutes.', 'Rate Limit Exceeded', array('response' => 429));
        }
        
        // Verify state
        $state = sanitize_text_field($_GET['state']);
        if (!get_transient('cfzt_auth_state_' . $state)) {
            $this->log_authentication('unknown', false, 'Invalid state parameter');
            wp_die('Invalid state parameter');
        }
        delete_transient('cfzt_auth_state_' . $state);
        
        // Exchange code for token
        $token_data = $this->exchange_code_for_token(sanitize_text_field($_GET['code']));
        
        if (!$token_data || !isset($token_data['access_token'])) {
            $this->log_authentication('unknown', false, 'Token exchange failed');
            wp_die('Failed to exchange authorization code. Please check your Cloudflare Zero Trust configuration.');
        }
        
        // Get user info
        $user_info = $this->get_user_info($token_data['access_token']);
        
        if (!$user_info) {
            $this->log_authentication('unknown', false, 'Failed to retrieve user info');
            wp_die('Failed to retrieve user information. Check your error logs for details.');
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
            wp_die('No email address provided by Cloudflare Zero Trust.');
        }
        
        // Check if user exists
        $user = get_user_by('email', $email);
        
        if (!$user && $options['auto_create_users'] === 'yes') {
            $user = $this->create_user($email, $user_info);
        }
        
        if ($user) {
            // Log the user in
            wp_set_current_user($user->ID);
            wp_set_auth_cookie($user->ID, true);
            
            // Update last login meta
            update_user_meta($user->ID, 'cfzt_last_login', current_time('mysql'));
            
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
            wp_die('User authentication failed. Auto-creation may be disabled or you may not have permission to access this site.');
        }
    }
    
    /**
     * Create new WordPress user
     * 
     * @param string $email User email
     * @param array $user_info User information from Cloudflare
     * @return WP_User|false User object or false on failure
     */
    private function create_user($email, $user_info) {
        $options = CFZT_Plugin::get_option();
        
        // Generate username
        $username = sanitize_user(current(explode('@', $email)));
        $username = $this->ensure_unique_username($username);
        
        $user_id = wp_create_user(
            $username,
            wp_generate_password(),
            $email
        );
        
        if (is_wp_error($user_id)) {
            error_log('[CF Zero Trust] Failed to create user: ' . $user_id->get_error_message());
            return false;
        }
        
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
        $display_name = '';
        if (isset($user_info['name'])) {
            $display_name = $user_info['name'];
        } elseif (isset($user_info['given_name']) || isset($user_info['family_name'])) {
            $display_name = trim(
                (isset($user_info['given_name']) ? $user_info['given_name'] : '') . ' ' . 
                (isset($user_info['family_name']) ? $user_info['family_name'] : '')
            );
        }
        
        if (!empty($display_name)) {
            wp_update_user(array(
                'ID' => $user_id,
                'display_name' => $display_name
            ));
        }
        
        // Trigger action for other plugins
        do_action('cfzt_user_created', $user, $user_info);
        
        return $user;
    }
    
    /**
     * Ensure username is unique
     * 
     * @param string $username Proposed username
     * @return string Unique username
     */
    private function ensure_unique_username($username) {
        $original = $username;
        $counter = 1;
        
        while (username_exists($username)) {
            $username = $original . $counter;
            $counter++;
        }
        
        return $username;
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
        $options = CFZT_Plugin::get_option();
        
        if (isset($options['enable_logging']) && $options['enable_logging'] === 'yes') {
            $status = $success ? 'SUCCESS' : 'FAILED';
            $log_message = sprintf(
                '[CF Zero Trust] Authentication %s for: %s from IP: %s',
                $status,
                $identifier,
                $_SERVER['REMOTE_ADDR']
            );
            
            if (!empty($message)) {
                $log_message .= ' - ' . $message;
            }
            
            error_log($log_message);
        }
        
        // Trigger action for other plugins to hook into
        do_action('cfzt_authentication_attempt', $identifier, $success, $message);
    }
}