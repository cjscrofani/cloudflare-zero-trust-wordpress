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
        add_action('login_init', array($this, 'handle_login_start'), 5);
        add_action('login_init', array($this, 'enforce_primary_mode_actions'), 6);
        add_action('init', array($this, 'handle_callback'));
        add_filter('authenticate', array($this, 'maybe_disable_wp_login'), 30, 3);
        add_action('wp_login', array($this, 'on_user_login'), 10, 2);
        add_action('wp_login_failed', array($this, 'on_login_failed'));
        add_action('wp_logout', array($this, 'handle_custom_logout_redirect'));
    }

    /**
     * Display formatted error message with troubleshooting steps
     *
     * @param string $error_title Main error title
     * @param string $error_message Error description
     * @param array $troubleshooting_steps Array of troubleshooting steps
     * @param int $response_code HTTP response code
     */
    private function display_error($error_title, $error_message, $troubleshooting_steps = array(), $response_code = 403) {
        $html = '<div style="font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, Oxygen-Sans, Ubuntu, Cantarell, \'Helvetica Neue\', sans-serif; max-width: 600px; margin: 50px auto; padding: 20px;">';

        // Error header
        $html .= '<div style="background: linear-gradient(135deg, #d63638, #c62828); color: white; padding: 20px; border-radius: 8px 8px 0 0;">';
        $html .= '<h1 style="margin: 0; font-size: 24px;">❌ ' . esc_html($error_title) . '</h1>';
        $html .= '</div>';

        // Error message
        $html .= '<div style="background: #fff; border: 1px solid #ddd; border-top: none; padding: 20px; border-radius: 0 0 8px 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">';
        $html .= '<p style="font-size: 16px; line-height: 1.6; color: #333;">' . esc_html($error_message) . '</p>';

        // Troubleshooting steps
        if (!empty($troubleshooting_steps)) {
            $html .= '<div style="background: #f0f6fc; border-left: 4px solid #2271b1; padding: 15px; margin: 20px 0;">';
            $html .= '<h3 style="margin: 0 0 10px 0; font-size: 16px; color: #2271b1;">🔧 Troubleshooting Steps:</h3>';
            $html .= '<ol style="margin: 0; padding-left: 20px;">';
            foreach ($troubleshooting_steps as $step) {
                $html .= '<li style="margin: 8px 0; line-height: 1.5;">' . wp_kses_post($step) . '</li>';
            }
            $html .= '</ol>';
            $html .= '</div>';
        }

        // Back button
        $html .= '<p style="margin-top: 20px;">';
        $html .= '<a href="' . esc_url(wp_login_url()) . '" style="display: inline-block; background: #2271b1; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: 600;">← ' . __('Back to Login', 'cf-zero-trust') . '</a>';
        $html .= ' <a href="' . esc_url(admin_url('options-general.php?page=cf-zero-trust')) . '" style="display: inline-block; background: #ddd; color: #333; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: 600; margin-left: 10px;">' . __('Plugin Settings', 'cf-zero-trust') . '</a>';
        $html .= '</p>';

        $html .= '</div>';
        $html .= '</div>';

        wp_die($html, $error_title, array('response' => $response_code));
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
            return self::get_login_start_url();
        }
    }

    /**
     * Local URL that begins an OIDC login
     *
     * The Cloudflare authorization URL is built per request in
     * handle_login_start(), because the state it carries has to be minted and
     * bound to the browser at the moment the flow starts. Before 1.0.5 the
     * state was a WordPress nonce shared by every logged-out visitor.
     *
     * @since 1.0.5
     *
     * @return string Empty string when the plugin is not configured.
     */
    public static function get_login_start_url() {
        $options = CFZT_Plugin::get_option();

        if (empty($options['team_domain']) || empty($options['client_id'])) {
            return '';
        }

        $args = array('cfzt_action' => 'login');
        if (!empty($_REQUEST['redirect_to'])) {
            $redirect_to = wp_validate_redirect((string) wp_unslash($_REQUEST['redirect_to']), '');
            if ('' !== $redirect_to) {
                $args['redirect_to'] = $redirect_to;
            }
        }

        return add_query_arg($args, wp_login_url());
    }

    /**
     * Begin a login: mint state, bind it to this browser, redirect to Cloudflare
     *
     * @since 1.0.5
     */
    public function handle_login_start() {
        if (!isset($_GET['cfzt_action']) || 'login' !== $_GET['cfzt_action']) {
            return;
        }

        $options = CFZT_Plugin::get_option();
        $auth_method = isset($options['auth_method']) ? $options['auth_method'] : CFZT_Plugin::AUTH_METHOD_OIDC;
        if ($auth_method === CFZT_Plugin::AUTH_METHOD_SAML) {
            return;
        }

        $auth_url = $this->get_oidc_auth_url();
        if ('' === $auth_url) {
            return;
        }

        wp_redirect($auth_url);
        exit;
    }

    /**
     * Refuse the password-reset and registration screens in primary mode
     *
     * They were only hidden with CSS, which left them fully functional for
     * anyone who typed the URL.
     *
     * @since 1.0.5
     */
    public function enforce_primary_mode_actions() {
        $options = CFZT_Plugin::get_option();
        if (!isset($options['login_mode']) || 'primary' !== $options['login_mode']) {
            return;
        }

        $action = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : 'login';
        $blocked = apply_filters('cfzt_primary_mode_blocked_actions', array(
            'lostpassword', 'retrievepassword', 'resetpass', 'rp', 'register',
        ));

        if (!in_array($action, $blocked, true)) {
            return;
        }

        $auth_url = $this->get_auth_url();
        if ('' !== $auth_url) {
            wp_redirect($auth_url);
            exit;
        }
    }

    /**
     * Get OIDC authorization URL for a freshly minted, browser-bound flow
     *
     * @return string Authorization URL
     */
    private function get_oidc_auth_url() {
        $options = CFZT_Plugin::get_option();
        
        if (empty($options['team_domain']) || empty($options['client_id'])) {
            return '';
        }

        // Random per-attempt state, stored under a random flow id that only
        // this browser holds (HttpOnly cookie). The callback is accepted only
        // when the cookie's flow carries exactly this state.
        $flow_id = bin2hex(random_bytes(16));
        $state = bin2hex(random_bytes(16));
        $redirect_to = !empty($_REQUEST['redirect_to'])
            ? wp_validate_redirect((string) wp_unslash($_REQUEST['redirect_to']), '')
            : '';

        set_transient('cfzt_auth_flow_' . hash('sha256', $flow_id), array(
            'state'       => $state,
            'redirect_to' => $redirect_to,
            'created'     => time(),
        ), 600);
        $this->set_flow_cookie($flow_id, time() + 600);
        
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
            $this->display_error(
                __('Rate Limit Exceeded', 'cf-zero-trust'),
                __('Too many authentication attempts have been made from your IP address. This is a security measure to prevent brute force attacks.', 'cf-zero-trust'),
                array(
                    __('Wait 5 minutes before trying again', 'cf-zero-trust'),
                    __('Clear your browser cookies and cache', 'cf-zero-trust'),
                    __('If this persists, contact your site administrator', 'cf-zero-trust')
                ),
                429
            );
        }

        // Verify state: the browser must present the cookie it was given when
        // the flow began, and that flow must carry exactly this state.
        $flow_id = isset($_COOKIE['cfzt_oidc_flow']) ? (string) $_COOKIE['cfzt_oidc_flow'] : '';
        $flow_key = 'cfzt_auth_flow_' . hash('sha256', $flow_id);
        $flow = preg_match('/^[a-f0-9]{32}$/', $flow_id) ? get_transient($flow_key) : false;
        $state = (string) wp_unslash($_GET['state']);

        if (!is_array($flow) || empty($flow['state']) || !hash_equals((string) $flow['state'], $state)) {
            $this->log_authentication('unknown', false, 'Invalid state parameter');
            $this->display_error(
                __('Invalid Authentication Request', 'cf-zero-trust'),
                __('This login did not start from this browser, or it took too long. Nothing has been changed.', 'cf-zero-trust'),
                array(
                    __('Try logging in again from the start', 'cf-zero-trust'),
                    __('Make sure you complete the login within 10 minutes', 'cf-zero-trust'),
                    __('Make sure your browser accepts cookies from this site', 'cf-zero-trust')
                )
            );
        }

        // One-shot: the flow is consumed whether or not the exchange succeeds.
        delete_transient($flow_key);
        $this->set_flow_cookie('', time() - YEAR_IN_SECONDS);
        $this->flow_redirect_to = isset($flow['redirect_to']) ? (string) $flow['redirect_to'] : '';

        // Exchange code for token
        $token_data = $this->exchange_code_for_token(sanitize_text_field($_GET['code']));

        if (!$token_data || !isset($token_data['access_token'])) {
            $this->log_authentication('unknown', false, 'Token exchange failed');
            $this->display_error(
                __('Token Exchange Failed', 'cf-zero-trust'),
                __('Unable to exchange the authorization code for an access token. This indicates a configuration issue with your Cloudflare application.', 'cf-zero-trust'),
                array(
                    __('Verify your <strong>Client Secret</strong> in plugin settings matches Cloudflare', 'cf-zero-trust'),
                    __('Check that your <strong>Team Domain</strong> is correct', 'cf-zero-trust'),
                    __('Ensure the <strong>Redirect URL</strong> matches exactly in Cloudflare: <code>' . esc_html(home_url('/wp-login.php?cfzt_callback=1')) . '</code>', 'cf-zero-trust'),
                    __('Test your connection using the "Test Connection" button in plugin settings', 'cf-zero-trust')
                )
            );
        }

        // Get user info
        $user_info = $this->get_user_info($token_data['access_token']);

        if (!$user_info) {
            $this->log_authentication('unknown', false, 'Failed to retrieve user info');
            $this->display_error(
                __('User Information Retrieval Failed', 'cf-zero-trust'),
                __('Successfully authenticated with Cloudflare, but unable to retrieve your user information. This suggests an issue with the Cloudflare API or your application configuration.', 'cf-zero-trust'),
                array(
                    __('Check your Cloudflare application status and settings', 'cf-zero-trust'),
                    __('Verify the application type (SaaS vs Self-hosted) is correct in plugin settings', 'cf-zero-trust'),
                    __('Ensure your Cloudflare Access policy allows access to user info', 'cf-zero-trust'),
                    __('Check WordPress error logs for more details', 'cf-zero-trust')
                )
            );
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
            $this->display_error(
                __('Missing Email Address', 'cf-zero-trust'),
                __('Cloudflare Zero Trust did not provide an email address for your account. An email address is required to create or match a WordPress user.', 'cf-zero-trust'),
                array(
                    __('Verify your Cloudflare Access policy includes email in the JWT claims', 'cf-zero-trust'),
                    __('Check that your identity provider (IdP) is properly configured', 'cf-zero-trust'),
                    __('Ensure your Cloudflare application is set up to pass user email information', 'cf-zero-trust'),
                    __('Contact your Cloudflare administrator if the issue persists', 'cf-zero-trust')
                )
            );
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

            // Determine redirect URL
            $redirect_to = $this->get_login_redirect_url();
            wp_safe_redirect($redirect_to);
            exit;
        } else {
            $this->log_authentication($email, false, 'User creation disabled or failed');
            $auto_create_enabled = isset($options['auto_create_users']) && $options['auto_create_users'] === 'yes';

            if (!$auto_create_enabled) {
                $this->display_error(
                    __('Account Not Found', 'cf-zero-trust'),
                    sprintf(__('No WordPress account exists for %s and automatic user creation is disabled.', 'cf-zero-trust'), '<strong>' . esc_html($email) . '</strong>'),
                    array(
                        __('Ask your site administrator to create a WordPress account for your email address', 'cf-zero-trust'),
                        __('Or, ask your administrator to enable "Auto-create Users" in plugin settings', 'cf-zero-trust'),
                        __('Ensure you\'re logging in with the correct Cloudflare account', 'cf-zero-trust')
                    )
                );
            } else {
                $this->display_error(
                    __('User Creation Failed', 'cf-zero-trust'),
                    sprintf(__('Automatic user creation is enabled, but creating an account for %s failed. This may be a permissions issue or a configuration problem.', 'cf-zero-trust'), '<strong>' . esc_html($email) . '</strong>'),
                    array(
                        __('Check WordPress error logs for more details about the failure', 'cf-zero-trust'),
                        __('Verify the default role setting in plugin configuration is valid', 'cf-zero-trust'),
                        __('Ensure WordPress has permission to create new users', 'cf-zero-trust'),
                        __('Contact your site administrator for assistance', 'cf-zero-trust')
                    )
                );
            }
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
            // Before 1.0.5 any request carrying ?cfzt_callback=1 was exempt
            // here, but the callback handler ignores requests without a code,
            // so the bare parameter let core's password check run and succeed.
            // The Cloudflare callback never goes through this filter at all
            // (it sets the auth cookie directly), so there is nothing to exempt.

            // Backup codes are this plugin's own emergency path; let the
            // handler at priority 40 decide, without the password result
            // leaking through.
            if (!empty($_POST['cfzt_backup_code']) && '' !== trim((string) $_POST['cfzt_backup_code'])) {
                return null;
            }

            // Allow programmatic authentication
            if (defined('DOING_AJAX') || defined('DOING_CRON') || defined('WP_CLI')
                || defined('XMLRPC_REQUEST') || defined('REST_REQUEST')) {
                return $user;
            }

            // Redirect to CF Zero Trust login
            $auth_url = $this->get_auth_url();
            if (!empty($auth_url)) {
                wp_redirect($auth_url);
                exit;
            }
        }
        
        return $user;
    }

    /**
     * Destination captured when the current flow began
     * @var string
     */
    private $flow_redirect_to = '';

    /**
     * Set or clear the flow cookie
     *
     * Written by hand so SameSite is sent on every supported PHP version. Lax
     * is required: the callback arrives as a top-level navigation from
     * Cloudflare, which Strict would refuse to attach the cookie to.
     *
     * @since 1.0.5
     *
     * @param string $value   Cookie value, empty to clear.
     * @param int    $expires Unix timestamp.
     */
    private function set_flow_cookie($value, $expires) {
        if (headers_sent()) {
            return;
        }

        $cookie = sprintf(
            'cfzt_oidc_flow=%s; Expires=%s; Max-Age=%d; Path=/; HttpOnly; SameSite=Lax',
            rawurlencode($value),
            gmdate('D, d M Y H:i:s T', $expires),
            max(0, $expires - time())
        );

        if (is_ssl()) {
            $cookie .= '; Secure';
        }

        header('Set-Cookie: ' . $cookie, false);
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

    /**
     * Get login redirect URL
     *
     * Checks for custom redirect URL, then $_REQUEST['redirect_to'], then defaults
     *
     * @return string Redirect URL
     */
    private function get_login_redirect_url() {
        $options = CFZT_Plugin::get_option();

        // Check for custom redirect URL setting
        if (!empty($options['redirect_after_login'])) {
            return $options['redirect_after_login'];
        }

        // Destination captured when the flow began (Cloudflare does not echo
        // redirect_to back), then any redirect_to on the current request.
        if ('' !== $this->flow_redirect_to) {
            return wp_validate_redirect($this->flow_redirect_to, admin_url());
        }
        if (isset($_REQUEST['redirect_to']) && !empty($_REQUEST['redirect_to'])) {
            $redirect = wp_validate_redirect($_REQUEST['redirect_to'], admin_url());
            return $redirect;
        }

        // Default to admin dashboard
        return admin_url();
    }

    /**
     * Handle custom logout redirect
     *
     * Redirects user to custom URL after logout if configured
     */
    public function handle_custom_logout_redirect() {
        $options = CFZT_Plugin::get_option();

        if (!empty($options['redirect_after_logout'])) {
            add_filter('logout_redirect', function($redirect_to, $requested_redirect_to, $user) use ($options) {
                return $options['redirect_after_logout'];
            }, 10, 3);
        }
    }
}