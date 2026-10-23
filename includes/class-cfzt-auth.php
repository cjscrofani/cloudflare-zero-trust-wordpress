<?php
/**
 * Authentication handler for Cloudflare Zero Trust
 *
 * Implements the OIDC authorization-code flow against a Cloudflare Access
 * application. Every login starts at a local endpoint
 * (wp-login.php?cfzt_action=login) that mints a random state and nonce, binds
 * them to the browser with a short-lived HttpOnly cookie, and only then
 * redirects to Cloudflare. The callback accepts a code only when the browser
 * presenting it also holds the cookie for that exact state, which is what
 * closes login CSRF and code injection.
 *
 * @package CloudflareZeroTrustLogin
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class CFZT_Auth {

    /**
     * Query argument that starts a login
     */
    const START_ACTION = 'login';

    /**
     * Cookie that ties an in-progress login to one browser
     */
    const FLOW_COOKIE = 'cfzt_oidc_flow';

    /**
     * How long a started login stays valid, in seconds
     */
    const FLOW_TTL = 600;

    /**
     * OIDC scopes requested from Cloudflare
     *
     * `groups` is what role mapping reads; without it Cloudflare omits the
     * claim and every mapped user falls back to the default role.
     */
    const SCOPES = 'openid email profile groups';

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
        add_action('login_init', array($this, 'handle_login_start'), 5);
        add_action('login_init', array($this, 'enforce_primary_mode_actions'), 6);
        add_action('init', array($this, 'handle_callback'));
        add_filter('authenticate', array($this, 'maybe_disable_wp_login'), 30, 3);
        add_action('wp_login', array($this, 'on_user_login'), 10, 2);
        add_action('wp_login_failed', array($this, 'on_login_failed'));
        add_action('wp_logout', array($this, 'handle_custom_logout_redirect'));
    }

    /**
     * Whether enough is configured to send anyone to Cloudflare
     *
     * @return bool
     */
    public static function is_configured(): bool {
        $options = CFZT_Plugin::get_option();
        return !empty($options['team_domain']) && !empty($options['client_id']);
    }

    /**
     * Local URL that begins a Cloudflare login
     *
     * This is what the login button and primary-mode redirects point at. The
     * real Cloudflare authorization URL is built per request in
     * handle_login_start(), because it needs state that must be minted and
     * bound to the browser at the moment the flow starts.
     *
     * @since 2.0.0
     *
     * @param string $redirect_to Optional. Where to send the user after login.
     * @return string Empty string when the plugin is not configured.
     */
    public static function get_login_start_url(string $redirect_to = ''): string {
        if (!self::is_configured()) {
            return '';
        }

        $args = array('cfzt_action' => self::START_ACTION);
        if ('' !== $redirect_to) {
            $args['redirect_to'] = $redirect_to;
        }

        return add_query_arg($args, wp_login_url());
    }

    /**
     * Get authorization URL
     *
     * Kept for callers from 1.x; returns the local start URL.
     *
     * @return string
     */
    public function get_auth_url() {
        return self::get_login_start_url($this->requested_redirect_to());
    }

    /**
     * Begin a login: mint state, bind it to this browser, redirect to Cloudflare
     *
     * Runs on login_init so headers have not been sent yet.
     *
     * @since 2.0.0
     *
     * @return void
     */
    public function handle_login_start() {
        if (!isset($_GET['cfzt_action']) || self::START_ACTION !== $_GET['cfzt_action']) {
            return;
        }

        if (!self::is_configured()) {
            return;
        }

        if ($this->security->is_rate_limited()) {
            $this->rate_limited_error();
        }

        $flow_id = bin2hex(random_bytes(16));
        $state = bin2hex(random_bytes(16));
        $nonce = bin2hex(random_bytes(16));

        set_transient(self::flow_key($flow_id), array(
            'state'       => $state,
            'nonce'       => $nonce,
            'redirect_to' => $this->requested_redirect_to(),
            'created'     => time(),
        ), self::FLOW_TTL);

        $this->set_flow_cookie($flow_id, time() + self::FLOW_TTL);

        wp_redirect($this->build_authorize_url($state, $nonce));
        exit;
    }

    /**
     * Build the Cloudflare authorization URL for one flow
     *
     * @param string $state Per-flow state.
     * @param string $nonce Per-flow OIDC nonce.
     * @return string
     */
    private function build_authorize_url(string $state, string $nonce): string {
        $options = CFZT_Plugin::get_option();
        $app_type = isset($options['app_type']) ? $options['app_type'] : CFZT_Plugin::APP_TYPE_SELF_HOSTED;

        if (CFZT_Plugin::APP_TYPE_SAAS === $app_type) {
            $auth_endpoint = 'https://' . $options['team_domain'] . '/cdn-cgi/access/sso/oidc/' . $options['client_id'] . '/authorization';
        } else {
            $auth_endpoint = 'https://' . $options['team_domain'] . '/cdn-cgi/access/authorize';
        }

        $params = array(
            'client_id'     => $options['client_id'],
            'redirect_uri'  => CFZT_Plugin::get_redirect_uri(),
            'response_type' => 'code',
            'scope'         => self::SCOPES,
            'state'         => $state,
            'nonce'         => $nonce,
        );

        return $auth_endpoint . '?' . http_build_query($params);
    }

    /**
     * Handle the OIDC callback
     */
    public function handle_callback() {
        if (!isset($_GET['cfzt_callback']) || !isset($_GET['code']) || !isset($_GET['state'])) {
            return;
        }

        if ($this->security->is_rate_limited()) {
            $this->rate_limited_error();
        }

        // The browser must present the cookie it was given when the flow began.
        $flow_id = isset($_COOKIE[self::FLOW_COOKIE]) ? (string) $_COOKIE[self::FLOW_COOKIE] : '';
        $flow = preg_match('/^[a-f0-9]{32}$/', $flow_id) ? get_transient(self::flow_key($flow_id)) : false;
        $state = (string) wp_unslash($_GET['state']);

        if (!is_array($flow) || empty($flow['state']) || !hash_equals((string) $flow['state'], $state)) {
            $this->security->record_failed_attempt();
            $this->log_authentication('unknown', false, 'Invalid state parameter');
            $this->display_error(
                __('Invalid Authentication Request', 'cf-zero-trust'),
                __('This login did not start from this browser, or it took too long. Nothing has been changed.', 'cf-zero-trust'),
                array(
                    __('Try logging in again from the start', 'cf-zero-trust'),
                    __('Make sure you complete the login within 10 minutes', 'cf-zero-trust'),
                    __('Make sure your browser accepts cookies from this site', 'cf-zero-trust'),
                )
            );
        }

        // One-shot: the flow is consumed whether or not the exchange succeeds.
        delete_transient(self::flow_key($flow_id));
        $this->set_flow_cookie('', time() - YEAR_IN_SECONDS);

        // Exchange code for token
        $token_data = $this->exchange_code_for_token(sanitize_text_field(wp_unslash($_GET['code'])));

        if (!$token_data || !isset($token_data['access_token'])) {
            $this->security->record_failed_attempt();
            $this->log_authentication('unknown', false, 'Token exchange failed');
            $this->display_error(
                __('Token Exchange Failed', 'cf-zero-trust'),
                __('Unable to exchange the authorization code for an access token. This indicates a configuration issue with your Cloudflare application.', 'cf-zero-trust'),
                array(
                    __('Verify your <strong>Client Secret</strong> in plugin settings matches Cloudflare', 'cf-zero-trust'),
                    __('Check that your <strong>Team Domain</strong> is correct', 'cf-zero-trust'),
                    __('Ensure the <strong>Redirect URL</strong> matches exactly in Cloudflare: <code>' . esc_html(CFZT_Plugin::get_redirect_uri()) . '</code>', 'cf-zero-trust'),
                    __('Test your connection using the "Test Connection" button in plugin settings', 'cf-zero-trust')
                )
            );
        }

        // The ID token arrived over our own TLS connection to the token
        // endpoint, so its claims are authentic without a signature check.
        // Still confirm it answers *this* flow and was minted for *this* app.
        if (!empty($token_data['id_token']) && !$this->id_token_matches_flow((string) $token_data['id_token'], (string) $flow['nonce'])) {
            $this->security->record_failed_attempt();
            $this->log_authentication('unknown', false, 'ID token did not match the login request');
            $this->display_error(
                __('Invalid Authentication Response', 'cf-zero-trust'),
                __('Cloudflare returned a token that does not belong to this login attempt. Nothing has been changed.', 'cf-zero-trust'),
                array(
                    __('Try logging in again from the start', 'cf-zero-trust'),
                    __('If this keeps happening, check that the Client ID in plugin settings matches the Cloudflare application', 'cf-zero-trust'),
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
        $this->authenticate_user($user_info, isset($flow['redirect_to']) ? (string) $flow['redirect_to'] : '');
    }

    /**
     * Check an ID token's nonce, audience and issuer against the flow
     *
     * @param string $id_token Raw JWT.
     * @param string $nonce    Nonce minted when the flow began.
     * @return bool
     */
    private function id_token_matches_flow(string $id_token, string $nonce): bool {
        $parts = explode('.', $id_token);
        if (3 !== count($parts)) {
            return false;
        }

        $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
        if (!is_array($payload)) {
            return false;
        }

        if (empty($payload['nonce']) || !hash_equals($nonce, (string) $payload['nonce'])) {
            return false;
        }

        $options = CFZT_Plugin::get_option();
        $audience = isset($payload['aud']) ? (array) $payload['aud'] : array();
        if (!in_array($options['client_id'], $audience, true)) {
            return false;
        }

        if (!empty($payload['iss']) && 0 !== strpos((string) $payload['iss'], 'https://' . $options['team_domain'])) {
            return false;
        }

        if (isset($payload['exp']) && (int) $payload['exp'] < time() - MINUTE_IN_SECONDS) {
            return false;
        }

        return true;
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
        $app_type = isset($options['app_type']) ? $options['app_type'] : CFZT_Plugin::APP_TYPE_SELF_HOSTED;

        if (CFZT_Plugin::APP_TYPE_SAAS === $app_type) {
            $token_url = 'https://' . $options['team_domain'] . '/cdn-cgi/access/sso/oidc/' . $options['client_id'] . '/token';
        } else {
            $token_url = 'https://' . $options['team_domain'] . '/cdn-cgi/access/token';
        }

        $response = wp_remote_post($token_url, array(
            'timeout' => 30,
            'body' => array(
                'grant_type' => 'authorization_code',
                'client_id' => $options['client_id'],
                'client_secret' => $this->security->get_client_secret(),
                'code' => $code,
                'redirect_uri' => CFZT_Plugin::get_redirect_uri()
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
        $app_type = isset($options['app_type']) ? $options['app_type'] : CFZT_Plugin::APP_TYPE_SELF_HOSTED;

        if (CFZT_Plugin::APP_TYPE_SAAS === $app_type) {
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
     * @param array  $user_info   User information from Cloudflare
     * @param string $redirect_to Destination captured when the flow began
     */
    private function authenticate_user($user_info, string $redirect_to = '') {
        $options = CFZT_Plugin::get_option();

        // Get email from user info
        $email = isset($user_info['email']) ? $user_info['email'] : '';
        if (empty($email) && isset($user_info['preferred_username'])) {
            $email = $user_info['preferred_username'];
        }

        if (empty($email) || !is_email($email)) {
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

        // Domain restrictions apply to every Cloudflare login, not only the
        // first one that happens to create the account.
        if (!CFZT_User_Helper::is_email_domain_allowed($email)) {
            $this->log_authentication($email, false, 'Email domain not allowed');
            $this->display_error(
                __('Email Domain Not Allowed', 'cf-zero-trust'),
                sprintf(
                    /* translators: %s: email address */
                    __('%s is not in a domain this site accepts logins from.', 'cf-zero-trust'),
                    '<strong>' . esc_html($email) . '</strong>'
                ),
                array(
                    __('Ask your site administrator to add your email domain under Email Domain Restrictions', 'cf-zero-trust'),
                    __('Make sure you signed in to Cloudflare with the right account', 'cf-zero-trust'),
                )
            );
        }

        // Check if user exists
        $user = get_user_by('email', $email);
        $auto_create_enabled = isset($options['auto_create_users']) && CFZT_Plugin::OPTION_YES === $options['auto_create_users'];

        if (!$user && $auto_create_enabled) {
            $user = CFZT_User_Helper::create_user($email, $user_info, 'oidc');
        } elseif ($user) {
            CFZT_User_Helper::sync_role_from_claims($user, $user_info);
        }

        if ($user) {
            // Log the user in
            wp_set_current_user($user->ID);
            wp_set_auth_cookie($user->ID, true);

            // Update last login meta
            CFZT_User_Helper::update_last_login($user->ID, 'oidc');

            // Log successful authentication
            $this->log_authentication($email, true);

            // Trigger action for other plugins
            do_action('cfzt_user_authenticated', $user, $user_info);

            wp_safe_redirect($this->get_login_redirect_url($redirect_to));
            exit;
        }

        $this->log_authentication($email, false, 'User creation disabled or failed');

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
        }

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

    /**
     * In primary mode, route interactive password logins to Cloudflare
     *
     * Runs at priority 30, after core's password check (20) and before the
     * backup-code handler (40). Whatever core decided about the password is
     * discarded here: in primary mode a password never grants access, so the
     * exploitable exemption for "callback-looking" requests is gone. The only
     * interactive path left open is a backup code, which is this plugin's own
     * emergency door.
     *
     * @param WP_User|WP_Error|null $user
     * @param string $username
     * @param string $password
     * @return WP_User|WP_Error|null
     */
    public function maybe_disable_wp_login($user, $username, $password) {
        if (!self::is_primary_mode()) {
            return $user;
        }

        // Backup codes are the emergency path; let the handler at 40 decide,
        // without the password result leaking through.
        if (!empty($_POST['cfzt_backup_code']) && '' !== trim((string) $_POST['cfzt_backup_code'])) {
            return null;
        }

        // Non-interactive contexts authenticate their own way.
        if (defined('DOING_AJAX') || defined('DOING_CRON') || defined('WP_CLI')
            || defined('XMLRPC_REQUEST') || defined('REST_REQUEST')) {
            return $user;
        }

        $start_url = self::get_login_start_url($this->requested_redirect_to());
        if ('' !== $start_url) {
            wp_safe_redirect($start_url);
            exit;
        }

        return $user;
    }

    /**
     * In primary mode, refuse the password-reset and registration screens
     *
     * They were only hidden with CSS before, which left them fully functional
     * for anyone who typed the URL.
     *
     * @since 2.0.0
     *
     * @return void
     */
    public function enforce_primary_mode_actions() {
        if (!self::is_primary_mode()) {
            return;
        }

        $action = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : 'login';

        /**
         * Filter the wp-login.php actions that primary mode refuses.
         *
         * @since 2.0.0
         *
         * @param array $blocked Action names.
         */
        $blocked = apply_filters('cfzt_primary_mode_blocked_actions', array(
            'lostpassword', 'retrievepassword', 'resetpass', 'rp', 'register',
        ));

        if (!in_array($action, $blocked, true)) {
            return;
        }

        $start_url = self::get_login_start_url();
        if ('' !== $start_url) {
            wp_safe_redirect($start_url);
            exit;
        }
    }

    /**
     * Whether Cloudflare is the only permitted login method
     *
     * @return bool
     */
    public static function is_primary_mode(): bool {
        $options = CFZT_Plugin::get_option();
        return isset($options['login_mode']) && CFZT_Plugin::LOGIN_MODE_PRIMARY === $options['login_mode'];
    }

    /**
     * Handle user login event
     *
     * @param string $user_login Username
     * @param WP_User $user User object
     */
    public function on_user_login($user_login, $user) {
        if (get_user_meta($user->ID, 'cfzt_user', true)) {
            $method = get_user_meta($user->ID, 'cfzt_auth_method', true);
            $this->log_authentication($user->user_email, true, '', $method ? (string) $method : 'password');
        }
    }

    /**
     * Handle failed login
     *
     * @param string $username Username
     */
    public function on_login_failed($username) {
        $this->log_authentication(CFZT_Logger::sanitize_identifier((string) $username), false, 'WordPress login failed', 'password');
    }

    /**
     * Log authentication attempts
     *
     * @param string $identifier Email or username
     * @param bool   $success    Success status
     * @param string $message    Optional message
     * @param string $method     Authentication method
     */
    private function log_authentication($identifier, $success, $message = '', $method = 'oidc') {
        CFZT_Logger::auth_attempt($identifier, $success, $method, $message);
    }

    /**
     * Get login redirect URL
     *
     * Order: the configured redirect, then the destination captured when the
     * flow began, then the dashboard.
     *
     * @param string $redirect_to Destination captured when the flow began.
     * @return string Redirect URL
     */
    private function get_login_redirect_url(string $redirect_to = '') {
        $options = CFZT_Plugin::get_option();

        if (!empty($options['redirect_after_login'])) {
            return $options['redirect_after_login'];
        }

        if ('' !== $redirect_to) {
            return wp_validate_redirect($redirect_to, admin_url());
        }

        return admin_url();
    }

    /**
     * The redirect_to the current request asked for, if any
     *
     * @return string
     */
    private function requested_redirect_to(): string {
        if (empty($_REQUEST['redirect_to'])) {
            return '';
        }
        return wp_validate_redirect((string) wp_unslash($_REQUEST['redirect_to']), '');
    }

    /**
     * Transient key for a flow id
     *
     * @param string $flow_id Flow id from the cookie.
     * @return string
     */
    private static function flow_key(string $flow_id): string {
        return 'cfzt_auth_flow_' . hash('sha256', $flow_id);
    }

    /**
     * Set or clear the flow cookie
     *
     * Written by hand so SameSite is sent on every supported PHP version. Lax
     * is required: the callback arrives as a top-level navigation from
     * Cloudflare, which Strict would refuse to attach the cookie to.
     *
     * @param string $value   Cookie value, empty to clear.
     * @param int    $expires Unix timestamp.
     * @return void
     */
    private function set_flow_cookie(string $value, int $expires): void {
        if (headers_sent()) {
            return;
        }

        $cookie = sprintf(
            '%s=%s; Expires=%s; Max-Age=%d; Path=/; HttpOnly; SameSite=Lax',
            self::FLOW_COOKIE,
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
     * Stop with the rate-limit error page
     *
     * @return void
     */
    private function rate_limited_error(): void {
        $this->display_error(
            __('Rate Limit Exceeded', 'cf-zero-trust'),
            __('Too many failed authentication attempts have been made from your IP address. This is a security measure to prevent brute force attacks.', 'cf-zero-trust'),
            array(
                __('Wait 5 minutes before trying again', 'cf-zero-trust'),
                __('If this persists, contact your site administrator', 'cf-zero-trust')
            ),
            429
        );
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
        $html .= '<p style="font-size: 16px; line-height: 1.6; color: #333;">' . wp_kses_post($error_message) . '</p>';

        // Troubleshooting steps
        if (!empty($troubleshooting_steps)) {
            $html .= '<div style="background: #f0f6fc; border-left: 4px solid #2271b1; padding: 15px; margin: 20px 0;">';
            $html .= '<h3 style="margin: 0 0 10px 0; font-size: 16px; color: #2271b1;">🔧 ' . esc_html__('Troubleshooting Steps:', 'cf-zero-trust') . '</h3>';
            $html .= '<ol style="margin: 0; padding-left: 20px;">';
            foreach ($troubleshooting_steps as $step) {
                $html .= '<li style="margin: 8px 0; line-height: 1.5;">' . wp_kses_post($step) . '</li>';
            }
            $html .= '</ol>';
            $html .= '</div>';
        }

        // Back button
        $html .= '<p style="margin-top: 20px;">';
        $html .= '<a href="' . esc_url(wp_login_url()) . '" style="display: inline-block; background: #2271b1; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: 600;">← ' . esc_html__('Back to Login', 'cf-zero-trust') . '</a>';
        $html .= ' <a href="' . esc_url(admin_url('options-general.php?page=cf-zero-trust')) . '" style="display: inline-block; background: #ddd; color: #333; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: 600; margin-left: 10px;">' . esc_html__('Plugin Settings', 'cf-zero-trust') . '</a>';
        $html .= '</p>';

        $html .= '</div>';
        $html .= '</div>';

        wp_die($html, $error_title, array('response' => $response_code));
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
