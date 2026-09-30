<?php
/**
 * Guided setup endpoints for automatic Cloudflare provisioning
 *
 * Exposes the two admin-AJAX actions the setup wizard needs: one to validate a
 * pasted Cloudflare API token and describe the accounts it can reach, and one
 * to create the Access application and save its credentials.
 *
 * The API token is accepted per request and is deliberately never written to
 * the database, so the site never holds a credential capable of changing
 * Cloudflare configuration after setup finishes.
 *
 * @package CloudflareZeroTrustLogin
 * @since   1.1.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class CFZT_Setup {

    /**
     * Nonce action shared by the setup endpoints
     */
    const NONCE_ACTION = 'cfzt_setup';

    /**
     * Provisioner instance
     * @var CFZT_Provisioner
     */
    private $provisioner;

    /**
     * Constructor
     *
     * @param CFZT_Security $security Security handler.
     */
    public function __construct($security) {
        $this->provisioner = new CFZT_Provisioner($security);
        $this->init_hooks();
    }

    /**
     * Register hooks
     */
    private function init_hooks() {
        add_action('wp_ajax_cfzt_connect_cloudflare', array($this, 'ajax_connect'));
        add_action('wp_ajax_cfzt_provision_app', array($this, 'ajax_provision'));
    }

    /**
     * Validate a token and return the accounts it can reach
     */
    public function ajax_connect() {
        $token = $this->authorize_request();

        $account_id = isset($_POST['account_id'])
            ? $this->sanitize_account_id(wp_unslash($_POST['account_id']))
            : '';

        $result = $this->provisioner->connect($token, $account_id);

        if (is_wp_error($result)) {
            wp_send_json_error(array(
                'code'    => $result->get_error_code(),
                'message' => $result->get_error_message(),
            ));
        }

        wp_send_json_success($result);
    }

    /**
     * Create the Access application and store its credentials
     */
    public function ajax_provision() {
        $token = $this->authorize_request();

        $account_id = isset($_POST['account_id'])
            ? $this->sanitize_account_id(wp_unslash($_POST['account_id']))
            : '';

        $args = array(
            'app_name'             => isset($_POST['app_name']) ? sanitize_text_field(wp_unslash($_POST['app_name'])) : '',
            'policy_mode'          => isset($_POST['policy_mode']) ? sanitize_key(wp_unslash($_POST['policy_mode'])) : CFZT_Provisioner::POLICY_EMAIL_DOMAIN,
            'policy_value'         => isset($_POST['policy_value']) ? sanitize_text_field(wp_unslash($_POST['policy_value'])) : '',
            'session_duration'     => isset($_POST['session_duration']) ? sanitize_text_field(wp_unslash($_POST['session_duration'])) : '',
            'app_launcher_visible' => !empty($_POST['app_launcher_visible']) && 'false' !== $_POST['app_launcher_visible'],
            'overwrite'            => !empty($_POST['overwrite']) && 'false' !== $_POST['overwrite'],
        );

        $result = $this->provisioner->provision($token, $account_id, $args);

        if (is_wp_error($result)) {
            wp_send_json_error(array(
                'code'    => $result->get_error_code(),
                'message' => $result->get_error_message(),
                // Lets the UI offer a confirm-and-retry instead of a dead end.
                'can_overwrite' => 'cfzt_app_exists' === $result->get_error_code(),
                'data'    => $result->get_error_data(),
            ));
        }

        wp_send_json_success($result);
    }

    /**
     * Verify nonce and capability, then extract the token
     *
     * Sends a JSON error and exits if the request is not authorized or the
     * token is malformed.
     *
     * @return string Validated token.
     */
    private function authorize_request(): string {
        if (!check_ajax_referer(self::NONCE_ACTION, 'nonce', false)) {
            wp_send_json_error(array(
                'code'    => 'cfzt_bad_nonce',
                'message' => __('Security check failed. Reload the page and try again.', 'cf-zero-trust'),
            ));
        }

        if (!current_user_can('manage_options')) {
            wp_send_json_error(array(
                'code'    => 'cfzt_forbidden',
                'message' => __('You do not have permission to run setup.', 'cf-zero-trust'),
            ));
        }

        // Not passed through sanitize_text_field: that would silently mangle a
        // mistyped token into a different-but-valid-looking string. Validate
        // the shape instead and reject anything unexpected.
        $token = isset($_POST['token']) ? trim((string) wp_unslash($_POST['token'])) : '';

        if ('' === $token) {
            wp_send_json_error(array(
                'code'    => 'cfzt_no_token',
                'message' => __('Paste your Cloudflare API token first.', 'cf-zero-trust'),
            ));
        }

        if (!preg_match('/^[A-Za-z0-9_\-]{20,200}$/', $token)) {
            wp_send_json_error(array(
                'code'    => 'cfzt_malformed_token',
                'message' => __('That does not look like a Cloudflare API token. Copy the whole token, without surrounding quotes or spaces.', 'cf-zero-trust'),
            ));
        }

        return $token;
    }

    /**
     * Sanitize a Cloudflare account id
     *
     * @param mixed $value Raw input.
     * @return string Empty string if the value is not a plausible account id.
     */
    private function sanitize_account_id($value): string {
        $value = is_string($value) ? strtolower(trim($value)) : '';

        return preg_match('/^[a-f0-9]{32}$/', $value) ? $value : '';
    }
}
