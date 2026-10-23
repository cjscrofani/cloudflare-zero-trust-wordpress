<?php
/**
 * Minimal Cloudflare API v4 client
 *
 * A thin, dependency-free wrapper around the endpoints this plugin needs to
 * provision a Zero Trust Access application. Authenticates with a bearer
 * token, which may be either a user API token or an account-owned token.
 *
 * The token is never persisted by this class and is never written to logs.
 *
 * @package CloudflareZeroTrustLogin
 * @since   1.1.0
 *
 * @example
 * $api = new CFZT_Cloudflare_API($token);
 * $accounts = $api->get_accounts();
 * if (is_wp_error($accounts)) {
 *     echo $accounts->get_error_message();
 * }
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class CFZT_Cloudflare_API {

    /**
     * Cloudflare API v4 base URL
     */
    const API_BASE = 'https://api.cloudflare.com/client/v4';

    /**
     * Request timeout in seconds
     */
    const TIMEOUT = 20;

    /**
     * Bearer token used for all requests
     * @var string
     */
    private $token;

    /**
     * Constructor
     *
     * @param string $token Cloudflare API token.
     */
    public function __construct(string $token) {
        $this->token = trim($token);
    }

    /**
     * Whether a non-empty token was supplied
     *
     * @return bool
     */
    public function has_token(): bool {
        return $this->token !== '';
    }

    /**
     * List accounts the token can see
     *
     * @return array|WP_Error Array of account objects.
     */
    public function get_accounts() {
        return $this->request('GET', '/accounts', null, array('per_page' => 50));
    }

    /**
     * Get a single account by id
     *
     * Used as a fallback when listing accounts is not permitted by the token.
     *
     * @param string $account_id Cloudflare account id.
     * @return array|WP_Error
     */
    public function get_account(string $account_id) {
        return $this->request('GET', '/accounts/' . rawurlencode($account_id));
    }

    /**
     * Get the Zero Trust organization for an account
     *
     * The `auth_domain` field of the response is the team domain the plugin
     * needs (e.g. `yourteam.cloudflareaccess.com`).
     *
     * @param string $account_id Cloudflare account id.
     * @return array|WP_Error
     */
    public function get_access_organization(string $account_id) {
        return $this->request('GET', '/accounts/' . rawurlencode($account_id) . '/access/organizations');
    }

    /**
     * List configured identity providers for an account
     *
     * @param string $account_id Cloudflare account id.
     * @return array|WP_Error
     */
    public function get_identity_providers(string $account_id) {
        return $this->request('GET', '/accounts/' . rawurlencode($account_id) . '/access/identity_providers');
    }

    /**
     * List Access applications for an account
     *
     * @param string $account_id Cloudflare account id.
     * @return array|WP_Error
     */
    public function get_access_apps(string $account_id) {
        return $this->request('GET', '/accounts/' . rawurlencode($account_id) . '/access/apps', null, array('per_page' => 100));
    }

    /**
     * Create an Access application
     *
     * For SaaS OIDC applications the response contains `saas_app.client_secret`,
     * which Cloudflare returns *only* on this POST. It cannot be read back later.
     *
     * @param string $account_id Cloudflare account id.
     * @param array  $body       Application payload.
     * @return array|WP_Error
     */
    public function create_access_app(string $account_id, array $body) {
        return $this->request('POST', '/accounts/' . rawurlencode($account_id) . '/access/apps', $body);
    }

    /**
     * Delete an Access application
     *
     * Used to roll back a partially completed provision.
     *
     * @param string $account_id Cloudflare account id.
     * @param string $app_id     Application id.
     * @return array|WP_Error
     */
    public function delete_access_app(string $account_id, string $app_id) {
        return $this->request('DELETE', '/accounts/' . rawurlencode($account_id) . '/access/apps/' . rawurlencode($app_id));
    }

    /**
     * Perform an API request and unwrap the Cloudflare envelope
     *
     * @param string     $method HTTP method.
     * @param string     $path   Path relative to the API base.
     * @param array|null $body   Optional JSON body.
     * @param array      $query  Optional query arguments.
     * @return array|WP_Error The `result` payload on success.
     */
    private function request(string $method, string $path, $body = null, array $query = array()) {
        if (!$this->has_token()) {
            return new WP_Error(
                'cfzt_api_no_token',
                __('No Cloudflare API token was provided.', 'cf-zero-trust')
            );
        }

        $url = self::API_BASE . $path;
        if (!empty($query)) {
            $url = add_query_arg($query, $url);
        }

        $args = array(
            'method'    => $method,
            'timeout'   => self::TIMEOUT,
            'sslverify' => true,
            'headers'   => array(
                'Authorization' => 'Bearer ' . $this->token,
                'Content-Type'  => 'application/json',
                'Accept'        => 'application/json',
            ),
        );

        if (null !== $body) {
            $args['body'] = wp_json_encode($body);
        }

        $response = wp_remote_request($url, $args);

        if (is_wp_error($response)) {
            return new WP_Error(
                'cfzt_api_http_error',
                sprintf(
                    /* translators: %s: transport level error message */
                    __('Could not reach the Cloudflare API: %s', 'cf-zero-trust'),
                    $response->get_error_message()
                )
            );
        }

        $status = (int) wp_remote_retrieve_response_code($response);
        $decoded = json_decode(wp_remote_retrieve_body($response), true);

        if (!is_array($decoded)) {
            return new WP_Error(
                'cfzt_api_bad_response',
                sprintf(
                    /* translators: %d: HTTP status code */
                    __('Cloudflare returned an unreadable response (HTTP %d).', 'cf-zero-trust'),
                    $status
                )
            );
        }

        if (empty($decoded['success'])) {
            return $this->build_error($status, $decoded, $path);
        }

        // Some endpoints (e.g. DELETE) return a null result on success.
        return isset($decoded['result']) && is_array($decoded['result']) ? $decoded['result'] : array();
    }

    /**
     * Translate a Cloudflare error envelope into an actionable WP_Error
     *
     * @param int    $status  HTTP status code.
     * @param array  $decoded Decoded response body.
     * @param string $path    Request path, used to tailor guidance.
     * @return WP_Error
     */
    private function build_error(int $status, array $decoded, string $path): WP_Error {
        $messages = array();
        $codes = array();

        if (!empty($decoded['errors']) && is_array($decoded['errors'])) {
            foreach ($decoded['errors'] as $error) {
                if (!empty($error['message'])) {
                    $messages[] = $error['message'];
                }
                if (isset($error['code'])) {
                    $codes[] = (int) $error['code'];
                }
            }
        }

        $detail = !empty($messages)
            ? implode('; ', $messages)
            : sprintf(
                /* translators: %d: HTTP status code */
                __('HTTP %d', 'cf-zero-trust'),
                $status
            );

        // Invalid, expired or malformed token. A bare 400 is *not* this: it
        // is Cloudflare rejecting the request body, and telling the user to
        // re-create their token would send them in exactly the wrong direction.
        if (401 === $status || array_intersect($codes, array(1000, 6003, 9109))) {
            return new WP_Error(
                'cfzt_api_unauthorized',
                sprintf(
                    /* translators: %s: error detail from Cloudflare */
                    __('Cloudflare rejected the API token: %s. Check that you pasted the whole token and that it has not been revoked.', 'cf-zero-trust'),
                    $detail
                ),
                array('status' => $status)
            );
        }

        if (400 === $status) {
            return new WP_Error(
                'cfzt_api_bad_request',
                sprintf(
                    /* translators: %s: error detail from Cloudflare */
                    __('Cloudflare rejected the request: %s', 'cf-zero-trust'),
                    $detail
                ),
                array('status' => $status)
            );
        }

        // Token authenticated but is missing a permission.
        if (403 === $status) {
            return new WP_Error(
                'cfzt_api_forbidden',
                sprintf(
                    /* translators: %s: error detail from Cloudflare */
                    __('The API token is valid but does not have permission for this action: %s. It needs "Access: Apps and Policies" set to Edit.', 'cf-zero-trust'),
                    $detail
                ),
                array('status' => $status)
            );
        }

        // No Zero Trust organization on this account yet.
        if (404 === $status && false !== strpos($path, '/access/organizations')) {
            return new WP_Error(
                'cfzt_no_zero_trust_org',
                __('This Cloudflare account does not have a Zero Trust organization yet. Open the Zero Trust dashboard and choose a team domain, then try again.', 'cf-zero-trust'),
                array('status' => $status)
            );
        }

        if (429 === $status) {
            return new WP_Error(
                'cfzt_api_rate_limited',
                __('Cloudflare is rate limiting these requests. Wait a minute and try again.', 'cf-zero-trust'),
                array('status' => $status)
            );
        }

        return new WP_Error(
            'cfzt_api_error',
            sprintf(
                /* translators: %s: error detail from Cloudflare */
                __('Cloudflare API error: %s', 'cf-zero-trust'),
                $detail
            ),
            array('status' => $status)
        );
    }
}
