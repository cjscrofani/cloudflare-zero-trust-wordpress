<?php
/**
 * Provisions a Cloudflare Zero Trust Access application for this site
 *
 * Given any bearer token with "Access: Apps and Policies" edit permission,
 * this class discovers the account and team domain, creates a SaaS OIDC
 * application pointed at this site's callback URL, and writes the resulting
 * credentials into the plugin settings.
 *
 * The credential source is deliberately not this class's concern. It accepts a
 * token string, so a pasted API token today and an OAuth access token later
 * both work without changes here.
 *
 * Cloudflare returns the OIDC client secret only in the response to the
 * create call, so capturing it at creation is the entire reason this exists.
 *
 * @package CloudflareZeroTrustLogin
 * @since   1.1.0
 *
 * @example
 * $provisioner = new CFZT_Provisioner($security);
 * $result = $provisioner->provision($token, $account_id, array(
 *     'app_name'    => 'My Site Login',
 *     'policy_mode' => 'email_domain',
 *     'policy_value'=> 'example.com',
 * ));
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class CFZT_Provisioner {

    /**
     * Policy modes
     */
    const POLICY_EVERYONE     = 'everyone';
    const POLICY_EMAIL_DOMAIN = 'email_domain';
    const POLICY_EMAILS       = 'emails';

    /**
     * Default Access session duration
     */
    const DEFAULT_SESSION_DURATION = '24h';

    /**
     * Security handler, used for encrypting the stored client secret
     * @var CFZT_Security
     */
    private $security;

    /**
     * Constructor
     *
     * @param CFZT_Security $security Security handler.
     */
    public function __construct($security) {
        $this->security = $security;
    }

    /**
     * Validate a token and describe what it can reach
     *
     * Returns the list of accounts along with each one's Zero Trust team
     * domain, so the UI can let the user pick and can warn about accounts that
     * have no Zero Trust organization yet.
     *
     * @param string $token      Cloudflare API token.
     * @param string $account_id Optional. Look up only this account, for tokens
     *                           that cannot list accounts.
     * @return array|WP_Error
     */
    public function connect(string $token, string $account_id = '') {
        $api = new CFZT_Cloudflare_API($token);

        if (!$api->has_token()) {
            return new WP_Error(
                'cfzt_no_token',
                __('Paste your Cloudflare API token first.', 'zero-trust-login-for-cloudflare')
            );
        }

        if ('' !== $account_id) {
            $account = $api->get_account($account_id);
            if (is_wp_error($account)) {
                return $account;
            }
            $accounts = array($account);
        } else {
            $accounts = $api->get_accounts();
            if (is_wp_error($accounts)) {
                return $accounts;
            }
        }

        if (empty($accounts)) {
            return new WP_Error(
                'cfzt_no_accounts',
                __('This token cannot see any Cloudflare accounts. This usually means it is missing Account → Account Settings → Read, which Cloudflare requires before a token can list accounts. Edit the token in Cloudflare to add that permission, then try again.', 'zero-trust-login-for-cloudflare')
            );
        }

        $described = array();

        foreach ($accounts as $account) {
            if (empty($account['id'])) {
                continue;
            }

            $entry = array(
                'id'          => $account['id'],
                'name'        => isset($account['name']) ? $account['name'] : $account['id'],
                'team_domain' => '',
                'ready'       => false,
                'notice'      => '',
            );

            $org = $api->get_access_organization($account['id']);

            if (is_wp_error($org)) {
                $entry['notice'] = $org->get_error_message();
            } elseif (!empty($org['auth_domain'])) {
                $entry['team_domain'] = $org['auth_domain'];
                $entry['ready'] = true;
            } else {
                $entry['notice'] = __('No Zero Trust team domain is set for this account yet.', 'zero-trust-login-for-cloudflare');
            }

            $described[] = $entry;
        }

        return array(
            'accounts'     => $described,
            'redirect_uri' => CFZT_Plugin::get_redirect_uri(),
        );
    }

    /**
     * Create the Access application and save its credentials
     *
     * @param string $token      Cloudflare API token.
     * @param string $account_id Cloudflare account id.
     * @param array  $args       {
     *     @type string $app_name             Application name shown in Cloudflare.
     *     @type string $policy_mode          One of the POLICY_* constants.
     *     @type string $policy_value         Domain list or email list, per mode.
     *     @type string $session_duration     Access session duration, e.g. "24h".
     *     @type bool   $app_launcher_visible Show the app in the App Launcher.
     *     @type bool   $replace_existing     Delete any app already pointing at this
     *                                        site's callback before creating the new one.
     * }
     * @return array|WP_Error
     */
    public function provision(string $token, string $account_id, array $args) {
        $api = new CFZT_Cloudflare_API($token);

        if (!$api->has_token()) {
            return new WP_Error(
                'cfzt_no_token',
                __('Paste your Cloudflare API token first.', 'zero-trust-login-for-cloudflare')
            );
        }

        if ('' === trim($account_id)) {
            return new WP_Error(
                'cfzt_no_account',
                __('Choose which Cloudflare account to create the application in.', 'zero-trust-login-for-cloudflare')
            );
        }

        // The team domain is required for authentication, so resolve it first.
        $org = $api->get_access_organization($account_id);
        if (is_wp_error($org)) {
            return $org;
        }

        if (empty($org['auth_domain'])) {
            return new WP_Error(
                'cfzt_no_team_domain',
                __('This account has no Zero Trust team domain. Set one in the Zero Trust dashboard, then run setup again.', 'zero-trust-login-for-cloudflare')
            );
        }

        $team_domain = $org['auth_domain'];
        $redirect_uri = CFZT_Plugin::get_redirect_uri();

        // wp-config constants win over anything we store, and the new secret
        // is returned by Cloudflare exactly once. Provisioning now would create
        // a live application whose secret nobody has. Refuse up front.
        if ((defined('CFZT_CLIENT_ID') && CFZT_CLIENT_ID) || (defined('CFZT_CLIENT_SECRET') && CFZT_CLIENT_SECRET)) {
            return new WP_Error(
                'cfzt_constants_defined',
                __('CFZT_CLIENT_ID or CFZT_CLIENT_SECRET is defined in wp-config.php, and those values override anything saved here. Remove the constants (or create the application manually and update them), then run setup again.', 'zero-trust-login-for-cloudflare')
            );
        }

        // One callback, one application. If something already points at this
        // site, either stop and ask, or replace it when the user has confirmed.
        $existing = $this->find_apps_by_redirect_uri($api, $account_id, $redirect_uri);
        if (is_wp_error($existing)) {
            return $existing;
        }

        if (!empty($existing) && empty($args['replace_existing'])) {
            $first = $existing[0];
            return new WP_Error(
                'cfzt_app_exists',
                sprintf(
                    /* translators: %s: existing Cloudflare application name */
                    __('An Access application called "%s" already points at this site. You can replace it: the old application will be deleted from Cloudflare and a new one created with fresh credentials.', 'zero-trust-login-for-cloudflare'),
                    isset($first['name']) ? $first['name'] : __('Untitled', 'zero-trust-login-for-cloudflare')
                ),
                array(
                    'existing_app_id'   => isset($first['id']) ? $first['id'] : '',
                    'existing_app_name' => isset($first['name']) ? $first['name'] : '',
                )
            );
        }

        foreach ($existing as $old_app) {
            if (empty($old_app['id'])) {
                continue;
            }
            $deleted = $api->delete_access_app($account_id, $old_app['id']);
            if (is_wp_error($deleted)) {
                return new WP_Error(
                    'cfzt_replace_failed',
                    sprintf(
                        /* translators: %s: error detail from Cloudflare */
                        __('Could not delete the existing application, so nothing was changed: %s', 'zero-trust-login-for-cloudflare'),
                        $deleted->get_error_message()
                    )
                );
            }
        }

        $policy = $this->build_policy($args);
        if (is_wp_error($policy)) {
            return $policy;
        }

        $body = array(
            'name'                 => $this->resolve_app_name($args),
            'type'                 => 'saas',
            'session_duration'     => $this->resolve_session_duration($args),
            'app_launcher_visible' => !empty($args['app_launcher_visible']),
            'saas_app'             => array(
                'auth_type'     => 'oidc',
                'redirect_uris' => array($redirect_uri),
                'grant_types'   => array('authorization_code'),
                'scopes'        => array('openid', 'email', 'profile', 'groups'),
            ),
            'policies'             => array($policy),
        );

        /**
         * Filter the Access application payload before it is sent to Cloudflare.
         *
         * @since 2.0.0
         *
         * @param array  $body       Application payload.
         * @param string $account_id Cloudflare account id.
         */
        $body = apply_filters('cfzt_provision_app_body', $body, $account_id);

        $app = $api->create_access_app($account_id, $body);
        if (is_wp_error($app)) {
            return $app;
        }

        $client_id = isset($app['saas_app']['client_id']) ? $app['saas_app']['client_id'] : '';
        $client_secret = isset($app['saas_app']['client_secret']) ? $app['saas_app']['client_secret'] : '';

        // Without both halves the app is useless to us, and the secret can
        // never be retrieved again, so remove the orphan rather than leave it.
        if ('' === $client_id || '' === $client_secret) {
            if (!empty($app['id'])) {
                $api->delete_access_app($account_id, $app['id']);
            }

            return new WP_Error(
                'cfzt_no_credentials_returned',
                __('Cloudflare created the application but did not return OIDC credentials, so it was removed again. Please retry, or create the application manually.', 'zero-trust-login-for-cloudflare')
            );
        }

        $this->save_credentials(array(
            'team_domain'   => $team_domain,
            'client_id'     => $client_id,
            'client_secret' => $client_secret,
            'account_id'    => $account_id,
            'app_id'        => isset($app['id']) ? $app['id'] : '',
        ));

        if (class_exists('CFZT_Logger')) {
            CFZT_Logger::info('Provisioned Cloudflare Access application', array(
                'account_id'  => $account_id,
                'app_id'      => isset($app['id']) ? $app['id'] : '',
                'team_domain' => $team_domain,
            ));
        }

        return array(
            'app_id'       => isset($app['id']) ? $app['id'] : '',
            'app_name'     => isset($app['name']) ? $app['name'] : '',
            'team_domain'  => $team_domain,
            'client_id'    => $client_id,
            'redirect_uri' => $redirect_uri,
            'warnings'     => $this->collect_warnings($api, $account_id),
        );
    }

    /**
     * Find every SaaS application already pointing at our callback
     *
     * @param CFZT_Cloudflare_API $api          API client.
     * @param string              $account_id   Cloudflare account id.
     * @param string              $redirect_uri Callback URL to match.
     * @return array|WP_Error Matching apps (possibly empty), WP_Error on failure.
     */
    private function find_apps_by_redirect_uri(CFZT_Cloudflare_API $api, string $account_id, string $redirect_uri) {
        $apps = $api->get_access_apps($account_id);

        if (is_wp_error($apps)) {
            // Listing is a courtesy check. A token that can create but not list
            // should not be blocked from provisioning.
            if ('cfzt_api_forbidden' === $apps->get_error_code()) {
                return array();
            }
            return $apps;
        }

        $matches = array();
        foreach ($apps as $app) {
            if (empty($app['saas_app']['redirect_uris']) || !is_array($app['saas_app']['redirect_uris'])) {
                continue;
            }
            if (in_array($redirect_uri, $app['saas_app']['redirect_uris'], true)) {
                $matches[] = $app;
            }
        }

        return $matches;
    }

    /**
     * Build the inline Access policy that decides who may log in
     *
     * @param array $args Provision arguments.
     * @return array|WP_Error
     */
    private function build_policy(array $args) {
        $mode = isset($args['policy_mode']) ? $args['policy_mode'] : self::POLICY_EMAIL_DOMAIN;
        $raw_value = isset($args['policy_value']) ? $args['policy_value'] : '';
        $include = array();

        switch ($mode) {
            case self::POLICY_EVERYONE:
                // Must serialize as a JSON object, not an empty array.
                $include[] = array('everyone' => (object) array());
                break;

            case self::POLICY_EMAILS:
                foreach ($this->split_list($raw_value) as $email) {
                    if (!is_email($email)) {
                        return new WP_Error(
                            'cfzt_invalid_policy_email',
                            sprintf(
                                /* translators: %s: the invalid email address */
                                __('"%s" is not a valid email address.', 'zero-trust-login-for-cloudflare'),
                                $email
                            )
                        );
                    }
                    $include[] = array('email' => array('email' => $email));
                }
                if (empty($include)) {
                    return new WP_Error(
                        'cfzt_no_policy_emails',
                        __('List at least one email address that should be allowed to log in.', 'zero-trust-login-for-cloudflare')
                    );
                }
                break;

            case self::POLICY_EMAIL_DOMAIN:
            default:
                foreach ($this->split_list($raw_value) as $domain) {
                    $domain = ltrim($domain, '@');
                    if (!preg_match('/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i', $domain)) {
                        return new WP_Error(
                            'cfzt_invalid_policy_domain',
                            sprintf(
                                /* translators: %s: the invalid domain */
                                __('"%s" is not a valid email domain.', 'zero-trust-login-for-cloudflare'),
                                $domain
                            )
                        );
                    }
                    $include[] = array('email_domain' => array('domain' => $domain));
                }
                if (empty($include)) {
                    return new WP_Error(
                        'cfzt_no_policy_domains',
                        __('Enter at least one email domain that should be allowed to log in.', 'zero-trust-login-for-cloudflare')
                    );
                }
                break;
        }

        return array(
            // Named for what it does: it admits people to the WordPress login,
            // not to an administrator role. Roles come from plugin settings.
            'name'     => sprintf(
                /* translators: %s: site host name */
                __('WordPress login (%s)', 'zero-trust-login-for-cloudflare'),
                wp_parse_url(home_url(), PHP_URL_HOST)
            ),
            'decision' => 'allow',
            'include'  => $include,
        );
    }

    /**
     * Split a comma or newline separated list into trimmed, non-empty values
     *
     * @param string $value Raw input.
     * @return array
     */
    private function split_list(string $value): array {
        $parts = preg_split('/[\s,;]+/', strtolower(trim($value)));
        if (!is_array($parts)) {
            return array();
        }
        return array_values(array_filter(array_map('trim', $parts), 'strlen'));
    }

    /**
     * Resolve the application name, falling back to the site name
     *
     * @param array $args Provision arguments.
     * @return string
     */
    private function resolve_app_name(array $args): string {
        $name = isset($args['app_name']) ? trim($args['app_name']) : '';

        if ('' === $name) {
            $name = sprintf(
                /* translators: %s: WordPress site name */
                __('%s (WordPress)', 'zero-trust-login-for-cloudflare'),
                wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES)
            );
        }

        // Cloudflare rejects excessively long names.
        return substr($name, 0, 100);
    }

    /**
     * Resolve the Access session duration
     *
     * @param array $args Provision arguments.
     * @return string
     */
    private function resolve_session_duration(array $args): string {
        $duration = isset($args['session_duration']) ? strtolower(trim($args['session_duration'])) : '';

        // Cloudflare accepts minutes and hours only; express days as hours.
        if (preg_match('/^(\d+)d$/', $duration, $m)) {
            return ((int) $m[1] * 24) . 'h';
        }

        if (!preg_match('/^\d+[mh]$/', $duration)) {
            return self::DEFAULT_SESSION_DURATION;
        }

        return $duration;
    }

    /**
     * Collect non-fatal warnings worth surfacing after a successful provision
     *
     * @param CFZT_Cloudflare_API $api        API client.
     * @param string              $account_id Cloudflare account id.
     * @return array List of human readable warnings.
     */
    private function collect_warnings(CFZT_Cloudflare_API $api, string $account_id): array {
        $warnings = array();

        // An Access app with no identity provider cannot authenticate anyone.
        $idps = $api->get_identity_providers($account_id);
        if (!is_wp_error($idps) && empty($idps)) {
            $warnings[] = __('This Cloudflare account has no identity providers configured. Add one (or enable One-time PIN) in Zero Trust → Settings → Authentication, or nobody will be able to log in.', 'zero-trust-login-for-cloudflare');
        }

        if (!$this->security->is_encryption_available()) {
            $warnings[] = __('OpenSSL is not available, so the client secret is stored with basic obfuscation only. Consider defining CFZT_CLIENT_SECRET in wp-config.php instead.', 'zero-trust-login-for-cloudflare');
        }

        if (!is_ssl()) {
            $warnings[] = __('This site is not served over HTTPS. Cloudflare will not be able to complete the login redirect until it is.', 'zero-trust-login-for-cloudflare');
        }

        return $warnings;
    }

    /**
     * Persist the provisioned credentials into plugin settings
     *
     * Merges into the existing option rather than replacing it, so unrelated
     * settings survive. The client secret is encrypted on the way in, matching
     * how the settings form stores it.
     *
     * @param array $data Provisioned values.
     * @return void
     */
    private function save_credentials(array $data): void {
        $options = get_option('cfzt_settings', array());
        if (!is_array($options)) {
            $options = array();
        }

        $options['auth_method']   = CFZT_Plugin::AUTH_METHOD_OIDC;
        $options['app_type']      = CFZT_Plugin::APP_TYPE_SAAS;
        $options['team_domain']   = $data['team_domain'];
        $options['client_id']     = $data['client_id'];

        $options['client_secret'] = $this->security->encrypt_data($data['client_secret']);

        // Provenance, so the UI can tell a provisioned app from a hand-made one.
        $options['provisioned_account_id'] = $data['account_id'];
        $options['provisioned_app_id']     = $data['app_id'];
        $options['provisioned_at']         = current_time('mysql');

        // Sensible defaults for a first run, without clobbering existing choices.
        if (!isset($options['login_mode'])) {
            $options['login_mode'] = CFZT_Plugin::LOGIN_MODE_SECONDARY;
        }
        if (!isset($options['auto_create_users'])) {
            $options['auto_create_users'] = CFZT_Plugin::OPTION_YES;
        }
        if (empty($options['default_role'])) {
            $options['default_role'] = CFZT_Plugin::DEFAULT_ROLE;
        }
        if (!isset($options['enable_logging'])) {
            $options['enable_logging'] = CFZT_Plugin::OPTION_NO;
        }

        // Bypasses the form sanitizer, which would otherwise encrypt the
        // already-encrypted secret a second time.
        CFZT_Plugin::save_settings($options);

        // The setup is demonstrably complete now, so stop nagging about it.
        update_option('cfzt_activation_notice_dismissed', true);
        delete_transient('cfzt_activation_notice');
    }

    /**
     * Build a Cloudflare dashboard deep link that pre-selects the needed token permissions
     *
     * Cloudflare surfaces a notice for permission keys it cannot resolve rather
     * than silently dropping them, so a stale key degrades to "user picks the
     * permission by hand" rather than "user gets a broken token".
     *
     * @return string
     */
    public static function get_token_template_url(): string {
        /**
         * Filter the permission groups requested by the token deep link.
         *
         * @since 2.0.0
         *
         * @param array $keys Permission group keys.
         */
        // Keys are the template keys from Cloudflare's "API token template URLs"
        // reference (developers.cloudflare.com/fundamentals/api/how-to/account-owned-token-template/),
        // not the permission group ids or labels: `access` is "Access: Apps and
        // Policies", `access_acct` is "Access: Organizations, Identity Providers,
        // and Groups", and `account_settings` is "Account Settings". The last one
        // is what lets GET /accounts list the account at all: with only the two
        // Access permissions Cloudflare returns an empty list and setup cannot
        // start. Verified against the live dashboard and a real provision on
        // 2026-10-23.
        $permission_keys = apply_filters('cfzt_token_permission_keys', array(
            array('key' => 'access', 'type' => 'edit'),
            array('key' => 'access_acct', 'type' => 'read'),
            array('key' => 'account_settings', 'type' => 'read'),
        ));

        // These values are rawurlencode()d deliberately. WordPress's
        // add_query_arg() does NOT encode values (build_query() passes
        // $urlencode = false), so an unencoded JSON value survives until
        // esc_url() strips {, } and " as invalid URL characters, silently
        // mangling the permission list into something Cloudflare cannot read.
        return add_query_arg(
            array(
                'permissionGroupKeys' => rawurlencode(wp_json_encode($permission_keys)),
                'accountId'           => '*',
                'zoneId'              => 'all',
                'name'                => rawurlencode(sprintf(
                    /* translators: %s: site host name */
                    __('WordPress Zero Trust setup (%s)', 'zero-trust-login-for-cloudflare'),
                    wp_parse_url(home_url(), PHP_URL_HOST)
                )),
            ),
            'https://dash.cloudflare.com/profile/api-tokens' // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- deep link to the Cloudflare dashboard for creating a token; nothing is loaded from it
        );
    }
}
