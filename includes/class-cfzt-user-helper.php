<?php
/**
 * User management helper for Cloudflare Zero Trust
 *
 * Shared user creation and management functionality used by OIDC authentication.
 *
 * @package CloudflareZeroTrustLogin
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class CFZT_User_Helper {

    /**
     * Create new WordPress user from authentication data
     *
     * @param string $email User email address
     * @param array $user_info User information from authentication provider
     * @param string $auth_method Authentication method used (e.g. 'oidc')
     * @return WP_User|false User object on success, false on failure
     */
    public static function create_user(string $email, array $user_info, string $auth_method = 'oidc') {
        $options = CFZT_Plugin::get_option();

        // Check email domain restrictions
        if (!self::is_email_domain_allowed($email)) {
            CFZT_Logger::warning('Email domain not allowed', array(
                'email' => $email,
                'auth_method' => $auth_method
            ));
            return false;
        }

        // Use the full email address as the username so accounts are unambiguous
        // across domains (jane@a.com and jane@b.com must not collide as "jane").
        // Strict sanitisation mirrors what wp_insert_user() applies, so what we
        // check for uniqueness is what WordPress will actually store.
        $username = sanitize_user(strtolower($email), true);
        $username = apply_filters('cfzt_new_username', $username, $email, $user_info);
        $username = self::ensure_unique_username($username);

        // Create the user with a random password
        $user_id = wp_create_user(
            $username,
            wp_generate_password(32, true, true),
            $email
        );

        if (is_wp_error($user_id)) {
            CFZT_Logger::error('Failed to create user', array(
                'email' => $email,
                'error' => $user_id->get_error_message(),
                'auth_method' => $auth_method
            ));
            return false;
        }

        $user = get_user_by('id', $user_id);

        if (!$user) {
            CFZT_Logger::error('User created but could not be retrieved', array(
                'user_id' => $user_id,
                'email' => $email
            ));
            return false;
        }

        // Set user role (check role mapping first)
        $role = self::determine_user_role($user_info, $options);
        $user->set_role($role);

        // Update user meta
        update_user_meta($user_id, 'cfzt_user', true);
        update_user_meta($user_id, 'cfzt_auth_method', $auth_method);

        // Store the unique identifier (sub)
        $sub = isset($user_info['sub']) ? $user_info['sub'] : $email;
        update_user_meta($user_id, 'cfzt_sub', $sub);

        // Store additional claims if available
        if (isset($user_info['iss'])) {
            update_user_meta($user_id, 'cfzt_issuer', $user_info['iss']);
        }

        // Update display name if available
        $display_name = self::get_display_name_from_user_info($user_info);
        if (!empty($display_name)) {
            wp_update_user(array(
                'ID' => $user_id,
                'display_name' => $display_name
            ));
        }

        // Log successful user creation
        CFZT_Logger::user_created($user_id, $email, $auth_method);

        // Trigger action for other plugins to hook into
        do_action('cfzt_user_created', $user, $user_info);

        return $user;
    }

    /**
     * Extract display name from user info
     *
     * @param array $user_info User information from authentication provider
     * @return string Display name or empty string
     */
    private static function get_display_name_from_user_info(array $user_info): string {
        // Try full name first
        if (isset($user_info['name']) && !empty($user_info['name'])) {
            return sanitize_text_field($user_info['name']);
        }

        // Construct from given_name and family_name
        if (isset($user_info['given_name']) || isset($user_info['family_name'])) {
            $given_name = isset($user_info['given_name']) ? sanitize_text_field($user_info['given_name']) : '';
            $family_name = isset($user_info['family_name']) ? sanitize_text_field($user_info['family_name']) : '';

            return trim($given_name . ' ' . $family_name);
        }

        return '';
    }

    /**
     * Ensure username is unique by appending numbers if necessary
     *
     * @param string $username Proposed username
     * @return string Unique username
     */
    private static function ensure_unique_username(string $username): string {
        $original = $username;
        $counter = 1;

        while (username_exists($username)) {
            $username = $original . $counter;
            $counter++;
        }

        return $username;
    }

    /**
     * Update user login timestamp
     *
     * @param int $user_id User ID
     * @param string $auth_method Authentication method used
     */
    public static function update_last_login(int $user_id, string $auth_method = 'oidc'): void {
        update_user_meta($user_id, 'cfzt_last_login', current_time('mysql'));
        update_user_meta($user_id, 'cfzt_auth_method', $auth_method);
    }

    /**
     * Check if user was created by Cloudflare Zero Trust
     *
     * @param int|WP_User $user User ID or user object
     * @return bool True if user was created by this plugin
     */
    public static function is_cfzt_user($user): bool {
        if (is_numeric($user)) {
            $user_id = $user;
        } elseif ($user instanceof WP_User) {
            $user_id = $user->ID;
        } else {
            return false;
        }

        return (bool) get_user_meta($user_id, 'cfzt_user', true);
    }

    /**
     * Whether an email address passes the configured domain restrictions
     *
     * Applied on every Cloudflare login, not only at account creation. With
     * no restrictions configured every domain is allowed.
     *
     * @since 2.0.0
     *
     * @param string $email User email address
     * @return bool
     */
    public static function is_email_domain_allowed(string $email): bool {
        $options = CFZT_Plugin::get_option();
        $allowed_domains = isset($options['email_domain_restrictions']) ? trim((string) $options['email_domain_restrictions']) : '';

        if ('' === $allowed_domains) {
            return true;
        }

        $at = strrchr($email, '@');
        $email_domain = false === $at ? '' : strtolower(substr($at, 1));

        $domains = array_filter(array_map('trim', preg_split('/[\s,;]+/', $allowed_domains)));
        $domains = array_map('strtolower', array_map(function ($domain) {
            return ltrim($domain, '@');
        }, $domains));

        return '' !== $email_domain && in_array($email_domain, $domains, true);
    }

    /**
     * Re-apply group-to-role mapping for an existing plugin-managed user
     *
     * Runs on every login so a user whose Cloudflare group changes gets the
     * matching WordPress role without being deleted and recreated. Deliberately
     * does nothing when no mapping is configured, when the account was not
     * created by this plugin (hand-made administrators keep their role), or
     * when Cloudflare sent no group claim at all, since an absent claim is not
     * evidence that the user left every group.
     *
     * @since 2.0.0
     *
     * @param WP_User $user      Existing user.
     * @param array   $user_info Claims from Cloudflare.
     * @return void
     */
    public static function sync_role_from_claims(WP_User $user, array $user_info): void {
        $options = CFZT_Plugin::get_option();

        if (empty($options['role_mapping']) || !is_array($options['role_mapping'])) {
            return;
        }

        if (!self::is_cfzt_user($user) || !self::has_group_claim($user_info)) {
            return;
        }

        /**
         * Filter whether role mapping is re-applied on every login.
         *
         * @since 2.0.0
         *
         * @param bool    $sync      Default true.
         * @param WP_User $user      The user logging in.
         * @param array   $user_info Claims from Cloudflare.
         */
        if (!apply_filters('cfzt_sync_role_on_login', true, $user, $user_info)) {
            return;
        }

        $role = self::determine_user_role($user_info, $options);
        if (!in_array($role, (array) $user->roles, true)) {
            $user->set_role($role);
            CFZT_Logger::info('Role updated from Cloudflare groups', array(
                'user_id' => $user->ID,
                'role'    => $role,
            ));
        }
    }

    /**
     * Whether the claims carry any group information
     *
     * @param array $user_info Claims from Cloudflare.
     * @return bool
     */
    private static function has_group_claim(array $user_info): bool {
        return (isset($user_info['groups']) && is_array($user_info['groups']))
            || isset($user_info['group']);
    }

    /**
     * Determine user role based on Cloudflare groups
     *
     * @param array $user_info User information from authentication provider
     * @param array $options Plugin options
     * @return string WordPress role slug
     */
    private static function determine_user_role(array $user_info, array $options): string {
        $default_role = isset($options['default_role']) ? $options['default_role'] : CFZT_Plugin::DEFAULT_ROLE;
        if (!get_role($default_role)) {
            $default_role = CFZT_Plugin::DEFAULT_ROLE;
        }

        // Check if role mapping is configured
        if (empty($options['role_mapping']) || !is_array($options['role_mapping'])) {
            return $default_role;
        }

        // Get user's groups from user info
        $user_groups = array();
        if (isset($user_info['groups']) && is_array($user_info['groups'])) {
            $user_groups = $user_info['groups'];
        } elseif (isset($user_info['group'])) {
            $user_groups = array($user_info['group']);
        }

        // If no groups found, return default role
        if (empty($user_groups)) {
            return $default_role;
        }

        // Check each mapping (first match wins)
        foreach ($options['role_mapping'] as $mapping) {
            if (empty($mapping['group']) || empty($mapping['role'])) {
                continue;
            }

            // Check if user is in this group
            foreach ($user_groups as $group) {
                if (is_string($group) && strcasecmp($group, $mapping['group']) === 0) {
                    // Verify the role exists in WordPress
                    if (get_role($mapping['role'])) {
                        CFZT_Logger::info('Role mapped via group', array(
                            'group' => $mapping['group'],
                            'role' => $mapping['role']
                        ));
                        return $mapping['role'];
                    }
                }
            }
        }

        return $default_role;
    }
}
