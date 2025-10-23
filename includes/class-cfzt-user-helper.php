<?php
/**
 * User management helper for Cloudflare Zero Trust
 *
 * Shared user creation and management functionality used by both OIDC and SAML authentication.
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
     * @param string $auth_method Authentication method used ('oidc' or 'saml')
     * @return WP_User|false User object on success, false on failure
     */
    public static function create_user(string $email, array $user_info, string $auth_method = 'oidc') {
        $options = CFZT_Plugin::get_option();

        // Generate username from email
        $username = sanitize_user(current(explode('@', $email)));
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

        // Set user role
        $default_role = isset($options['default_role']) ? $options['default_role'] : CFZT_Plugin::DEFAULT_ROLE;
        $user->set_role($default_role);

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
}
