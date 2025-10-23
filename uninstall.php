<?php
/**
 * Uninstall handler for Cloudflare Zero Trust Login
 *
 * @package CloudflareZeroTrustLogin
 */

// If uninstall not called from WordPress, then exit
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Only run if not a multisite or if network admin
if (!is_multisite() || is_super_admin()) {
    // Remove plugin options
    delete_option('cfzt_settings');
    delete_option('cfzt_activated_time');
    delete_option('cfzt_version');
    delete_option('cfzt_activation_notice_dismissed');

    // Remove user meta for all users
    global $wpdb;
    
    // Get all users with CF Zero Trust meta
    $users = get_users(array(
        'meta_key' => 'cfzt_user',
        'meta_value' => true,
        'fields' => 'ID'
    ));
    
    // Remove CF Zero Trust related user meta
    foreach ($users as $user_id) {
        delete_user_meta($user_id, 'cfzt_user');
        delete_user_meta($user_id, 'cfzt_sub');
        delete_user_meta($user_id, 'cfzt_issuer');
        delete_user_meta($user_id, 'cfzt_auth_method');
        delete_user_meta($user_id, 'cfzt_last_login');
        delete_user_meta($user_id, 'cfzt_backup_codes');
        delete_user_meta($user_id, 'cfzt_onboarding_dismissed');
    }

    // Also clean up any other cfzt_* user meta that might exist
    $wpdb->query("DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE 'cfzt_%'");
    
    // Clean up transients
    // This includes: cfzt_auth_state_*, cfzt_attempts_*, cfzt_flush_rewrite_rules, and GitHub updater cache
    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_cfzt_%'");
    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_cfzt_%'");
    
    // Clean up any sessions
    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_wp_session_cfzt_%'");

    // Drop logs table
    $table_name = $wpdb->prefix . 'cfzt_logs';
    $wpdb->query("DROP TABLE IF EXISTS $table_name");

    // Remove database version option
    delete_option('cfzt_db_version');

    // Remove any scheduled events (if any were added in the future)
    wp_clear_scheduled_hook('cfzt_cleanup_transients');

    // Flush rewrite rules to clean up any custom endpoints
    flush_rewrite_rules();
}