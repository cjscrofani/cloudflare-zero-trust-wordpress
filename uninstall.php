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
        delete_user_meta($user_id, 'cfzt_last_login');
    }
    
    // Clean up transients
    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_cfzt_%'");
    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_cfzt_%'");
    
    // Clean up any sessions
    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_wp_session_cfzt_%'");
    
    // Remove any scheduled events (if any were added in the future)
    wp_clear_scheduled_hook('cfzt_cleanup_transients');
    
    // Flush rewrite rules to clean up any custom endpoints
    flush_rewrite_rules();
}