<?php
/**
 * Plugin Name: Cloudflare Zero Trust Login for WordPress
 * Plugin URI: https://github.com/cjscrofani/cloudflare-zero-trust-wordpress
 * Description: Secure WordPress authentication using Cloudflare Zero Trust OIDC (OpenID Connect). Supports both SaaS and Self-hosted applications with built-in security features.
 * Version: 1.0.1
 * Author: GDWS
 * License: GPL v2 or later
 * Text Domain: cf-zero-trust
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('CFZT_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('CFZT_PLUGIN_URL', plugin_dir_url(__FILE__));
define('CFZT_PLUGIN_BASENAME', plugin_basename(__FILE__));
define('CFZT_PLUGIN_FILE', __FILE__);
define('CFZT_PLUGIN_VERSION', '1.0.0');

// GitHub repository details
define('CFZT_GITHUB_USERNAME', 'cjscrofani');
define('CFZT_GITHUB_REPOSITORY', 'cloudflare-zero-trust-wordpress');

// Check for environment variables or wp-config constants
if (!defined('CFZT_CLIENT_ID')) {
    define('CFZT_CLIENT_ID', getenv('CFZT_CLIENT_ID') ?: '');
}
if (!defined('CFZT_CLIENT_SECRET')) {
    define('CFZT_CLIENT_SECRET', getenv('CFZT_CLIENT_SECRET') ?: '');
}

// Require the main plugin class
require_once CFZT_PLUGIN_DIR . 'includes/class-cfzt-plugin.php';

// Initialize the plugin
function cfzt_init() {
    CFZT_Plugin::get_instance();
}
add_action('plugins_loaded', 'cfzt_init');

// Activation hook
register_activation_hook(__FILE__, array('CFZT_Plugin', 'activate'));

// Deactivation hook
register_deactivation_hook(__FILE__, array('CFZT_Plugin', 'deactivate'));
