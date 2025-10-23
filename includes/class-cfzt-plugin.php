<?php
/**
 * Main plugin class that coordinates all components
 *
 * This is the core class that initializes and manages all plugin components.
 * It follows the Singleton pattern to ensure only one instance exists and
 * coordinates authentication, security, admin UI, and update checking.
 *
 * @package CloudflareZeroTrustLogin
 * @since   1.0.0
 *
 * @example
 * // Get the plugin instance
 * $plugin = CFZT_Plugin::get_instance();
 *
 * @example
 * // Get plugin settings
 * $options = CFZT_Plugin::get_option();
 * $auth_method = CFZT_Plugin::get_option('auth_method', 'oauth2');
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class CFZT_Plugin {

    // Authentication method constants
    const AUTH_METHOD_OIDC = 'oauth2';
    const AUTH_METHOD_SAML = 'saml';

    // Application type constants
    const APP_TYPE_SAAS = 'saas';
    const APP_TYPE_SELF_HOSTED = 'self-hosted';

    // Login mode constants
    const LOGIN_MODE_PRIMARY = 'primary';
    const LOGIN_MODE_SECONDARY = 'secondary';

    // Boolean string constants
    const OPTION_YES = 'yes';
    const OPTION_NO = 'no';

    // Default role
    const DEFAULT_ROLE = 'subscriber';

    /**
     * Plugin instance
     * @var CFZT_Plugin|null
     */
    private static $instance = null;

    /**
     * Cached plugin options
     * @var array|null
     */
    private static $cached_options = null;

    /**
     * Plugin components
     */
    private $auth;
    private $admin;
    private $security;
    private $login_ui;
    private $github_updater;
    
    /**
     * Get plugin instance
     * @return CFZT_Plugin
     */
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Constructor
     */
    private function __construct() {
        $this->load_dependencies();
        $this->init_components();
        $this->init_hooks();
    }
    
    /**
     * Load required files
     */
    private function load_dependencies() {
        require_once CFZT_PLUGIN_DIR . 'includes/class-cfzt-logger.php';
        require_once CFZT_PLUGIN_DIR . 'includes/class-cfzt-security.php';
        require_once CFZT_PLUGIN_DIR . 'includes/class-cfzt-user-helper.php';
        require_once CFZT_PLUGIN_DIR . 'includes/class-cfzt-auth.php';
        require_once CFZT_PLUGIN_DIR . 'includes/class-cfzt-admin.php';
        require_once CFZT_PLUGIN_DIR . 'includes/class-cfzt-login-ui.php';

        // Load GitHub updater if it exists
        $updater_file = CFZT_PLUGIN_DIR . 'includes/class-github-updater.php';
        if (file_exists($updater_file)) {
            require_once $updater_file;
        }
    }
    
    /**
     * Initialize plugin components
     */
    private function init_components() {
        $this->security = new CFZT_Security();
        $this->auth = new CFZT_Auth($this->security);
        $this->admin = new CFZT_Admin($this->security);
        $this->login_ui = new CFZT_Login_UI();
        
        // Initialize GitHub updater
        if (class_exists('CFZT_GitHub_Updater')) {
            $this->github_updater = new CFZT_GitHub_Updater(
                CFZT_PLUGIN_FILE,
                CFZT_GITHUB_USERNAME,
                CFZT_GITHUB_REPOSITORY
            );
        }
    }
    
    /**
     * Initialize hooks
     */
    private function init_hooks() {
        // Text domain
        add_action('init', array($this, 'load_textdomain'));
        
        // Settings link on plugins page
        add_filter('plugin_action_links_' . CFZT_PLUGIN_BASENAME, array($this, 'add_settings_link'));
    }
    
    /**
     * Load plugin text domain
     */
    public function load_textdomain() {
        load_plugin_textdomain('cf-zero-trust', false, dirname(CFZT_PLUGIN_BASENAME) . '/languages');
    }
    
    /**
     * Add settings link to plugins page
     * 
     * @param array $links Plugin action links
     * @return array Modified links
     */
    public function add_settings_link($links) {
        $settings_link = '<a href="' . admin_url('options-general.php?page=cf-zero-trust') . '">' . __('Settings', 'cf-zero-trust') . '</a>';
        array_unshift($links, $settings_link);
        return $links;
    }
    
    /**
     * Plugin activation
     */
    public static function activate() {
        // Check PHP version requirement
        if (version_compare(PHP_VERSION, '7.2', '<')) {
            deactivate_plugins(CFZT_PLUGIN_BASENAME);
            wp_die(
                '<h1>' . __('Plugin Activation Error', 'cf-zero-trust') . '</h1>' .
                '<p>' . sprintf(
                    __('Cloudflare Zero Trust Login requires PHP version 7.2 or higher. You are running PHP %s.', 'cf-zero-trust'),
                    PHP_VERSION
                ) . '</p>' .
                '<p><a href="' . admin_url('plugins.php') . '">' . __('Return to Plugins', 'cf-zero-trust') . '</a></p>',
                __('Plugin Activation Error', 'cf-zero-trust'),
                array('back_link' => true)
            );
        }

        // Check WordPress version requirement
        global $wp_version;
        if (version_compare($wp_version, '5.0', '<')) {
            deactivate_plugins(CFZT_PLUGIN_BASENAME);
            wp_die(
                '<h1>' . __('Plugin Activation Error', 'cf-zero-trust') . '</h1>' .
                '<p>' . sprintf(
                    __('Cloudflare Zero Trust Login requires WordPress version 5.0 or higher. You are running WordPress %s.', 'cf-zero-trust'),
                    $wp_version
                ) . '</p>' .
                '<p><a href="' . admin_url('plugins.php') . '">' . __('Return to Plugins', 'cf-zero-trust') . '</a></p>',
                __('Plugin Activation Error', 'cf-zero-trust'),
                array('back_link' => true)
            );
        }

        // Check if settings already exist (don't overwrite on re-activation)
        if (!get_option('cfzt_settings')) {
            add_option('cfzt_settings', array(
                'auth_method' => self::AUTH_METHOD_OIDC,
                'app_type' => self::APP_TYPE_SAAS,
                'team_domain' => '',
                'client_id' => '',
                'client_secret' => '',
                'login_mode' => self::LOGIN_MODE_SECONDARY,
                'auto_create_users' => self::OPTION_YES,
                'default_role' => self::DEFAULT_ROLE,
                'enable_logging' => self::OPTION_NO
            ));
        }

        // Create directories if needed
        $dirs = array(
            CFZT_PLUGIN_DIR . 'includes',
            CFZT_PLUGIN_DIR . 'templates',
            CFZT_PLUGIN_DIR . 'assets',
            CFZT_PLUGIN_DIR . 'assets/css',
            CFZT_PLUGIN_DIR . 'languages'
        );

        foreach ($dirs as $dir) {
            if (!file_exists($dir)) {
                wp_mkdir_p($dir);
            }
        }

        // Set activation timestamp
        add_option('cfzt_activated_time', current_time('timestamp'));
        update_option('cfzt_version', CFZT_PLUGIN_VERSION);

        // Set activation notice flag
        set_transient('cfzt_activation_notice', true, 60 * 60 * 24); // Show for 24 hours

        // Flush rewrite rules for SAML endpoints
        flush_rewrite_rules();

        // Log activation (if logger is available)
        if (class_exists('CFZT_Logger')) {
            CFZT_Logger::info('Plugin activated', array('version' => CFZT_PLUGIN_VERSION));
        }
    }
    
    /**
     * Plugin deactivation
     */
    public static function deactivate() {
        // Log deactivation (if logger is available)
        if (class_exists('CFZT_Logger')) {
            CFZT_Logger::info('Plugin deactivated');
        }

        // Clean up transients
        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_cfzt_%'");
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_cfzt_%'");

        // Clear options cache
        self::clear_options_cache();

        // Flush rewrite rules to remove SAML endpoints
        flush_rewrite_rules();

        // Note: We intentionally do NOT delete settings or user meta on deactivation
        // Only uninstall.php should do that (when plugin is fully deleted)
    }
    
    /**
     * Get plugin option with automatic caching
     *
     * This method retrieves plugin settings from the database and caches them
     * for the duration of the request to improve performance. It also handles
     * environment variable overrides for sensitive credentials.
     *
     * @since 1.0.0
     *
     * @param string|null $option Optional. Specific option key to retrieve. If null, returns all options.
     * @param mixed $default Optional. Default value to return if option doesn't exist.
     * @return mixed Option value, array of all options if $option is null, or $default if not found.
     *
     * @example
     * // Get all options
     * $options = CFZT_Plugin::get_option();
     *
     * @example
     * // Get specific option with default
     * $auth_method = CFZT_Plugin::get_option('auth_method', 'oauth2');
     */
    public static function get_option($option = null, $default = null) {
        // Use cached options if available
        if (self::$cached_options === null) {
            self::$cached_options = get_option('cfzt_settings', array());

            // Override with constants if defined
            if (defined('CFZT_CLIENT_ID') && CFZT_CLIENT_ID) {
                self::$cached_options['client_id'] = CFZT_CLIENT_ID;
            }
            if (defined('CFZT_CLIENT_SECRET') && CFZT_CLIENT_SECRET) {
                self::$cached_options['client_secret'] = CFZT_CLIENT_SECRET;
                self::$cached_options['client_secret_is_constant'] = true;
            }
        }

        if (null === $option) {
            return self::$cached_options;
        }

        return isset(self::$cached_options[$option]) ? self::$cached_options[$option] : $default;
    }

    /**
     * Clear the options cache
     *
     * Call this method after updating plugin settings to ensure that the next
     * call to get_option() retrieves fresh data from the database instead of
     * using stale cached values.
     *
     * @since 1.0.3
     *
     * @return void
     *
     * @example
     * update_option('cfzt_settings', $new_settings);
     * CFZT_Plugin::clear_options_cache();
     */
    public static function clear_options_cache(): void {
        self::$cached_options = null;
    }
}