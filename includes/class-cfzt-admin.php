<?php
/**
 * Admin settings and UI handler
 *
 * @package CloudflareZeroTrustLogin
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class CFZT_Admin {
    
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
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('admin_notices', array($this, 'admin_notices'));
        add_action('admin_notices', array($this, 'activation_notice'));
        add_action('admin_notices', array($this, 'onboarding_checklist_notice'));
        add_action('wp_ajax_cfzt_dismiss_activation_notice', array($this, 'dismiss_activation_notice'));
        add_action('wp_ajax_cfzt_dismiss_onboarding_checklist', array($this, 'ajax_dismiss_onboarding_checklist'));
        add_action('wp_ajax_cfzt_test_connection', array($this, 'ajax_test_connection'));
        add_filter('pre_update_option_cfzt_settings', array($this, 'protect_constants'), 10, 2);
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
        add_action('wp_ajax_cfzt_check_for_updates', array($this, 'ajax_check_for_updates'));
        add_action('wp_ajax_cfzt_get_logs', array($this, 'ajax_get_logs'));
        add_action('wp_ajax_cfzt_export_logs', array($this, 'ajax_export_logs'));
        add_action('wp_ajax_cfzt_clear_logs', array($this, 'ajax_clear_logs'));

        // Users list customization
        add_filter('manage_users_columns', array($this, 'add_user_columns'));
        add_filter('manage_users_custom_column', array($this, 'render_user_column'), 10, 3);
        add_filter('manage_users_sortable_columns', array($this, 'make_user_columns_sortable'));
        add_action('pre_get_users', array($this, 'sort_users_by_cfzt'));
        add_filter('views_users', array($this, 'add_cfzt_users_filter'));
        add_action('pre_get_users', array($this, 'filter_cfzt_users'));

        // Import/export
        add_action('wp_ajax_cfzt_export_settings', array($this, 'ajax_export_settings'));
        add_action('wp_ajax_cfzt_import_settings', array($this, 'ajax_import_settings'));
    }
    
    /**
     * Add admin menu
     */
    public function add_admin_menu() {
        // Main settings page
        add_options_page(
            __('Cloudflare Zero Trust Settings', 'cf-zero-trust'),
            __('CF Zero Trust', 'cf-zero-trust'),
            'manage_options',
            'cf-zero-trust',
            array($this, 'settings_page')
        );

        // Dashboard page under Tools menu for easy access
        add_management_page(
            __('CF Zero Trust Dashboard', 'cf-zero-trust'),
            __('CF Zero Trust', 'cf-zero-trust'),
            'manage_options',
            'cf-zero-trust-dashboard',
            array($this, 'dashboard_page')
        );

        // Logs page under Tools menu
        add_management_page(
            __('CF Zero Trust Logs', 'cf-zero-trust'),
            __('CF Zero Trust Logs', 'cf-zero-trust'),
            'manage_options',
            'cf-zero-trust-logs',
            array($this, 'logs_page')
        );
    }
    
    /**
     * Register settings
     */
    public function register_settings() {
        register_setting('cfzt_settings_group', 'cfzt_settings', array($this, 'sanitize_settings'));
        
        // Main section
        add_settings_section(
            'cfzt_main_section',
            __('General Configuration', 'cf-zero-trust'),
            array($this, 'main_section_callback'),
            'cf-zero-trust'
        );
        
        // Add general settings fields
        $general_fields = array(
            'auth_method' => __('Authentication Method', 'cf-zero-trust'),
            'team_domain' => __('Team Domain', 'cf-zero-trust'),
            'login_mode' => __('Login Mode', 'cf-zero-trust'),
            'auto_create_users' => __('Auto-create Users', 'cf-zero-trust'),
            'default_role' => __('Default User Role', 'cf-zero-trust'),
            'enable_logging' => __('Enable Authentication Logging', 'cf-zero-trust')
        );
        
        foreach ($general_fields as $field => $label) {
            add_settings_field(
                'cfzt_' . $field,
                $label,
                array($this, 'field_callback'),
                'cf-zero-trust',
                'cfzt_main_section',
                array('field' => $field)
            );
        }
        
        // OIDC section
        add_settings_section(
            'cfzt_oidc_section',
            __('OIDC Configuration', 'cf-zero-trust'),
            array($this, 'oidc_section_callback'),
            'cf-zero-trust'
        );
        
        $oidc_fields = array(
            'app_type' => __('Application Type', 'cf-zero-trust'),
            'client_id' => __('Client ID', 'cf-zero-trust'),
            'client_secret' => __('Client Secret', 'cf-zero-trust'),
        );
        
        foreach ($oidc_fields as $field => $label) {
            add_settings_field(
                'cfzt_oidc_' . $field,
                $label,
                array($this, 'field_callback'),
                'cf-zero-trust',
                'cfzt_oidc_section',
                array('field' => $field)
            );
        }
        
        // SAML section
        add_settings_section(
            'cfzt_saml_section',
            __('SAML Configuration', 'cf-zero-trust'),
            array($this, 'saml_section_callback'),
            'cf-zero-trust'
        );
        
        $saml_fields = array(
            'saml_sso_target_url' => __('SSO Target URL ID', 'cf-zero-trust'),
            'saml_sp_entity_id' => __('SP Entity ID', 'cf-zero-trust'),
            'saml_x509_cert' => __('X.509 Certificate', 'cf-zero-trust'),
        );
        
        foreach ($saml_fields as $field => $label) {
            add_settings_field(
                'cfzt_' . $field,
                $label,
                array($this, 'field_callback'),
                'cf-zero-trust',
                'cfzt_saml_section',
                array('field' => $field)
            );
        }
    }
    
    /**
     * Sanitize settings
     *
     * @param array $input Raw input
     * @return array Sanitized settings
     */
    public function sanitize_settings($input) {
        // Clear the options cache since we're updating settings
        CFZT_Plugin::clear_options_cache();

        $sanitized = array();

        // General settings
        $sanitized['auth_method'] = sanitize_text_field($input['auth_method']);
        $sanitized['team_domain'] = sanitize_text_field($input['team_domain']);
        $sanitized['login_mode'] = sanitize_text_field($input['login_mode']);
        $sanitized['auto_create_users'] = sanitize_text_field($input['auto_create_users']);
        $sanitized['default_role'] = sanitize_text_field($input['default_role']);
        $sanitized['enable_logging'] = sanitize_text_field($input['enable_logging']);

        // OIDC settings
        $sanitized['app_type'] = sanitize_text_field($input['app_type']);
        $sanitized['client_id'] = sanitize_text_field($input['client_id']);

        // Encrypt sensitive data
        $sanitized['client_secret'] = $this->security->encrypt_data(sanitize_text_field($input['client_secret']));

        // SAML settings
        $sanitized['saml_sso_target_url'] = sanitize_text_field($input['saml_sso_target_url']);
        $sanitized['saml_sp_entity_id'] = sanitize_text_field($input['saml_sp_entity_id']);
        $sanitized['saml_x509_cert'] = sanitize_textarea_field($input['saml_x509_cert']);

        // Email domain restrictions
        if (isset($input['email_domain_restrictions'])) {
            $sanitized['email_domain_restrictions'] = sanitize_textarea_field($input['email_domain_restrictions']);
        }

        // Custom redirect URLs
        if (isset($input['redirect_after_login'])) {
            $sanitized['redirect_after_login'] = esc_url_raw($input['redirect_after_login']);
        }
        if (isset($input['redirect_after_logout'])) {
            $sanitized['redirect_after_logout'] = esc_url_raw($input['redirect_after_logout']);
        }

        // Role mapping
        if (isset($input['role_mapping']) && is_array($input['role_mapping'])) {
            $sanitized['role_mapping'] = array();
            foreach ($input['role_mapping'] as $mapping) {
                if (!empty($mapping['group'])) {
                    $sanitized['role_mapping'][] = array(
                        'group' => sanitize_text_field($mapping['group']),
                        'role' => sanitize_text_field($mapping['role'])
                    );
                }
            }
        }

        // Clear rewrite rules when auth method changes
        $current_options = get_option('cfzt_settings', array());
        if (isset($current_options['auth_method']) && $current_options['auth_method'] !== $sanitized['auth_method']) {
            set_transient('cfzt_flush_rewrite_rules', true);
        }

        // Dismiss activation notice when plugin is configured
        $is_configured = !empty($sanitized['team_domain']) && !empty($sanitized['client_id']) && !empty($sanitized['client_secret']);
        if ($is_configured) {
            update_option('cfzt_activation_notice_dismissed', true);
            delete_transient('cfzt_activation_notice');

            // Set success message with next steps
            set_transient('cfzt_settings_saved_success', true, 60);
        }

        return $sanitized;
    }
    
    /**
     * Main section callback
     */
    public function main_section_callback() {
        echo '<p>' . __('Configure your Cloudflare Zero Trust integration settings below.', 'cf-zero-trust') . '</p>';
    }
    
    /**
     * OIDC section callback
     */
    public function oidc_section_callback() {
        $options = CFZT_Plugin::get_option();
        $display = (isset($options['auth_method']) && $options['auth_method'] === 'oauth2') ? 'block' : 'none';
        echo '<div id="cfzt-oidc-settings" style="display: ' . $display . ';">';
        echo '<p>' . __('Configure OIDC (OpenID Connect) specific settings.', 'cf-zero-trust') . '</p>';
        echo '</div>';
    }
    
    /**
     * SAML section callback
     */
    public function saml_section_callback() {
        $options = CFZT_Plugin::get_option();
        $display = (isset($options['auth_method']) && $options['auth_method'] === 'saml') ? 'block' : 'none';
        echo '<div id="cfzt-saml-settings" style="display: ' . $display . ';">';
        echo '<p>' . __('Configure SAML specific settings.', 'cf-zero-trust') . '</p>';
        
        // Show metadata URL
        $auth = new CFZT_Auth($this->security);
        $metadata_url = $auth->get_saml_metadata_url();
        if ($metadata_url) {
            echo '<p><strong>' . __('SP Metadata URL:', 'cf-zero-trust') . '</strong> <code>' . esc_url($metadata_url) . '</code></p>';
            echo '<p class="description">' . __('Provide this metadata URL to Cloudflare when configuring your SAML application.', 'cf-zero-trust') . '</p>';
        }
        echo '</div>';
    }
    
    /**
     * Field callback
     * 
     * @param array $args Field arguments
     */
    public function field_callback($args) {
        $field = $args['field'];
        $options = CFZT_Plugin::get_option();
        $value = isset($options[$field]) ? $options[$field] : '';
        
        switch ($field) {
            case 'auth_method':
                $this->render_auth_method_field($value);
                break;
                
            case 'app_type':
                $this->render_app_type_field($value);
                break;
                
            case 'team_domain':
                $this->render_team_domain_field($value);
                break;
                
            case 'client_id':
                $this->render_client_id_field($value);
                break;
                
            case 'client_secret':
                $this->render_client_secret_field($value, $options);
                break;
                
            case 'login_mode':
                $this->render_login_mode_field($value);
                break;
                
            case 'auto_create_users':
                $this->render_auto_create_field($value);
                break;
                
            case 'default_role':
                $this->render_default_role_field($value);
                break;
                
            case 'enable_logging':
                $this->render_logging_field($value);
                break;
                
            case 'saml_sso_target_url':
                $this->render_saml_sso_target_url_field($value);
                break;
                
            case 'saml_sp_entity_id':
                $this->render_saml_sp_entity_id_field($value);
                break;
                
            case 'saml_x509_cert':
                $this->render_saml_x509_cert_field($value);
                break;
        }
    }
    
    /**
     * Render auth method field
     */
    private function render_auth_method_field($value) {
        ?>
        <select name="cfzt_settings[auth_method]" id="cfzt_auth_method">
            <option value="oauth2" <?php selected($value, 'oauth2'); ?>><?php _e('OIDC (OpenID Connect)', 'cf-zero-trust'); ?></option>
            <option value="saml" <?php selected($value, 'saml'); ?>><?php _e('SAML', 'cf-zero-trust'); ?></option>
        </select>
        <p class="description"><?php _e('Choose the authentication protocol to use with Cloudflare Zero Trust.', 'cf-zero-trust'); ?></p>
        <?php
    }
    
    /**
     * Render app type field
     */
    private function render_app_type_field($value) {
        $value = !empty($value) ? $value : 'saas';
        ?>
        <select name="cfzt_settings[app_type]">
            <option value="saas" <?php selected($value, 'saas'); ?>><?php _e('SaaS (Recommended)', 'cf-zero-trust'); ?></option>
            <option value="self-hosted" <?php selected($value, 'self-hosted'); ?>><?php _e('Self-hosted', 'cf-zero-trust'); ?></option>
        </select>
        <p class="description"><?php _e('Choose the application type you created in Cloudflare Zero Trust. SaaS apps provide standard OIDC endpoints.', 'cf-zero-trust'); ?></p>
        <?php
    }
    
    /**
     * Render team domain field
     */
    private function render_team_domain_field($value) {
        ?>
        <input type="text" name="cfzt_settings[team_domain]" value="<?php echo esc_attr($value); ?>" class="regular-text" />
        <p class="description">
            <?php _e('Your Cloudflare Zero Trust team domain (e.g., <code>yourteam.cloudflareaccess.com</code>)', 'cf-zero-trust'); ?><br>
            <?php _e('This is the hostname from your Issuer URL, without https://', 'cf-zero-trust'); ?>
        </p>
        <?php
    }
    
    /**
     * Render client ID field
     */
    private function render_client_id_field($value) {
        $from_constant = defined('CFZT_CLIENT_ID') && CFZT_CLIENT_ID;
        ?>
        <input type="text" name="cfzt_settings[client_id]" value="<?php echo esc_attr($value); ?>" class="regular-text" <?php echo $from_constant ? 'readonly' : ''; ?> />
        <?php if ($from_constant): ?>
            <p class="description"><strong><?php _e('Value set via constant/environment variable', 'cf-zero-trust'); ?></strong></p>
        <?php else: ?>
            <p class="description"><?php _e('Client ID from your Cloudflare Zero Trust OIDC application.', 'cf-zero-trust'); ?></p>
        <?php endif; ?>
        <?php
    }
    
    /**
     * Render client secret field
     */
    private function render_client_secret_field($value, $options) {
        $from_constant = defined('CFZT_CLIENT_SECRET') && CFZT_CLIENT_SECRET;
        
        if ($from_constant) {
            $display_value = '[SET VIA CONSTANT]';
        } else {
            $display_value = isset($options['client_secret']) ? $this->security->decrypt_data($options['client_secret']) : '';
        }
        ?>
        <input type="password" name="cfzt_settings[client_secret]" value="<?php echo esc_attr($display_value); ?>" class="regular-text" <?php echo $from_constant ? 'readonly' : ''; ?> />
        <?php if ($from_constant): ?>
            <p class="description"><strong><?php _e('Value set via constant/environment variable (hidden for security)', 'cf-zero-trust'); ?></strong></p>
        <?php else: ?>
            <p class="description"><?php _e('Client Secret from your Cloudflare Zero Trust OIDC application.', 'cf-zero-trust'); ?></p>
        <?php endif; ?>
        <?php
    }
    
    /**
     * Render login mode field
     */
    private function render_login_mode_field($value) {
        $value = !empty($value) ? $value : 'secondary';
        ?>
        <select name="cfzt_settings[login_mode]">
            <option value="secondary" <?php selected($value, 'secondary'); ?>><?php _e('Secondary (Show both login options)', 'cf-zero-trust'); ?></option>
            <option value="primary" <?php selected($value, 'primary'); ?>><?php _e('Primary (Disable WordPress login)', 'cf-zero-trust'); ?></option>
        </select>
        <p class="description"><?php _e('Choose whether to use Cloudflare Zero Trust as the only login method or alongside WordPress login.', 'cf-zero-trust'); ?></p>
        <?php
    }
    
    /**
     * Render auto create users field
     */
    private function render_auto_create_field($value) {
        $value = !empty($value) ? $value : 'yes';
        ?>
        <select name="cfzt_settings[auto_create_users]">
            <option value="yes" <?php selected($value, 'yes'); ?>><?php _e('Yes', 'cf-zero-trust'); ?></option>
            <option value="no" <?php selected($value, 'no'); ?>><?php _e('No', 'cf-zero-trust'); ?></option>
        </select>
        <p class="description"><?php _e('Automatically create WordPress users for authenticated Cloudflare Zero Trust users.', 'cf-zero-trust'); ?></p>
        <?php
    }
    
    /**
     * Render default role field
     */
    private function render_default_role_field($value) {
        $value = !empty($value) ? $value : 'subscriber';
        ?>
        <select name="cfzt_settings[default_role]">
            <?php wp_dropdown_roles($value); ?>
        </select>
        <p class="description"><?php _e('Default role for auto-created users.', 'cf-zero-trust'); ?></p>
        <?php
    }
    
    /**
     * Render logging field
     */
    private function render_logging_field($value) {
        $value = !empty($value) ? $value : 'no';
        ?>
        <select name="cfzt_settings[enable_logging]">
            <option value="yes" <?php selected($value, 'yes'); ?>><?php _e('Yes', 'cf-zero-trust'); ?></option>
            <option value="no" <?php selected($value, 'no'); ?>><?php _e('No', 'cf-zero-trust'); ?></option>
        </select>
        <p class="description"><?php _e('Log authentication attempts to the WordPress error log.', 'cf-zero-trust'); ?></p>
        <?php
    }
    
    /**
     * Render SAML SSO Target URL field
     */
    private function render_saml_sso_target_url_field($value) {
        ?>
        <input type="text" name="cfzt_settings[saml_sso_target_url]" value="<?php echo esc_attr($value); ?>" class="regular-text" />
        <p class="description">
            <?php _e('The SSO target URL ID from your Cloudflare SAML configuration.', 'cf-zero-trust'); ?><br>
            <?php _e('This is the unique identifier in the SSO endpoint URL after /saml/', 'cf-zero-trust'); ?>
        </p>
        <?php
    }
    
    /**
     * Render SAML SP Entity ID field
     */
    private function render_saml_sp_entity_id_field($value) {
        ?>
        <input type="text" name="cfzt_settings[saml_sp_entity_id]" value="<?php echo esc_attr($value); ?>" class="regular-text" placeholder="<?php echo esc_attr(home_url()); ?>" />
        <p class="description">
            <?php _e('Service Provider Entity ID. If left empty, your site URL will be used.', 'cf-zero-trust'); ?><br>
            <?php _e('This must match the Entity ID configured in Cloudflare.', 'cf-zero-trust'); ?>
        </p>
        <?php
    }
    
    /**
     * Render SAML X.509 Certificate field
     */
    private function render_saml_x509_cert_field($value) {
        ?>
        <textarea name="cfzt_settings[saml_x509_cert]" rows="10" cols="50" class="large-text code"><?php echo esc_textarea($value); ?></textarea>
        <p class="description">
            <?php _e('X.509 Certificate from Cloudflare for signature validation (optional but recommended).', 'cf-zero-trust'); ?><br>
            <?php _e('Include the entire certificate including BEGIN/END lines.', 'cf-zero-trust'); ?>
        </p>
        <?php
    }
    
    /**
     * Settings page
     */
    public function settings_page() {
        require_once CFZT_PLUGIN_DIR . 'templates/admin-page.php';
    }

    /**
     * Dashboard page callback
     */
    public function dashboard_page() {
        require_once CFZT_PLUGIN_DIR . 'templates/dashboard-page.php';
    }

    /**
     * Logs page callback
     */
    public function logs_page() {
        require_once CFZT_PLUGIN_DIR . 'templates/logs-page.php';
    }

    /**
     * Admin notices
     */
    public function admin_notices() {
        // Check if we need to flush rewrite rules
        if (get_transient('cfzt_flush_rewrite_rules')) {
            flush_rewrite_rules();
            delete_transient('cfzt_flush_rewrite_rules');
        }

        $screen = get_current_screen();
        if ($screen && $screen->id === 'settings_page_cf-zero-trust') {
            // Show success message with next steps
            if (get_transient('cfzt_settings_saved_success')) {
                delete_transient('cfzt_settings_saved_success');
                $login_url = wp_login_url();
                ?>
                <div class="notice notice-success is-dismissible">
                    <h3 style="margin: 10px 0;"><?php _e('Configuration Saved Successfully!', 'cf-zero-trust'); ?></h3>
                    <p><?php _e('Your Cloudflare Zero Trust settings have been saved. Here are your next steps:', 'cf-zero-trust'); ?></p>
                    <ol style="margin-left: 20px;">
                        <li><strong><?php _e('Test Your Connection:', 'cf-zero-trust'); ?></strong> <?php _e('Use the test button below to verify your configuration', 'cf-zero-trust'); ?></li>
                        <li><strong><?php _e('Try Logging In:', 'cf-zero-trust'); ?></strong> <a href="<?php echo esc_url($login_url); ?>" target="_blank"><?php _e('Visit your login page', 'cf-zero-trust'); ?></a></li>
                        <li><strong><?php _e('Monitor Activity:', 'cf-zero-trust'); ?></strong> <?php _e('Check authentication logs if logging is enabled', 'cf-zero-trust'); ?></li>
                    </ol>
                    <p style="margin-top: 15px;">
                        <a href="<?php echo esc_url($login_url); ?>" class="button button-primary" target="_blank">
                            <span class="dashicons dashicons-external" style="margin-top: 3px;"></span> <?php _e('View Login Page', 'cf-zero-trust'); ?>
                        </a>
                        <button type="button" id="cfzt-test-connection-btn" class="button button-secondary">
                            <span class="dashicons dashicons-yes-alt" style="margin-top: 3px;"></span> <?php _e('Test Connection', 'cf-zero-trust'); ?>
                        </button>
                    </p>
                </div>
                <?php
            }
            if (!$this->security->is_encryption_available()) {
                ?>
                <div class="notice notice-warning">
                    <p><?php _e('OpenSSL is not available on your server. Client secrets will be stored with basic obfuscation instead of strong encryption. Consider enabling OpenSSL for better security.', 'cf-zero-trust'); ?></p>
                </div>
                <?php
            }

            // Check SAML requirements
            $options = CFZT_Plugin::get_option();
            if (isset($options['auth_method']) && $options['auth_method'] === 'saml') {
                if (!class_exists('DOMDocument')) {
                    ?>
                    <div class="notice notice-error">
                        <p><?php _e('The PHP DOM extension is required for SAML authentication but is not installed. Please install the php-xml package.', 'cf-zero-trust'); ?></p>
                    </div>
                    <?php
                }
            }
        }
    }

    /**
     * Show activation notice to guide users to settings
     */
    public function activation_notice() {
        // Only show to admins
        if (!current_user_can('manage_options')) {
            return;
        }

        // Check if notice was dismissed
        if (get_option('cfzt_activation_notice_dismissed')) {
            return;
        }

        // Check if transient exists (recently activated)
        if (!get_transient('cfzt_activation_notice')) {
            return;
        }

        // Check if plugin is already configured
        $options = CFZT_Plugin::get_option();
        $is_configured = !empty($options['team_domain']) && !empty($options['client_id']) && !empty($options['client_secret']);

        if ($is_configured) {
            // Plugin is configured, dismiss the notice
            delete_transient('cfzt_activation_notice');
            return;
        }

        // Don't show on our settings page
        $screen = get_current_screen();
        if ($screen && $screen->id === 'settings_page_cf-zero-trust') {
            return;
        }

        ?>
        <div class="notice notice-success is-dismissible cfzt-activation-notice" data-notice="cfzt-activation">
            <div style="display: flex; align-items: center; padding: 10px 0;">
                <div style="flex: 1;">
                    <h3 style="margin: 0 0 10px 0;">
                        <?php _e('Welcome to Cloudflare Zero Trust Login!', 'cf-zero-trust'); ?>
                    </h3>
                    <p style="margin: 0 0 10px 0;">
                        <?php _e('Thank you for installing Cloudflare Zero Trust Login for WordPress. To get started, you\'ll need to configure your Cloudflare credentials.', 'cf-zero-trust'); ?>
                    </p>
                    <p style="margin: 0;">
                        <a href="<?php echo esc_url(admin_url('options-general.php?page=cf-zero-trust')); ?>" class="button button-primary">
                            <?php _e('Configure Plugin Now', 'cf-zero-trust'); ?>
                        </a>
                        <a href="https://github.com/<?php echo CFZT_GITHUB_USERNAME . '/' . CFZT_GITHUB_REPOSITORY; ?>#readme" class="button button-secondary" target="_blank">
                            <?php _e('View Documentation', 'cf-zero-trust'); ?>
                        </a>
                    </p>
                </div>
                <div style="margin-left: 20px;">
                    <svg width="80" height="80" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" fill="#f38020" opacity="0.2"/>
                        <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z" fill="#f38020"/>
                    </svg>
                </div>
            </div>
        </div>

        <script>
        jQuery(document).ready(function($) {
            // Handle dismiss button
            $('.cfzt-activation-notice').on('click', '.notice-dismiss', function() {
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'cfzt_dismiss_activation_notice',
                        nonce: '<?php echo wp_create_nonce('cfzt_dismiss_notice'); ?>'
                    }
                });
            });
        });
        </script>

        <style>
        .cfzt-activation-notice {
            border-left-color: #f38020 !important;
        }
        .cfzt-activation-notice h3 {
            color: #1d2327;
        }
        </style>
        <?php
    }

    /**
     * AJAX handler to dismiss activation notice
     */
    public function dismiss_activation_notice() {
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'cfzt_dismiss_notice')) {
            wp_send_json_error(__('Security check failed.', 'cf-zero-trust'));
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to perform this action.', 'cf-zero-trust'));
        }

        // Dismiss the notice
        update_option('cfzt_activation_notice_dismissed', true);
        delete_transient('cfzt_activation_notice');

        wp_send_json_success();
    }

    /**
     * Display onboarding checklist notice
     */
    public function onboarding_checklist_notice() {
        // Only show to admins
        if (!current_user_can('manage_options')) {
            return;
        }

        // Check if checklist was dismissed
        if (get_user_meta(get_current_user_id(), 'cfzt_onboarding_dismissed', true)) {
            return;
        }

        // Only show on relevant admin pages
        $screen = get_current_screen();
        $show_on_pages = array('dashboard', 'settings_page_cf-zero-trust', 'tools_page_cf-zero-trust-dashboard');
        if (!$screen || !in_array($screen->id, $show_on_pages)) {
            return;
        }

        // Get setup progress
        $progress = CFZT_Plugin::get_setup_progress();

        // Don't show if setup is complete
        if ($progress['percentage'] >= 100) {
            return;
        }

        // Define checklist items with actions
        $options = CFZT_Plugin::get_option();
        $auth_method = isset($options['auth_method']) ? $options['auth_method'] : 'oauth2';

        $checklist = array(
            array(
                'title' => __('Configure Team Domain', 'cf-zero-trust'),
                'completed' => !empty($options['team_domain']),
                'action_url' => admin_url('options-general.php?page=cf-zero-trust#team-domain'),
                'action_text' => __('Configure', 'cf-zero-trust')
            ),
            array(
                'title' => $auth_method === 'saml'
                    ? __('Configure SAML Settings', 'cf-zero-trust')
                    : __('Configure OIDC Credentials', 'cf-zero-trust'),
                'completed' => $auth_method === 'saml'
                    ? !empty($options['saml_sso_target_url'])
                    : (!empty($options['client_id']) && !empty($options['client_secret'])),
                'action_url' => admin_url('options-general.php?page=cf-zero-trust#auth-credentials'),
                'action_text' => __('Configure', 'cf-zero-trust')
            ),
            array(
                'title' => __('Choose Login Mode', 'cf-zero-trust'),
                'completed' => isset($options['login_mode']),
                'action_url' => admin_url('options-general.php?page=cf-zero-trust#login-mode'),
                'action_text' => __('Choose', 'cf-zero-trust')
            ),
            array(
                'title' => __('Test Connection', 'cf-zero-trust'),
                'completed' => false, // Always show as pending action
                'action_url' => admin_url('options-general.php?page=cf-zero-trust#test-connection'),
                'action_text' => __('Test Now', 'cf-zero-trust'),
                'optional' => true
            ),
            array(
                'title' => __('Review Security Settings', 'cf-zero-trust'),
                'completed' => isset($options['default_role']) && isset($options['auto_create_users']),
                'action_url' => admin_url('options-general.php?page=cf-zero-trust#security'),
                'action_text' => __('Review', 'cf-zero-trust')
            )
        );

        ?>
        <div class="notice notice-info cfzt-onboarding-notice is-dismissible" data-dismiss-nonce="<?php echo wp_create_nonce('cfzt_dismiss_onboarding'); ?>">
            <div style="display: flex; align-items: flex-start; padding: 12px 0;">
                <div style="font-size: 32px; margin-right: 15px;">🚀</div>
                <div style="flex: 1;">
                    <h3 style="margin: 0 0 10px 0; font-size: 16px;">
                        <?php _e('Complete Your Cloudflare Zero Trust Setup', 'cf-zero-trust'); ?>
                    </h3>
                    <p style="margin: 0 0 15px 0;">
                        <?php printf(__('You\'re %d%% done! Complete these steps to secure your WordPress login:', 'cf-zero-trust'), $progress['percentage']); ?>
                    </p>

                    <div class="cfzt-onboarding-checklist" style="margin-bottom: 10px;">
                        <?php foreach ($checklist as $item): ?>
                            <div class="cfzt-checklist-item" style="display: flex; align-items: center; margin: 8px 0;">
                                <?php if ($item['completed']): ?>
                                    <span class="dashicons dashicons-yes-alt" style="color: #00a32a; font-size: 20px; margin-right: 8px;"></span>
                                <?php else: ?>
                                    <span class="dashicons dashicons-marker" style="color: #f38020; font-size: 20px; margin-right: 8px;"></span>
                                <?php endif; ?>

                                <span style="flex: 1; <?php echo $item['completed'] ? 'text-decoration: line-through; opacity: 0.6;' : ''; ?>">
                                    <?php echo esc_html($item['title']); ?>
                                    <?php if (isset($item['optional']) && $item['optional']): ?>
                                        <em style="color: #646970; font-size: 12px;">(<?php _e('recommended', 'cf-zero-trust'); ?>)</em>
                                    <?php endif; ?>
                                </span>

                                <?php if (!$item['completed']): ?>
                                    <a href="<?php echo esc_url($item['action_url']); ?>" class="button button-small" style="margin-left: 10px;">
                                        <?php echo esc_html($item['action_text']); ?>
                                    </a>
                                <?php endif; ?>
                            </div>
                        <?php endforeach; ?>
                    </div>

                    <p style="margin: 10px 0 0 0;">
                        <a href="<?php echo esc_url(admin_url('options-general.php?page=cf-zero-trust')); ?>" class="button button-primary">
                            <?php _e('Go to Settings', 'cf-zero-trust'); ?>
                        </a>
                        <a href="<?php echo esc_url(admin_url('tools.php?page=cf-zero-trust-dashboard')); ?>" class="button">
                            <?php _e('View Dashboard', 'cf-zero-trust'); ?>
                        </a>
                    </p>
                </div>
            </div>
        </div>

        <style>
        .cfzt-onboarding-notice {
            border-left-color: #f38020 !important;
        }
        .cfzt-onboarding-notice h3 {
            color: #1d2327;
        }
        .cfzt-onboarding-checklist {
            background: #fff;
            padding: 12px;
            border-radius: 4px;
            border: 1px solid #ddd;
        }
        </style>

        <script>
        jQuery(document).ready(function($) {
            $('.cfzt-onboarding-notice').on('click', '.notice-dismiss', function() {
                var nonce = $('.cfzt-onboarding-notice').data('dismiss-nonce');
                $.post(ajaxurl, {
                    action: 'cfzt_dismiss_onboarding_checklist',
                    nonce: nonce
                });
            });
        });
        </script>
        <?php
    }

    /**
     * AJAX handler to dismiss onboarding checklist
     */
    public function ajax_dismiss_onboarding_checklist() {
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'cfzt_dismiss_onboarding')) {
            wp_send_json_error(__('Security check failed.', 'cf-zero-trust'));
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to perform this action.', 'cf-zero-trust'));
        }

        // Dismiss the checklist for this user
        update_user_meta(get_current_user_id(), 'cfzt_onboarding_dismissed', true);

        wp_send_json_success();
    }

    /**
     * AJAX handler to test Cloudflare connection
     */
    public function ajax_test_connection() {
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'cfzt_test_connection')) {
            wp_send_json_error(__('Security check failed.', 'cf-zero-trust'));
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to test the connection.', 'cf-zero-trust'));
        }

        // Get current settings
        $options = CFZT_Plugin::get_option();
        $auth_method = isset($options['auth_method']) ? $options['auth_method'] : 'oauth2';
        $team_domain = isset($options['team_domain']) ? $options['team_domain'] : '';

        // Validate required fields
        if (empty($team_domain)) {
            wp_send_json_error(array(
                'message' => __('Team Domain is required. Please configure your settings first.', 'cf-zero-trust'),
                'issues' => array(__('Missing team domain', 'cf-zero-trust'))
            ));
        }

        $issues = array();
        $warnings = array();

        // Test OIDC connection
        if ($auth_method === 'oauth2') {
            $client_id = isset($options['client_id']) ? $options['client_id'] : '';
            $app_type = isset($options['app_type']) ? $options['app_type'] : 'saas';

            if (empty($client_id)) {
                $issues[] = __('Client ID is not configured', 'cf-zero-trust');
            }

            // Test discovery endpoint
            $discovery_url = 'https://' . $team_domain . '/.well-known/openid-configuration';
            $response = wp_remote_get($discovery_url, array(
                'timeout' => 10,
                'sslverify' => true
            ));

            if (is_wp_error($response)) {
                $issues[] = sprintf(
                    __('Failed to connect to Cloudflare: %s', 'cf-zero-trust'),
                    $response->get_error_message()
                );
                $issues[] = sprintf(
                    __('Attempted URL: %s', 'cf-zero-trust'),
                    $discovery_url
                );
            } else {
                $status_code = wp_remote_retrieve_response_code($response);
                $body = wp_remote_retrieve_body($response);

                if ($status_code !== 200) {
                    $issues[] = sprintf(
                        __('Discovery endpoint returned status %d', 'cf-zero-trust'),
                        $status_code
                    );
                } else {
                    $discovery_data = json_decode($body, true);

                    if (!$discovery_data || !isset($discovery_data['issuer'])) {
                        $issues[] = __('Invalid discovery document received', 'cf-zero-trust');
                    } else {
                        // Verify issuer contains team domain
                        if (strpos($discovery_data['issuer'], $team_domain) === false) {
                            $warnings[] = sprintf(
                                __('Team domain "%s" does not match issuer "%s"', 'cf-zero-trust'),
                                $team_domain,
                                $discovery_data['issuer']
                            );
                        }
                    }
                }
            }

            // Check client secret
            $client_secret = isset($options['client_secret']) ? $this->security->decrypt_data($options['client_secret']) : '';
            if (empty($client_secret)) {
                $issues[] = __('Client Secret is not configured', 'cf-zero-trust');
            }

        } else {
            // Test SAML configuration
            $sso_target_url = isset($options['saml_sso_target_url']) ? $options['saml_sso_target_url'] : '';

            if (empty($sso_target_url)) {
                $issues[] = __('SAML SSO Target URL is not configured', 'cf-zero-trust');
            }

            // Check for DOMDocument
            if (!class_exists('DOMDocument')) {
                $issues[] = __('PHP DOM extension is required for SAML but is not installed', 'cf-zero-trust');
            }

            $warnings[] = __('SAML signature validation is not implemented - not recommended for production', 'cf-zero-trust');
        }

        // Check SSL
        if (!is_ssl() && !defined('WP_DEBUG')) {
            $warnings[] = __('Your site is not using HTTPS. This is required for production use.', 'cf-zero-trust');
        }

        // Check encryption
        if (!$this->security->is_encryption_available()) {
            $warnings[] = __('OpenSSL is not available. Client secrets are stored with basic obfuscation only.', 'cf-zero-trust');
        }

        // Return results (HTML-escape for XSS prevention)
        if (!empty($issues)) {
            wp_send_json_error(array(
                'message' => __('Connection test failed. Please fix the following issues:', 'cf-zero-trust'),
                'issues' => array_map('esc_html', $issues),
                'warnings' => array_map('esc_html', $warnings)
            ));
        } elseif (!empty($warnings)) {
            wp_send_json_success(array(
                'message' => __('Connection test passed with warnings:', 'cf-zero-trust'),
                'warnings' => array_map('esc_html', $warnings)
            ));
        } else {
            wp_send_json_success(array(
                'message' => __('Connection test passed! Your configuration looks good.', 'cf-zero-trust'),
                'details' => array(
                    __('Team domain is reachable', 'cf-zero-trust'),
                    __('Discovery endpoint is valid', 'cf-zero-trust'),
                    __('All required fields are configured', 'cf-zero-trust')
                )
            ));
        }
    }
    
    /**
     * Prevent overwriting constants in database
     * 
     * @param array $new_value New settings value
     * @param array $old_value Old settings value
     * @return array Modified settings
     */
    public function protect_constants($new_value, $old_value) {
        if (defined('CFZT_CLIENT_ID') && CFZT_CLIENT_ID) {
            $new_value['client_id'] = isset($old_value['client_id']) ? $old_value['client_id'] : '';
        }
        if (defined('CFZT_CLIENT_SECRET') && CFZT_CLIENT_SECRET) {
            $new_value['client_secret'] = isset($old_value['client_secret']) ? $old_value['client_secret'] : '';
        }
        return $new_value;
    }
    
    /**
     * Enqueue admin scripts
     * 
     * @param string $hook Current admin page hook
     */
    public function enqueue_admin_scripts($hook) {
        if ($hook !== 'settings_page_cf-zero-trust') {
            return;
        }
        
        // Check if JS file exists, if not create it
        $js_file = CFZT_PLUGIN_DIR . 'assets/js/cfzt-admin.js';
        if (!file_exists($js_file)) {
            $this->create_admin_js();
        }
        
        wp_enqueue_script(
            'cfzt-admin',
            CFZT_PLUGIN_URL . 'assets/js/cfzt-admin.js',
            array('jquery'),
            CFZT_PLUGIN_VERSION,
            true
        );
        
        wp_localize_script('cfzt-admin', 'cfztAdmin', array(
            'nonce' => wp_create_nonce('cfzt_check_updates'),
            'checkingText' => __('Checking...', 'cf-zero-trust'),
            'errorText' => __('Error checking for updates. Please try again.', 'cf-zero-trust'),
            'updateNowText' => __('Update Now', 'cf-zero-trust'),
            'showDetailsText' => __('Show Details', 'cf-zero-trust'),
            'hideDetailsText' => __('Hide Details', 'cf-zero-trust')
        ));
        
        // Add inline CSS for update check status and user column
        wp_add_inline_style('common', '
            #cfzt-update-check-status {
                margin: 10px 0;
                padding: 10px;
                display: none;
            }
            #cfzt-update-check-status.notice-success,
            #cfzt-update-check-status.notice-warning,
            #cfzt-update-check-status.notice-error {
                display: block;
            }
            #cfzt-update-check-status .spinner {
                visibility: visible;
            }
            #cfzt-security-details {
                display: none;
            }
            #cfzt-oidc-settings,
            #cfzt-saml-settings {
                margin-top: 20px;
            }
            .cfzt-section-hidden {
                display: none;
            }
            .cfzt-badge {
                display: inline-flex;
                align-items: center;
                padding: 3px 8px;
                border-radius: 3px;
                font-size: 11px;
                font-weight: 600;
                line-height: 1;
            }
            .cfzt-badge-active {
                background: #00a0d2;
                color: #fff;
            }
            .cfzt-user-status {
                line-height: 1.8;
            }
        ');
    }
    
    /**
     * Create admin JavaScript file
     */
    private function create_admin_js() {
        $js_content = '/**
 * Cloudflare Zero Trust Login Admin JavaScript
 */
(function($) {
    \'use strict\';

    $(document).ready(function() {
        // Toggle authentication method sections
        function toggleAuthSections() {
            var authMethod = $(\'#cfzt_auth_method\').val();
            
            if (authMethod === \'saml\') {
                $(\'#cfzt-oidc-settings\').hide();
                $(\'#cfzt-saml-settings\').show();
                // Hide OIDC fields
                $(\'tr\').filter(function() {
                    return this.id && this.id.match(/^cfzt_oidc_/);
                }).hide();
                // Show SAML fields
                $(\'tr\').filter(function() {
                    return this.id && this.id.match(/^cfzt_saml_/);
                }).show();
            } else {
                $(\'#cfzt-oidc-settings\').show();
                $(\'#cfzt-saml-settings\').hide();
                // Show OIDC fields
                $(\'tr\').filter(function() {
                    return this.id && this.id.match(/^cfzt_oidc_/);
                }).show();
                // Hide SAML fields
                $(\'tr\').filter(function() {
                    return this.id && this.id.match(/^cfzt_saml_/);
                }).hide();
            }
        }
        
        // Initial toggle
        toggleAuthSections();
        
        // Toggle on change
        $(\'#cfzt_auth_method\').on(\'change\', toggleAuthSections);
        
        // Manual update check
        $(\'#cfzt-check-updates\').on(\'click\', function(e) {
            e.preventDefault();
            
            var $button = $(this);
            var $status = $(\'#cfzt-update-check-status\');
            var originalText = $button.text();
            
            // Disable button and show loading state
            $button.prop(\'disabled\', true).text(cfztAdmin.checkingText);
            $status.removeClass(\'notice-success notice-error\').html(\'<span class="spinner is-active" style="float: none; margin: 0;"></span> \' + cfztAdmin.checkingText);
            
            // Make AJAX request
            $.ajax({
                url: ajaxurl,
                type: \'POST\',
                data: {
                    action: \'cfzt_check_for_updates\',
                    nonce: cfztAdmin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        var message = response.data.message;
                        var statusClass = response.data.hasUpdate ? \'notice-warning\' : \'notice-success\';
                        
                        $status.addClass(statusClass).html(message);
                        
                        // If update available, show update link
                        if (response.data.hasUpdate && response.data.updateUrl) {
                            $status.append(\' <a href="\' + response.data.updateUrl + \'">\' + cfztAdmin.updateNowText + \'</a>\');
                        }
                    } else {
                        $status.addClass(\'notice-error\').html(response.data || cfztAdmin.errorText);
                    }
                },
                error: function() {
                    $status.addClass(\'notice-error\').html(cfztAdmin.errorText);
                },
                complete: function() {
                    // Re-enable button
                    $button.prop(\'disabled\', false).text(originalText);
                }
            });
        });
        
        // Toggle security details
        $(\'#cfzt-toggle-security\').on(\'click\', function(e) {
            e.preventDefault();
            $(\'#cfzt-security-details\').slideToggle();
            $(this).text($(this).text() === cfztAdmin.showDetailsText ? cfztAdmin.hideDetailsText : cfztAdmin.showDetailsText);
        });
    });

})(jQuery);';
        
        // Create directories if they don't exist
        wp_mkdir_p(CFZT_PLUGIN_DIR . 'assets/js');
        
        // Write JS file
        file_put_contents(CFZT_PLUGIN_DIR . 'assets/js/cfzt-admin.js', $js_content);
    }
    
    /**
     * AJAX handler for checking updates
     */
    public function ajax_check_for_updates() {
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'cfzt_check_updates')) {
            wp_send_json_error(__('Security check failed.', 'cf-zero-trust'));
        }
        
        // Check permissions
        if (!current_user_can('update_plugins')) {
            wp_send_json_error(__('You do not have permission to check for updates.', 'cf-zero-trust'));
        }
        
        // Check if GitHub updater is available
        if (!class_exists('CFZT_GitHub_Updater')) {
            wp_send_json_error(__('Update checker is not available.', 'cf-zero-trust'));
        }
        
        // Get the updater instance
        $updater = new CFZT_GitHub_Updater(
            CFZT_PLUGIN_FILE,
            CFZT_GITHUB_USERNAME,
            CFZT_GITHUB_REPOSITORY
        );
        
        // Force check for updates
        $update_info = $updater->force_check();
        
        if ($update_info === false) {
            // Check if we have any release at all
            wp_send_json_success(array(
                'hasUpdate' => false,
                'message' => sprintf(
                    __('No updates available. Current version: %s', 'cf-zero-trust'),
                    CFZT_PLUGIN_VERSION
                )
            ));
        } elseif ($update_info['has_update']) {
            // Update available
            wp_send_json_success(array(
                'hasUpdate' => true,
                'message' => sprintf(
                    __('Update available! Version %s → %s', 'cf-zero-trust'),
                    $update_info['current_version'],
                    $update_info['latest_version']
                ),
                'updateUrl' => admin_url('plugins.php'),
                'releaseUrl' => $update_info['release_url']
            ));
        } else {
            // Up to date
            wp_send_json_success(array(
                'hasUpdate' => false,
                'message' => sprintf(
                    __('You have the latest version (%s)', 'cf-zero-trust'),
                    $update_info['current_version']
                )
            ));
        }
    }

    /**
     * AJAX handler to get logs
     */
    public function ajax_get_logs() {
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'cfzt_logs_action')) {
            wp_send_json_error(__('Security check failed.', 'cf-zero-trust'));
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to view logs.', 'cf-zero-trust'));
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'cfzt_logs';

        // Get filter parameters
        $level = isset($_POST['level']) ? sanitize_text_field($_POST['level']) : '';
        $search = isset($_POST['search']) ? sanitize_text_field($_POST['search']) : '';
        $date_from = isset($_POST['date_from']) ? sanitize_text_field($_POST['date_from']) : '';
        $date_to = isset($_POST['date_to']) ? sanitize_text_field($_POST['date_to']) : '';
        $auth_method = isset($_POST['auth_method']) ? sanitize_text_field($_POST['auth_method']) : '';
        $success_filter = isset($_POST['success_filter']) ? sanitize_text_field($_POST['success_filter']) : '';
        $page = isset($_POST['page']) ? max(1, intval($_POST['page'])) : 1;
        $per_page = 20;
        $offset = ($page - 1) * $per_page;

        // Build query
        $where = array('1=1');
        $where_values = array();

        if (!empty($level)) {
            $where[] = 'log_level = %s';
            $where_values[] = $level;
        }

        if (!empty($search)) {
            $where[] = '(message LIKE %s OR identifier LIKE %s)';
            $where_values[] = '%' . $wpdb->esc_like($search) . '%';
            $where_values[] = '%' . $wpdb->esc_like($search) . '%';
        }

        if (!empty($date_from)) {
            $where[] = 'log_time >= %s';
            $where_values[] = $date_from . ' 00:00:00';
        }

        if (!empty($date_to)) {
            $where[] = 'log_time <= %s';
            $where_values[] = $date_to . ' 23:59:59';
        }

        if (!empty($auth_method)) {
            $where[] = 'auth_method = %s';
            $where_values[] = $auth_method;
        }

        if ($success_filter !== '') {
            $where[] = 'success = %d';
            $where_values[] = intval($success_filter);
        }

        $where_clause = implode(' AND ', $where);

        // Get total count
        if (!empty($where_values)) {
            $count_query = $wpdb->prepare("SELECT COUNT(*) FROM $table_name WHERE $where_clause", $where_values);
        } else {
            $count_query = "SELECT COUNT(*) FROM $table_name WHERE $where_clause";
        }
        $total = $wpdb->get_var($count_query);

        // Get logs
        if (!empty($where_values)) {
            $logs_query = $wpdb->prepare(
                "SELECT * FROM $table_name WHERE $where_clause ORDER BY log_time DESC LIMIT %d OFFSET %d",
                array_merge($where_values, array($per_page, $offset))
            );
        } else {
            $logs_query = $wpdb->prepare(
                "SELECT * FROM $table_name WHERE $where_clause ORDER BY log_time DESC LIMIT %d OFFSET %d",
                $per_page,
                $offset
            );
        }
        $logs = $wpdb->get_results($logs_query);

        wp_send_json_success(array(
            'logs' => $logs,
            'total' => $total,
            'page' => $page,
            'per_page' => $per_page,
            'total_pages' => ceil($total / $per_page)
        ));
    }

    /**
     * AJAX handler to export logs to CSV
     */
    public function ajax_export_logs() {
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'cfzt_logs_action')) {
            wp_die(__('Security check failed.', 'cf-zero-trust'));
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have permission to export logs.', 'cf-zero-trust'));
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'cfzt_logs';

        // Get filter parameters
        $level = isset($_POST['level']) ? sanitize_text_field($_POST['level']) : '';
        $search = isset($_POST['search']) ? sanitize_text_field($_POST['search']) : '';
        $date_from = isset($_POST['date_from']) ? sanitize_text_field($_POST['date_from']) : '';
        $date_to = isset($_POST['date_to']) ? sanitize_text_field($_POST['date_to']) : '';
        $auth_method = isset($_POST['auth_method']) ? sanitize_text_field($_POST['auth_method']) : '';
        $success_filter = isset($_POST['success_filter']) ? sanitize_text_field($_POST['success_filter']) : '';

        // Build query (same as get_logs)
        $where = array('1=1');
        $where_values = array();

        if (!empty($level)) {
            $where[] = 'log_level = %s';
            $where_values[] = $level;
        }

        if (!empty($search)) {
            $where[] = '(message LIKE %s OR identifier LIKE %s)';
            $where_values[] = '%' . $wpdb->esc_like($search) . '%';
            $where_values[] = '%' . $wpdb->esc_like($search) . '%';
        }

        if (!empty($date_from)) {
            $where[] = 'log_time >= %s';
            $where_values[] = $date_from . ' 00:00:00';
        }

        if (!empty($date_to)) {
            $where[] = 'log_time <= %s';
            $where_values[] = $date_to . ' 23:59:59';
        }

        if (!empty($auth_method)) {
            $where[] = 'auth_method = %s';
            $where_values[] = $auth_method;
        }

        if ($success_filter !== '') {
            $where[] = 'success = %d';
            $where_values[] = intval($success_filter);
        }

        $where_clause = implode(' AND ', $where);

        // Get all matching logs
        if (!empty($where_values)) {
            $logs_query = $wpdb->prepare("SELECT * FROM $table_name WHERE $where_clause ORDER BY log_time DESC", $where_values);
        } else {
            $logs_query = "SELECT * FROM $table_name WHERE $where_clause ORDER BY log_time DESC";
        }
        $logs = $wpdb->get_results($logs_query, ARRAY_A);

        // Generate CSV
        $filename = 'cfzt-logs-' . date('Y-m-d-His') . '.csv';

        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename=' . $filename);

        $output = fopen('php://output', 'w');

        // Add BOM for Excel UTF-8 support
        fprintf($output, chr(0xEF).chr(0xBB).chr(0xBF));

        // CSV headers
        fputcsv($output, array('Time', 'Level', 'Message', 'Identifier', 'Auth Method', 'Success', 'IP Address', 'User Agent'));

        // CSV data
        foreach ($logs as $log) {
            fputcsv($output, array(
                $log['log_time'],
                $log['log_level'],
                $log['message'],
                $log['identifier'],
                $log['auth_method'],
                $log['success'] ? 'Yes' : 'No',
                $log['ip_address'],
                $log['user_agent']
            ));
        }

        fclose($output);
        exit;
    }

    /**
     * AJAX handler to clear all logs
     */
    public function ajax_clear_logs() {
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'cfzt_logs_action')) {
            wp_send_json_error(__('Security check failed.', 'cf-zero-trust'));
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to clear logs.', 'cf-zero-trust'));
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'cfzt_logs';

        // Delete all logs
        $deleted = $wpdb->query("TRUNCATE TABLE $table_name");

        if ($deleted !== false) {
            CFZT_Logger::info('Authentication logs cleared by admin', array(
                'admin_user' => wp_get_current_user()->user_login
            ));

            wp_send_json_success(__('All logs have been cleared.', 'cf-zero-trust'));
        } else {
            wp_send_json_error(__('Failed to clear logs.', 'cf-zero-trust'));
        }
    }

    /**
     * Add custom columns to users list
     *
     * @param array $columns Existing columns
     * @return array Modified columns
     */
    public function add_user_columns($columns) {
        // Insert column after the email column
        $new_columns = array();
        foreach ($columns as $key => $value) {
            $new_columns[$key] = $value;
            if ($key === 'email') {
                $new_columns['cfzt_status'] = __('CF Zero Trust', 'cf-zero-trust');
            }
        }
        return $new_columns;
    }

    /**
     * Render custom user column content
     *
     * @param string $output Custom column output
     * @param string $column_name Column name
     * @param int $user_id User ID
     * @return string Column content
     */
    public function render_user_column($output, $column_name, $user_id) {
        if ($column_name !== 'cfzt_status') {
            return $output;
        }

        if (!CFZT_User_Helper::is_cfzt_user($user_id)) {
            return '<span style="color: #999;">—</span>';
        }

        $auth_method = get_user_meta($user_id, 'cfzt_auth_method', true);
        $last_login = get_user_meta($user_id, 'cfzt_last_login', true);

        $output = '<div class="cfzt-user-status">';
        $output .= '<span class="cfzt-badge cfzt-badge-active">';
        $output .= '<span class="dashicons dashicons-cloud" style="font-size: 14px; width: 14px; height: 14px; margin-right: 3px;"></span>';
        $output .= __('Active', 'cf-zero-trust');
        $output .= '</span>';

        if ($auth_method) {
            $method_label = strtoupper($auth_method);
            $output .= '<br><small style="color: #666;">' . sprintf(__('Method: %s', 'cf-zero-trust'), $method_label) . '</small>';
        }

        if ($last_login) {
            $last_login_formatted = human_time_diff(strtotime($last_login), current_time('timestamp'));
            $output .= '<br><small style="color: #999;">' . sprintf(__('Last login: %s ago', 'cf-zero-trust'), $last_login_formatted) . '</small>';
        }

        $output .= '</div>';

        return $output;
    }

    /**
     * Make custom columns sortable
     *
     * @param array $columns Sortable columns
     * @return array Modified sortable columns
     */
    public function make_user_columns_sortable($columns) {
        $columns['cfzt_status'] = 'cfzt_user';
        return $columns;
    }

    /**
     * Sort users by CF Zero Trust status
     *
     * @param WP_User_Query $query User query
     */
    public function sort_users_by_cfzt($query) {
        if (!is_admin()) {
            return;
        }

        $orderby = $query->get('orderby');
        if ($orderby === 'cfzt_user') {
            $query->set('meta_key', 'cfzt_user');
            $query->set('orderby', 'meta_value');
        }
    }

    /**
     * Add filter link for CF Zero Trust users
     *
     * @param array $views Existing views
     * @return array Modified views
     */
    public function add_cfzt_users_filter($views) {
        global $wpdb;

        // Count CF Zero Trust users
        $count = $wpdb->get_var(
            "SELECT COUNT(DISTINCT user_id)
             FROM {$wpdb->usermeta}
             WHERE meta_key = 'cfzt_user'
             AND meta_value = '1'"
        );

        if ($count > 0) {
            $class = '';
            if (isset($_GET['cfzt_users']) && $_GET['cfzt_users'] === '1') {
                $class = 'current';
            }

            $url = add_query_arg('cfzt_users', '1', admin_url('users.php'));
            $views['cfzt_users'] = sprintf(
                '<a href="%s" class="%s">%s <span class="count">(%d)</span></a>',
                esc_url($url),
                $class,
                __('CF Zero Trust Users', 'cf-zero-trust'),
                $count
            );
        }

        return $views;
    }

    /**
     * Filter users to show only CF Zero Trust users
     *
     * @param WP_User_Query $query User query
     */
    public function filter_cfzt_users($query) {
        if (!is_admin()) {
            return;
        }

        if (isset($_GET['cfzt_users']) && $_GET['cfzt_users'] === '1') {
            $query->set('meta_key', 'cfzt_user');
            $query->set('meta_value', '1');
        }
    }

    /**
     * AJAX handler to export settings
     */
    public function ajax_export_settings() {
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'cfzt_import_export')) {
            wp_send_json_error(__('Security check failed.', 'cf-zero-trust'));
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to export settings.', 'cf-zero-trust'));
        }

        // Get current settings
        $options = CFZT_Plugin::get_option();

        // Decrypt client secret for export
        if (!empty($options['client_secret'])) {
            $options['client_secret'] = $this->security->decrypt_data($options['client_secret']);
        }

        // Add metadata
        $export_data = array(
            'version' => CFZT_PLUGIN_VERSION,
            'exported_at' => current_time('mysql'),
            'site_url' => home_url(),
            'settings' => $options
        );

        // Return JSON
        wp_send_json_success(array(
            'data' => $export_data,
            'filename' => 'cfzt-settings-' . date('Y-m-d-His') . '.json'
        ));
    }

    /**
     * AJAX handler to import settings
     */
    public function ajax_import_settings() {
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'cfzt_import_export')) {
            wp_send_json_error(__('Security check failed.', 'cf-zero-trust'));
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to import settings.', 'cf-zero-trust'));
        }

        // Get import data
        if (empty($_POST['import_data'])) {
            wp_send_json_error(__('No import data provided.', 'cf-zero-trust'));
        }

        // Decode JSON
        $import_data = json_decode(stripslashes($_POST['import_data']), true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            wp_send_json_error(__('Invalid JSON format.', 'cf-zero-trust'));
        }

        // Validate structure
        if (!isset($import_data['settings']) || !is_array($import_data['settings'])) {
            wp_send_json_error(__('Invalid import file structure.', 'cf-zero-trust'));
        }

        $settings = $import_data['settings'];

        // Validate required fields
        $required_fields = array('auth_method', 'team_domain');
        foreach ($required_fields as $field) {
            if (!isset($settings[$field])) {
                wp_send_json_error(sprintf(__('Missing required field: %s', 'cf-zero-trust'), $field));
            }
        }

        // Sanitize and encrypt as needed
        $sanitized = array();

        // General settings
        $sanitized['auth_method'] = sanitize_text_field($settings['auth_method']);
        $sanitized['team_domain'] = sanitize_text_field($settings['team_domain']);
        $sanitized['login_mode'] = isset($settings['login_mode']) ? sanitize_text_field($settings['login_mode']) : 'secondary';
        $sanitized['auto_create_users'] = isset($settings['auto_create_users']) ? sanitize_text_field($settings['auto_create_users']) : 'yes';
        $sanitized['default_role'] = isset($settings['default_role']) ? sanitize_text_field($settings['default_role']) : 'subscriber';
        $sanitized['enable_logging'] = isset($settings['enable_logging']) ? sanitize_text_field($settings['enable_logging']) : 'no';

        // OIDC settings
        if (isset($settings['app_type'])) {
            $sanitized['app_type'] = sanitize_text_field($settings['app_type']);
        }
        if (isset($settings['client_id'])) {
            $sanitized['client_id'] = sanitize_text_field($settings['client_id']);
        }
        if (isset($settings['client_secret'])) {
            // Encrypt the client secret
            $sanitized['client_secret'] = $this->security->encrypt_data(sanitize_text_field($settings['client_secret']));
        }

        // SAML settings
        if (isset($settings['saml_sso_target_url'])) {
            $sanitized['saml_sso_target_url'] = sanitize_text_field($settings['saml_sso_target_url']);
        }
        if (isset($settings['saml_sp_entity_id'])) {
            $sanitized['saml_sp_entity_id'] = sanitize_text_field($settings['saml_sp_entity_id']);
        }
        if (isset($settings['saml_x509_cert'])) {
            $sanitized['saml_x509_cert'] = sanitize_textarea_field($settings['saml_x509_cert']);
        }

        // Role mapping (with proper sanitization)
        if (isset($settings['role_mapping']) && is_array($settings['role_mapping'])) {
            $sanitized['role_mapping'] = array();
            foreach ($settings['role_mapping'] as $mapping) {
                if (is_array($mapping) && !empty($mapping['group']) && !empty($mapping['role'])) {
                    $sanitized['role_mapping'][] = array(
                        'group' => sanitize_text_field($mapping['group']),
                        'role' => sanitize_text_field($mapping['role'])
                    );
                }
            }
        }

        // Email domain restrictions
        if (isset($settings['email_domain_restrictions'])) {
            $sanitized['email_domain_restrictions'] = sanitize_textarea_field($settings['email_domain_restrictions']);
        }

        // Custom redirect URLs
        if (isset($settings['redirect_after_login'])) {
            $sanitized['redirect_after_login'] = esc_url_raw($settings['redirect_after_login']);
        }
        if (isset($settings['redirect_after_logout'])) {
            $sanitized['redirect_after_logout'] = esc_url_raw($settings['redirect_after_logout']);
        }

        // Save settings
        update_option('cfzt_settings', $sanitized);

        // Clear options cache
        CFZT_Plugin::clear_options_cache();

        // Log the import
        CFZT_Logger::info('Settings imported', array(
            'admin_user' => wp_get_current_user()->user_login,
            'from_version' => isset($import_data['version']) ? $import_data['version'] : 'unknown',
            'from_site' => isset($import_data['site_url']) ? $import_data['site_url'] : 'unknown'
        ));

        wp_send_json_success(__('Settings imported successfully!', 'cf-zero-trust'));
    }
}