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
     * Values the settings form may store for its enumerated options
     */
    const ALLOWED_LOGIN_MODES = array(CFZT_Plugin::LOGIN_MODE_PRIMARY, CFZT_Plugin::LOGIN_MODE_SECONDARY);
    const ALLOWED_APP_TYPES   = array(CFZT_Plugin::APP_TYPE_SAAS, CFZT_Plugin::APP_TYPE_SELF_HOSTED);
    const ALLOWED_YES_NO      = array(CFZT_Plugin::OPTION_YES, CFZT_Plugin::OPTION_NO);

    /**
     * When true, sanitize_settings() passes its input through untouched
     *
     * Set by CFZT_Plugin::save_settings() around programmatic writes that
     * already hold prepared, encrypted values. See that method for why.
     *
     * @since 2.0.0
     * @var bool
     */
    public static $raw_write = false;

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
        add_action('admin_notices', array($this, 'saml_removal_notice'));
        add_action('wp_ajax_cfzt_dismiss_saml_notice', array($this, 'ajax_dismiss_saml_notice'));
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
            __('Cloudflare Zero Trust Settings', 'zero-trust-login-for-cloudflare'),
            __('CF Zero Trust', 'zero-trust-login-for-cloudflare'),
            'manage_options',
            'cf-zero-trust',
            array($this, 'settings_page')
        );

        // Dashboard page under Tools menu for easy access
        add_management_page(
            __('CF Zero Trust Dashboard', 'zero-trust-login-for-cloudflare'),
            __('CF Zero Trust', 'zero-trust-login-for-cloudflare'),
            'manage_options',
            'cf-zero-trust-dashboard',
            array($this, 'dashboard_page')
        );

        // Logs page under Tools menu
        add_management_page(
            __('CF Zero Trust Logs', 'zero-trust-login-for-cloudflare'),
            __('CF Zero Trust Logs', 'zero-trust-login-for-cloudflare'),
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
            __('General Configuration', 'zero-trust-login-for-cloudflare'),
            array($this, 'main_section_callback'),
            'cf-zero-trust'
        );
        
        // Add general settings fields
        $general_fields = array(
            'team_domain' => __('Team Domain', 'zero-trust-login-for-cloudflare'),
            'login_mode' => __('Login Mode', 'zero-trust-login-for-cloudflare'),
            'auto_create_users' => __('Auto-create Users', 'zero-trust-login-for-cloudflare'),
            'default_role' => __('Default User Role', 'zero-trust-login-for-cloudflare'),
            'enable_logging' => __('Enable Authentication Logging', 'zero-trust-login-for-cloudflare')
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
            __('OIDC Configuration', 'zero-trust-login-for-cloudflare'),
            array($this, 'oidc_section_callback'),
            'cf-zero-trust'
        );
        
        $oidc_fields = array(
            'app_type' => __('Application Type', 'zero-trust-login-for-cloudflare'),
            'client_id' => __('Client ID', 'zero-trust-login-for-cloudflare'),
            'client_secret' => __('Client Secret', 'zero-trust-login-for-cloudflare'),
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
    }
    
    /**
     * Warn that SAML was removed and this site was migrated onto OIDC
     *
     * Deliberately not auto-dismissing: a site that was using SAML is not
     * authenticating anyone until it is reconfigured, so this stays until an
     * administrator acknowledges it.
     *
     * @since 2.0.0
     *
     * @return void
     */
    public function saml_removal_notice() {
        if (!$this->should_show_saml_removal_notice()) {
            return;
        }

        $state = get_option('cfzt_saml_removed_notice');
        $settings_url = admin_url('options-general.php?page=cf-zero-trust');
        ?>
        <div class="notice notice-warning cfzt-saml-removed-notice is-dismissible"
             data-cfzt-dismiss-action="cfzt_dismiss_saml_notice"
             data-cfzt-dismiss-nonce="<?php echo esc_attr(wp_create_nonce('cfzt_dismiss_saml_notice')); ?>">
            <h3 style="margin-bottom: 5px;"><?php esc_html_e('SAML support has been removed', 'zero-trust-login-for-cloudflare'); ?></h3>
            <p>
                <?php esc_html_e('This site was configured to authenticate with SAML. That implementation never verified response signatures, so it has been removed rather than left in place. Cloudflare Zero Trust authentication now runs over OIDC only.', 'zero-trust-login-for-cloudflare'); ?>
            </p>
            <?php if ('login_restored' === $state) : ?>
                <p>
                    <strong><?php esc_html_e('Your login mode was changed from "Cloudflare only" back to "Cloudflare alongside WordPress login"', 'zero-trust-login-for-cloudflare'); ?></strong>
                    <?php esc_html_e('so that you can still reach your site while you reconfigure. Set it back once OIDC is working.', 'zero-trust-login-for-cloudflare'); ?>
                </p>
            <?php endif; ?>
            <p>
                <a href="<?php echo esc_url($settings_url); ?>" class="button button-primary">
                    <?php esc_html_e('Set up OIDC', 'zero-trust-login-for-cloudflare'); ?>
                </a>
            </p>
        </div>
        <?php
    }

    /**
     * Whether the SAML removal notice should render on this request
     *
     * Shared by the notice and by enqueue_admin_scripts(), which loads the
     * dismiss script and notice styles only when a notice will appear.
     *
     * @return bool
     */
    private function should_show_saml_removal_notice(): bool {
        return current_user_can('manage_options') && !empty(get_option('cfzt_saml_removed_notice'));
    }

    /**
     * Dismiss the SAML removal notice
     *
     * @since 2.0.0
     *
     * @return void
     */
    public function ajax_dismiss_saml_notice() {
        if (!isset($_POST['nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['nonce'])), 'cfzt_dismiss_saml_notice')) {
            wp_send_json_error(__('Security check failed.', 'zero-trust-login-for-cloudflare'));
        }

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Permission denied.', 'zero-trust-login-for-cloudflare'));
        }

        delete_option('cfzt_saml_removed_notice');
        wp_send_json_success();
    }

    /**
     * Sanitize settings submitted from the settings forms
     *
     * Rebuilds the option from scratch, so anything a given form does not
     * render has to be carried over from the stored value explicitly or it is
     * silently lost. The Advanced form renders none of the "advanced" fields.
     *
     * @param array $input Raw input
     * @return array Sanitized settings
     */
    public function sanitize_settings($input) {
        // Programmatic write with prepared values: nothing to do.
        if (self::$raw_write) {
            return is_array($input) ? $input : array();
        }

        // Clear the options cache since we're updating settings
        CFZT_Plugin::clear_options_cache();

        $input = is_array($input) ? $input : array();
        $existing = get_option('cfzt_settings', array());
        $existing = is_array($existing) ? $existing : array();

        $sanitized = array();

        // General settings
        $sanitized['auth_method'] = CFZT_Plugin::AUTH_METHOD_OIDC;
        $sanitized['team_domain'] = $this->sanitize_team_domain($this->field($input, $existing, 'team_domain'));
        $sanitized['login_mode'] = $this->sanitize_enum($this->field($input, $existing, 'login_mode'), self::ALLOWED_LOGIN_MODES, CFZT_Plugin::LOGIN_MODE_SECONDARY);
        $sanitized['auto_create_users'] = $this->sanitize_enum($this->field($input, $existing, 'auto_create_users'), self::ALLOWED_YES_NO, CFZT_Plugin::OPTION_YES);
        $sanitized['enable_logging'] = $this->sanitize_enum($this->field($input, $existing, 'enable_logging'), self::ALLOWED_YES_NO, CFZT_Plugin::OPTION_NO);

        $default_role = sanitize_key($this->field($input, $existing, 'default_role'));
        $sanitized['default_role'] = get_role($default_role) ? $default_role : CFZT_Plugin::DEFAULT_ROLE;

        // OIDC settings
        $sanitized['app_type'] = $this->sanitize_enum($this->field($input, $existing, 'app_type'), self::ALLOWED_APP_TYPES, CFZT_Plugin::APP_TYPE_SAAS);
        $sanitized['client_id'] = sanitize_text_field($this->field($input, $existing, 'client_id'));

        // Client secret. The forms never echo the stored secret back, so an
        // empty field means "keep what I have". A value already carrying the
        // encryption marker is stored as is; anything else is plaintext from
        // the admin and is encrypted exactly once.
        $secret_input = isset($input['client_secret']) ? trim((string) $input['client_secret']) : '';
        if ('' === $secret_input || '[SET VIA CONSTANT]' === $secret_input) {
            $sanitized['client_secret'] = isset($existing['client_secret']) ? (string) $existing['client_secret'] : '';
        } elseif ($this->security->is_encrypted($secret_input)) {
            $sanitized['client_secret'] = $secret_input;
        } else {
            $sanitized['client_secret'] = $this->security->encrypt_data(sanitize_text_field($secret_input));
        }

        // Advanced fields: present in the wizard form, absent from the Advanced
        // form. Fall back to the stored value whenever the form did not send one.
        $sanitized['email_domain_restrictions'] = isset($input['email_domain_restrictions'])
            ? sanitize_textarea_field($input['email_domain_restrictions'])
            : (isset($existing['email_domain_restrictions']) ? (string) $existing['email_domain_restrictions'] : '');

        foreach (array('redirect_after_login', 'redirect_after_logout') as $url_key) {
            $sanitized[$url_key] = isset($input[$url_key])
                ? esc_url_raw(trim((string) $input[$url_key]))
                : (isset($existing[$url_key]) ? (string) $existing[$url_key] : '');
        }

        // Role mapping. A form that renders the rows sends a sentinel even when
        // every row was removed, which is how "clear all mappings" is told
        // apart from "this form has no mapping fields".
        if (isset($input['role_mapping']) && is_array($input['role_mapping'])) {
            $sanitized['role_mapping'] = $this->sanitize_role_mapping($input['role_mapping']);
        } elseif (!empty($input['role_mapping_submitted'])) {
            $sanitized['role_mapping'] = array();
        } elseif (isset($existing['role_mapping']) && is_array($existing['role_mapping'])) {
            $sanitized['role_mapping'] = $this->sanitize_role_mapping($existing['role_mapping']);
        } else {
            $sanitized['role_mapping'] = array();
        }

        // Provisioning provenance is never rendered by a form; always carry it.
        foreach (array('provisioned_account_id', 'provisioned_app_id', 'provisioned_at') as $provenance_key) {
            if (isset($existing[$provenance_key])) {
                $sanitized[$provenance_key] = sanitize_text_field((string) $existing[$provenance_key]);
            }
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
     * Read a scalar field from the submitted input, falling back to the stored value
     *
     * @param array  $input    Submitted values.
     * @param array  $existing Stored values.
     * @param string $key      Field name.
     * @return string
     */
    private function field(array $input, array $existing, string $key): string {
        if (isset($input[$key]) && is_scalar($input[$key])) {
            return (string) $input[$key];
        }
        return isset($existing[$key]) && is_scalar($existing[$key]) ? (string) $existing[$key] : '';
    }

    /**
     * Constrain a value to a known list
     *
     * @param string $value   Submitted value.
     * @param array  $allowed Permitted values.
     * @param string $default Used when the value is not permitted.
     * @return string
     */
    private function sanitize_enum(string $value, array $allowed, string $default): string {
        $value = sanitize_key($value);
        return in_array($value, $allowed, true) ? $value : $default;
    }

    /**
     * Reduce a team domain to a bare hostname
     *
     * Accepts what people paste (a full issuer URL, a trailing slash) and
     * stores only the host, which is all the auth code ever uses.
     *
     * @param string $value Submitted value.
     * @return string
     */
    private function sanitize_team_domain(string $value): string {
        $value = strtolower(trim(sanitize_text_field($value)));
        if ('' === $value) {
            return '';
        }
        if (false !== strpos($value, '://')) {
            $host = wp_parse_url($value, PHP_URL_HOST);
            $value = is_string($host) ? $host : '';
        }
        $value = rtrim(preg_replace('#/.*$#', '', $value), '.');
        return preg_match('/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/', $value) ? $value : '';
    }

    /**
     * Sanitize a list of group-to-role mappings
     *
     * @param array $rows Submitted or stored rows.
     * @return array
     */
    private function sanitize_role_mapping(array $rows): array {
        $clean = array();
        foreach ($rows as $mapping) {
            if (!is_array($mapping) || empty($mapping['group']) || empty($mapping['role'])) {
                continue;
            }
            $role = sanitize_key((string) $mapping['role']);
            if (!get_role($role)) {
                continue;
            }
            $clean[] = array(
                'group' => sanitize_text_field((string) $mapping['group']),
                'role'  => $role,
            );
        }
        return $clean;
    }

    /**
     * Main section callback
     */
    public function main_section_callback() {
        echo '<p>' . esc_html__('Configure your Cloudflare Zero Trust integration settings below.', 'zero-trust-login-for-cloudflare') . '</p>';
    }
    
    /**
     * OIDC section callback
     */
    public function oidc_section_callback() {
        echo '<p>' . esc_html__('Configure OIDC (OpenID Connect) specific settings.', 'zero-trust-login-for-cloudflare') . '</p>';
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
                
        }
    }
    
    /**
     * Render app type field
     */
    private function render_app_type_field($value) {
        $value = !empty($value) ? $value : 'saas';
        ?>
        <select name="cfzt_settings[app_type]">
            <option value="saas" <?php selected($value, 'saas'); ?>><?php esc_html_e('SaaS (Recommended)', 'zero-trust-login-for-cloudflare'); ?></option>
            <option value="self-hosted" <?php selected($value, 'self-hosted'); ?>><?php esc_html_e('Self-hosted', 'zero-trust-login-for-cloudflare'); ?></option>
        </select>
        <p class="description"><?php esc_html_e('Choose the application type you created in Cloudflare Zero Trust. SaaS apps provide standard OIDC endpoints.', 'zero-trust-login-for-cloudflare'); ?></p>
        <?php
    }
    
    /**
     * Render team domain field
     */
    private function render_team_domain_field($value) {
        ?>
        <input type="text" name="cfzt_settings[team_domain]" value="<?php echo esc_attr($value); ?>" class="regular-text" />
        <p class="description">
            <?php echo wp_kses_post(__('Your Cloudflare Zero Trust team domain (e.g., <code>yourteam.cloudflareaccess.com</code>)', 'zero-trust-login-for-cloudflare')); ?><br>
            <?php esc_html_e('This is the hostname from your Issuer URL, without https://', 'zero-trust-login-for-cloudflare'); ?>
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
            <p class="description"><strong><?php esc_html_e('Value set via constant/environment variable', 'zero-trust-login-for-cloudflare'); ?></strong></p>
        <?php else: ?>
            <p class="description"><?php esc_html_e('Client ID from your Cloudflare Zero Trust OIDC application.', 'zero-trust-login-for-cloudflare'); ?></p>
        <?php endif; ?>
        <?php
    }
    
    /**
     * Render client secret field
     */
    private function render_client_secret_field($value, $options) {
        $from_constant = defined('CFZT_CLIENT_SECRET') && CFZT_CLIENT_SECRET;
        $has_secret = !$from_constant && !empty($options['client_secret']) && '' !== $this->security->get_client_secret();

        // The stored secret is never written into the page. Encryption at rest
        // is pointless if every settings-page load hands it to any browser
        // extension, cache or shoulder-surfer in plaintext.
        if ($from_constant) {
            $placeholder = __('Set via CFZT_CLIENT_SECRET constant', 'zero-trust-login-for-cloudflare');
        } elseif ($has_secret) {
            $placeholder = __('Saved. Leave blank to keep the current secret.', 'zero-trust-login-for-cloudflare');
        } else {
            $placeholder = '';
        }
        ?>
        <input type="password" name="cfzt_settings[client_secret]" value="" class="regular-text" autocomplete="new-password" placeholder="<?php echo esc_attr($placeholder); ?>" <?php echo $from_constant ? 'readonly' : ''; ?> />
        <?php if ($from_constant): ?>
            <p class="description"><strong><?php esc_html_e('Value set via constant/environment variable (hidden for security)', 'zero-trust-login-for-cloudflare'); ?></strong></p>
        <?php elseif ($has_secret): ?>
            <p class="description"><?php esc_html_e('A client secret is saved and encrypted. Enter a new one only to replace it.', 'zero-trust-login-for-cloudflare'); ?></p>
        <?php else: ?>
            <p class="description"><?php esc_html_e('Client Secret from your Cloudflare Zero Trust OIDC application.', 'zero-trust-login-for-cloudflare'); ?></p>
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
            <option value="secondary" <?php selected($value, 'secondary'); ?>><?php esc_html_e('Secondary (Show both login options)', 'zero-trust-login-for-cloudflare'); ?></option>
            <option value="primary" <?php selected($value, 'primary'); ?>><?php esc_html_e('Primary (Disable WordPress login)', 'zero-trust-login-for-cloudflare'); ?></option>
        </select>
        <p class="description"><?php esc_html_e('Choose whether to use Cloudflare Zero Trust as the only login method or alongside WordPress login.', 'zero-trust-login-for-cloudflare'); ?></p>
        <?php
    }
    
    /**
     * Render auto create users field
     */
    private function render_auto_create_field($value) {
        $value = !empty($value) ? $value : 'yes';
        ?>
        <select name="cfzt_settings[auto_create_users]">
            <option value="yes" <?php selected($value, 'yes'); ?>><?php esc_html_e('Yes', 'zero-trust-login-for-cloudflare'); ?></option>
            <option value="no" <?php selected($value, 'no'); ?>><?php esc_html_e('No', 'zero-trust-login-for-cloudflare'); ?></option>
        </select>
        <p class="description"><?php esc_html_e('Automatically create WordPress users for authenticated Cloudflare Zero Trust users.', 'zero-trust-login-for-cloudflare'); ?></p>
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
        <p class="description"><?php esc_html_e('Default role for auto-created users.', 'zero-trust-login-for-cloudflare'); ?></p>
        <?php
    }
    
    /**
     * Render logging field
     */
    private function render_logging_field($value) {
        $value = !empty($value) ? $value : 'no';
        ?>
        <select name="cfzt_settings[enable_logging]">
            <option value="yes" <?php selected($value, 'yes'); ?>><?php esc_html_e('Yes', 'zero-trust-login-for-cloudflare'); ?></option>
            <option value="no" <?php selected($value, 'no'); ?>><?php esc_html_e('No', 'zero-trust-login-for-cloudflare'); ?></option>
        </select>
        <p class="description"><?php esc_html_e('Log authentication attempts to the WordPress error log.', 'zero-trust-login-for-cloudflare'); ?></p>
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
        $screen = get_current_screen();
        if ($screen && $screen->id === 'settings_page_cf-zero-trust') {
            // Show success message with next steps
            if (get_transient('cfzt_settings_saved_success')) {
                delete_transient('cfzt_settings_saved_success');
                $login_url = wp_login_url();
                ?>
                <div class="notice notice-success is-dismissible">
                    <h3 style="margin: 10px 0;"><?php esc_html_e('Configuration Saved Successfully!', 'zero-trust-login-for-cloudflare'); ?></h3>
                    <p><?php esc_html_e('Your Cloudflare Zero Trust settings have been saved. Here are your next steps:', 'zero-trust-login-for-cloudflare'); ?></p>
                    <ol style="margin-left: 20px;">
                        <li><strong><?php esc_html_e('Test Your Connection:', 'zero-trust-login-for-cloudflare'); ?></strong> <?php esc_html_e('Use the test button below to verify your configuration', 'zero-trust-login-for-cloudflare'); ?></li>
                        <li><strong><?php esc_html_e('Try Logging In:', 'zero-trust-login-for-cloudflare'); ?></strong> <a href="<?php echo esc_url($login_url); ?>" target="_blank"><?php esc_html_e('Visit your login page', 'zero-trust-login-for-cloudflare'); ?></a></li>
                        <li><strong><?php esc_html_e('Monitor Activity:', 'zero-trust-login-for-cloudflare'); ?></strong> <?php esc_html_e('Check authentication logs if logging is enabled', 'zero-trust-login-for-cloudflare'); ?></li>
                    </ol>
                    <p style="margin-top: 15px;">
                        <a href="<?php echo esc_url($login_url); ?>" class="button button-primary" target="_blank">
                            <span class="dashicons dashicons-external" style="margin-top: 3px;"></span> <?php esc_html_e('View Login Page', 'zero-trust-login-for-cloudflare'); ?>
                        </a>
                        <button type="button" id="cfzt-test-connection-btn" class="button button-secondary">
                            <span class="dashicons dashicons-yes-alt" style="margin-top: 3px;"></span> <?php esc_html_e('Test Connection', 'zero-trust-login-for-cloudflare'); ?>
                        </button>
                    </p>
                </div>
                <?php
            }
            if (!$this->security->is_encryption_available()) {
                ?>
                <div class="notice notice-warning">
                    <p><?php esc_html_e('OpenSSL is not available on your server. Client secrets will be stored with basic obfuscation instead of strong encryption. Consider enabling OpenSSL for better security.', 'zero-trust-login-for-cloudflare'); ?></p>
                </div>
                <?php
            }
        }
    }

    /**
     * Show activation notice to guide users to settings
     */
    public function activation_notice() {
        if (!$this->should_show_activation_notice()) {
            return;
        }
        ?>
        <div class="notice notice-success is-dismissible cfzt-activation-notice"
             data-cfzt-dismiss-action="cfzt_dismiss_activation_notice"
             data-cfzt-dismiss-nonce="<?php echo esc_attr(wp_create_nonce('cfzt_dismiss_notice')); ?>">
            <div style="display: flex; align-items: center; padding: 10px 0;">
                <div style="flex: 1;">
                    <h3 style="margin: 0 0 10px 0;">
                        <?php esc_html_e('Welcome to Zero Trust Login for Cloudflare!', 'zero-trust-login-for-cloudflare'); ?>
                    </h3>
                    <p style="margin: 0 0 10px 0;">
                        <?php esc_html_e('Thank you for installing Zero Trust Login for Cloudflare. To get started, you\'ll need to configure your Cloudflare credentials.', 'zero-trust-login-for-cloudflare'); ?>
                    </p>
                    <p style="margin: 0;">
                        <a href="<?php echo esc_url(admin_url('options-general.php?page=cf-zero-trust')); ?>" class="button button-primary">
                            <?php esc_html_e('Configure Plugin Now', 'zero-trust-login-for-cloudflare'); ?>
                        </a>
                        <a href="<?php echo esc_url('https://github.com/' . CFZT_GITHUB_USERNAME . '/' . CFZT_GITHUB_REPOSITORY . '#readme'); ?>" class="button button-secondary" target="_blank">
                            <?php esc_html_e('View Documentation', 'zero-trust-login-for-cloudflare'); ?>
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
        <?php
    }

    /**
     * Whether the activation welcome notice should render on this request
     *
     * @return bool
     */
    private function should_show_activation_notice(): bool {
        if (!current_user_can('manage_options') || get_option('cfzt_activation_notice_dismissed')) {
            return false;
        }

        // Only shortly after activation
        if (!get_transient('cfzt_activation_notice')) {
            return false;
        }

        // Nothing to welcome once credentials are in place
        $options = CFZT_Plugin::get_option();
        if (!empty($options['team_domain']) && !empty($options['client_id']) && !empty($options['client_secret'])) {
            delete_transient('cfzt_activation_notice');
            return false;
        }

        // The settings page is where the notice sends people; no need there.
        // get_current_screen() only exists inside wp-admin, and some front-end
        // editors fire admin_enqueue_scripts, which calls this.
        $screen = function_exists('get_current_screen') ? get_current_screen() : null;
        return !($screen && $screen->id === 'settings_page_cf-zero-trust');
    }

    /**
     * AJAX handler to dismiss activation notice
     */
    public function dismiss_activation_notice() {
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['nonce'])), 'cfzt_dismiss_notice')) {
            wp_send_json_error(__('Security check failed.', 'zero-trust-login-for-cloudflare'));
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to perform this action.', 'zero-trust-login-for-cloudflare'));
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
        if (!$this->should_show_onboarding_checklist()) {
            return;
        }

        $progress = CFZT_Plugin::get_setup_progress();

        // Define checklist items with actions
        $options = CFZT_Plugin::get_option();

        $checklist = array(
            array(
                'title' => __('Configure Team Domain', 'zero-trust-login-for-cloudflare'),
                'completed' => !empty($options['team_domain']),
                'action_url' => admin_url('options-general.php?page=cf-zero-trust#team-domain'),
                'action_text' => __('Configure', 'zero-trust-login-for-cloudflare')
            ),
            array(
                'title' => __('Configure OIDC Credentials', 'zero-trust-login-for-cloudflare'),
                'completed' => !empty($options['client_id']) && !empty($options['client_secret']),
                'action_url' => admin_url('options-general.php?page=cf-zero-trust#auth-credentials'),
                'action_text' => __('Configure', 'zero-trust-login-for-cloudflare')
            ),
            array(
                'title' => __('Choose Login Mode', 'zero-trust-login-for-cloudflare'),
                'completed' => isset($options['login_mode']),
                'action_url' => admin_url('options-general.php?page=cf-zero-trust#login-mode'),
                'action_text' => __('Choose', 'zero-trust-login-for-cloudflare')
            ),
            array(
                'title' => __('Test Connection', 'zero-trust-login-for-cloudflare'),
                'completed' => false, // Always show as pending action
                'action_url' => admin_url('options-general.php?page=cf-zero-trust#test-connection'),
                'action_text' => __('Test Now', 'zero-trust-login-for-cloudflare'),
                'optional' => true
            ),
            array(
                'title' => __('Review Security Settings', 'zero-trust-login-for-cloudflare'),
                'completed' => isset($options['default_role']) && isset($options['auto_create_users']),
                'action_url' => admin_url('options-general.php?page=cf-zero-trust#security'),
                'action_text' => __('Review', 'zero-trust-login-for-cloudflare')
            )
        );

        ?>
        <div class="notice notice-info cfzt-onboarding-notice is-dismissible"
             data-cfzt-dismiss-action="cfzt_dismiss_onboarding_checklist"
             data-cfzt-dismiss-nonce="<?php echo esc_attr(wp_create_nonce('cfzt_dismiss_onboarding')); ?>">
            <div style="display: flex; align-items: flex-start; padding: 12px 0;">
                <div style="font-size: 32px; margin-right: 15px;">🚀</div>
                <div style="flex: 1;">
                    <h3 style="margin: 0 0 10px 0; font-size: 16px;">
                        <?php esc_html_e('Complete Your Cloudflare Zero Trust Setup', 'zero-trust-login-for-cloudflare'); ?>
                    </h3>
                    <p style="margin: 0 0 15px 0;">
                        <?php /* translators: %d: percentage of setup steps completed */ printf(esc_html__('You\'re %d%% done! Complete these steps to secure your WordPress login:', 'zero-trust-login-for-cloudflare'), (int) $progress['percentage']); ?>
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
                                        <em style="color: #646970; font-size: 12px;">(<?php esc_html_e('recommended', 'zero-trust-login-for-cloudflare'); ?>)</em>
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
                            <?php esc_html_e('Go to Settings', 'zero-trust-login-for-cloudflare'); ?>
                        </a>
                        <a href="<?php echo esc_url(admin_url('tools.php?page=cf-zero-trust-dashboard')); ?>" class="button">
                            <?php esc_html_e('View Dashboard', 'zero-trust-login-for-cloudflare'); ?>
                        </a>
                    </p>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Whether the onboarding checklist should render on this request
     *
     * @return bool
     */
    private function should_show_onboarding_checklist(): bool {
        if (!current_user_can('manage_options')) {
            return false;
        }

        if (get_user_meta(get_current_user_id(), 'cfzt_onboarding_dismissed', true)) {
            return false;
        }

        // Only on the WordPress dashboard and the plugin's own pages
        // (and never outside wp-admin, see should_show_activation_notice())
        if (!function_exists('get_current_screen')) {
            return false;
        }
        $screen = get_current_screen();
        $show_on_pages = array('dashboard', 'settings_page_cf-zero-trust', 'tools_page_cf-zero-trust-dashboard');
        if (!$screen || !in_array($screen->id, $show_on_pages, true)) {
            return false;
        }

        $progress = CFZT_Plugin::get_setup_progress();
        return $progress['percentage'] < 100;
    }

    /**
     * AJAX handler to dismiss onboarding checklist
     */
    public function ajax_dismiss_onboarding_checklist() {
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['nonce'])), 'cfzt_dismiss_onboarding')) {
            wp_send_json_error(__('Security check failed.', 'zero-trust-login-for-cloudflare'));
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to perform this action.', 'zero-trust-login-for-cloudflare'));
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
        if (!isset($_POST['nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['nonce'])), 'cfzt_test_connection')) {
            wp_send_json_error(__('Security check failed.', 'zero-trust-login-for-cloudflare'));
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to test the connection.', 'zero-trust-login-for-cloudflare'));
        }

        // Get current settings
        $options = CFZT_Plugin::get_option();
        $team_domain = isset($options['team_domain']) ? $options['team_domain'] : '';

        // Validate required fields
        if (empty($team_domain)) {
            wp_send_json_error(array(
                'message' => __('Team Domain is required. Please configure your settings first.', 'zero-trust-login-for-cloudflare'),
                'issues' => array(__('Missing team domain', 'zero-trust-login-for-cloudflare'))
            ));
        }

        $issues = array();
        $warnings = array();

        // Test OIDC connection
        {
            $client_id = isset($options['client_id']) ? $options['client_id'] : '';
            $app_type = isset($options['app_type']) ? $options['app_type'] : 'saas';

            if (empty($client_id)) {
                $issues[] = __('Client ID is not configured', 'zero-trust-login-for-cloudflare');
            }

            // Test discovery endpoint
            $discovery_url = 'https://' . $team_domain . '/.well-known/openid-configuration';
            $response = wp_remote_get($discovery_url, array(
                'timeout' => 10,
                'sslverify' => true
            ));

            if (is_wp_error($response)) {
                $issues[] = sprintf(
                    /* translators: %s: error message */
                    __('Failed to connect to Cloudflare: %s', 'zero-trust-login-for-cloudflare'),
                    $response->get_error_message()
                );
                $issues[] = sprintf(
                    /* translators: %s: URL that was requested */
                    __('Attempted URL: %s', 'zero-trust-login-for-cloudflare'),
                    $discovery_url
                );
            } else {
                $status_code = wp_remote_retrieve_response_code($response);
                $body = wp_remote_retrieve_body($response);

                if ($status_code !== 200) {
                    $issues[] = sprintf(
                        /* translators: %d: HTTP status code */
                        __('Discovery endpoint returned status %d', 'zero-trust-login-for-cloudflare'),
                        $status_code
                    );
                } else {
                    $discovery_data = json_decode($body, true);

                    if (!$discovery_data || !isset($discovery_data['issuer'])) {
                        $issues[] = __('Invalid discovery document received', 'zero-trust-login-for-cloudflare');
                    } else {
                        // Verify issuer contains team domain
                        if (strpos($discovery_data['issuer'], $team_domain) === false) {
                            $warnings[] = sprintf(
                                /* translators: 1: configured team domain, 2: issuer from the discovery document */
                                __('Team domain "%1$s" does not match issuer "%2$s"', 'zero-trust-login-for-cloudflare'),
                                $team_domain,
                                $discovery_data['issuer']
                            );
                        }
                    }
                }
            }

            // Check client secret decrypts to something usable
            if ('' === $this->security->get_client_secret()) {
                $issues[] = __('Client Secret is not configured or cannot be decrypted. Enter it again in the settings.', 'zero-trust-login-for-cloudflare');
            }

        }

        // Check SSL
        if (!is_ssl() && !defined('WP_DEBUG')) {
            $warnings[] = __('Your site is not using HTTPS. This is required for production use.', 'zero-trust-login-for-cloudflare');
        }

        // Check encryption
        if (!$this->security->is_encryption_available()) {
            $warnings[] = __('OpenSSL is not available. Client secrets are stored with basic obfuscation only.', 'zero-trust-login-for-cloudflare');
        }

        // Return results (HTML-escape for XSS prevention)
        if (!empty($issues)) {
            wp_send_json_error(array(
                'message' => __('Connection test failed. Please fix the following issues:', 'zero-trust-login-for-cloudflare'),
                'issues' => array_map('esc_html', $issues),
                'warnings' => array_map('esc_html', $warnings)
            ));
        } elseif (!empty($warnings)) {
            wp_send_json_success(array(
                'message' => __('Connection test passed with warnings:', 'zero-trust-login-for-cloudflare'),
                'warnings' => array_map('esc_html', $warnings)
            ));
        } else {
            wp_send_json_success(array(
                'message' => __('Connection test passed! Your configuration looks good.', 'zero-trust-login-for-cloudflare'),
                'details' => array(
                    __('Team domain is reachable', 'zero-trust-login-for-cloudflare'),
                    __('Discovery endpoint is valid', 'zero-trust-login-for-cloudflare'),
                    __('All required fields are configured', 'zero-trust-login-for-cloudflare')
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
     * Enqueue admin styles and scripts
     *
     * Each plugin screen gets its own stylesheet and script, loaded only on
     * that screen. Strings and nonces reach the scripts through
     * wp_localize_script() so the templates contain no inline JavaScript.
     *
     * @param string $hook Current admin page hook
     */
    public function enqueue_admin_scripts($hook) {
        $version = CFZT_PLUGIN_VERSION;

        // Dismiss handler and styling for the plugin's admin notices, which
        // can appear on screens other than its own.
        if ($this->should_show_saml_removal_notice()
            || $this->should_show_activation_notice()
            || $this->should_show_onboarding_checklist()
        ) {
            wp_enqueue_style('cfzt-notices', CFZT_PLUGIN_URL . 'assets/css/cfzt-notices.css', array(), $version);
            wp_enqueue_script('cfzt-notices', CFZT_PLUGIN_URL . 'assets/js/cfzt-notices.js', array('jquery'), $version, true);
        }

        switch ($hook) {
            case 'users.php':
                // The "Cloudflare" badge in the custom users column
                wp_enqueue_style('cfzt-users', CFZT_PLUGIN_URL . 'assets/css/cfzt-users.css', array(), $version);
                break;

            case 'settings_page_cf-zero-trust':
                wp_enqueue_style('cfzt-admin', CFZT_PLUGIN_URL . 'assets/css/cfzt-admin.css', array(), $version);

                wp_enqueue_script('cfzt-admin', CFZT_PLUGIN_URL . 'assets/js/cfzt-admin.js', array('jquery'), $version, true);
                wp_localize_script('cfzt-admin', 'cfztAdmin', array(
                    'nonce' => wp_create_nonce('cfzt_check_updates'),
                    'checkingText' => __('Checking...', 'zero-trust-login-for-cloudflare'),
                    'errorText' => __('Error checking for updates. Please try again.', 'zero-trust-login-for-cloudflare'),
                    'updateNowText' => __('Update Now', 'zero-trust-login-for-cloudflare'),
                    'showDetailsText' => __('Show Details', 'zero-trust-login-for-cloudflare'),
                    'hideDetailsText' => __('Hide Details', 'zero-trust-login-for-cloudflare')
                ));

                wp_enqueue_script('cfzt-settings', CFZT_PLUGIN_URL . 'assets/js/cfzt-settings.js', array('jquery'), $version, true);
                wp_localize_script('cfzt-settings', 'cfztSettings', $this->settings_script_data());
                break;

            case 'tools_page_cf-zero-trust-dashboard':
                wp_enqueue_style('cfzt-dashboard', CFZT_PLUGIN_URL . 'assets/css/cfzt-dashboard.css', array(), $version);
                wp_enqueue_script('cfzt-dashboard', CFZT_PLUGIN_URL . 'assets/js/cfzt-dashboard.js', array('jquery'), $version, true);
                wp_localize_script('cfzt-dashboard', 'cfztDashboard', array(
                    'nonce' => wp_create_nonce('cfzt_test_connection'),
                    'i18n' => array(
                        'testing' => __('Testing...', 'zero-trust-login-for-cloudflare'),
                        'results' => __('Connection Test Results', 'zero-trust-login-for-cloudflare'),
                        'warnings' => __('Warnings:', 'zero-trust-login-for-cloudflare'),
                        'failed' => __('Connection test failed', 'zero-trust-login-for-cloudflare'),
                        'unexpected' => __('Connection test failed unexpectedly. Please try again.', 'zero-trust-login-for-cloudflare'),
                    ),
                ));
                break;

            case 'tools_page_cf-zero-trust-logs':
                wp_enqueue_style('cfzt-logs', CFZT_PLUGIN_URL . 'assets/css/cfzt-logs.css', array(), $version);
                wp_enqueue_script('cfzt-logs', CFZT_PLUGIN_URL . 'assets/js/cfzt-logs.js', array('jquery'), $version, true);
                wp_localize_script('cfzt-logs', 'cfztLogs', array(
                    'i18n' => array(
                        'failedToLoadLogs' => __('Failed to load logs.', 'zero-trust-login-for-cloudflare'),
                        'noLogsFoundMatchingYour' => __('No logs found matching your filters.', 'zero-trust-login-for-cloudflare'),
                        'success' => __('Success', 'zero-trust-login-for-cloudflare'),
                        'failed' => __('Failed', 'zero-trust-login-for-cloudflare'),
                        'showing' => __('Showing', 'zero-trust-login-for-cloudflare'),
                        'of' => __('of', 'zero-trust-login-for-cloudflare'),
                        'logs' => __('logs', 'zero-trust-login-for-cloudflare'),
                        'page' => __('Page', 'zero-trust-login-for-cloudflare'),
                        'areYouSureYouWant' => __('Are you sure you want to clear all logs? This action cannot be undone.', 'zero-trust-login-for-cloudflare'),
                        'failedToClearLogs' => __('Failed to clear logs.', 'zero-trust-login-for-cloudflare'),
                    ),
                    'nonces' => array(
                        'logsAction' => wp_create_nonce('cfzt_logs_action'),
                    ),
                ));
                break;
        }
    }

    /**
     * Data for the settings page script
     *
     * @return array
     */
    private function settings_script_data(): array {
        $options = CFZT_Plugin::get_option();
        $role_mappings = isset($options['role_mapping']) && is_array($options['role_mapping']) ? $options['role_mapping'] : array();

        return array(
            // The template renders one empty row when nothing is mapped, so
            // new rows must number from 1 in that case.
            'roleMappingCount' => max(1, count($role_mappings)),
            'roles' => wp_roles()->get_names(),
            'i18n' => array(
                'copiedToClipboard' => __('Copied to clipboard!', 'zero-trust-login-for-cloudflare'),
                'copied' => __('Copied!', 'zero-trust-login-for-cloudflare'),
                'failedToCopyPleaseCopy' => __('Failed to copy. Please copy manually.', 'zero-trust-login-for-cloudflare'),
                'switchToAdvancedMode' => __('Switch to Advanced Mode', 'zero-trust-login-for-cloudflare'),
                'switchToWizardMode' => __('Switch to Wizard Mode', 'zero-trust-login-for-cloudflare'),
                'hideRemainingTasks' => __('Hide remaining tasks', 'zero-trust-login-for-cloudflare'),
                'viewRemainingTasks' => __('View remaining tasks', 'zero-trust-login-for-cloudflare'),
                'pleaseEnterYourTeamDomain' => __('Please enter your Team Domain', 'zero-trust-login-for-cloudflare'),
                'pleaseEnterYourClientId' => __('Please enter your Client ID', 'zero-trust-login-for-cloudflare'),
                'pleaseEnterYourClientSecret' => __('Please enter your Client Secret', 'zero-trust-login-for-cloudflare'),
                'newSecretEntered' => __('New secret entered', 'zero-trust-login-for-cloudflare'),
                'keepingSavedSecret' => __('Keeping saved secret', 'zero-trust-login-for-cloudflare'),
                'notSet' => __('Not set', 'zero-trust-login-for-cloudflare'),
                'authenticationMethod' => __('Authentication Method', 'zero-trust-login-for-cloudflare'),
                'teamDomain' => __('Team Domain', 'zero-trust-login-for-cloudflare'),
                'applicationType' => __('Application Type', 'zero-trust-login-for-cloudflare'),
                'clientId' => __('Client ID', 'zero-trust-login-for-cloudflare'),
                'clientSecret' => __('Client Secret', 'zero-trust-login-for-cloudflare'),
                'loginMode' => __('Login Mode', 'zero-trust-login-for-cloudflare'),
                'autoCreateUsers' => __('Auto-create Users', 'zero-trust-login-for-cloudflare'),
                'enabled' => __('Enabled', 'zero-trust-login-for-cloudflare'),
                'disabled' => __('Disabled', 'zero-trust-login-for-cloudflare'),
                'defaultRole' => __('Default Role', 'zero-trust-login-for-cloudflare'),
                'savingConfiguration' => __('Saving configuration...', 'zero-trust-login-for-cloudflare'),
                'tipPressStrongCtrlCmd' => __('Tip: Press <strong>Ctrl/Cmd + S</strong> to save', 'zero-trust-login-for-cloudflare'),
                'testing' => __('Testing...', 'zero-trust-login-for-cloudflare'),
                'warnings' => __('Warnings:', 'zero-trust-login-for-cloudflare'),
                'connectionTestPassed' => __('Connection test passed!', 'zero-trust-login-for-cloudflare'),
                'connectionTestFailed' => __('Connection test failed', 'zero-trust-login-for-cloudflare'),
                'additionalWarnings' => __('Additional warnings:', 'zero-trust-login-for-cloudflare'),
                'anUnexpectedErrorOccurredPlease' => __('An unexpected error occurred. Please try again.', 'zero-trust-login-for-cloudflare'),
                'shouldEndWithCloudflareaccessCom' => __('Should end with .cloudflareaccess.com', 'zero-trust-login-for-cloudflare'),
                'validTeamDomainFormat' => __('Valid team domain format', 'zero-trust-login-for-cloudflare'),
                'clientIdSeemsTooShort' => __('Client ID seems too short', 'zero-trust-login-for-cloudflare'),
                'clientIdUsuallyContainsOnly' => __('Client ID usually contains only hex characters', 'zero-trust-login-for-cloudflare'),
                'validClientIdFormat' => __('Valid client ID format', 'zero-trust-login-for-cloudflare'),
                'valueSetViaConstantCannot' => __('Value set via constant (cannot be changed here)', 'zero-trust-login-for-cloudflare'),
                'clientSecretSeemsTooShort' => __('Client secret seems too short', 'zero-trust-login-for-cloudflare'),
                'clientSecretLooksGood' => __('Client secret looks good', 'zero-trust-login-for-cloudflare'),
                'validUrlFormat' => __('Valid URL format', 'zero-trust-login-for-cloudflare'),
                'pleaseEnterAValidUrl' => __('Please enter a valid URL', 'zero-trust-login-for-cloudflare'),
                'shouldContainOnlyLettersNumbers' => __('Should contain only letters, numbers, hyphens, and underscores', 'zero-trust-login-for-cloudflare'),
                'validFormat' => __('Valid format', 'zero-trust-login-for-cloudflare'),
                'cloudflareGroupName' => __('Cloudflare group name', 'zero-trust-login-for-cloudflare'),
                'pleaseSelectAValidJson' => __('Please select a valid JSON file.', 'zero-trust-login-for-cloudflare'),
                'exporting' => __('Exporting...', 'zero-trust-login-for-cloudflare'),
                'settingsExportedSuccessfully' => __('Settings exported successfully!', 'zero-trust-login-for-cloudflare'),
                'exportSuccessful' => __('Export Successful!', 'zero-trust-login-for-cloudflare'),
                'yourSettingsHaveBeenDownloaded' => __('Your settings have been downloaded as', 'zero-trust-login-for-cloudflare'),
                'exportFailed' => __('Export failed', 'zero-trust-login-for-cloudflare'),
                'exportFailedPleaseTryAgain' => __('Export failed. Please try again.', 'zero-trust-login-for-cloudflare'),
                'pleaseSelectAFileFirst' => __('Please select a file first.', 'zero-trust-login-for-cloudflare'),
                'warningThisWillReplaceYour' => __('Warning: This will replace your current settings. Are you sure you want to continue?', 'zero-trust-login-for-cloudflare'),
                'importing' => __('Importing...', 'zero-trust-login-for-cloudflare'),
                'settingsImportedSuccessfullyReloadingPage' => __('Settings imported successfully! Reloading page...', 'zero-trust-login-for-cloudflare'),
                'importSuccessful' => __('Import Successful!', 'zero-trust-login-for-cloudflare'),
                'thePageWillReloadIn' => __('The page will reload in 2 seconds...', 'zero-trust-login-for-cloudflare'),
                'importFailed' => __('Import failed', 'zero-trust-login-for-cloudflare'),
                'importFailed2' => __('Import Failed', 'zero-trust-login-for-cloudflare'),
                'importFailedPleaseTryAgain' => __('Import failed. Please try again.', 'zero-trust-login-for-cloudflare'),
                'allowedEmailAddresses' => __('Allowed email addresses', 'zero-trust-login-for-cloudflare'),
                'allowedEmailDomains' => __('Allowed email domains', 'zero-trust-login-for-cloudflare'),
                'pasteYourCloudflareApiToken' => __('Paste your Cloudflare API token first.', 'zero-trust-login-for-cloudflare'),
                'connecting' => __('Connecting…', 'zero-trust-login-for-cloudflare'),
                'couldNotConnectToCloudflare' => __('Could not connect to Cloudflare.', 'zero-trust-login-for-cloudflare'),
                'noZeroTrustTeamDomain' => __('no Zero Trust team domain', 'zero-trust-login-for-cloudflare'),
                'noneOfTheAccountsThis' => __('None of the accounts this token can reach have a Zero Trust team domain yet. Set one up in the Cloudflare Zero Trust dashboard, then connect again.', 'zero-trust-login-for-cloudflare'),
                'tokenAcceptedChooseAnAccount' => __('Token accepted. Choose an account and confirm who should be able to log in.', 'zero-trust-login-for-cloudflare'),
                'tokenAcceptedConfirmWhoShould' => __('Token accepted. Confirm who should be able to log in.', 'zero-trust-login-for-cloudflare'),
                'theRequestFailedCheckYour' => __('The request failed. Check your connection and try again.', 'zero-trust-login-for-cloudflare'),
                'creatingApplication' => __('Creating application…', 'zero-trust-login-for-cloudflare'),
                'provisioningFailed' => __('Provisioning failed.', 'zero-trust-login-for-cloudflare'),
                'replaceTheExistingApplication' => __('Replace the existing application', 'zero-trust-login-for-cloudflare'),
                'doneTheAccessApplicationWas' => __('Done. The Access application was created and your credentials are saved.', 'zero-trust-login-for-cloudflare'),
                'continue' => __('Continue', 'zero-trust-login-for-cloudflare'),
                'youCanNowDeleteThe' => __('You can now delete the API token in Cloudflare — it is no longer needed.', 'zero-trust-login-for-cloudflare'),
                'cloudflareApplicationCreated' => __('Cloudflare application created', 'zero-trust-login-for-cloudflare'),
            ),
            'nonces' => array(
                'testConnection' => wp_create_nonce('cfzt_test_connection'),
                'importExport' => wp_create_nonce('cfzt_import_export'),
                'setup' => wp_create_nonce(CFZT_Setup::NONCE_ACTION),
            ),
        );
    }
    
    /**
     * AJAX handler for checking updates
     */
    public function ajax_check_for_updates() {
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['nonce'])), 'cfzt_check_updates')) {
            wp_send_json_error(__('Security check failed.', 'zero-trust-login-for-cloudflare'));
        }
        
        // Check permissions
        if (!current_user_can('update_plugins')) {
            wp_send_json_error(__('You do not have permission to check for updates.', 'zero-trust-login-for-cloudflare'));
        }
        
        // Check if GitHub updater is available
        if (!class_exists('CFZT_GitHub_Updater')) {
            wp_send_json_error(__('Update checker is not available.', 'zero-trust-login-for-cloudflare'));
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
                    /* translators: %s: installed plugin version */
                    __('No updates available. Current version: %s', 'zero-trust-login-for-cloudflare'),
                    CFZT_PLUGIN_VERSION
                )
            ));
        } elseif ($update_info['has_update']) {
            // Update available
            wp_send_json_success(array(
                'hasUpdate' => true,
                'message' => sprintf(
                    /* translators: 1: installed version, 2: available version */
                    __('Update available! Version %1$s → %2$s', 'zero-trust-login-for-cloudflare'),
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
                    /* translators: %s: installed plugin version */
                    __('You have the latest version (%s)', 'zero-trust-login-for-cloudflare'),
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
        if (!isset($_POST['nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['nonce'])), 'cfzt_logs_action')) {
            wp_send_json_error(__('Security check failed.', 'zero-trust-login-for-cloudflare'));
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to view logs.', 'zero-trust-login-for-cloudflare'));
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'cfzt_logs';

        // Get filter parameters
        $level = isset($_POST['level']) ? sanitize_text_field(wp_unslash($_POST['level'])) : '';
        $search = isset($_POST['search']) ? sanitize_text_field(wp_unslash($_POST['search'])) : '';
        $date_from = isset($_POST['date_from']) ? sanitize_text_field(wp_unslash($_POST['date_from'])) : '';
        $date_to = isset($_POST['date_to']) ? sanitize_text_field(wp_unslash($_POST['date_to'])) : '';
        $auth_method = isset($_POST['auth_method']) ? sanitize_text_field(wp_unslash($_POST['auth_method'])) : '';
        $success_filter = isset($_POST['success_filter']) ? sanitize_text_field(wp_unslash($_POST['success_filter'])) : '';
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

        // phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL, WordPress.DB.PreparedSQLPlaceholders, PluginCheck.Security.DirectDB -- plugin's own log table; $where_clause is built above from fixed column comparisons with placeholders, and their values are bound here
        if (!empty($where_values)) {
            $total = (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$table_name} WHERE {$where_clause}", $where_values));
        } else {
            $total = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$table_name} WHERE {$where_clause}");
        }
        $logs = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$table_name} WHERE {$where_clause} ORDER BY log_time DESC LIMIT %d OFFSET %d",
            array_merge($where_values, array($per_page, $offset))
        ));
        // phpcs:enable

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
        if (!isset($_POST['nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['nonce'])), 'cfzt_logs_action')) {
            wp_die(esc_html__('Security check failed.', 'zero-trust-login-for-cloudflare'));
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to export logs.', 'zero-trust-login-for-cloudflare'));
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'cfzt_logs';

        // Get filter parameters
        $level = isset($_POST['level']) ? sanitize_text_field(wp_unslash($_POST['level'])) : '';
        $search = isset($_POST['search']) ? sanitize_text_field(wp_unslash($_POST['search'])) : '';
        $date_from = isset($_POST['date_from']) ? sanitize_text_field(wp_unslash($_POST['date_from'])) : '';
        $date_to = isset($_POST['date_to']) ? sanitize_text_field(wp_unslash($_POST['date_to'])) : '';
        $auth_method = isset($_POST['auth_method']) ? sanitize_text_field(wp_unslash($_POST['auth_method'])) : '';
        $success_filter = isset($_POST['success_filter']) ? sanitize_text_field(wp_unslash($_POST['success_filter'])) : '';

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

        // Get all matching logs.
        // phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL, WordPress.DB.PreparedSQLPlaceholders, PluginCheck.Security.DirectDB -- plugin's own log table; $where_clause is built above from fixed column comparisons with placeholders, and their values are bound here
        if (!empty($where_values)) {
            $logs = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$table_name} WHERE {$where_clause} ORDER BY log_time DESC", $where_values), ARRAY_A);
        } else {
            $logs = $wpdb->get_results("SELECT * FROM {$table_name} WHERE {$where_clause} ORDER BY log_time DESC", ARRAY_A);
        }
        // phpcs:enable

        // Generate CSV
        $filename = 'cfzt-logs-' . gmdate('Y-m-d-His') . '.csv';

        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename=' . $filename);

        $output = fopen('php://output', 'w');

        // Add BOM for Excel UTF-8 support
        fprintf($output, chr(0xEF).chr(0xBB).chr(0xBF));

        // CSV headers
        fputcsv($output, array('Time', 'Level', 'Message', 'Identifier', 'Auth Method', 'Success', 'IP Address', 'User Agent'));

        // CSV data. Message, identifier and user agent are attacker supplied
        // (failed logins), so neutralise anything a spreadsheet would run as
        // a formula.
        foreach ($logs as $log) {
            fputcsv($output, array_map(array($this, 'csv_safe'), array(
                $log['log_time'],
                $log['log_level'],
                $log['message'],
                $log['identifier'],
                $log['auth_method'],
                $log['success'] ? 'Yes' : 'No',
                $log['ip_address'],
                $log['user_agent']
            )));
        }

        fclose($output); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- php://output stream, not a file
        exit;
    }

    /**
     * Prevent a CSV cell from being interpreted as a spreadsheet formula
     *
     * @param mixed $value Cell value.
     * @return string
     */
    private function csv_safe($value): string {
        $value = (string) $value;
        if ('' !== $value && false !== strpos("=+-@\t\r", $value[0])) {
            return "'" . $value;
        }
        return $value;
    }

    /**
     * AJAX handler to clear all logs
     */
    public function ajax_clear_logs() {
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['nonce'])), 'cfzt_logs_action')) {
            wp_send_json_error(__('Security check failed.', 'zero-trust-login-for-cloudflare'));
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to clear logs.', 'zero-trust-login-for-cloudflare'));
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'cfzt_logs';

        // Delete all logs
        $deleted = $wpdb->query("TRUNCATE TABLE {$table_name}"); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- plugin's own log table, name built from $wpdb->prefix

        if ($deleted !== false) {
            CFZT_Logger::info('Authentication logs cleared by admin', array(
                'admin_user' => wp_get_current_user()->user_login
            ));

            wp_send_json_success(__('All logs have been cleared.', 'zero-trust-login-for-cloudflare'));
        } else {
            wp_send_json_error(__('Failed to clear logs.', 'zero-trust-login-for-cloudflare'));
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
                $new_columns['cfzt_status'] = __('CF Zero Trust', 'zero-trust-login-for-cloudflare');
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
        $output .= __('Active', 'zero-trust-login-for-cloudflare');
        $output .= '</span>';

        if ($auth_method) {
            $method_label = strtoupper($auth_method);
            $output .= '<br><small style="color: #666;">' . sprintf(/* translators: %s: authentication method name */ __('Method: %s', 'zero-trust-login-for-cloudflare'), esc_html($method_label)) . '</small>';
        }

        if ($last_login) {
            $last_login_formatted = human_time_diff(strtotime($last_login), current_time('timestamp'));
            $output .= '<br><small style="color: #999;">' . sprintf(/* translators: %s: human-readable time span, e.g. "3 hours" */ __('Last login: %s ago', 'zero-trust-login-for-cloudflare'), esc_html($last_login_formatted)) . '</small>';
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
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one COUNT over usermeta for the list-table view link
        $count = $wpdb->get_var(
            "SELECT COUNT(DISTINCT user_id)
             FROM {$wpdb->usermeta}
             WHERE meta_key = 'cfzt_user'
             AND meta_value = '1'"
        );

        if ($count > 0) {
            $class = '';
            if (isset($_GET['cfzt_users']) && '1' === sanitize_key(wp_unslash($_GET['cfzt_users']))) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only view filter on the users list
                $class = 'current';
            }

            $url = add_query_arg('cfzt_users', '1', admin_url('users.php'));
            $views['cfzt_users'] = sprintf(
                '<a href="%s" class="%s">%s <span class="count">(%d)</span></a>',
                esc_url($url),
                $class,
                __('CF Zero Trust Users', 'zero-trust-login-for-cloudflare'),
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

        if (isset($_GET['cfzt_users']) && '1' === sanitize_key(wp_unslash($_GET['cfzt_users']))) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only view filter on the users list
            $query->set('meta_key', 'cfzt_user');
            $query->set('meta_value', '1');
        }
    }

    /**
     * AJAX handler to export settings
     */
    public function ajax_export_settings() {
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['nonce'])), 'cfzt_import_export')) {
            wp_send_json_error(__('Security check failed.', 'zero-trust-login-for-cloudflare'));
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to export settings.', 'zero-trust-login-for-cloudflare'));
        }

        // Get current settings
        $options = CFZT_Plugin::get_option();

        // The client secret never leaves the site in a download: the encrypted
        // form is bound to this site's salts and the plaintext form would turn
        // a settings backup into a credential. Enter it again after importing.
        // Provenance refers to one Cloudflare account and app, so it stays too.
        unset(
            $options['client_secret'],
            $options['client_secret_is_constant'],
            $options['provisioned_account_id'],
            $options['provisioned_app_id'],
            $options['provisioned_at']
        );

        // Add metadata
        $export_data = array(
            'version' => CFZT_PLUGIN_VERSION,
            'exported_at' => current_time('mysql'),
            'site_url' => home_url(),
            'secret_included' => false,
            'settings' => $options
        );

        // Return JSON
        wp_send_json_success(array(
            'data' => $export_data,
            'filename' => 'cfzt-settings-' . gmdate('Y-m-d-His') . '.json'
        ));
    }

    /**
     * AJAX handler to import settings
     */
    public function ajax_import_settings() {
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['nonce'])), 'cfzt_import_export')) {
            wp_send_json_error(__('Security check failed.', 'zero-trust-login-for-cloudflare'));
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('You do not have permission to import settings.', 'zero-trust-login-for-cloudflare'));
        }

        // Get import data
        if (empty($_POST['import_data'])) {
            wp_send_json_error(__('No import data provided.', 'zero-trust-login-for-cloudflare'));
        }

        // Decode JSON
        $import_data = json_decode(wp_unslash($_POST['import_data']), true); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- JSON document: decoded, structure-checked and every field sanitized below

        if (json_last_error() !== JSON_ERROR_NONE) {
            wp_send_json_error(__('Invalid JSON format.', 'zero-trust-login-for-cloudflare'));
        }

        // Validate structure
        if (!isset($import_data['settings']) || !is_array($import_data['settings'])) {
            wp_send_json_error(__('Invalid import file structure.', 'zero-trust-login-for-cloudflare'));
        }

        $settings = $import_data['settings'];

        // Validate required fields
        $required_fields = array('auth_method', 'team_domain');
        foreach ($required_fields as $field) {
            if (!isset($settings[$field])) {
                /* translators: %s: settings field name */
                wp_send_json_error(sprintf(__('Missing required field: %s', 'zero-trust-login-for-cloudflare'), $field));
            }
        }

        $existing = get_option('cfzt_settings', array());
        $existing = is_array($existing) ? $existing : array();

        $sanitized = array();

        // General settings
        $sanitized['auth_method'] = CFZT_Plugin::AUTH_METHOD_OIDC;
        $sanitized['team_domain'] = $this->sanitize_team_domain((string) $settings['team_domain']);
        $sanitized['login_mode'] = $this->sanitize_enum(isset($settings['login_mode']) ? (string) $settings['login_mode'] : '', self::ALLOWED_LOGIN_MODES, CFZT_Plugin::LOGIN_MODE_SECONDARY);
        $sanitized['auto_create_users'] = $this->sanitize_enum(isset($settings['auto_create_users']) ? (string) $settings['auto_create_users'] : '', self::ALLOWED_YES_NO, CFZT_Plugin::OPTION_YES);
        $sanitized['enable_logging'] = $this->sanitize_enum(isset($settings['enable_logging']) ? (string) $settings['enable_logging'] : '', self::ALLOWED_YES_NO, CFZT_Plugin::OPTION_NO);

        $default_role = isset($settings['default_role']) ? sanitize_key((string) $settings['default_role']) : '';
        $sanitized['default_role'] = get_role($default_role) ? $default_role : CFZT_Plugin::DEFAULT_ROLE;

        // OIDC settings
        $sanitized['app_type'] = $this->sanitize_enum(isset($settings['app_type']) ? (string) $settings['app_type'] : '', self::ALLOWED_APP_TYPES, CFZT_Plugin::APP_TYPE_SAAS);
        $sanitized['client_id'] = isset($settings['client_id']) ? sanitize_text_field((string) $settings['client_id']) : '';

        // Client secret. Exports made by 2.0.0+ do not contain one; older
        // exports carry it in plaintext. Encrypt once here and write with the
        // sanitizer bypassed, so it is never encrypted a second time.
        $secret_restored = false;
        if (!empty($settings['client_secret']) && is_string($settings['client_secret'])) {
            $sanitized['client_secret'] = $this->security->encrypt_data(sanitize_text_field($settings['client_secret']));
            $secret_restored = true;
        } else {
            $sanitized['client_secret'] = isset($existing['client_secret']) ? (string) $existing['client_secret'] : '';
        }

        // Role mapping (with proper sanitization)
        $sanitized['role_mapping'] = isset($settings['role_mapping']) && is_array($settings['role_mapping'])
            ? $this->sanitize_role_mapping($settings['role_mapping'])
            : array();

        // Email domain restrictions
        $sanitized['email_domain_restrictions'] = isset($settings['email_domain_restrictions'])
            ? sanitize_textarea_field((string) $settings['email_domain_restrictions'])
            : '';

        // Custom redirect URLs
        foreach (array('redirect_after_login', 'redirect_after_logout') as $url_key) {
            $sanitized[$url_key] = isset($settings[$url_key]) ? esc_url_raw((string) $settings[$url_key]) : '';
        }

        // Provenance belongs to this site's Cloudflare app, not the import.
        foreach (array('provisioned_account_id', 'provisioned_app_id', 'provisioned_at') as $provenance_key) {
            if (isset($existing[$provenance_key])) {
                $sanitized[$provenance_key] = $existing[$provenance_key];
            }
        }

        // Save settings (bypassing the form sanitizer, see CFZT_Plugin::save_settings)
        CFZT_Plugin::save_settings($sanitized);

        // Log the import
        CFZT_Logger::info('Settings imported', array(
            'admin_user' => wp_get_current_user()->user_login,
            'from_version' => isset($import_data['version']) && is_scalar($import_data['version']) ? sanitize_text_field((string) $import_data['version']) : 'unknown',
            'from_site' => isset($import_data['site_url']) && is_scalar($import_data['site_url']) ? esc_url_raw((string) $import_data['site_url']) : 'unknown'
        ));

        if (!$secret_restored && '' === $sanitized['client_secret']) {
            wp_send_json_success(__('Settings imported. This export did not include a client secret, so enter it in the OIDC settings before testing login.', 'zero-trust-login-for-cloudflare'));
        }

        wp_send_json_success(__('Settings imported successfully!', 'zero-trust-login-for-cloudflare'));
    }
}