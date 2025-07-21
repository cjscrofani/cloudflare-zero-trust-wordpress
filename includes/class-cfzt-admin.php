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
        add_filter('pre_update_option_cfzt_settings', array($this, 'protect_constants'), 10, 2);
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
        add_action('wp_ajax_cfzt_check_for_updates', array($this, 'ajax_check_for_updates'));
    }
    
    /**
     * Add admin menu
     */
    public function add_admin_menu() {
        add_options_page(
            __('Cloudflare Zero Trust Settings', 'cf-zero-trust'),
            __('CF Zero Trust', 'cf-zero-trust'),
            'manage_options',
            'cf-zero-trust',
            array($this, 'settings_page')
        );
    }
    
    /**
     * Register settings
     */
    public function register_settings() {
        register_setting('cfzt_settings_group', 'cfzt_settings', array($this, 'sanitize_settings'));
        
        add_settings_section(
            'cfzt_main_section',
            __('Cloudflare Zero Trust Configuration', 'cf-zero-trust'),
            array($this, 'section_callback'),
            'cf-zero-trust'
        );
        
        // Add settings fields
        $fields = array(
            'auth_method' => __('Authentication Method', 'cf-zero-trust'),
            'app_type' => __('Application Type', 'cf-zero-trust'),
            'team_domain' => __('Team Domain', 'cf-zero-trust'),
            'client_id' => __('Client ID', 'cf-zero-trust'),
            'client_secret' => __('Client Secret', 'cf-zero-trust'),
            'login_mode' => __('Login Mode', 'cf-zero-trust'),
            'auto_create_users' => __('Auto-create Users', 'cf-zero-trust'),
            'default_role' => __('Default User Role', 'cf-zero-trust'),
            'enable_logging' => __('Enable Authentication Logging', 'cf-zero-trust')
        );
        
        foreach ($fields as $field => $label) {
            add_settings_field(
                'cfzt_' . $field,
                $label,
                array($this, 'field_callback'),
                'cf-zero-trust',
                'cfzt_main_section',
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
        $sanitized = array();
        
        $sanitized['auth_method'] = sanitize_text_field($input['auth_method']);
        $sanitized['app_type'] = sanitize_text_field($input['app_type']);
        $sanitized['team_domain'] = sanitize_text_field($input['team_domain']);
        $sanitized['client_id'] = sanitize_text_field($input['client_id']);
        
        // Encrypt sensitive data
        $sanitized['client_secret'] = $this->security->encrypt_data(sanitize_text_field($input['client_secret']));
        
        $sanitized['login_mode'] = sanitize_text_field($input['login_mode']);
        $sanitized['auto_create_users'] = sanitize_text_field($input['auto_create_users']);
        $sanitized['default_role'] = sanitize_text_field($input['default_role']);
        $sanitized['enable_logging'] = sanitize_text_field($input['enable_logging']);
        
        return $sanitized;
    }
    
    /**
     * Section callback
     */
    public function section_callback() {
        echo '<p>' . __('Configure your Cloudflare Zero Trust integration settings below.', 'cf-zero-trust') . '</p>';
        
        // Show plugin version and update status
        echo '<p><strong>' . __('Plugin Version:', 'cf-zero-trust') . '</strong> ' . CFZT_PLUGIN_VERSION;
        
        // Check if update is available
        $update_data = get_site_transient('update_plugins');
        if (isset($update_data->response[CFZT_PLUGIN_BASENAME])) {
            echo ' <span style="color: #d63638;">— ' . 
                 sprintf(__('Update available (v%s)', 'cf-zero-trust'), $update_data->response[CFZT_PLUGIN_BASENAME]->new_version) . 
                 '</span>';
        }
        
        echo '</p>';
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
        }
    }
    
    /**
     * Render auth method field
     */
    private function render_auth_method_field($value) {
        ?>
        <select name="cfzt_settings[auth_method]">
            <option value="oauth2" <?php selected($value, 'oauth2'); ?>><?php _e('OIDC (OpenID Connect)', 'cf-zero-trust'); ?></option>
            <option value="saml" <?php selected($value, 'saml'); ?>><?php _e('SAML (Coming Soon)', 'cf-zero-trust'); ?></option>
        </select>
        <p class="description"><?php _e('OIDC (OpenID Connect) is the authentication protocol used by Cloudflare Zero Trust.', 'cf-zero-trust'); ?></p>
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
     * Settings page
     */
    public function settings_page() {
        require_once CFZT_PLUGIN_DIR . 'templates/admin-page.php';
    }
    
    /**
     * Admin notices
     */
    public function admin_notices() {
        $screen = get_current_screen();
        if ($screen && $screen->id === 'settings_page_cf-zero-trust') {
            if (!$this->security->is_encryption_available()) {
                ?>
                <div class="notice notice-warning">
                    <p><?php _e('OpenSSL is not available on your server. Client secrets will be stored with basic obfuscation instead of strong encryption. Consider enabling OpenSSL for better security.', 'cf-zero-trust'); ?></p>
                </div>
                <?php
            }
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
        
        // Add inline CSS for update check status
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
}