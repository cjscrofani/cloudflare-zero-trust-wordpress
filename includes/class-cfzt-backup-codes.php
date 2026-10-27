<?php
/**
 * Backup codes manager for Cloudflare Zero Trust
 *
 * Provides emergency access codes for users who lose access to their Cloudflare account.
 *
 * @package CloudflareZeroTrustLogin
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class CFZT_Backup_Codes {

    /**
     * Number of backup codes to generate
     */
    const CODE_COUNT = 10;

    /**
     * Length of each backup code
     */
    const CODE_LENGTH = 8;

    /**
     * User meta key for storing backup codes
     */
    const META_KEY = 'cfzt_backup_codes';

    /**
     * Security instance
     * @var CFZT_Security
     */
    private $security;

    /**
     * Initialize hooks
     */
    public function __construct() {
        $this->security = new CFZT_Security();

        add_action('wp_ajax_cfzt_generate_backup_codes', array($this, 'ajax_generate_backup_codes'));
        add_filter('authenticate', array($this, 'authenticate_with_backup_code'), 40, 3);
        add_action('show_user_profile', array($this, 'display_user_profile_section'));
        add_action('edit_user_profile', array($this, 'display_user_profile_section'));
        add_action('login_form', array($this, 'display_backup_code_link'));
    }

    /**
     * Generate backup codes for a user
     *
     * @param int $user_id User ID
     * @return array Array of plain text backup codes
     */
    public static function generate_codes($user_id) {
        $codes = array();
        $hashed_codes = array();

        // Generate random codes
        for ($i = 0; $i < self::CODE_COUNT; $i++) {
            $code = self::generate_random_code();
            $codes[] = $code;

            // Store hashed version
            $hashed_codes[] = array(
                'hash' => wp_hash_password($code),
                'used' => false,
                'created' => current_time('mysql')
            );
        }

        // Store hashed codes in user meta
        update_user_meta($user_id, self::META_KEY, $hashed_codes);

        // Log generation
        CFZT_Logger::info('Backup codes generated', array(
            'user_id' => $user_id,
            'admin_user' => wp_get_current_user()->user_login,
            'count' => self::CODE_COUNT
        ));

        return $codes;
    }

    /**
     * Generate a random backup code
     *
     * @return string Random code in format XXXX-XXXX
     */
    private static function generate_random_code() {
        $characters = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Exclude similar characters
        $code = '';

        for ($i = 0; $i < self::CODE_LENGTH; $i++) {
            $code .= $characters[random_int(0, strlen($characters) - 1)];

            // Add hyphen after 4 characters
            if ($i === 3) {
                $code .= '-';
            }
        }

        return $code;
    }

    /**
     * Get remaining backup codes count for a user
     *
     * @param int $user_id User ID
     * @return int Number of unused codes
     */
    public static function get_remaining_count($user_id) {
        $codes = get_user_meta($user_id, self::META_KEY, true);

        if (!$codes || !is_array($codes)) {
            return 0;
        }

        $unused = array_filter($codes, function($code) {
            return is_array($code) && isset($code['used']) && !$code['used'];
        });

        return count($unused);
    }

    /**
     * Verify and consume a backup code
     *
     * @param int $user_id User ID
     * @param string $code Code to verify
     * @return bool True if code is valid and consumed
     */
    public static function verify_and_consume($user_id, $code) {
        $codes = get_user_meta($user_id, self::META_KEY, true);

        if (!$codes || !is_array($codes)) {
            return false;
        }

        // Normalize code (remove spaces, uppercase)
        $code = strtoupper(str_replace(' ', '', $code));

        // Check each code
        foreach ($codes as $index => $stored_code) {
            if ($stored_code['used']) {
                continue;
            }

            // Verify password hash
            if (wp_check_password($code, $stored_code['hash'])) {
                // Mark as used
                $codes[$index]['used'] = true;
                $codes[$index]['used_at'] = current_time('mysql');
                update_user_meta($user_id, self::META_KEY, $codes);

                CFZT_Logger::info('Backup code used', array(
                    'user_id' => $user_id,
                    'remaining' => self::get_remaining_count($user_id)
                ));

                return true;
            }
        }

        return false;
    }

    /**
     * Clear all backup codes for a user
     *
     * @param int $user_id User ID
     */
    public static function clear_codes($user_id) {
        delete_user_meta($user_id, self::META_KEY);

        CFZT_Logger::info('Backup codes cleared', array(
            'user_id' => $user_id,
            'admin_user' => wp_get_current_user()->user_login
        ));
    }

    /**
     * AJAX handler for generating backup codes
     */
    public function ajax_generate_backup_codes() {
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['nonce'])), 'cfzt_backup_codes')) {
            wp_send_json_error(__('Security check failed.', 'zero-trust-login-for-cloudflare'));
        }

        $user_id = isset($_POST['user_id']) ? intval($_POST['user_id']) : 0;

        if (!$user_id || !get_user_by('id', $user_id)) {
            wp_send_json_error(__('Invalid user ID.', 'zero-trust-login-for-cloudflare'));
        }

        // The meta capability, not the primitive: a role that may edit *some*
        // users must not be able to mint a login for an administrator.
        if (!current_user_can('edit_user', $user_id)) {
            wp_send_json_error(__('You do not have permission to generate backup codes for this user.', 'zero-trust-login-for-cloudflare'));
        }

        if (!CFZT_User_Helper::is_cfzt_user($user_id)) {
            wp_send_json_error(__('Backup codes are only available for Cloudflare Zero Trust users.', 'zero-trust-login-for-cloudflare'));
        }

        // Generate codes
        $codes = self::generate_codes($user_id);

        wp_send_json_success(array(
            'codes' => $codes,
            'count' => count($codes)
        ));
    }

    /**
     * Authenticate user with backup code
     *
     * @param WP_User|WP_Error|null $user
     * @param string $username
     * @param string $password
     * @return WP_User|WP_Error|null
     */
    public function authenticate_with_backup_code($user, $username, $password) {
        // Only process if a backup code was actually submitted. The field is
        // always present in the login form (hidden until "Use a backup code" is
        // clicked), so an isset() check here would hijack every ordinary
        // password login and reject it with "enter both username and backup code".
        if (empty($_POST['cfzt_backup_code']) || '' === trim(sanitize_text_field(wp_unslash($_POST['cfzt_backup_code'])))) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- wp-login.php form submission; the core login form carries no nonce
            return $user;
        }

        // Prevent programmatic access
        if (defined('DOING_AJAX') || defined('DOING_CRON') || defined('WP_CLI')) {
            return $user;
        }

        // Rate limiting check to prevent brute force attacks
        if ($this->security->is_rate_limited()) {
            CFZT_Logger::warning('Rate limit exceeded for backup code authentication', array(
                'ip' => $this->security->get_client_ip()
            ));
            return new WP_Error(
                'rate_limit_exceeded',
                __('Too many backup code attempts. Please try again in 5 minutes.', 'zero-trust-login-for-cloudflare')
            );
        }

        $backup_code = sanitize_text_field(wp_unslash($_POST['cfzt_backup_code'])); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- wp-login.php form submission; the core login form carries no nonce
        $username = isset($_POST['log']) ? sanitize_text_field(wp_unslash($_POST['log'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- as above

        if (empty($backup_code) || empty($username)) {
            return new WP_Error('empty_backup_code', __('Please enter both username and backup code.', 'zero-trust-login-for-cloudflare'));
        }

        // Get user by username or email
        $user = get_user_by('login', $username);
        if (!$user) {
            $user = get_user_by('email', $username);
        }

        if (!$user) {
            $this->security->record_failed_attempt();
            CFZT_Logger::warning('Backup code authentication failed - user not found', array(
                'username' => CFZT_Logger::sanitize_identifier($username)
            ));
            return new WP_Error('invalid_backup_code', __('Invalid username or backup code.', 'zero-trust-login-for-cloudflare'));
        }

        // Verify the user is a CFZT user
        if (!CFZT_User_Helper::is_cfzt_user($user)) {
            $this->security->record_failed_attempt();
            return new WP_Error('invalid_backup_code', __('Backup codes are only available for Cloudflare Zero Trust users.', 'zero-trust-login-for-cloudflare'));
        }

        // Verify and consume the code
        if (self::verify_and_consume($user->ID, $backup_code)) {
            // Update last login
            CFZT_User_Helper::update_last_login($user->ID, 'backup_code');

            CFZT_Logger::info('User authenticated with backup code', array(
                'user_id' => $user->ID,
                'username' => $username,
                'remaining_codes' => self::get_remaining_count($user->ID)
            ));

            return $user;
        }

        $this->security->record_failed_attempt();
        CFZT_Logger::warning('Invalid backup code attempted', array(
            'user_id' => $user->ID,
            'username' => CFZT_Logger::sanitize_identifier($username)
        ));
        return new WP_Error('invalid_backup_code', __('Invalid or already used backup code.', 'zero-trust-login-for-cloudflare'));
    }

    /**
     * Display backup codes section on user profile
     *
     * @param WP_User $user User object
     */
    public function display_user_profile_section($user) {
        // Only show for CFZT users
        if (!CFZT_User_Helper::is_cfzt_user($user)) {
            return;
        }

        // Check permissions
        if (!current_user_can('edit_user', $user->ID)) {
            return;
        }

        $remaining_count = self::get_remaining_count($user->ID);

        // Enqueued from the render hook (rather than admin_enqueue_scripts) so
        // the script only loads on profiles that actually show this section.
        // It goes in the footer, which is still ahead of us at this point.
        wp_enqueue_script(
            'cfzt-backup-codes',
            CFZT_PLUGIN_URL . 'assets/js/cfzt-backup-codes.js',
            array('jquery'),
            CFZT_PLUGIN_VERSION,
            true
        );
        wp_localize_script('cfzt-backup-codes', 'cfztBackupCodes', array(
            'userLogin' => $user->user_login,
            'nonces' => array(
                'backupCodes' => wp_create_nonce('cfzt_backup_codes'),
            ),
            'i18n' => array(
                'generatingNewBackupCodesWill' => __('Generating new backup codes will invalidate any existing codes. Continue?', 'zero-trust-login-for-cloudflare'),
                'generating' => __('Generating...', 'zero-trust-login-for-cloudflare'),
                'generateNewBackupCodes' => __('Generate New Backup Codes', 'zero-trust-login-for-cloudflare'),
                'error' => __('Error: ', 'zero-trust-login-for-cloudflare'),
                'copied' => __('Copied!', 'zero-trust-login-for-cloudflare'),
                'copyAllCodes' => __('Copy All Codes', 'zero-trust-login-for-cloudflare'),
                'backupCodes' => __('Backup Codes', 'zero-trust-login-for-cloudflare'),
                'cloudflareZeroTrustBackupCodes' => __('Cloudflare Zero Trust Backup Codes', 'zero-trust-login-for-cloudflare'),
                'user' => __('User:', 'zero-trust-login-for-cloudflare'),
                'generated' => __('Generated:', 'zero-trust-login-for-cloudflare'),
            ),
        ));
        ?>
        <h2><?php esc_html_e('Cloudflare Zero Trust Backup Codes', 'zero-trust-login-for-cloudflare'); ?></h2>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php esc_html_e('Emergency Access', 'zero-trust-login-for-cloudflare'); ?></th>
                <td>
                    <p class="description">
                        <?php esc_html_e('Backup codes provide emergency access if you lose access to your Cloudflare account. Each code can only be used once.', 'zero-trust-login-for-cloudflare'); ?>
                    </p>

                    <?php if ($remaining_count > 0): ?>
                        <p>
                            <strong><?php /* translators: %d: number of unused backup codes */ echo esc_html(sprintf(_n('%d backup code remaining', '%d backup codes remaining', $remaining_count, 'zero-trust-login-for-cloudflare'), $remaining_count)); ?></strong>
                        </p>
                    <?php else: ?>
                        <p style="color: #d63638;">
                            <strong><?php esc_html_e('No backup codes available', 'zero-trust-login-for-cloudflare'); ?></strong>
                        </p>
                    <?php endif; ?>

                    <button type="button" id="cfzt-generate-backup-codes" class="button" data-user-id="<?php echo esc_attr($user->ID); ?>">
                        <?php esc_html_e('Generate New Backup Codes', 'zero-trust-login-for-cloudflare'); ?>
                    </button>

                    <div id="cfzt-backup-codes-display" style="display: none; margin-top: 15px; padding: 15px; background: #f0f6fc; border: 1px solid #c3e6fc; border-radius: 4px;">
                        <p style="margin-top: 0;">
                            <strong><?php esc_html_e('Save these codes in a secure location. They will not be shown again.', 'zero-trust-login-for-cloudflare'); ?></strong>
                        </p>
                        <div id="cfzt-backup-codes-list" style="font-family: monospace; font-size: 14px; columns: 2; column-gap: 20px;">
                        </div>
                        <button type="button" id="cfzt-copy-backup-codes" class="button" style="margin-top: 10px;">
                            <span class="dashicons dashicons-clipboard" style="vertical-align: middle;"></span>
                            <?php esc_html_e('Copy All Codes', 'zero-trust-login-for-cloudflare'); ?>
                        </button>
                        <button type="button" id="cfzt-print-backup-codes" class="button" style="margin-top: 10px;">
                            <span class="dashicons dashicons-media-default" style="vertical-align: middle;"></span>
                            <?php esc_html_e('Print Codes', 'zero-trust-login-for-cloudflare'); ?>
                        </button>
                    </div>
                </td>
            </tr>
        </table>

        <?php
    }

    /**
     * Display backup code login link on login form
     */
    public function display_backup_code_link() {
        // Only accounts this plugin created can hold backup codes, so there is
        // nothing to offer until Cloudflare login exists.
        if (!CFZT_Auth::is_configured()) {
            return;
        }

        // Enqueued alongside the markup so the script is only loaded where the
        // toggle is rendered (wp-login.php, including the interim login).
        $this->enqueue_login_assets();
        ?>
        <p class="cfzt-backup-code-toggle" style="text-align: center; margin-top: 10px;">
            <a href="#" id="cfzt-use-backup-code" style="font-size: 13px;">
                <?php esc_html_e('Use a backup code', 'zero-trust-login-for-cloudflare'); ?>
            </a>
        </p>

        <div id="cfzt-backup-code-form" style="display: none; margin-top: 10px;">
            <p style="margin-bottom: 10px;">
                <label for="cfzt_backup_code"><?php esc_html_e('Backup Code', 'zero-trust-login-for-cloudflare'); ?></label>
                <input type="text" name="cfzt_backup_code" id="cfzt_backup_code" class="input" value="" size="20" autocomplete="off" placeholder="XXXX-XXXX" />
            </p>
            <p style="font-size: 13px; color: #50575e;">
                <?php esc_html_e('Enter one of your backup codes. Each code can only be used once.', 'zero-trust-login-for-cloudflare'); ?>
            </p>
        </div>
        <?php
    }

    /**
     * Enqueue the backup-code toggle script
     *
     * Called from display_backup_code_link() after its guard, so it only
     * loads where the toggle is rendered. The footer has not printed yet at
     * that point on wp-login.php or on a normal front-end page.
     */
    private function enqueue_login_assets() {
        wp_enqueue_script(
            'cfzt-login',
            CFZT_PLUGIN_URL . 'assets/js/cfzt-login.js',
            array(),
            CFZT_PLUGIN_VERSION,
            true
        );
        wp_localize_script('cfzt-login', 'cfztLoginBackup', array(
            // In primary mode the password form is hidden; the script moves
            // the toggle next to the Cloudflare button and reveals the form
            // (minus the password field) on demand.
            'primary' => CFZT_Auth::is_primary_mode() ? '1' : '',
            'i18n' => array(
                'useRegularLogin' => __('Use regular login', 'zero-trust-login-for-cloudflare'),
                'useABackupCode' => __('Use a backup code', 'zero-trust-login-for-cloudflare'),
            ),
        ));
    }
}
