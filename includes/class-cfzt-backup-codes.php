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
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'cfzt_backup_codes')) {
            wp_send_json_error(__('Security check failed.', 'cf-zero-trust'));
        }

        $user_id = isset($_POST['user_id']) ? intval($_POST['user_id']) : 0;

        if (!$user_id || !get_user_by('id', $user_id)) {
            wp_send_json_error(__('Invalid user ID.', 'cf-zero-trust'));
        }

        // The meta capability, not the primitive: a role that may edit *some*
        // users must not be able to mint a login for an administrator.
        if (!current_user_can('edit_user', $user_id)) {
            wp_send_json_error(__('You do not have permission to generate backup codes for this user.', 'cf-zero-trust'));
        }

        if (!CFZT_User_Helper::is_cfzt_user($user_id)) {
            wp_send_json_error(__('Backup codes are only available for Cloudflare Zero Trust users.', 'cf-zero-trust'));
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
        if (empty($_POST['cfzt_backup_code']) || '' === trim((string) $_POST['cfzt_backup_code'])) {
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
                __('Too many backup code attempts. Please try again in 5 minutes.', 'cf-zero-trust')
            );
        }

        $backup_code = sanitize_text_field(wp_unslash($_POST['cfzt_backup_code']));
        $username = isset($_POST['log']) ? sanitize_text_field(wp_unslash($_POST['log'])) : '';

        if (empty($backup_code) || empty($username)) {
            return new WP_Error('empty_backup_code', __('Please enter both username and backup code.', 'cf-zero-trust'));
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
            return new WP_Error('invalid_backup_code', __('Invalid username or backup code.', 'cf-zero-trust'));
        }

        // Verify the user is a CFZT user
        if (!CFZT_User_Helper::is_cfzt_user($user)) {
            $this->security->record_failed_attempt();
            return new WP_Error('invalid_backup_code', __('Backup codes are only available for Cloudflare Zero Trust users.', 'cf-zero-trust'));
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
        return new WP_Error('invalid_backup_code', __('Invalid or already used backup code.', 'cf-zero-trust'));
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
        ?>
        <h2><?php _e('Cloudflare Zero Trust Backup Codes', 'cf-zero-trust'); ?></h2>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php _e('Emergency Access', 'cf-zero-trust'); ?></th>
                <td>
                    <p class="description">
                        <?php _e('Backup codes provide emergency access if you lose access to your Cloudflare account. Each code can only be used once.', 'cf-zero-trust'); ?>
                    </p>

                    <?php if ($remaining_count > 0): ?>
                        <p>
                            <strong><?php echo sprintf(_n('%d backup code remaining', '%d backup codes remaining', $remaining_count, 'cf-zero-trust'), $remaining_count); ?></strong>
                        </p>
                    <?php else: ?>
                        <p style="color: #d63638;">
                            <strong><?php _e('No backup codes available', 'cf-zero-trust'); ?></strong>
                        </p>
                    <?php endif; ?>

                    <button type="button" id="cfzt-generate-backup-codes" class="button" data-user-id="<?php echo esc_attr($user->ID); ?>">
                        <?php _e('Generate New Backup Codes', 'cf-zero-trust'); ?>
                    </button>

                    <div id="cfzt-backup-codes-display" style="display: none; margin-top: 15px; padding: 15px; background: #f0f6fc; border: 1px solid #c3e6fc; border-radius: 4px;">
                        <p style="margin-top: 0;">
                            <strong><?php _e('Save these codes in a secure location. They will not be shown again.', 'cf-zero-trust'); ?></strong>
                        </p>
                        <div id="cfzt-backup-codes-list" style="font-family: monospace; font-size: 14px; columns: 2; column-gap: 20px;">
                        </div>
                        <button type="button" id="cfzt-copy-backup-codes" class="button" style="margin-top: 10px;">
                            <span class="dashicons dashicons-clipboard" style="vertical-align: middle;"></span>
                            <?php _e('Copy All Codes', 'cf-zero-trust'); ?>
                        </button>
                        <button type="button" id="cfzt-print-backup-codes" class="button" style="margin-top: 10px;">
                            <span class="dashicons dashicons-media-default" style="vertical-align: middle;"></span>
                            <?php _e('Print Codes', 'cf-zero-trust'); ?>
                        </button>
                    </div>
                </td>
            </tr>
        </table>

        <script>
        jQuery(document).ready(function($) {
            $('#cfzt-generate-backup-codes').on('click', function() {
                if (!confirm('<?php _e('Generating new backup codes will invalidate any existing codes. Continue?', 'cf-zero-trust'); ?>')) {
                    return;
                }

                var $button = $(this);
                $button.prop('disabled', true).text('<?php _e('Generating...', 'cf-zero-trust'); ?>');

                $.post(ajaxurl, {
                    action: 'cfzt_generate_backup_codes',
                    nonce: '<?php echo wp_create_nonce('cfzt_backup_codes'); ?>',
                    user_id: $button.data('user-id')
                }, function(response) {
                    if (response.success) {
                        var codes = response.data.codes;
                        var $list = $('#cfzt-backup-codes-list');
                        $list.empty();

                        codes.forEach(function(code) {
                            $list.append('<div style="margin: 5px 0;">' + code + '</div>');
                        });

                        $('#cfzt-backup-codes-display').slideDown();
                        $button.text('<?php _e('Generate New Backup Codes', 'cf-zero-trust'); ?>').prop('disabled', false);
                    } else {
                        alert('<?php _e('Error: ', 'cf-zero-trust'); ?>' + response.data);
                        $button.prop('disabled', false).text('<?php _e('Generate New Backup Codes', 'cf-zero-trust'); ?>');
                    }
                });
            });

            $('#cfzt-copy-backup-codes').on('click', function() {
                var codes = [];
                $('#cfzt-backup-codes-list div').each(function() {
                    codes.push($(this).text());
                });

                var text = codes.join('\n');
                navigator.clipboard.writeText(text).then(function() {
                    var $button = $('#cfzt-copy-backup-codes');
                    $button.text('<?php _e('Copied!', 'cf-zero-trust'); ?>');
                    setTimeout(function() {
                        $button.html('<span class="dashicons dashicons-clipboard" style="vertical-align: middle;"></span> <?php _e('Copy All Codes', 'cf-zero-trust'); ?>');
                    }, 2000);
                });
            });

            $('#cfzt-print-backup-codes').on('click', function() {
                var codes = [];
                $('#cfzt-backup-codes-list div').each(function() {
                    codes.push($(this).text());
                });

                var printWindow = window.open('', '', 'width=600,height=400');
                printWindow.document.write('<html><head><title><?php _e('Backup Codes', 'cf-zero-trust'); ?></title>');
                printWindow.document.write('<style>body { font-family: Arial, sans-serif; padding: 20px; } h1 { font-size: 18px; } code { display: block; margin: 10px 0; font-size: 16px; }</style>');
                printWindow.document.write('</head><body>');
                printWindow.document.write('<h1><?php _e('Cloudflare Zero Trust Backup Codes', 'cf-zero-trust'); ?></h1>');
                printWindow.document.write('<p><?php _e('User:', 'cf-zero-trust'); ?> <?php echo esc_js($user->user_login); ?></p>');
                printWindow.document.write('<p><?php _e('Generated:', 'cf-zero-trust'); ?> ' + new Date().toLocaleString() + '</p>');
                codes.forEach(function(code) {
                    printWindow.document.write('<code>' + code + '</code>');
                });
                printWindow.document.write('</body></html>');
                printWindow.document.close();
                printWindow.print();
            });
        });
        </script>
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

        $primary = CFZT_Auth::is_primary_mode();
        ?>
        <p class="cfzt-backup-code-toggle" style="text-align: center; margin-top: 10px;">
            <a href="#" id="cfzt-use-backup-code" style="font-size: 13px;">
                <?php _e('Use a backup code', 'cf-zero-trust'); ?>
            </a>
        </p>

        <div id="cfzt-backup-code-form" style="display: none; margin-top: 10px;">
            <p style="margin-bottom: 10px;">
                <label for="cfzt_backup_code"><?php _e('Backup Code', 'cf-zero-trust'); ?></label>
                <input type="text" name="cfzt_backup_code" id="cfzt_backup_code" class="input" value="" size="20" autocomplete="off" placeholder="XXXX-XXXX" />
            </p>
            <p style="font-size: 13px; color: #50575e;">
                <?php _e('Enter one of your backup codes. Each code can only be used once.', 'cf-zero-trust'); ?>
            </p>
        </div>

        <script>
        document.addEventListener('DOMContentLoaded', function() {
            var primary = <?php echo $primary ? 'true' : 'false'; ?>;
            var link = document.getElementById('cfzt-use-backup-code');
            var form = document.getElementById('cfzt-backup-code-form');
            var input = document.getElementById('cfzt_backup_code');
            var loginForm = document.getElementById('loginform');
            var wrapper = document.querySelector('.cfzt-login-wrapper');

            if (!link || !form) {
                return;
            }

            // In primary mode the password form is hidden, so the toggle has
            // to live outside it: move it next to the Cloudflare button and
            // reveal the form (minus the password field) on demand.
            if (primary && wrapper) {
                wrapper.appendChild(link.parentNode);
            }

            function setBackupMode(on) {
                document.body.classList.toggle('cfzt-backup-mode', on);
                form.style.display = on ? 'block' : 'none';
                link.textContent = on
                    ? '<?php echo esc_js(__('Use regular login', 'cf-zero-trust')); ?>'
                    : '<?php echo esc_js(__('Use a backup code', 'cf-zero-trust')); ?>';
                if (on) {
                    var userField = document.getElementById('user_login');
                    (userField && !userField.value ? userField : input).focus();
                } else {
                    input.value = '';
                }
                if (primary && loginForm) {
                    loginForm.style.display = on ? 'block' : 'none';
                }
            }

            link.addEventListener('click', function(e) {
                e.preventDefault();
                setBackupMode(form.style.display === 'none');
            });
        });
        </script>
        <?php
    }
}
