<?php
/**
 * Dashboard page template
 *
 * @package CloudflareZeroTrustLogin
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- included from a CFZT_Admin method, so these variables are local to that call

// Get plugin options and status
$options = CFZT_Plugin::get_option();
$security = new CFZT_Security();
$security_status = $security->get_security_status();
$is_configured = !empty($options['team_domain']) && !empty($options['client_id']) && !empty($options['client_secret']);

// Get setup progress
$setup_progress = CFZT_Plugin::get_setup_progress();

// Get authentication stats
global $wpdb;
// phpcs:disable WordPress.DB.DirectDatabaseQuery -- three COUNT queries for the dashboard tiles, rendered once per page view
$cfzt_users_count = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE meta_key = 'cfzt_user' AND meta_value = '1'");
$total_users = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->users}");

// Get recent logins (last 24 hours)
$yesterday = current_time('timestamp') - DAY_IN_SECONDS;
$recent_logins = $wpdb->get_var($wpdb->prepare(
    "SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE meta_key = 'cfzt_last_login' AND meta_value > %s",
    $yesterday
));

?>

<div class="wrap cfzt-dashboard">
    <!-- Header -->
    <div class="cfzt-dashboard-header">
        <h1><?php esc_html_e('Cloudflare Zero Trust Dashboard', 'zero-trust-login-for-cloudflare'); ?></h1>
        <p><?php esc_html_e('Monitor your authentication activity and system health', 'zero-trust-login-for-cloudflare'); ?></p>
    </div>

    <?php if (!$is_configured): ?>
        <div class="notice notice-warning">
            <p>
                <strong><?php esc_html_e('Plugin Not Configured', 'zero-trust-login-for-cloudflare'); ?></strong><br>
                <?php esc_html_e('Please configure your Cloudflare Zero Trust settings to start using the plugin.', 'zero-trust-login-for-cloudflare'); ?>
                <a href="<?php echo esc_url(admin_url('options-general.php?page=cf-zero-trust')); ?>" class="button button-primary" style="margin-left: 10px;">
                    <?php esc_html_e('Configure Now', 'zero-trust-login-for-cloudflare'); ?>
                </a>
            </p>
        </div>
    <?php endif; ?>

    <!-- Setup Progress -->
    <?php if ($setup_progress['percentage'] < 100): ?>
        <div class="cfzt-section" style="background: #f0f6fc; border: 1px solid #c3e6fc; border-radius: 8px; padding: 20px; margin-bottom: 30px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                <h2 style="margin: 0; font-size: 16px; display: flex; align-items: center; gap: 8px;">
                    <span class="dashicons dashicons-admin-settings" style="font-size: 18px;"></span>
                    <?php esc_html_e('Setup Progress', 'zero-trust-login-for-cloudflare'); ?>
                </h2>
                <span style="font-size: 20px; font-weight: 700; color: #f38020;">
                    <?php echo esc_html($setup_progress['percentage']); ?>%
                </span>
            </div>
            <div style="height: 12px; background: #ddd; border-radius: 6px; overflow: hidden; margin-bottom: 10px;">
                <div style="height: 100%; background: linear-gradient(90deg, #f38020, #f6821f); border-radius: 6px; width: <?php echo esc_attr($setup_progress['percentage']); ?>%; transition: width 0.3s ease;"></div>
            </div>
            <div style="font-size: 13px; color: #646970; margin-bottom: 10px;">
                <?php echo esc_html($setup_progress['completed_count']); ?> of <?php echo esc_html($setup_progress['total_count']); ?> configuration tasks completed
            </div>
            <?php if (!empty($setup_progress['incomplete'])): ?>
                <div style="background: white; border: 1px solid #ddd; border-radius: 4px; padding: 15px; margin-top: 15px;">
                    <strong style="display: block; margin-bottom: 10px;"><?php esc_html_e('Remaining Tasks:', 'zero-trust-login-for-cloudflare'); ?></strong>
                    <ul style="margin: 0; padding-left: 20px;">
                        <?php foreach ($setup_progress['incomplete'] as $task): ?>
                            <li style="margin: 5px 0;"><?php echo esc_html($task); ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>
            <div style="margin-top: 15px;">
                <a href="<?php echo esc_url(admin_url('options-general.php?page=cf-zero-trust')); ?>" class="button button-primary">
                    <?php esc_html_e('Complete Setup', 'zero-trust-login-for-cloudflare'); ?>
                </a>
            </div>
        </div>
    <?php endif; ?>

    <!-- Stats Grid -->
    <div class="cfzt-stats-grid">
        <!-- Total CF Users -->
        <div class="cfzt-stat-card">
            <div class="cfzt-stat-icon blue">
                <span class="dashicons dashicons-admin-users"></span>
            </div>
            <h3><?php esc_html_e('Cloudflare Users', 'zero-trust-login-for-cloudflare'); ?></h3>
            <div class="cfzt-stat-value"><?php echo esc_html(number_format_i18n($cfzt_users_count)); ?></div>
            <div class="cfzt-stat-label">
                <?php /* translators: %s: total number of WordPress users */ printf(esc_html__('of %s total users', 'zero-trust-login-for-cloudflare'), esc_html(number_format_i18n($total_users))); ?>
            </div>
        </div>

        <!-- Recent Logins -->
        <div class="cfzt-stat-card">
            <div class="cfzt-stat-icon green">
                <span class="dashicons dashicons-yes-alt"></span>
            </div>
            <h3><?php esc_html_e('Recent Logins (24h)', 'zero-trust-login-for-cloudflare'); ?></h3>
            <div class="cfzt-stat-value"><?php echo esc_html(number_format_i18n($recent_logins)); ?></div>
            <div class="cfzt-stat-label"><?php esc_html_e('Successful authentications', 'zero-trust-login-for-cloudflare'); ?></div>
        </div>

        <!-- Auth Method -->
        <div class="cfzt-stat-card">
            <div class="cfzt-stat-icon orange">
                <span class="dashicons dashicons-shield-alt"></span>
            </div>
            <h3><?php esc_html_e('Authentication Method', 'zero-trust-login-for-cloudflare'); ?></h3>
            <div class="cfzt-stat-value" style="font-size: 28px;">
                <?php esc_html_e('OIDC', 'zero-trust-login-for-cloudflare'); ?>
            </div>
            <div class="cfzt-stat-label">
                <?php esc_html_e('Production-ready', 'zero-trust-login-for-cloudflare'); ?>
            </div>
        </div>

        <!-- Login Mode -->
        <div class="cfzt-stat-card">
            <div class="cfzt-stat-icon purple">
                <span class="dashicons dashicons-admin-network"></span>
            </div>
            <h3><?php esc_html_e('Login Mode', 'zero-trust-login-for-cloudflare'); ?></h3>
            <div class="cfzt-stat-value" style="font-size: 22px;">
                <?php
                $login_mode = isset($options['login_mode']) ? $options['login_mode'] : 'secondary';
                echo $login_mode === 'primary' ? esc_html__('Primary', 'zero-trust-login-for-cloudflare') : esc_html__('Secondary', 'zero-trust-login-for-cloudflare');
                ?>
            </div>
            <div class="cfzt-stat-label">
                <?php echo $login_mode === 'primary' ? esc_html__('CF only', 'zero-trust-login-for-cloudflare') : esc_html__('CF + WordPress', 'zero-trust-login-for-cloudflare'); ?>
            </div>
        </div>
    </div>

    <!-- Health Check -->
    <div class="cfzt-section">
        <h2><?php esc_html_e('System Health', 'zero-trust-login-for-cloudflare'); ?></h2>

        <?php if ($is_configured): ?>
            <div class="cfzt-health-check">
                <div class="cfzt-health-icon success">✓</div>
                <div class="cfzt-health-content">
                    <div class="cfzt-health-title"><?php esc_html_e('Plugin Configured', 'zero-trust-login-for-cloudflare'); ?></div>
                    <div class="cfzt-health-desc"><?php esc_html_e('Cloudflare credentials are set and ready to use', 'zero-trust-login-for-cloudflare'); ?></div>
                </div>
            </div>
        <?php else: ?>
            <div class="cfzt-health-check">
                <div class="cfzt-health-icon error">✗</div>
                <div class="cfzt-health-content">
                    <div class="cfzt-health-title"><?php esc_html_e('Plugin Not Configured', 'zero-trust-login-for-cloudflare'); ?></div>
                    <div class="cfzt-health-desc"><?php esc_html_e('Please complete the setup wizard to configure Cloudflare credentials', 'zero-trust-login-for-cloudflare'); ?></div>
                </div>
            </div>
        <?php endif; ?>

        <?php if ($security_status['encryption_available']): ?>
            <div class="cfzt-health-check">
                <div class="cfzt-health-icon success">✓</div>
                <div class="cfzt-health-content">
                    <div class="cfzt-health-title"><?php esc_html_e('Encryption Available', 'zero-trust-login-for-cloudflare'); ?></div>
                    <div class="cfzt-health-desc"><?php /* translators: %s: encryption method name */ printf(esc_html__('Using %s for credential encryption', 'zero-trust-login-for-cloudflare'), esc_html($security_status['encryption_method'])); ?></div>
                </div>
            </div>
        <?php else: ?>
            <div class="cfzt-health-check">
                <div class="cfzt-health-icon warning">⚠</div>
                <div class="cfzt-health-content">
                    <div class="cfzt-health-title"><?php esc_html_e('Limited Encryption', 'zero-trust-login-for-cloudflare'); ?></div>
                    <div class="cfzt-health-desc"><?php esc_html_e('OpenSSL not available - using basic obfuscation. Consider enabling OpenSSL.', 'zero-trust-login-for-cloudflare'); ?></div>
                </div>
            </div>
        <?php endif; ?>

        <?php if (is_ssl()): ?>
            <div class="cfzt-health-check">
                <div class="cfzt-health-icon success">✓</div>
                <div class="cfzt-health-content">
                    <div class="cfzt-health-title"><?php esc_html_e('HTTPS Enabled', 'zero-trust-login-for-cloudflare'); ?></div>
                    <div class="cfzt-health-desc"><?php esc_html_e('Your site is using a secure SSL connection', 'zero-trust-login-for-cloudflare'); ?></div>
                </div>
            </div>
        <?php else: ?>
            <div class="cfzt-health-check">
                <div class="cfzt-health-icon error">✗</div>
                <div class="cfzt-health-content">
                    <div class="cfzt-health-title"><?php esc_html_e('HTTPS Not Enabled', 'zero-trust-login-for-cloudflare'); ?></div>
                    <div class="cfzt-health-desc"><?php esc_html_e('HTTPS is required for production use of Cloudflare Zero Trust', 'zero-trust-login-for-cloudflare'); ?></div>
                </div>
            </div>
        <?php endif; ?>

        <?php if (class_exists('CFZT_GitHub_Updater')): ?>
            <div class="cfzt-health-check">
                <div class="cfzt-health-icon success">✓</div>
                <div class="cfzt-health-content">
                    <div class="cfzt-health-title"><?php esc_html_e('Auto-Updates Enabled', 'zero-trust-login-for-cloudflare'); ?></div>
                    <div class="cfzt-health-desc"><?php /* translators: %s: update source, e.g. GitHub */ printf(esc_html__('Checking for updates from %s', 'zero-trust-login-for-cloudflare'), 'GitHub'); ?></div>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <!-- Quick Actions -->
    <div class="cfzt-section">
        <h2><?php esc_html_e('Quick Actions', 'zero-trust-login-for-cloudflare'); ?></h2>
        <div class="cfzt-quick-actions">
            <a href="<?php echo esc_url(admin_url('options-general.php?page=cf-zero-trust')); ?>" class="cfzt-action-btn">
                <span class="dashicons dashicons-admin-settings"></span>
                <?php esc_html_e('Plugin Settings', 'zero-trust-login-for-cloudflare'); ?>
            </a>

            <a href="<?php echo esc_url(wp_login_url()); ?>" class="cfzt-action-btn" target="_blank">
                <span class="dashicons dashicons-external"></span>
                <?php esc_html_e('View Login Page', 'zero-trust-login-for-cloudflare'); ?>
            </a>

            <a href="<?php echo esc_url(admin_url('users.php')); ?>" class="cfzt-action-btn">
                <span class="dashicons dashicons-admin-users"></span>
                <?php esc_html_e('Manage Users', 'zero-trust-login-for-cloudflare'); ?>
            </a>

            <button type="button" id="cfzt-dashboard-test-connection" class="cfzt-action-btn" style="border: none; cursor: pointer; text-align: left;">
                <span class="dashicons dashicons-yes-alt"></span>
                <?php esc_html_e('Test Connection', 'zero-trust-login-for-cloudflare'); ?>
            </button>

            <a href="<?php echo esc_url('https://github.com/' . CFZT_GITHUB_USERNAME . '/' . CFZT_GITHUB_REPOSITORY); ?>" class="cfzt-action-btn" target="_blank">
                <span class="dashicons dashicons-book"></span>
                <?php esc_html_e('Documentation', 'zero-trust-login-for-cloudflare'); ?>
            </a>

            <a href="<?php echo esc_url('https://github.com/' . CFZT_GITHUB_USERNAME . '/' . CFZT_GITHUB_REPOSITORY . '/issues'); ?>" class="cfzt-action-btn" target="_blank">
                <span class="dashicons dashicons-sos"></span>
                <?php esc_html_e('Get Support', 'zero-trust-login-for-cloudflare'); ?>
            </a>
        </div>
    </div>

    <div id="cfzt-dashboard-test-results"></div>
</div>
