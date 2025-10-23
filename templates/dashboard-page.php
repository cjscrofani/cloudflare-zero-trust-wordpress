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

// Get plugin options and status
$options = CFZT_Plugin::get_option();
$security = new CFZT_Security();
$security_status = $security->get_security_status();
$auth_method = isset($options['auth_method']) ? $options['auth_method'] : 'oauth2';
$is_configured = !empty($options['team_domain']) && !empty($options['client_id']) && !empty($options['client_secret']);

// Get authentication stats
global $wpdb;
$cfzt_users_count = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE meta_key = 'cfzt_user' AND meta_value = '1'");
$total_users = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->users}");

// Get recent logins (last 24 hours)
$yesterday = current_time('timestamp') - DAY_IN_SECONDS;
$recent_logins = $wpdb->get_var($wpdb->prepare(
    "SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE meta_key = 'cfzt_last_login' AND meta_value > %s",
    $yesterday
));

?>

<style>
.cfzt-dashboard {
    max-width: 1200px;
    margin: 20px 0;
}

.cfzt-dashboard-header {
    background: linear-gradient(135deg, #f38020, #f6821f);
    color: white;
    padding: 30px;
    border-radius: 8px;
    margin-bottom: 30px;
}

.cfzt-dashboard-header h1 {
    margin: 0 0 10px 0;
    font-size: 32px;
    color: white;
}

.cfzt-dashboard-header p {
    margin: 0;
    opacity: 0.9;
    font-size: 16px;
}

.cfzt-stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.cfzt-stat-card {
    background: white;
    border: 1px solid #ccd0d4;
    border-radius: 8px;
    padding: 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}

.cfzt-stat-card h3 {
    margin: 0 0 10px 0;
    font-size: 14px;
    color: #646970;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.cfzt-stat-value {
    font-size: 36px;
    font-weight: 700;
    color: #1d2327;
    margin: 10px 0;
}

.cfzt-stat-label {
    font-size: 13px;
    color: #646970;
}

.cfzt-stat-icon {
    width: 48px;
    height: 48px;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 24px;
    margin-bottom: 10px;
}

.cfzt-stat-icon.blue {
    background: #e7f5ff;
    color: #2271b1;
}

.cfzt-stat-icon.green {
    background: #edfaef;
    color: #00a32a;
}

.cfzt-stat-icon.orange {
    background: #fff7f0;
    color: #f38020;
}

.cfzt-stat-icon.purple {
    background: #f5f0ff;
    color: #7c3aed;
}

.cfzt-section {
    background: white;
    border: 1px solid #ccd0d4;
    border-radius: 8px;
    padding: 25px;
    margin-bottom: 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}

.cfzt-section h2 {
    margin: 0 0 20px 0;
    font-size: 20px;
    color: #1d2327;
}

.cfzt-health-check {
    display: flex;
    align-items: center;
    padding: 15px;
    background: #f6f7f7;
    border-radius: 6px;
    margin-bottom: 10px;
}

.cfzt-health-icon {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
    margin-right: 15px;
    flex-shrink: 0;
}

.cfzt-health-icon.success {
    background: #edfaef;
    color: #00a32a;
}

.cfzt-health-icon.warning {
    background: #fcf9e8;
    color: #dba617;
}

.cfzt-health-icon.error {
    background: #fcf2f2;
    color: #d63638;
}

.cfzt-health-content {
    flex: 1;
}

.cfzt-health-title {
    font-weight: 600;
    margin: 0 0 5px 0;
}

.cfzt-health-desc {
    font-size: 13px;
    color: #646970;
    margin: 0;
}

.cfzt-quick-actions {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
}

.cfzt-action-btn {
    display: flex;
    align-items: center;
    padding: 15px;
    background: #f6f7f7;
    border: 1px solid #ddd;
    border-radius: 6px;
    text-decoration: none;
    color: #2271b1;
    font-weight: 600;
    transition: all 0.2s;
}

.cfzt-action-btn:hover {
    background: #e7f7fe;
    border-color: #2271b1;
    transform: translateY(-2px);
    box-shadow: 0 4px 8px rgba(0,0,0,0.1);
}

.cfzt-action-btn .dashicons {
    margin-right: 10px;
    font-size: 20px;
}

@media (max-width: 782px) {
    .cfzt-stats-grid {
        grid-template-columns: 1fr;
    }

    .cfzt-quick-actions {
        grid-template-columns: 1fr;
    }

    .cfzt-dashboard-header {
        padding: 20px;
    }

    .cfzt-dashboard-header h1 {
        font-size: 24px;
    }
}
</style>

<div class="wrap cfzt-dashboard">
    <!-- Header -->
    <div class="cfzt-dashboard-header">
        <h1><?php _e('Cloudflare Zero Trust Dashboard', 'cf-zero-trust'); ?></h1>
        <p><?php _e('Monitor your authentication activity and system health', 'cf-zero-trust'); ?></p>
    </div>

    <?php if (!$is_configured): ?>
        <div class="notice notice-warning">
            <p>
                <strong><?php _e('Plugin Not Configured', 'cf-zero-trust'); ?></strong><br>
                <?php _e('Please configure your Cloudflare Zero Trust settings to start using the plugin.', 'cf-zero-trust'); ?>
                <a href="<?php echo esc_url(admin_url('options-general.php?page=cf-zero-trust')); ?>" class="button button-primary" style="margin-left: 10px;">
                    <?php _e('Configure Now', 'cf-zero-trust'); ?>
                </a>
            </p>
        </div>
    <?php endif; ?>

    <!-- Stats Grid -->
    <div class="cfzt-stats-grid">
        <!-- Total CF Users -->
        <div class="cfzt-stat-card">
            <div class="cfzt-stat-icon blue">
                <span class="dashicons dashicons-admin-users"></span>
            </div>
            <h3><?php _e('Cloudflare Users', 'cf-zero-trust'); ?></h3>
            <div class="cfzt-stat-value"><?php echo number_format_i18n($cfzt_users_count); ?></div>
            <div class="cfzt-stat-label">
                <?php printf(__('of %s total users', 'cf-zero-trust'), number_format_i18n($total_users)); ?>
            </div>
        </div>

        <!-- Recent Logins -->
        <div class="cfzt-stat-card">
            <div class="cfzt-stat-icon green">
                <span class="dashicons dashicons-yes-alt"></span>
            </div>
            <h3><?php _e('Recent Logins (24h)', 'cf-zero-trust'); ?></h3>
            <div class="cfzt-stat-value"><?php echo number_format_i18n($recent_logins); ?></div>
            <div class="cfzt-stat-label"><?php _e('Successful authentications', 'cf-zero-trust'); ?></div>
        </div>

        <!-- Auth Method -->
        <div class="cfzt-stat-card">
            <div class="cfzt-stat-icon orange">
                <span class="dashicons dashicons-shield-alt"></span>
            </div>
            <h3><?php _e('Authentication Method', 'cf-zero-trust'); ?></h3>
            <div class="cfzt-stat-value" style="font-size: 28px;">
                <?php echo $auth_method === 'saml' ? 'SAML' : 'OIDC'; ?>
            </div>
            <div class="cfzt-stat-label">
                <?php echo $auth_method === 'saml' ? __('Experimental mode', 'cf-zero-trust') : __('Production-ready', 'cf-zero-trust'); ?>
            </div>
        </div>

        <!-- Login Mode -->
        <div class="cfzt-stat-card">
            <div class="cfzt-stat-icon purple">
                <span class="dashicons dashicons-admin-network"></span>
            </div>
            <h3><?php _e('Login Mode', 'cf-zero-trust'); ?></h3>
            <div class="cfzt-stat-value" style="font-size: 22px;">
                <?php
                $login_mode = isset($options['login_mode']) ? $options['login_mode'] : 'secondary';
                echo $login_mode === 'primary' ? __('Primary', 'cf-zero-trust') : __('Secondary', 'cf-zero-trust');
                ?>
            </div>
            <div class="cfzt-stat-label">
                <?php echo $login_mode === 'primary' ? __('CF only', 'cf-zero-trust') : __('CF + WordPress', 'cf-zero-trust'); ?>
            </div>
        </div>
    </div>

    <!-- Health Check -->
    <div class="cfzt-section">
        <h2><?php _e('System Health', 'cf-zero-trust'); ?></h2>

        <?php if ($is_configured): ?>
            <div class="cfzt-health-check">
                <div class="cfzt-health-icon success">✓</div>
                <div class="cfzt-health-content">
                    <div class="cfzt-health-title"><?php _e('Plugin Configured', 'cf-zero-trust'); ?></div>
                    <div class="cfzt-health-desc"><?php _e('Cloudflare credentials are set and ready to use', 'cf-zero-trust'); ?></div>
                </div>
            </div>
        <?php else: ?>
            <div class="cfzt-health-check">
                <div class="cfzt-health-icon error">✗</div>
                <div class="cfzt-health-content">
                    <div class="cfzt-health-title"><?php _e('Plugin Not Configured', 'cf-zero-trust'); ?></div>
                    <div class="cfzt-health-desc"><?php _e('Please complete the setup wizard to configure Cloudflare credentials', 'cf-zero-trust'); ?></div>
                </div>
            </div>
        <?php endif; ?>

        <?php if ($security_status['encryption_available']): ?>
            <div class="cfzt-health-check">
                <div class="cfzt-health-icon success">✓</div>
                <div class="cfzt-health-content">
                    <div class="cfzt-health-title"><?php _e('Encryption Available', 'cf-zero-trust'); ?></div>
                    <div class="cfzt-health-desc"><?php printf(__('Using %s for credential encryption', 'cf-zero-trust'), $security_status['encryption_method']); ?></div>
                </div>
            </div>
        <?php else: ?>
            <div class="cfzt-health-check">
                <div class="cfzt-health-icon warning">⚠</div>
                <div class="cfzt-health-content">
                    <div class="cfzt-health-title"><?php _e('Limited Encryption', 'cf-zero-trust'); ?></div>
                    <div class="cfzt-health-desc"><?php _e('OpenSSL not available - using basic obfuscation. Consider enabling OpenSSL.', 'cf-zero-trust'); ?></div>
                </div>
            </div>
        <?php endif; ?>

        <?php if (is_ssl()): ?>
            <div class="cfzt-health-check">
                <div class="cfzt-health-icon success">✓</div>
                <div class="cfzt-health-content">
                    <div class="cfzt-health-title"><?php _e('HTTPS Enabled', 'cf-zero-trust'); ?></div>
                    <div class="cfzt-health-desc"><?php _e('Your site is using a secure SSL connection', 'cf-zero-trust'); ?></div>
                </div>
            </div>
        <?php else: ?>
            <div class="cfzt-health-check">
                <div class="cfzt-health-icon error">✗</div>
                <div class="cfzt-health-content">
                    <div class="cfzt-health-title"><?php _e('HTTPS Not Enabled', 'cf-zero-trust'); ?></div>
                    <div class="cfzt-health-desc"><?php _e('HTTPS is required for production use of Cloudflare Zero Trust', 'cf-zero-trust'); ?></div>
                </div>
            </div>
        <?php endif; ?>

        <?php if ($auth_method === 'saml'): ?>
            <?php if (class_exists('DOMDocument')): ?>
                <div class="cfzt-health-check">
                    <div class="cfzt-health-icon success">✓</div>
                    <div class="cfzt-health-content">
                        <div class="cfzt-health-title"><?php _e('PHP DOM Extension Available', 'cf-zero-trust'); ?></div>
                        <div class="cfzt-health-desc"><?php _e('Required for SAML support', 'cf-zero-trust'); ?></div>
                    </div>
                </div>
            <?php else: ?>
                <div class="cfzt-health-check">
                    <div class="cfzt-health-icon error">✗</div>
                    <div class="cfzt-health-content">
                        <div class="cfzt-health-title"><?php _e('PHP DOM Extension Missing', 'cf-zero-trust'); ?></div>
                        <div class="cfzt-health-desc"><?php _e('Required for SAML - please install php-xml package', 'cf-zero-trust'); ?></div>
                    </div>
                </div>
            <?php endif; ?>

            <div class="cfzt-health-check">
                <div class="cfzt-health-icon warning">⚠</div>
                <div class="cfzt-health-content">
                    <div class="cfzt-health-title"><?php _e('SAML Mode Active', 'cf-zero-trust'); ?></div>
                    <div class="cfzt-health-desc"><?php _e('SAML does not perform signature validation - not recommended for production', 'cf-zero-trust'); ?></div>
                </div>
            </div>
        <?php endif; ?>

        <?php if (class_exists('CFZT_GitHub_Updater')): ?>
            <div class="cfzt-health-check">
                <div class="cfzt-health-icon success">✓</div>
                <div class="cfzt-health-content">
                    <div class="cfzt-health-title"><?php _e('Auto-Updates Enabled', 'cf-zero-trust'); ?></div>
                    <div class="cfzt-health-desc"><?php printf(__('Checking for updates from %s', 'cf-zero-trust'), 'GitHub'); ?></div>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <!-- Quick Actions -->
    <div class="cfzt-section">
        <h2><?php _e('Quick Actions', 'cf-zero-trust'); ?></h2>
        <div class="cfzt-quick-actions">
            <a href="<?php echo esc_url(admin_url('options-general.php?page=cf-zero-trust')); ?>" class="cfzt-action-btn">
                <span class="dashicons dashicons-admin-settings"></span>
                <?php _e('Plugin Settings', 'cf-zero-trust'); ?>
            </a>

            <a href="<?php echo esc_url(wp_login_url()); ?>" class="cfzt-action-btn" target="_blank">
                <span class="dashicons dashicons-external"></span>
                <?php _e('View Login Page', 'cf-zero-trust'); ?>
            </a>

            <a href="<?php echo esc_url(admin_url('users.php')); ?>" class="cfzt-action-btn">
                <span class="dashicons dashicons-admin-users"></span>
                <?php _e('Manage Users', 'cf-zero-trust'); ?>
            </a>

            <button type="button" id="cfzt-dashboard-test-connection" class="cfzt-action-btn" style="border: none; cursor: pointer; text-align: left;">
                <span class="dashicons dashicons-yes-alt"></span>
                <?php _e('Test Connection', 'cf-zero-trust'); ?>
            </button>

            <a href="https://github.com/<?php echo CFZT_GITHUB_USERNAME . '/' . CFZT_GITHUB_REPOSITORY; ?>" class="cfzt-action-btn" target="_blank">
                <span class="dashicons dashicons-book"></span>
                <?php _e('Documentation', 'cf-zero-trust'); ?>
            </a>

            <a href="https://github.com/<?php echo CFZT_GITHUB_USERNAME . '/' . CFZT_GITHUB_REPOSITORY; ?>/issues" class="cfzt-action-btn" target="_blank">
                <span class="dashicons dashicons-sos"></span>
                <?php _e('Get Support', 'cf-zero-trust'); ?>
            </a>
        </div>
    </div>

    <div id="cfzt-dashboard-test-results"></div>
</div>

<script>
jQuery(document).ready(function($) {
    'use strict';

    // Test connection from dashboard
    $('#cfzt-dashboard-test-connection').on('click', function() {
        var $btn = $(this);
        var $resultsContainer = $('#cfzt-dashboard-test-results');
        var originalHtml = $btn.html();

        $btn.prop('disabled', true).html('<span class="dashicons dashicons-update" style="animation: spin 1s linear infinite;"></span> Testing...');
        $resultsContainer.empty();

        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'cfzt_test_connection',
                nonce: '<?php echo wp_create_nonce('cfzt_test_connection'); ?>'
            },
            success: function(response) {
                var html = '<div class="cfzt-section" style="margin-top: 20px;">';
                html += '<h2>Connection Test Results</h2>';

                if (response.success) {
                    html += '<div class="cfzt-health-check"><div class="cfzt-health-icon success">✓</div>';
                    html += '<div class="cfzt-health-content"><div class="cfzt-health-title">' + response.data.message + '</div>';

                    if (response.data.details && response.data.details.length > 0) {
                        html += '<ul style="margin: 10px 0 0 0; padding-left: 20px;">';
                        response.data.details.forEach(function(detail) {
                            html += '<li>' + detail + '</li>';
                        });
                        html += '</ul>';
                    }

                    if (response.data.warnings && response.data.warnings.length > 0) {
                        html += '<div style="margin-top: 10px;"><strong>Warnings:</strong><ul style="margin: 5px 0 0 0; padding-left: 20px;">';
                        response.data.warnings.forEach(function(warning) {
                            html += '<li>' + warning + '</li>';
                        });
                        html += '</ul></div>';
                    }

                    html += '</div></div>';
                } else {
                    html += '<div class="cfzt-health-check"><div class="cfzt-health-icon error">✗</div>';
                    html += '<div class="cfzt-health-content"><div class="cfzt-health-title">' + (response.data.message || 'Connection test failed') + '</div>';

                    if (response.data.issues && response.data.issues.length > 0) {
                        html += '<ul style="margin: 10px 0 0 0; padding-left: 20px; color: #d63638;">';
                        response.data.issues.forEach(function(issue) {
                            html += '<li>' + issue + '</li>';
                        });
                        html += '</ul>';
                    }

                    html += '</div></div>';
                }

                html += '</div>';
                $resultsContainer.html(html);
            },
            error: function() {
                $resultsContainer.html('<div class="notice notice-error"><p>Connection test failed unexpectedly. Please try again.</p></div>');
            },
            complete: function() {
                $btn.prop('disabled', false).html(originalHtml);
            }
        });
    });

    // Add spinning animation
    $('<style>@keyframes spin { 100% { transform: rotate(360deg); } }</style>').appendTo('head');
});
</script>
