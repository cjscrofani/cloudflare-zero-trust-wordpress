<?php
/**
 * Logs viewer page template
 *
 * @package CloudflareZeroTrustLogin
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- included from a CFZT_Admin method, so these variables are local to that call

// Check if logging is enabled
$options = CFZT_Plugin::get_option();
$logging_enabled = isset($options['enable_logging']) && $options['enable_logging'] === CFZT_Plugin::OPTION_YES;
?>

<div class="wrap">
    <h1>
        <span class="dashicons dashicons-list-view" style="font-size: 32px; width: 32px; height: 32px;"></span>
        <?php esc_html_e('Cloudflare Zero Trust Authentication Logs', 'zero-trust-login-for-cloudflare'); ?>
    </h1>

    <?php if (!$logging_enabled): ?>
        <div class="notice notice-warning">
            <p>
                <strong><?php esc_html_e('Logging is currently disabled.', 'zero-trust-login-for-cloudflare'); ?></strong>
                <?php esc_html_e('Enable logging in the', 'zero-trust-login-for-cloudflare'); ?>
                <a href="<?php echo esc_url(admin_url('options-general.php?page=cf-zero-trust')); ?>">
                    <?php esc_html_e('plugin settings', 'zero-trust-login-for-cloudflare'); ?>
                </a>
                <?php esc_html_e('to start recording authentication attempts.', 'zero-trust-login-for-cloudflare'); ?>
            </p>
        </div>
    <?php endif; ?>

    <div class="cfzt-logs-container">
        <!-- Filters -->
        <div class="cfzt-logs-filters">
            <div class="cfzt-filter-row">
                <div class="cfzt-filter-group">
                    <label for="cfzt-filter-level"><?php esc_html_e('Log Level:', 'zero-trust-login-for-cloudflare'); ?></label>
                    <select id="cfzt-filter-level">
                        <option value=""><?php esc_html_e('All Levels', 'zero-trust-login-for-cloudflare'); ?></option>
                        <option value="ERROR"><?php esc_html_e('Error', 'zero-trust-login-for-cloudflare'); ?></option>
                        <option value="WARNING"><?php esc_html_e('Warning', 'zero-trust-login-for-cloudflare'); ?></option>
                        <option value="INFO"><?php esc_html_e('Info', 'zero-trust-login-for-cloudflare'); ?></option>
                        <option value="DEBUG"><?php esc_html_e('Debug', 'zero-trust-login-for-cloudflare'); ?></option>
                    </select>
                </div>

                <div class="cfzt-filter-group">
                    <label for="cfzt-filter-auth-method"><?php esc_html_e('Auth Method:', 'zero-trust-login-for-cloudflare'); ?></label>
                    <select id="cfzt-filter-auth-method">
                        <option value=""><?php esc_html_e('All Methods', 'zero-trust-login-for-cloudflare'); ?></option>
                        <option value="oidc"><?php esc_html_e('OIDC', 'zero-trust-login-for-cloudflare'); ?></option>
                    </select>
                </div>

                <div class="cfzt-filter-group">
                    <label for="cfzt-filter-success"><?php esc_html_e('Status:', 'zero-trust-login-for-cloudflare'); ?></label>
                    <select id="cfzt-filter-success">
                        <option value=""><?php esc_html_e('All', 'zero-trust-login-for-cloudflare'); ?></option>
                        <option value="1"><?php esc_html_e('Success', 'zero-trust-login-for-cloudflare'); ?></option>
                        <option value="0"><?php esc_html_e('Failed', 'zero-trust-login-for-cloudflare'); ?></option>
                    </select>
                </div>

                <div class="cfzt-filter-group">
                    <label for="cfzt-filter-search"><?php esc_html_e('Search:', 'zero-trust-login-for-cloudflare'); ?></label>
                    <input type="text" id="cfzt-filter-search" placeholder="<?php esc_attr_e('Email or message...', 'zero-trust-login-for-cloudflare'); ?>" />
                </div>
            </div>

            <div class="cfzt-filter-row">
                <div class="cfzt-filter-group">
                    <label for="cfzt-filter-date-from"><?php esc_html_e('From:', 'zero-trust-login-for-cloudflare'); ?></label>
                    <input type="date" id="cfzt-filter-date-from" />
                </div>

                <div class="cfzt-filter-group">
                    <label for="cfzt-filter-date-to"><?php esc_html_e('To:', 'zero-trust-login-for-cloudflare'); ?></label>
                    <input type="date" id="cfzt-filter-date-to" />
                </div>

                <div class="cfzt-filter-group cfzt-filter-actions">
                    <button type="button" id="cfzt-apply-filters" class="button button-primary">
                        <?php esc_html_e('Apply Filters', 'zero-trust-login-for-cloudflare'); ?>
                    </button>
                    <button type="button" id="cfzt-reset-filters" class="button">
                        <?php esc_html_e('Reset', 'zero-trust-login-for-cloudflare'); ?>
                    </button>
                </div>
            </div>
        </div>

        <!-- Actions -->
        <div class="cfzt-logs-actions">
            <button type="button" id="cfzt-export-logs" class="button">
                <span class="dashicons dashicons-download"></span> <?php esc_html_e('Export to CSV', 'zero-trust-login-for-cloudflare'); ?>
            </button>
            <button type="button" id="cfzt-clear-logs" class="button button-link-delete">
                <span class="dashicons dashicons-trash"></span> <?php esc_html_e('Clear All Logs', 'zero-trust-login-for-cloudflare'); ?>
            </button>
            <button type="button" id="cfzt-refresh-logs" class="button">
                <span class="dashicons dashicons-update"></span> <?php esc_html_e('Refresh', 'zero-trust-login-for-cloudflare'); ?>
            </button>
        </div>

        <!-- Loading indicator -->
        <div id="cfzt-logs-loading" style="display: none;">
            <span class="spinner is-active"></span> <?php esc_html_e('Loading logs...', 'zero-trust-login-for-cloudflare'); ?>
        </div>

        <!-- Logs table -->
        <div class="cfzt-logs-table-container">
            <table class="wp-list-table widefat fixed striped" id="cfzt-logs-table">
                <thead>
                    <tr>
                        <th class="cfzt-col-time"><?php esc_html_e('Time', 'zero-trust-login-for-cloudflare'); ?></th>
                        <th class="cfzt-col-level"><?php esc_html_e('Level', 'zero-trust-login-for-cloudflare'); ?></th>
                        <th class="cfzt-col-message"><?php esc_html_e('Message', 'zero-trust-login-for-cloudflare'); ?></th>
                        <th class="cfzt-col-identifier"><?php esc_html_e('User', 'zero-trust-login-for-cloudflare'); ?></th>
                        <th class="cfzt-col-method"><?php esc_html_e('Method', 'zero-trust-login-for-cloudflare'); ?></th>
                        <th class="cfzt-col-status"><?php esc_html_e('Status', 'zero-trust-login-for-cloudflare'); ?></th>
                        <th class="cfzt-col-ip"><?php esc_html_e('IP Address', 'zero-trust-login-for-cloudflare'); ?></th>
                    </tr>
                </thead>
                <tbody id="cfzt-logs-tbody">
                    <tr class="no-items">
                        <td colspan="7"><?php esc_html_e('No logs found.', 'zero-trust-login-for-cloudflare'); ?></td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- Pagination -->
        <div class="cfzt-logs-pagination">
            <div class="cfzt-pagination-info">
                <span id="cfzt-pagination-info"></span>
            </div>
            <div class="cfzt-pagination-links">
                <button type="button" id="cfzt-page-first" class="button" disabled>
                    <span class="dashicons dashicons-arrow-left-alt2"></span> <?php esc_html_e('First', 'zero-trust-login-for-cloudflare'); ?>
                </button>
                <button type="button" id="cfzt-page-prev" class="button" disabled>
                    <span class="dashicons dashicons-arrow-left-alt"></span> <?php esc_html_e('Previous', 'zero-trust-login-for-cloudflare'); ?>
                </button>
                <span id="cfzt-page-numbers"></span>
                <button type="button" id="cfzt-page-next" class="button" disabled>
                    <?php esc_html_e('Next', 'zero-trust-login-for-cloudflare'); ?> <span class="dashicons dashicons-arrow-right-alt"></span>
                </button>
                <button type="button" id="cfzt-page-last" class="button" disabled>
                    <?php esc_html_e('Last', 'zero-trust-login-for-cloudflare'); ?> <span class="dashicons dashicons-arrow-right-alt2"></span>
                </button>
            </div>
        </div>
    </div>
</div>
