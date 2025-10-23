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

// Check if logging is enabled
$options = CFZT_Plugin::get_option();
$logging_enabled = isset($options['enable_logging']) && $options['enable_logging'] === CFZT_Plugin::OPTION_YES;
?>

<div class="wrap">
    <h1>
        <span class="dashicons dashicons-list-view" style="font-size: 32px; width: 32px; height: 32px;"></span>
        <?php _e('Cloudflare Zero Trust Authentication Logs', 'cf-zero-trust'); ?>
    </h1>

    <?php if (!$logging_enabled): ?>
        <div class="notice notice-warning">
            <p>
                <strong><?php _e('Logging is currently disabled.', 'cf-zero-trust'); ?></strong>
                <?php _e('Enable logging in the', 'cf-zero-trust'); ?>
                <a href="<?php echo esc_url(admin_url('options-general.php?page=cf-zero-trust')); ?>">
                    <?php _e('plugin settings', 'cf-zero-trust'); ?>
                </a>
                <?php _e('to start recording authentication attempts.', 'cf-zero-trust'); ?>
            </p>
        </div>
    <?php endif; ?>

    <div class="cfzt-logs-container">
        <!-- Filters -->
        <div class="cfzt-logs-filters">
            <div class="cfzt-filter-row">
                <div class="cfzt-filter-group">
                    <label for="cfzt-filter-level"><?php _e('Log Level:', 'cf-zero-trust'); ?></label>
                    <select id="cfzt-filter-level">
                        <option value=""><?php _e('All Levels', 'cf-zero-trust'); ?></option>
                        <option value="ERROR"><?php _e('Error', 'cf-zero-trust'); ?></option>
                        <option value="WARNING"><?php _e('Warning', 'cf-zero-trust'); ?></option>
                        <option value="INFO"><?php _e('Info', 'cf-zero-trust'); ?></option>
                        <option value="DEBUG"><?php _e('Debug', 'cf-zero-trust'); ?></option>
                    </select>
                </div>

                <div class="cfzt-filter-group">
                    <label for="cfzt-filter-auth-method"><?php _e('Auth Method:', 'cf-zero-trust'); ?></label>
                    <select id="cfzt-filter-auth-method">
                        <option value=""><?php _e('All Methods', 'cf-zero-trust'); ?></option>
                        <option value="oidc"><?php _e('OIDC', 'cf-zero-trust'); ?></option>
                        <option value="saml"><?php _e('SAML', 'cf-zero-trust'); ?></option>
                    </select>
                </div>

                <div class="cfzt-filter-group">
                    <label for="cfzt-filter-success"><?php _e('Status:', 'cf-zero-trust'); ?></label>
                    <select id="cfzt-filter-success">
                        <option value=""><?php _e('All', 'cf-zero-trust'); ?></option>
                        <option value="1"><?php _e('Success', 'cf-zero-trust'); ?></option>
                        <option value="0"><?php _e('Failed', 'cf-zero-trust'); ?></option>
                    </select>
                </div>

                <div class="cfzt-filter-group">
                    <label for="cfzt-filter-search"><?php _e('Search:', 'cf-zero-trust'); ?></label>
                    <input type="text" id="cfzt-filter-search" placeholder="<?php esc_attr_e('Email or message...', 'cf-zero-trust'); ?>" />
                </div>
            </div>

            <div class="cfzt-filter-row">
                <div class="cfzt-filter-group">
                    <label for="cfzt-filter-date-from"><?php _e('From:', 'cf-zero-trust'); ?></label>
                    <input type="date" id="cfzt-filter-date-from" />
                </div>

                <div class="cfzt-filter-group">
                    <label for="cfzt-filter-date-to"><?php _e('To:', 'cf-zero-trust'); ?></label>
                    <input type="date" id="cfzt-filter-date-to" />
                </div>

                <div class="cfzt-filter-group cfzt-filter-actions">
                    <button type="button" id="cfzt-apply-filters" class="button button-primary">
                        <?php _e('Apply Filters', 'cf-zero-trust'); ?>
                    </button>
                    <button type="button" id="cfzt-reset-filters" class="button">
                        <?php _e('Reset', 'cf-zero-trust'); ?>
                    </button>
                </div>
            </div>
        </div>

        <!-- Actions -->
        <div class="cfzt-logs-actions">
            <button type="button" id="cfzt-export-logs" class="button">
                <span class="dashicons dashicons-download"></span> <?php _e('Export to CSV', 'cf-zero-trust'); ?>
            </button>
            <button type="button" id="cfzt-clear-logs" class="button button-link-delete">
                <span class="dashicons dashicons-trash"></span> <?php _e('Clear All Logs', 'cf-zero-trust'); ?>
            </button>
            <button type="button" id="cfzt-refresh-logs" class="button">
                <span class="dashicons dashicons-update"></span> <?php _e('Refresh', 'cf-zero-trust'); ?>
            </button>
        </div>

        <!-- Loading indicator -->
        <div id="cfzt-logs-loading" style="display: none;">
            <span class="spinner is-active"></span> <?php _e('Loading logs...', 'cf-zero-trust'); ?>
        </div>

        <!-- Logs table -->
        <div class="cfzt-logs-table-container">
            <table class="wp-list-table widefat fixed striped" id="cfzt-logs-table">
                <thead>
                    <tr>
                        <th class="cfzt-col-time"><?php _e('Time', 'cf-zero-trust'); ?></th>
                        <th class="cfzt-col-level"><?php _e('Level', 'cf-zero-trust'); ?></th>
                        <th class="cfzt-col-message"><?php _e('Message', 'cf-zero-trust'); ?></th>
                        <th class="cfzt-col-identifier"><?php _e('User', 'cf-zero-trust'); ?></th>
                        <th class="cfzt-col-method"><?php _e('Method', 'cf-zero-trust'); ?></th>
                        <th class="cfzt-col-status"><?php _e('Status', 'cf-zero-trust'); ?></th>
                        <th class="cfzt-col-ip"><?php _e('IP Address', 'cf-zero-trust'); ?></th>
                    </tr>
                </thead>
                <tbody id="cfzt-logs-tbody">
                    <tr class="no-items">
                        <td colspan="7"><?php _e('No logs found.', 'cf-zero-trust'); ?></td>
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
                    <span class="dashicons dashicons-arrow-left-alt2"></span> <?php _e('First', 'cf-zero-trust'); ?>
                </button>
                <button type="button" id="cfzt-page-prev" class="button" disabled>
                    <span class="dashicons dashicons-arrow-left-alt"></span> <?php _e('Previous', 'cf-zero-trust'); ?>
                </button>
                <span id="cfzt-page-numbers"></span>
                <button type="button" id="cfzt-page-next" class="button" disabled>
                    <?php _e('Next', 'cf-zero-trust'); ?> <span class="dashicons dashicons-arrow-right-alt"></span>
                </button>
                <button type="button" id="cfzt-page-last" class="button" disabled>
                    <?php _e('Last', 'cf-zero-trust'); ?> <span class="dashicons dashicons-arrow-right-alt2"></span>
                </button>
            </div>
        </div>
    </div>
</div>

<style>
.cfzt-logs-container {
    margin-top: 20px;
}

.cfzt-logs-filters {
    background: #fff;
    border: 1px solid #ccd0d4;
    padding: 20px;
    margin-bottom: 20px;
}

.cfzt-filter-row {
    display: flex;
    gap: 15px;
    margin-bottom: 15px;
    flex-wrap: wrap;
}

.cfzt-filter-row:last-child {
    margin-bottom: 0;
}

.cfzt-filter-group {
    display: flex;
    flex-direction: column;
    min-width: 150px;
}

.cfzt-filter-group label {
    font-weight: 600;
    margin-bottom: 5px;
    font-size: 12px;
}

.cfzt-filter-group select,
.cfzt-filter-group input[type="text"],
.cfzt-filter-group input[type="date"] {
    padding: 6px 10px;
    border: 1px solid #8c8f94;
    border-radius: 3px;
}

.cfzt-filter-actions {
    justify-content: flex-end;
    flex-direction: row;
    align-items: flex-end;
    gap: 10px;
}

.cfzt-logs-actions {
    display: flex;
    gap: 10px;
    margin-bottom: 15px;
}

.cfzt-logs-actions .button .dashicons {
    line-height: 28px;
}

#cfzt-logs-loading {
    padding: 20px;
    text-align: center;
    background: #fff;
    border: 1px solid #ccd0d4;
}

.cfzt-logs-table-container {
    background: #fff;
    border: 1px solid #ccd0d4;
}

#cfzt-logs-table {
    margin: 0;
}

#cfzt-logs-table th {
    font-weight: 600;
}

.cfzt-col-time { width: 150px; }
.cfzt-col-level { width: 80px; }
.cfzt-col-message { width: auto; }
.cfzt-col-identifier { width: 180px; }
.cfzt-col-method { width: 80px; }
.cfzt-col-status { width: 80px; }
.cfzt-col-ip { width: 130px; }

.cfzt-log-level {
    display: inline-block;
    padding: 3px 8px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
}

.cfzt-log-level-error {
    background: #dc3232;
    color: #fff;
}

.cfzt-log-level-warning {
    background: #f0b849;
    color: #000;
}

.cfzt-log-level-info {
    background: #00a0d2;
    color: #fff;
}

.cfzt-log-level-debug {
    background: #82878c;
    color: #fff;
}

.cfzt-log-status {
    display: inline-block;
    padding: 3px 8px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: 600;
}

.cfzt-log-status-success {
    background: #46b450;
    color: #fff;
}

.cfzt-log-status-failed {
    background: #dc3232;
    color: #fff;
}

.cfzt-log-method {
    text-transform: uppercase;
    font-weight: 600;
    font-size: 11px;
    color: #666;
}

.cfzt-logs-pagination {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 15px;
    padding: 15px;
    background: #fff;
    border: 1px solid #ccd0d4;
}

.cfzt-pagination-info {
    font-weight: 600;
}

.cfzt-pagination-links {
    display: flex;
    gap: 5px;
    align-items: center;
}

#cfzt-page-numbers {
    margin: 0 10px;
    font-weight: 600;
}

@media (max-width: 768px) {
    .cfzt-filter-row {
        flex-direction: column;
    }

    .cfzt-filter-group {
        width: 100%;
    }

    .cfzt-logs-pagination {
        flex-direction: column;
        gap: 15px;
    }

    .cfzt-pagination-links {
        flex-wrap: wrap;
    }
}
</style>

<script>
jQuery(document).ready(function($) {
    let currentPage = 1;
    let currentFilters = {};

    // Load logs
    function loadLogs(page = 1) {
        currentPage = page;

        $('#cfzt-logs-loading').show();
        $('#cfzt-logs-table-container').hide();

        const filters = {
            action: 'cfzt_get_logs',
            nonce: '<?php echo wp_create_nonce('cfzt_logs_action'); ?>',
            page: page,
            level: $('#cfzt-filter-level').val(),
            search: $('#cfzt-filter-search').val(),
            date_from: $('#cfzt-filter-date-from').val(),
            date_to: $('#cfzt-filter-date-to').val(),
            auth_method: $('#cfzt-filter-auth-method').val(),
            success_filter: $('#cfzt-filter-success').val()
        };

        currentFilters = filters;

        $.post(ajaxurl, filters, function(response) {
            $('#cfzt-logs-loading').hide();
            $('#cfzt-logs-table-container').show();

            if (response.success) {
                displayLogs(response.data.logs);
                updatePagination(response.data);
            } else {
                alert(response.data || '<?php _e('Failed to load logs.', 'cf-zero-trust'); ?>');
            }
        });
    }

    // Display logs in table
    function displayLogs(logs) {
        const tbody = $('#cfzt-logs-tbody');
        tbody.empty();

        if (logs.length === 0) {
            tbody.append('<tr class="no-items"><td colspan="7"><?php _e('No logs found matching your filters.', 'cf-zero-trust'); ?></td></tr>');
            return;
        }

        logs.forEach(function(log) {
            const levelClass = 'cfzt-log-level-' + log.log_level.toLowerCase();
            const statusClass = log.success ? 'cfzt-log-status-success' : 'cfzt-log-status-failed';
            const statusText = log.success ? '<?php _e('Success', 'cf-zero-trust'); ?>' : '<?php _e('Failed', 'cf-zero-trust'); ?>';

            const row = $('<tr>');
            row.append('<td>' + escapeHtml(log.log_time) + '</td>');
            row.append('<td><span class="cfzt-log-level ' + levelClass + '">' + escapeHtml(log.log_level) + '</span></td>');
            row.append('<td>' + escapeHtml(log.message) + '</td>');
            row.append('<td>' + escapeHtml(log.identifier || '-') + '</td>');
            row.append('<td><span class="cfzt-log-method">' + escapeHtml(log.auth_method || '-') + '</span></td>');
            row.append('<td>' + (log.auth_method ? '<span class="cfzt-log-status ' + statusClass + '">' + statusText + '</span>' : '-') + '</td>');
            row.append('<td>' + escapeHtml(log.ip_address || '-') + '</td>');

            tbody.append(row);
        });
    }

    // Update pagination
    function updatePagination(data) {
        const info = '<?php _e('Showing', 'cf-zero-trust'); ?> ' +
                     ((data.page - 1) * data.per_page + 1) + ' - ' +
                     Math.min(data.page * data.per_page, data.total) + ' <?php _e('of', 'cf-zero-trust'); ?> ' +
                     data.total + ' <?php _e('logs', 'cf-zero-trust'); ?>';
        $('#cfzt-pagination-info').text(info);

        $('#cfzt-page-numbers').text('<?php _e('Page', 'cf-zero-trust'); ?> ' + data.page + ' <?php _e('of', 'cf-zero-trust'); ?> ' + data.total_pages);

        // Enable/disable buttons
        $('#cfzt-page-first, #cfzt-page-prev').prop('disabled', data.page === 1);
        $('#cfzt-page-next, #cfzt-page-last').prop('disabled', data.page === data.total_pages || data.total_pages === 0);
    }

    // Escape HTML
    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Event handlers
    $('#cfzt-apply-filters, #cfzt-refresh-logs').on('click', function() {
        loadLogs(1);
    });

    $('#cfzt-reset-filters').on('click', function() {
        $('#cfzt-filter-level').val('');
        $('#cfzt-filter-auth-method').val('');
        $('#cfzt-filter-success').val('');
        $('#cfzt-filter-search').val('');
        $('#cfzt-filter-date-from').val('');
        $('#cfzt-filter-date-to').val('');
        loadLogs(1);
    });

    // Enter key on search field
    $('#cfzt-filter-search').on('keypress', function(e) {
        if (e.which === 13) {
            loadLogs(1);
        }
    });

    // Pagination
    $('#cfzt-page-first').on('click', function() {
        loadLogs(1);
    });

    $('#cfzt-page-prev').on('click', function() {
        if (currentPage > 1) {
            loadLogs(currentPage - 1);
        }
    });

    $('#cfzt-page-next').on('click', function() {
        loadLogs(currentPage + 1);
    });

    $('#cfzt-page-last').on('click', function() {
        const lastPage = parseInt($('#cfzt-page-numbers').text().split(' ').pop());
        loadLogs(lastPage);
    });

    // Export logs
    $('#cfzt-export-logs').on('click', function() {
        const form = $('<form>', {
            method: 'POST',
            action: ajaxurl
        });

        $.each(currentFilters, function(key, value) {
            if (key !== 'page') {
                form.append($('<input>', {
                    type: 'hidden',
                    name: key,
                    value: value
                }));
            }
        });

        form.append($('<input>', {
            type: 'hidden',
            name: 'action',
            value: 'cfzt_export_logs'
        }));

        $('body').append(form);
        form.submit();
        form.remove();
    });

    // Clear logs
    $('#cfzt-clear-logs').on('click', function() {
        if (!confirm('<?php _e('Are you sure you want to clear all logs? This action cannot be undone.', 'cf-zero-trust'); ?>')) {
            return;
        }

        $.post(ajaxurl, {
            action: 'cfzt_clear_logs',
            nonce: '<?php echo wp_create_nonce('cfzt_logs_action'); ?>'
        }, function(response) {
            if (response.success) {
                alert(response.data);
                loadLogs(1);
            } else {
                alert(response.data || '<?php _e('Failed to clear logs.', 'cf-zero-trust'); ?>');
            }
        });
    });

    // Initial load
    loadLogs(1);
});
</script>
