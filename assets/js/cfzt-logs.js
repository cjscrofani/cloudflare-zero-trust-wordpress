/**
 * Zero Trust Login for Cloudflare: logs page
 */
jQuery(document).ready(function($) {
    'use strict';

    var i18n = cfztLogs.i18n;
    var nonces = cfztLogs.nonces;

    // Translations are inserted into markup below, so encode them first.
    function escHtml(value) {
        return String(value === null || value === undefined ? '' : value).replace(/[&<>"']/g, function(c) {
            return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'}[c];
        });
    }

    let currentPage = 1;
    let currentFilters = {};

    // Load logs
    function loadLogs(page = 1) {
        currentPage = page;

        $('#cfzt-logs-loading').show();
        $('.cfzt-logs-table-container').hide();

        const filters = {
            action: 'cfzt_get_logs',
            nonce: nonces.logsAction,
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
            $('.cfzt-logs-table-container').show();

            if (response.success) {
                displayLogs(response.data.logs);
                updatePagination(response.data);
            } else {
                alert(response.data || i18n.failedToLoadLogs);
            }
        });
    }

    // Display logs in table
    function displayLogs(logs) {
        const tbody = $('#cfzt-logs-tbody');
        tbody.empty();

        if (logs.length === 0) {
            tbody.append('<tr class="no-items"><td colspan="7">' + escHtml(i18n.noLogsFoundMatchingYour) + '</td></tr>');
            return;
        }

        logs.forEach(function(log) {
            const levelClass = 'cfzt-log-level-' + log.log_level.toLowerCase();
            const statusClass = log.success ? 'cfzt-log-status-success' : 'cfzt-log-status-failed';
            const statusText = escHtml(log.success ? i18n.success : i18n.failed);

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
        const info = i18n.showing + ' ' +
                     ((data.page - 1) * data.per_page + 1) + ' - ' +
                     Math.min(data.page * data.per_page, data.total) + ' ' + i18n.of + ' ' +
                     data.total + ' ' + i18n.logs;
        $('#cfzt-pagination-info').text(info);

        $('#cfzt-page-numbers').text(i18n.page + ' ' + data.page + ' ' + i18n.of + ' ' + data.total_pages);

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
        if (!confirm(i18n.areYouSureYouWant)) {
            return;
        }

        $.post(ajaxurl, {
            action: 'cfzt_clear_logs',
            nonce: nonces.logsAction
        }, function(response) {
            if (response.success) {
                alert(response.data);
                loadLogs(1);
            } else {
                alert(response.data || i18n.failedToClearLogs);
            }
        });
    });

    // Initial load
    loadLogs(1);
});
