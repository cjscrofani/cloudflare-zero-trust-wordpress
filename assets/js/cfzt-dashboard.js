/**
 * Zero Trust Login for Cloudflare: dashboard page
 */
jQuery(document).ready(function($) {
    'use strict';

    var i18n = cfztDashboard.i18n;

    // Translations are inserted into markup below, so encode them first.
    function escHtml(value) {
        return String(value === null || value === undefined ? '' : value).replace(/[&<>"']/g, function(c) {
            return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'}[c];
        });
    }

    // Test connection from dashboard
    $('#cfzt-dashboard-test-connection').on('click', function() {
        var $btn = $(this);
        var $resultsContainer = $('#cfzt-dashboard-test-results');
        var originalHtml = $btn.html();

        $btn.prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span> ' + escHtml(i18n.testing));
        $resultsContainer.empty();

        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'cfzt_test_connection',
                nonce: cfztDashboard.nonce
            },
            success: function(response) {
                var html = '<div class="cfzt-section" style="margin-top: 20px;">';
                html += '<h2>' + escHtml(i18n.results) + '</h2>';

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
                        html += '<div style="margin-top: 10px;"><strong>' + escHtml(i18n.warnings) + '</strong><ul style="margin: 5px 0 0 0; padding-left: 20px;">';
                        response.data.warnings.forEach(function(warning) {
                            html += '<li>' + warning + '</li>';
                        });
                        html += '</ul></div>';
                    }

                    html += '</div></div>';
                } else {
                    html += '<div class="cfzt-health-check"><div class="cfzt-health-icon error">✗</div>';
                    html += '<div class="cfzt-health-content"><div class="cfzt-health-title">' + (response.data.message || escHtml(i18n.failed)) + '</div>';

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
                $resultsContainer.html($('<div class="notice notice-error">').append($('<p>').text(i18n.unexpected)));
            },
            complete: function() {
                $btn.prop('disabled', false).html(originalHtml);
            }
        });
    });
});
