/**
 * Zero Trust Login for Cloudflare: backup codes on the profile screen
 */
jQuery(document).ready(function($) {
    'use strict';

    var i18n = cfztBackupCodes.i18n;
    var nonces = cfztBackupCodes.nonces;

    // Translations are inserted into markup below, so encode them first.
    function escHtml(value) {
        return String(value === null || value === undefined ? '' : value).replace(/[&<>"']/g, function(c) {
            return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'}[c];
        });
    }

    function escapeHtml(text) {
        return $('<div>').text(text === null || text === undefined ? '' : String(text)).html();
    }

    $('#cfzt-generate-backup-codes').on('click', function() {
        if (!confirm(i18n.generatingNewBackupCodesWill)) {
            return;
        }

        var $button = $(this);
        $button.prop('disabled', true).text(i18n.generating);

        $.post(ajaxurl, {
            action: 'cfzt_generate_backup_codes',
            nonce: nonces.backupCodes,
            user_id: $button.data('user-id')
        }, function(response) {
            if (response.success) {
                var codes = response.data.codes;
                var $list = $('#cfzt-backup-codes-list');
                $list.empty();

                codes.forEach(function(code) {
                    $list.append($('<div style="margin: 5px 0;">').text(code));
                });

                $('#cfzt-backup-codes-display').slideDown();
                $button.text(i18n.generateNewBackupCodes).prop('disabled', false);
            } else {
                alert(i18n.error + response.data);
                $button.prop('disabled', false).text(i18n.generateNewBackupCodes);
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
            $button.text(i18n.copied);
            setTimeout(function() {
                $button.html('<span class="dashicons dashicons-clipboard" style="vertical-align: middle;"></span> ' + escHtml(i18n.copyAllCodes));
            }, 2000);
        });
    });

    $('#cfzt-print-backup-codes').on('click', function() {
        var codes = [];
        $('#cfzt-backup-codes-list div').each(function() {
            codes.push($(this).text());
        });

        var printWindow = window.open('', '', 'width=600,height=400');
        printWindow.document.write('<html><head><title>' + escHtml(i18n.backupCodes) + '</title>');
        printWindow.document.write('<style>body { font-family: Arial, sans-serif; padding: 20px; } h1 { font-size: 18px; } code { display: block; margin: 10px 0; font-size: 16px; }</style>');
        printWindow.document.write('</head><body>');
        printWindow.document.write('<h1>' + escHtml(i18n.cloudflareZeroTrustBackupCodes) + '</h1>');
        printWindow.document.write('<p>' + escHtml(i18n.user) + ' ' + escapeHtml(cfztBackupCodes.userLogin) + '</p>');
        printWindow.document.write('<p>' + escHtml(i18n.generated) + ' ' + new Date().toLocaleString() + '</p>');
        codes.forEach(function(code) {
            printWindow.document.write('<code>' + escapeHtml(code) + '</code>');
        });
        printWindow.document.write('</body></html>');
        printWindow.document.close();
        printWindow.print();
    });
});
