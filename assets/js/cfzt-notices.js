/**
 * Zero Trust Login for Cloudflare: dismissible admin notices
 *
 * A notice that carries data-cfzt-dismiss-action posts that AJAX action,
 * with the nonce from data-cfzt-dismiss-nonce, when its dismiss button is
 * clicked. WordPress itself removes the notice from the page.
 */
jQuery(function($) {
    'use strict';

    $(document).on('click', '.notice[data-cfzt-dismiss-action] .notice-dismiss', function() {
        var $notice = $(this).closest('.notice');

        $.post(ajaxurl, {
            action: $notice.data('cfzt-dismiss-action'),
            nonce: $notice.data('cfzt-dismiss-nonce')
        });
    });
});
