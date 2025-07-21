/**
 * Cloudflare Zero Trust Login Admin JavaScript
 */
(function($) {
    'use strict';

    $(document).ready(function() {
        // Manual update check
        $('#cfzt-check-updates').on('click', function(e) {
            e.preventDefault();
            
            var $button = $(this);
            var $status = $('#cfzt-update-check-status');
            var originalText = $button.text();
            
            // Disable button and show loading state
            $button.prop('disabled', true).text(cfztAdmin.checkingText);
            $status.removeClass('notice-success notice-error').html('<span class="spinner is-active" style="float: none; margin: 0;"></span> ' + cfztAdmin.checkingText);
            
            // Make AJAX request
            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'cfzt_check_for_updates',
                    nonce: cfztAdmin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        var message = response.data.message;
                        var statusClass = response.data.hasUpdate ? 'notice-warning' : 'notice-success';
                        
                        $status.addClass(statusClass).html(message);
                        
                        // If update available, show update link
                        if (response.data.hasUpdate && response.data.updateUrl) {
                            $status.append(' <a href="' + response.data.updateUrl + '">' + cfztAdmin.updateNowText + '</a>');
                        }
                    } else {
                        $status.addClass('notice-error').html(response.data || cfztAdmin.errorText);
                    }
                },
                error: function() {
                    $status.addClass('notice-error').html(cfztAdmin.errorText);
                },
                complete: function() {
                    // Re-enable button
                    $button.prop('disabled', false).text(originalText);
                }
            });
        });
        
        // Toggle security details
        $('#cfzt-toggle-security').on('click', function(e) {
            e.preventDefault();
            $('#cfzt-security-details').slideToggle();
            $(this).text($(this).text() === cfztAdmin.showDetailsText ? cfztAdmin.hideDetailsText : cfztAdmin.showDetailsText);
        });
    });

})(jQuery);