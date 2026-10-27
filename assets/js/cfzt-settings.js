/**
 * Zero Trust Login for Cloudflare: settings page
 *
 * Strings and nonces arrive on the cfztSettings object (wp_localize_script).
 */
jQuery(document).ready(function($) {
    'use strict';

    var i18n = cfztSettings.i18n;
    var nonces = cfztSettings.nonces;

    // Translations are inserted into markup below, so encode them first.
    function escHtml(value) {
        return String(value === null || value === undefined ? '' : value).replace(/[&<>"']/g, function(c) {
            return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'}[c];
        });
    }

    var currentStep = 1;
    var totalSteps = 3;

    // Toast notification function
    function showToast(message, type) {
        type = type || 'success';
        var icon = type === 'success' ? '✓' : '✕';
        var $toast = $('<div class="cfzt-toast ' + type + '">')
            .append($('<span class="cfzt-toast-icon">').text(icon))
            .append($('<span>').text(message));

        $('body').append($toast);

        setTimeout(function() {
            $toast.fadeOut(300, function() {
                $(this).remove();
            });
        }, 3000);
    }

    // Copy to clipboard functionality
    $('.cfzt-copy-btn').on('click', function(e) {
        e.preventDefault();
        var targetId = $(this).data('clipboard-target');
        var $target = $('#' + targetId);
        var text = $target.text().trim();

        // Create temporary textarea
        var $temp = $('<textarea>');
        $('body').append($temp);
        $temp.val(text).select();

        try {
            document.execCommand('copy');
            showToast(i18n.copiedToClipboard, 'success');

            // Visual feedback on button
            var $btn = $(this);
            var originalHtml = $btn.html();
            $btn.html('<span class="dashicons dashicons-yes" style="margin-top: 3px;"></span> ' + escHtml(i18n.copied));
            $btn.addClass('button-primary');

            setTimeout(function() {
                $btn.html(originalHtml);
                $btn.removeClass('button-primary');
            }, 2000);
        } catch (err) {
            showToast(i18n.failedToCopyPleaseCopy, 'error');
        }

        $temp.remove();
    });

    // Mode toggle
    $('#cfzt-toggle-mode').on('click', function() {
        // Read the state before toggling: a panel mid-slide still counts as
        // visible. Decide from that, not from the (translated) button text.
        var wizardWillShow = !$('#cfzt-wizard-mode').is(':visible');

        $('#cfzt-wizard-mode').slideToggle();
        $('#cfzt-advanced-mode').slideToggle();

        $(this).text(wizardWillShow ? i18n.switchToAdvancedMode : i18n.switchToWizardMode);
    });

    // Toggle remaining tasks
    $('.cfzt-toggle-tasks').on('click', function() {
        var tasksWillShow = !$('.cfzt-remaining-tasks').is(':visible');
        $('.cfzt-remaining-tasks').slideToggle();
        $(this).html(tasksWillShow
            ? escHtml(i18n.hideRemainingTasks) + ' ▲'
            : escHtml(i18n.viewRemainingTasks) + ' ▼');
    });

    // Contextual help tooltips
    var activeTooltip = null;

    $('.cfzt-help-icon').on('click', function(e) {
        e.stopPropagation();
        var $icon = $(this);
        var tooltipText = $icon.data('tooltip');

        // Remove any existing tooltips
        $('.cfzt-tooltip').remove();

        // If clicking the same icon, just close
        if (activeTooltip === $icon[0]) {
            activeTooltip = null;
            return;
        }

        // Create new tooltip
        var $tooltip = $('<div class="cfzt-tooltip active">' + tooltipText + '</div>');
        $('body').append($tooltip);

        // Position tooltip
        var iconOffset = $icon.offset();
        var iconHeight = $icon.outerHeight();
        var tooltipWidth = $tooltip.outerWidth();

        $tooltip.css({
            top: iconOffset.top + iconHeight + 10,
            left: Math.max(10, iconOffset.left - (tooltipWidth / 2) + 9) // Center under icon
        });

        // Adjust if tooltip goes off screen
        var tooltipRight = $tooltip.offset().left + tooltipWidth;
        var windowWidth = $(window).width();
        if (tooltipRight > windowWidth - 10) {
            $tooltip.css('left', windowWidth - tooltipWidth - 10);
        }

        activeTooltip = $icon[0];
    });

    // Close tooltip when clicking elsewhere
    $(document).on('click', function() {
        $('.cfzt-tooltip').remove();
        activeTooltip = null;
    });

    // Close tooltip on escape key
    $(document).on('keydown', function(e) {
        if (e.key === 'Escape') {
            $('.cfzt-tooltip').remove();
            activeTooltip = null;
        }
    });

    // Radio card selection
    $('.cfzt-radio-card input[type="radio"]').on('change', function() {
        $('.cfzt-radio-card').removeClass('selected');
        $(this).closest('.cfzt-radio-card').addClass('selected');

    });

    // Navigation
    $('#cfzt-next-step').on('click', function() {
        if (currentStep < totalSteps) {
            // Validate current step
            if (!validateStep(currentStep)) {
                return;
            }

            currentStep++;
            showStep(currentStep);
        }
    });

    $('#cfzt-prev-step').on('click', function() {
        if (currentStep > 1) {
            currentStep--;
            showStep(currentStep);
        }
    });

    // Tab click navigation
    $('.cfzt-wizard-tab').on('click', function() {
        var step = parseInt($(this).data('step'));
        if (step < currentStep || step === 1) {
            currentStep = step;
            showStep(currentStep);
        }
    });

    function showStep(step) {
        // Update steps
        $('.cfzt-wizard-step').removeClass('active');
        $('.cfzt-wizard-step[data-step="' + step + '"]').addClass('active');

        // Update tabs
        $('.cfzt-wizard-tab').removeClass('active');
        $('.cfzt-wizard-tab[data-step="' + step + '"]').addClass('active');

        // Mark completed tabs
        $('.cfzt-wizard-tab').each(function() {
            var tabStep = parseInt($(this).data('step'));
            if (tabStep < step) {
                $(this).addClass('completed');
            } else {
                $(this).removeClass('completed');
            }
        });

        // Update buttons
        if (step === 1) {
            $('#cfzt-prev-step').hide();
        } else {
            $('#cfzt-prev-step').show();
        }

        if (step === totalSteps) {
            $('#cfzt-next-step').hide();
            $('#cfzt-save-btn').show();

            // Populate review
            populateReview();
        } else {
            $('#cfzt-next-step').show();
            $('#cfzt-save-btn').hide();
        }
    }

    function validateStep(step) {
        if (step === 2) {
            if (!$('#cfzt_team_domain').val()) {
                alert(i18n.pleaseEnterYourTeamDomain);
                return false;
            }
            if (!$('#cfzt_client_id').val()) {
                alert(i18n.pleaseEnterYourClientId);
                return false;
            }
            // An empty secret field means "keep the saved one" once a secret exists.
            var $secret = $('#cfzt_client_secret');
            if (!$secret.val() && $secret.data('has-secret') !== 1) {
                alert(i18n.pleaseEnterYourClientSecret);
                return false;
            }
        }
        return true;
    }

    // Everything here is the admin's own input, but build it with text() so
    // nothing is ever interpreted as markup.
    function populateReview() {
        var $list = $('#cfzt-review-list').empty();

        function row(label, value) {
            $('<li>').text(label + ': ').append($('<strong>').text(value)).appendTo($list);
        }

        var clientId = $('#cfzt_client_id').val() || '';
        var $secret = $('#cfzt_client_secret');
        var secretState = $secret.val()
            ? i18n.newSecretEntered
            : ($secret.data('has-secret') === 1
                ? i18n.keepingSavedSecret
                : i18n.notSet);

        row(i18n.authenticationMethod, 'OIDC');
        row(i18n.teamDomain, $('#cfzt_team_domain').val());
        row(i18n.applicationType, $('#cfzt_app_type option:selected').text());
        row(i18n.clientId, clientId.length > 20 ? clientId.substring(0, 20) + '…' : clientId);
        row(i18n.clientSecret, secretState);
        row(i18n.loginMode, $('#cfzt_login_mode option:selected').text());
        row(i18n.autoCreateUsers, $('#cfzt_auto_create_users').val() === 'yes'
            ? i18n.enabled
            : i18n.disabled);
        row(i18n.defaultRole, $('#cfzt_default_role option:selected').text());
    }

    // Initialize
    showStep(1);

    // Keyboard shortcuts
    $(document).on('keydown', function(e) {
        // Cmd/Ctrl + S to save
        if ((e.metaKey || e.ctrlKey) && e.key === 's') {
            e.preventDefault();

            // Check which form is visible and submit it
            if ($('#cfzt-wizard-mode').is(':visible')) {
                if (currentStep === totalSteps) {
                    $('#cfzt-save-btn').click();
                    showToast(i18n.savingConfiguration, 'success');
                }
            } else if ($('#cfzt-advanced-mode').is(':visible')) {
                $('#cfzt-advanced-mode form').submit();
                showToast(i18n.savingConfiguration, 'success');
            }
        }

        // Escape closes tooltips only (handled above). It used to click every
        // notice's dismiss button too, which permanently dismissed the
        // "SAML was removed" warning for anyone who pressed Escape once.
    });

    // Show keyboard hint tooltip on form focus
    var keyboardHintShown = false;
    $('form input, form select, form textarea').one('focus', function() {
        if (!keyboardHintShown) {
            keyboardHintShown = true;
            var hint = $('<div class="cfzt-toast" style="bottom: 80px; background: #2271b1;">' +
                '<span class="dashicons dashicons-info" style="margin-top: 3px;"></span>' +
                // This string carries its own <strong> markup on purpose.
                '<span>' + i18n.tipPressStrongCtrlCmd + '</span>' +
                '</div>');
            $('body').append(hint);
            setTimeout(function() {
                hint.fadeOut(300, function() { $(this).remove(); });
            }, 4000);
        }
    });

    // Test connection functionality
    function testConnection($button, $resultsContainer) {
        var originalHtml = $button.html();
        $button.prop('disabled', true).html('<span class="dashicons dashicons-update spin" style="margin-top: 3px;"></span> ' + escHtml(i18n.testing));

        if ($resultsContainer) {
            $resultsContainer.hide().html('');
        }

        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'cfzt_test_connection',
                nonce: nonces.testConnection
            },
            success: function(response) {
                var html = '';

                if (response.success) {
                    html = '<div class="cfzt-success-box" style="margin-top: 15px;">';
                    html += '<strong style="color: #00a32a;">✓ ' + response.data.message + '</strong>';

                    if (response.data.details && response.data.details.length > 0) {
                        html += '<ul style="margin: 10px 0 0 20px;">';
                        response.data.details.forEach(function(detail) {
                            html += '<li>' + detail + '</li>';
                        });
                        html += '</ul>';
                    }

                    if (response.data.warnings && response.data.warnings.length > 0) {
                        html += '<div style="margin-top: 10px; padding: 10px; background: rgba(255, 193, 7, 0.1); border-left: 3px solid #ffc107;">';
                        html += '<strong>⚠ ' + escHtml(i18n.warnings) + '</strong><ul style="margin: 5px 0 0 20px;">';
                        response.data.warnings.forEach(function(warning) {
                            html += '<li>' + warning + '</li>';
                        });
                        html += '</ul></div>';
                    }

                    html += '</div>';
                    showToast(i18n.connectionTestPassed, 'success');
                } else {
                    html = '<div class="cfzt-warning-box" style="margin-top: 15px; background: #fcf2f2; border-left-color: #d63638;">';
                    html += '<strong style="color: #d63638;">✗ ' + (response.data.message || escHtml(i18n.connectionTestFailed)) + '</strong>';

                    if (response.data.issues && response.data.issues.length > 0) {
                        html += '<ul style="margin: 10px 0 0 20px;">';
                        response.data.issues.forEach(function(issue) {
                            html += '<li>' + issue + '</li>';
                        });
                        html += '</ul>';
                    }

                    if (response.data.warnings && response.data.warnings.length > 0) {
                        html += '<div style="margin-top: 10px; padding: 10px; background: rgba(255, 193, 7, 0.1); border-left: 3px solid #ffc107;">';
                        html += '<strong>⚠ ' + escHtml(i18n.additionalWarnings) + '</strong><ul style="margin: 5px 0 0 20px;">';
                        response.data.warnings.forEach(function(warning) {
                            html += '<li>' + warning + '</li>';
                        });
                        html += '</ul></div>';
                    }

                    html += '</div>';
                    showToast(i18n.connectionTestFailed, 'error');
                }

                if ($resultsContainer) {
                    $resultsContainer.html(html).slideDown();
                }
            },
            error: function() {
                var html = '<div class="cfzt-warning-box" style="margin-top: 15px; background: #fcf2f2; border-left-color: #d63638;">';
                html += '<strong style="color: #d63638;">✗ ' + escHtml(i18n.connectionTestFailed) + '</strong>';
                html += '<p>' + escHtml(i18n.anUnexpectedErrorOccurredPlease) + '</p>';
                html += '</div>';

                if ($resultsContainer) {
                    $resultsContainer.html(html).slideDown();
                }
                showToast(i18n.connectionTestFailed, 'error');
            },
            complete: function() {
                $button.prop('disabled', false).html(originalHtml);
            }
        });
    }

    // Test connection from wizard
    $('#cfzt-test-connection-wizard').on('click', function() {
        testConnection($(this), $('#cfzt-test-results-wizard'));
    });

    // Test connection from success message
    $(document).on('click', '#cfzt-test-connection-btn', function() {
        testConnection($(this), null);
    });

    // Live validation for form fields
    function validateField($field, rules) {
        var value = $field.val().trim();
        var $validationMsg = $field.next('.cfzt-validation-message');

        // Create validation message element if it doesn't exist
        if ($validationMsg.length === 0) {
            $validationMsg = $('<span class="cfzt-validation-message"></span>');
            $field.after($validationMsg);
        }

        // Remove existing classes
        $field.removeClass('cfzt-field-valid cfzt-field-invalid cfzt-field-warning');
        $validationMsg.removeClass('valid invalid warning').text('');

        if (value === '') {
            return; // Don't validate empty fields (unless required)
        }

        var isValid = true;
        var message = '';
        var isWarning = false;

        // Apply validation rules
        if (rules.teamDomain) {
            if (!value.match(/^[a-z0-9][a-z0-9-]*\.cloudflareaccess\.com$/i)) {
                isValid = false;
                message = i18n.shouldEndWithCloudflareaccessCom;
            } else {
                message = i18n.validTeamDomainFormat;
            }
        }

        if (rules.clientId) {
            if (value.length < 16) {
                isValid = false;
                message = i18n.clientIdSeemsTooShort;
            } else if (!value.match(/^[a-f0-9]+$/i)) {
                isWarning = true;
                message = i18n.clientIdUsuallyContainsOnly;
            } else {
                message = i18n.validClientIdFormat;
            }
        }

        if (rules.clientSecret) {
            if (value === '[SET VIA CONSTANT]') {
                isWarning = true;
                message = i18n.valueSetViaConstantCannot;
            } else if (value.length < 16) {
                isValid = false;
                message = i18n.clientSecretSeemsTooShort;
            } else {
                message = i18n.clientSecretLooksGood;
            }
        }

        if (rules.url) {
            try {
                new URL(value);
                message = i18n.validUrlFormat;
            } catch (e) {
                isValid = false;
                message = i18n.pleaseEnterAValidUrl;
            }
        }

        if (rules.alphanumeric) {
            if (!value.match(/^[a-z0-9-_]+$/i)) {
                isValid = false;
                message = i18n.shouldContainOnlyLettersNumbers;
            } else {
                message = i18n.validFormat;
            }
        }

        // Update field appearance
        if (isValid && !isWarning) {
            $field.addClass('cfzt-field-valid');
            $validationMsg.addClass('valid').text(message);
        } else if (isWarning) {
            $field.addClass('cfzt-field-warning');
            $validationMsg.addClass('warning').text(message);
        } else {
            $field.addClass('cfzt-field-invalid');
            $validationMsg.addClass('invalid').text(message);
        }

        return isValid && !isWarning;
    }

    // Attach validation to fields
    $('#cfzt_team_domain').on('input blur', function() {
        validateField($(this), { teamDomain: true });
    });

    $('#cfzt_client_id').on('input blur', function() {
        validateField($(this), { clientId: true });
    });

    $('#cfzt_client_secret').on('input blur', function() {
        validateField($(this), { clientSecret: true });
    });

    // Trigger validation on existing values (for edit mode)
    setTimeout(function() {
        $('#cfzt_team_domain').each(function() {
            if ($(this).val().trim() !== '') {
                validateField($(this), { teamDomain: true });
            }
        });

        if ($('#cfzt_client_id').val().trim() !== '') {
            validateField($('#cfzt_client_id'), { clientId: true });
        }
    }, 500);

    // Role mapping - Add new row
    var roleMappingIndex = parseInt(cfztSettings.roleMappingCount, 10) || 0;
    $('#cfzt-add-role-mapping').on('click', function() {
        var roleOptions = '';
        $.each(cfztSettings.roles, function(roleValue, roleName) {
            roleOptions += '<option value="' + cfztEsc(roleValue) + '">' + cfztEsc(roleName) + '</option>';
        });

        var newRow = '<div class="cfzt-role-mapping-row" style="display: flex; gap: 10px; margin-bottom: 10px; align-items: center;">' +
            '<input type="text" name="cfzt_settings[role_mapping][' + roleMappingIndex + '][group]" placeholder="' + escHtml(i18n.cloudflareGroupName) + '" class="regular-text" style="flex: 1;">' +
            '<span>→</span>' +
            '<select name="cfzt_settings[role_mapping][' + roleMappingIndex + '][role]" class="regular-text" style="flex: 1;">' + roleOptions + '</select>' +
            '<button type="button" class="button cfzt-remove-mapping" style="color: #d63638;"><span class="dashicons dashicons-trash"></span></button>' +
            '</div>';

        $('#cfzt-role-mappings').append(newRow);
        roleMappingIndex++;
    });

    // Role mapping - Remove row
    // Removing the last row is allowed: an empty list simply disables mapping
    // (the hidden role_mapping_submitted field tells the server it was cleared
    // on purpose rather than omitted by a form without these fields).
    $(document).on('click', '.cfzt-remove-mapping', function() {
        $(this).closest('.cfzt-role-mapping-row').remove();
    });

    // Import/Export functionality
    var importFileData = null;

    // Enable import button when file is selected
    $('#cfzt-import-file').on('change', function() {
        var file = this.files[0];
        if (file && file.type === 'application/json') {
            var reader = new FileReader();
            reader.onload = function(e) {
                importFileData = e.target.result;
                $('#cfzt-import-settings').prop('disabled', false);
            };
            reader.readAsText(file);
        } else {
            importFileData = null;
            $('#cfzt-import-settings').prop('disabled', true);
            if (file) {
                alert(i18n.pleaseSelectAValidJson);
            }
        }
    });

    // Export settings
    $('#cfzt-export-settings').on('click', function() {
        var $btn = $(this);
        var originalHtml = $btn.html();

        $btn.prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span> ' + escHtml(i18n.exporting));

        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'cfzt_export_settings',
                nonce: nonces.importExport
            },
            success: function(response) {
                if (response.success) {
                    // Create download link
                    var dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(response.data.data, null, 2));
                    var downloadAnchor = document.createElement('a');
                    downloadAnchor.setAttribute("href", dataStr);
                    downloadAnchor.setAttribute("download", response.data.filename);
                    document.body.appendChild(downloadAnchor);
                    downloadAnchor.click();
                    downloadAnchor.remove();

                    showToast(i18n.settingsExportedSuccessfully, 'success');

                    var html = '<div class="notice notice-success"><p>';
                    html += '<strong>' + escHtml(i18n.exportSuccessful) + '</strong><br>';
                    html += escHtml(i18n.yourSettingsHaveBeenDownloaded) + ' <code>' + response.data.filename + '</code>';
                    html += '</p></div>';
                    $('#cfzt-import-export-result').html(html);
                } else {
                    showToast(response.data || i18n.exportFailed, 'error');
                }
            },
            error: function() {
                showToast(i18n.exportFailedPleaseTryAgain, 'error');
            },
            complete: function() {
                $btn.prop('disabled', false).html(originalHtml);
            }
        });
    });

    // Import settings
    $('#cfzt-import-settings').on('click', function() {
        if (!importFileData) {
            alert(i18n.pleaseSelectAFileFirst);
            return;
        }

        if (!confirm(i18n.warningThisWillReplaceYour)) {
            return;
        }

        var $btn = $(this);
        var originalHtml = $btn.html();

        $btn.prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span> ' + escHtml(i18n.importing));

        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'cfzt_import_settings',
                nonce: nonces.importExport,
                import_data: importFileData
            },
            success: function(response) {
                if (response.success) {
                    showToast(i18n.settingsImportedSuccessfullyReloadingPage, 'success');

                    var html = '<div class="notice notice-success"><p>';
                    html += '<strong>' + escHtml(i18n.importSuccessful) + '</strong><br>';
                    html += response.data + '<br>';
                    html += escHtml(i18n.thePageWillReloadIn);
                    html += '</p></div>';
                    $('#cfzt-import-export-result').html(html);

                    // Reload page after 2 seconds
                    setTimeout(function() {
                        window.location.reload();
                    }, 2000);
                } else {
                    showToast(response.data || i18n.importFailed, 'error');

                    var html = '<div class="notice notice-error"><p>';
                    html += '<strong>' + escHtml(i18n.importFailed2) + '</strong><br>';
                    html += response.data;
                    html += '</p></div>';
                    $('#cfzt-import-export-result').html(html);

                    $btn.prop('disabled', false).html(originalHtml);
                }
            },
            error: function() {
                showToast(i18n.importFailedPleaseTryAgain, 'error');
                $btn.prop('disabled', false).html(originalHtml);
            }
        });
    });

    /* ------------------------------------------------------------------
     * Automatic Cloudflare provisioning
     * ------------------------------------------------------------------ */

    var cfztSetupNonce = nonces.setup;

    // Cloudflare error messages are echoed back to us, so escape before
    // injecting them as HTML.
    function cfztEsc(value) {
        return $('<div>').text(value === null || value === undefined ? '' : String(value)).html();
    }

    function cfztStatus(type, message, items) {
        var cls = 'cfzt-info-box';
        if (type === 'error') {
            cls = 'cfzt-warning-box';
        } else if (type === 'success') {
            cls = 'cfzt-success-box';
        }

        var html = '<div class="' + cls + '"><p style="margin:0;"><strong>' + cfztEsc(message) + '</strong></p>';

        if (items && items.length) {
            html += '<ul style="margin:8px 0 0 20px; list-style: disc;">';
            $.each(items, function(i, item) {
                html += '<li>' + cfztEsc(item) + '</li>';
            });
            html += '</ul>';
        }

        html += '</div>';
        $('#cfzt-auto-status').html(html).show();
    }

    function cfztClearStatus() {
        $('#cfzt-auto-status').hide().empty();
    }

    // Keep the policy inputs in step with the chosen mode.
    $('#cfzt-policy-mode').on('change', function() {
        var mode = $(this).val();

        $('#cfzt-policy-value-wrap').toggle(mode !== 'everyone');
        $('#cfzt-everyone-warning').toggle(mode === 'everyone');

        if (mode === 'emails') {
            $('#cfzt-policy-value-label').text(i18n.allowedEmailAddresses);
        } else {
            $('#cfzt-policy-value-label').text(i18n.allowedEmailDomains);
        }
    });

    $('#cfzt-connect-btn').on('click', function() {
        var $btn = $(this);
        var originalText = $btn.text();
        var token = $.trim($('#cfzt-cf-token').val());

        if (!token) {
            cfztStatus('error', i18n.pasteYourCloudflareApiToken);
            return;
        }

        cfztClearStatus();
        $btn.prop('disabled', true).text(i18n.connecting);

        $.post(ajaxurl, {
            action: 'cfzt_connect_cloudflare',
            nonce: cfztSetupNonce,
            token: token
        }).done(function(response) {
            if (!response || !response.success) {
                var msg = (response && response.data && response.data.message)
                    ? response.data.message
                    : i18n.couldNotConnectToCloudflare;
                cfztStatus('error', msg);
                return;
            }

            var accounts = response.data.accounts || [];
            var $select = $('#cfzt-cf-account').empty();
            var readyCount = 0;

            $.each(accounts, function(i, account) {
                var label = account.name;

                if (account.ready) {
                    readyCount++;
                    label += ' — ' + account.team_domain;
                } else {
                    label += ' — ' + i18n.noZeroTrustTeamDomain;
                }

                $('<option>')
                    .val(account.id)
                    .text(label)
                    .prop('disabled', !account.ready)
                    .appendTo($select);
            });

            // Nothing to provision into: send them to set up Zero Trust first.
            if (readyCount === 0) {
                var notices = [];
                $.each(accounts, function(i, account) {
                    if (account.notice) {
                        notices.push(account.name + ': ' + account.notice);
                    }
                });
                cfztStatus('error', i18n.noneOfTheAccountsThis, notices);
                return;
            }

            // Preselect the first usable account.
            $select.find('option:not(:disabled)').first().prop('selected', true);

            $('#cfzt-auto-phase-token').hide();
            $('#cfzt-auto-phase-configure').show();
            $('#cfzt-account-wrap').toggle(accounts.length > 1);

            cfztStatus('info', accounts.length > 1
                ? i18n.tokenAcceptedChooseAnAccount
                : i18n.tokenAcceptedConfirmWhoShould);
        }).fail(function() {
            cfztStatus('error', i18n.theRequestFailedCheckYour);
        }).always(function() {
            $btn.prop('disabled', false).text(originalText);
        });
    });

    $('#cfzt-auto-back-btn').on('click', function() {
        $('#cfzt-auto-phase-configure').hide();
        $('#cfzt-auto-phase-token').show();
        $('#cfzt-cf-token').val('').focus();
        cfztClearStatus();
    });

    // Already provisioned: reveal the token form only on request.
    $('#cfzt-reprovision-btn').on('click', function() {
        $('#cfzt-provisioned-state').slideUp();
        $('#cfzt-auto-setup').slideDown();
        $('#cfzt-cf-token').focus();
    });

    // Once the credentials have been saved, nothing else on this page may
    // write to the option until it reloads: both forms still hold the values
    // rendered before provisioning and would overwrite the new ones.
    function cfztLockPage() {
        $('#cfzt-toggle-mode, #cfzt-next-step, #cfzt-prev-step, #cfzt-save-btn').prop('disabled', true);
        $('#cfzt-advanced-mode form :input').prop('disabled', true);
        $('#cfzt-wizard-form').on('submit', function(e) { e.preventDefault(); });
    }

    function cfztProvision(replaceExisting) {
        var $btn = $('#cfzt-provision-btn');
        var originalText = $btn.text();

        cfztClearStatus();
        $btn.prop('disabled', true).text(i18n.creatingApplication);

        $.post(ajaxurl, {
            action: 'cfzt_provision_app',
            nonce: cfztSetupNonce,
            token: $.trim($('#cfzt-cf-token').val()),
            account_id: $('#cfzt-cf-account').val(),
            app_name: $('#cfzt-app-name').val(),
            policy_mode: $('#cfzt-policy-mode').val(),
            policy_value: $('#cfzt-policy-value').val(),
            replace_existing: replaceExisting ? 'true' : 'false'
        }).done(function(response) {
            if (!response || !response.success) {
                var data = response && response.data ? response.data : {};
                var msg = data.message || i18n.provisioningFailed;

                // An existing app is recoverable: offer to replace it.
                if (data.can_replace) {
                    cfztStatus('error', msg);
                    $('#cfzt-auto-status').append(
                        $('<p>').append(
                            $('<button type="button" class="button">')
                                .text(i18n.replaceTheExistingApplication)
                                .on('click', function() { cfztProvision(true); })
                        )
                    );
                    return;
                }

                cfztStatus('error', msg);
                return;
            }

            var result = response.data || {};

            // Credentials are already saved server side. Lock every other
            // form on the page and reload so everything renders from the
            // database rather than from stale pre-provisioning values.
            $('#cfzt-auto-phase-configure').hide();
            $('#cfzt-cf-token').val('');
            cfztLockPage();

            var warnings = result.warnings || [];
            cfztStatus(
                'success',
                i18n.doneTheAccessApplicationWas,
                warnings
            );

            $('#cfzt-auto-status').append(
                $('<p>').append(
                    $('<button type="button" class="button button-primary">')
                        .text(i18n.continue)
                        .on('click', function() { window.location.reload(); })
                ).append(
                    $('<span style="margin-left:10px;">').text(
                        i18n.youCanNowDeleteThe
                    )
                )
            );

            showToast(i18n.cloudflareApplicationCreated, 'success');

            // Give the reader a moment with any warnings, then reload. Without
            // warnings there is nothing to read, so go straight away.
            setTimeout(function() { window.location.reload(); }, warnings.length ? 8000 : 1500);
        }).fail(function() {
            cfztStatus('error', i18n.theRequestFailedCheckYour);
        }).always(function() {
            $btn.prop('disabled', false).text(originalText);
        });
    }

    $('#cfzt-provision-btn').on('click', function() {
        cfztProvision(false);
    });
});
