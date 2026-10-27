/**
 * Zero Trust Login for Cloudflare: "Use a backup code" toggle on wp-login.php
 */
document.addEventListener('DOMContentLoaded', function() {
    'use strict';

    var i18n = cfztLoginBackup.i18n;
    var primary = !!cfztLoginBackup.primary;
    var link = document.getElementById('cfzt-use-backup-code');
    var form = document.getElementById('cfzt-backup-code-form');
    var input = document.getElementById('cfzt_backup_code');
    var loginForm = document.getElementById('loginform');
    var wrapper = document.querySelector('.cfzt-login-wrapper');

    if (!link || !form) {
        return;
    }

    // In primary mode the password form is hidden, so the toggle has
    // to live outside it: move it next to the Cloudflare button and
    // reveal the form (minus the password field) on demand.
    if (primary && wrapper) {
        wrapper.appendChild(link.parentNode);
    }

    function setBackupMode(on) {
        document.body.classList.toggle('cfzt-backup-mode', on);
        form.style.display = on ? 'block' : 'none';
        link.textContent = on
            ? i18n.useRegularLogin
            : i18n.useABackupCode;
        if (on) {
            var userField = document.getElementById('user_login');
            (userField && !userField.value ? userField : input).focus();
        } else {
            input.value = '';
        }
        if (primary && loginForm) {
            loginForm.style.display = on ? 'block' : 'none';
        }
    }

    link.addEventListener('click', function(e) {
        e.preventDefault();
        setBackupMode(form.style.display === 'none');
    });
});
