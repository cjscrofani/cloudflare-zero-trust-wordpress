<?php
/**
 * Admin settings page template
 *
 * @package CloudflareZeroTrustLogin
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Get security status
$security = new CFZT_Security();
$security_status = $security->get_security_status();
$options = CFZT_Plugin::get_option();

// Check if setup is complete
$is_configured = !empty($options['team_domain']) && !empty($options['client_id']) && !empty($options['client_secret']);
$has_saved_secret = !empty($options['client_secret']) && '' !== $security->get_client_secret();
$secret_from_constant = defined('CFZT_CLIENT_SECRET') && CFZT_CLIENT_SECRET;
$constants_defined = $secret_from_constant || (defined('CFZT_CLIENT_ID') && CFZT_CLIENT_ID);

// Was the Access application created by this plugin?
$provisioned = !empty($options['provisioned_app_id']);

// Get setup progress
$setup_progress = CFZT_Plugin::get_setup_progress();
?>

<style>
/* No automatic dark mode here: the WordPress admin has no dark theme, so a
   prefers-color-scheme block only darkened this card while core-styled headings
   and labels stayed near-black, making the page unreadable. */
.cfzt-wizard-container {
    max-width: 900px;
    margin: 20px 0;
    background: #fff;
    border: 1px solid #ccd0d4;
    box-shadow: 0 1px 1px rgba(0,0,0,.04);
}

.cfzt-wizard-header {
    background: linear-gradient(135deg, #f38020, #f6821f);
    color: #fff;
    padding: 30px;
    text-align: center;
}

.cfzt-wizard-header h1 {
    color: #fff;
    margin: 0 0 10px 0;
    font-size: 28px;
}

.cfzt-wizard-header p {
    margin: 0;
    opacity: 0.9;
    font-size: 16px;
}

.cfzt-wizard-tabs {
    display: flex;
    background: #f0f0f1;
    border-bottom: 1px solid #ccd0d4;
    margin: 0;
    padding: 0;
}

.cfzt-wizard-tab {
    flex: 1;
    padding: 15px 20px;
    text-align: center;
    cursor: pointer;
    border-bottom: 3px solid transparent;
    transition: all 0.3s;
    font-weight: 600;
    color: #50575e;
}

.cfzt-wizard-tab.active {
    background: #fff;
    border-bottom-color: #f38020;
    color: #f38020;
}

.cfzt-wizard-tab.completed {
    color: #00a32a;
}

.cfzt-wizard-tab:hover:not(.active) {
    background: #fff;
}

.cfzt-wizard-step {
    padding: 30px;
    display: none;
}

.cfzt-wizard-step.active {
    display: block;
}

.cfzt-step-title {
    font-size: 24px;
    margin: 0 0 10px 0;
    color: #1d2327;
}

.cfzt-step-description {
    font-size: 14px;
    color: #646970;
    margin: 0 0 25px 0;
}

.cfzt-form-group {
    margin-bottom: 25px;
}

.cfzt-form-group label {
    display: block;
    font-weight: 600;
    margin-bottom: 8px;
    color: #1d2327;
}

.cfzt-form-group .description {
    font-size: 13px;
    color: #646970;
    margin-top: 5px;
    line-height: 1.5;
}

.cfzt-form-group input[type="text"],
.cfzt-form-group input[type="password"],
.cfzt-form-group select,
.cfzt-form-group textarea {
    width: 100%;
    max-width: 500px;
}

.cfzt-wizard-actions {
    display: flex;
    justify-content: space-between;
    padding: 20px 30px;
    background: #f6f7f7;
    border-top: 1px solid #ccd0d4;
}

.cfzt-info-box {
    background: #e7f7fe;
    border-left: 4px solid #2271b1;
    padding: 15px;
    margin: 20px 0;
}

.cfzt-warning-box {
    background: #fcf9e8;
    border-left: 4px solid #dba617;
    padding: 15px;
    margin: 20px 0;
}

.cfzt-success-box {
    background: #edfaef;
    border-left: 4px solid #00a32a;
    padding: 15px;
    margin: 20px 0;
}

.cfzt-code-block {
    background: #f6f7f7;
    border: 1px solid #ccd0d4;
    padding: 15px;
    font-family: Consolas, Monaco, monospace;
    font-size: 13px;
    overflow-x: auto;
    margin: 15px 0;
}

.cfzt-wizard-mode-toggle {
    text-align: right;
    padding: 15px 30px;
    background: #f6f7f7;
    border-bottom: 1px solid #ccd0d4;
}

.cfzt-checklist {
    list-style: none;
    padding: 0;
    margin: 20px 0;
}

.cfzt-checklist li {
    padding: 10px 0 10px 30px;
    position: relative;
}

.cfzt-checklist li:before {
    content: "✓";
    position: absolute;
    left: 0;
    color: #00a32a;
    font-weight: bold;
}

.cfzt-radio-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
    margin: 15px 0;
}

.cfzt-radio-card {
    border: 2px solid #dcdcde;
    border-radius: 4px;
    padding: 20px;
    cursor: pointer;
    transition: all 0.3s;
}

.cfzt-radio-card:hover {
    border-color: #f38020;
}

.cfzt-radio-card input[type="radio"] {
    margin-right: 10px;
}

.cfzt-radio-card.selected {
    border-color: #f38020;
    background: #fff7f0;
}

.cfzt-radio-card-title {
    font-weight: 600;
    font-size: 16px;
    margin-bottom: 8px;
}

.cfzt-radio-card-desc {
    font-size: 13px;
    color: #646970;
}

/* Setup Progress Indicator */
.cfzt-setup-progress-container {
    padding: 20px;
    background: #f0f6fc;
    border-bottom: 1px solid #ccd0d4;
}

.cfzt-progress-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;
}

.cfzt-progress-title {
    font-weight: 600;
    font-size: 14px;
    display: flex;
    align-items: center;
    gap: 6px;
}

.cfzt-progress-percentage {
    font-weight: 700;
    font-size: 18px;
    color: #f38020;
}

.cfzt-progress-bar-wrapper {
    height: 8px;
    background: #ddd;
    border-radius: 4px;
    overflow: hidden;
    margin-bottom: 10px;
}

.cfzt-progress-bar {
    height: 100%;
    background: linear-gradient(90deg, #f38020, #f6821f);
    border-radius: 4px;
    transition: width 0.3s ease;
}

.cfzt-progress-details {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 13px;
    color: #646970;
}

.cfzt-toggle-tasks {
    color: #2271b1;
    text-decoration: none;
    font-size: 13px;
}

.cfzt-toggle-tasks:hover {
    color: #135e96;
}

.cfzt-remaining-tasks {
    margin-top: 15px;
    padding: 15px;
    background: #fff;
    border: 1px solid #ddd;
    border-radius: 4px;
}

.cfzt-remaining-tasks ul {
    list-style: none;
    margin: 0;
    padding: 0;
}

.cfzt-remaining-tasks li {
    padding: 8px 0 8px 24px;
    position: relative;
    color: #646970;
}

.cfzt-remaining-tasks li:before {
    content: "○";
    position: absolute;
    left: 0;
    color: #f38020;
    font-weight: bold;
}

.cfzt-setup-complete {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 15px 20px;
    background: #edfaef;
    border-bottom: 1px solid #ccd0d4;
    color: #1d2327;
}

.cfzt-setup-complete strong {
    color: #00a32a;
}

/* Contextual Help Tooltips */
.cfzt-help-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    background: #2271b1;
    color: white;
    font-size: 12px;
    font-weight: 600;
    cursor: help;
    margin-left: 6px;
    position: relative;
}

.cfzt-help-icon:hover {
    background: #135e96;
}

.cfzt-tooltip {
    position: absolute;
    background: #1d2327;
    color: #fff;
    padding: 12px 15px;
    border-radius: 4px;
    font-size: 13px;
    line-height: 1.5;
    max-width: 300px;
    z-index: 10000;
    box-shadow: 0 2px 8px rgba(0,0,0,0.3);
    display: none;
    font-weight: normal;
    text-align: left;
}

.cfzt-tooltip.active {
    display: block;
}

.cfzt-tooltip::before {
    content: '';
    position: absolute;
    top: -6px;
    left: 20px;
    width: 0;
    height: 0;
    border-left: 6px solid transparent;
    border-right: 6px solid transparent;
    border-bottom: 6px solid #1d2327;
}

.cfzt-tooltip a {
    color: #72aee6;
    text-decoration: underline;
}

.cfzt-tooltip a:hover {
    color: #a5d2ff;
}

/* Import/Export Boxes */
.cfzt-import-export-box {
    background: #fff;
    border: 1px solid #ccd0d4;
    border-radius: 4px;
    padding: 20px;
}

.cfzt-import-export-box h3 {
    margin: 0 0 10px 0;
    font-size: 16px;
}

.cfzt-import-export-box p {
    margin: 0 0 15px 0;
    font-size: 13px;
    color: #646970;
}

/* Mobile responsiveness */
@media (max-width: 782px) {
    .cfzt-wizard-header {
        padding: 20px;
    }

    .cfzt-wizard-header h1 {
        font-size: 22px;
    }

    .cfzt-wizard-tabs {
        flex-direction: column;
    }

    .cfzt-wizard-tab {
        border-bottom: 1px solid #ccd0d4;
        border-left: 3px solid transparent;
    }

    .cfzt-wizard-tab.active {
        border-left-color: #f38020;
        border-bottom-color: #ccd0d4;
    }

    .cfzt-wizard-step {
        padding: 20px;
    }

    .cfzt-step-title {
        font-size: 20px;
    }

    .cfzt-wizard-actions {
        flex-direction: column-reverse;
        gap: 10px;
    }

    .cfzt-wizard-actions > div {
        width: 100%;
    }

    .cfzt-wizard-actions button {
        width: 100%;
    }

    .cfzt-radio-cards {
        grid-template-columns: 1fr;
    }

    .cfzt-form-group input[type="text"],
    .cfzt-form-group input[type="password"],
    .cfzt-form-group select,
    .cfzt-form-group textarea {
        max-width: 100%;
    }

    .cfzt-code-block {
        font-size: 12px;
        overflow-x: auto;
    }

    .cfzt-toast {
        bottom: 10px;
        right: 10px;
        left: 10px;
        max-width: none;
    }

    .cfzt-info-box,
    .cfzt-warning-box,
    .cfzt-success-box {
        padding: 12px;
    }

    .cfzt-copy-btn {
        display: block;
        width: 100%;
        margin-top: 10px !important;
        margin-left: 0 !important;
        float: none !important;
    }
}

@media (max-width: 600px) {
    .cfzt-wizard-container {
        margin: 10px 0;
    }

    .cfzt-wizard-mode-toggle {
        padding: 10px 15px;
    }

    .cfzt-step-description {
        font-size: 13px;
    }

    .notice.cfzt-activation-notice > div {
        flex-direction: column;
        text-align: center;
    }

    .notice.cfzt-activation-notice svg {
        margin: 0 auto 15px;
    }
}
</style>

<div class="wrap">
    <div class="cfzt-wizard-container">
        <!-- Header -->
        <div class="cfzt-wizard-header">
            <h1><?php esc_html_e('Cloudflare Zero Trust Login', 'cf-zero-trust'); ?></h1>
            <p><?php esc_html_e('Secure WordPress authentication with Cloudflare Zero Trust', 'cf-zero-trust'); ?></p>
        </div>

        <!-- Setup Progress Indicator -->
        <?php if ($setup_progress['percentage'] < 100): ?>
        <div class="cfzt-setup-progress-container">
            <div class="cfzt-progress-header">
                <span class="cfzt-progress-title">
                    <span class="dashicons dashicons-admin-settings" style="font-size: 16px; width: 16px; height: 16px;"></span>
                    <?php _e('Setup Progress', 'cf-zero-trust'); ?>
                </span>
                <span class="cfzt-progress-percentage"><?php echo esc_html($setup_progress['percentage']); ?>%</span>
            </div>
            <div class="cfzt-progress-bar-wrapper">
                <div class="cfzt-progress-bar" style="width: <?php echo esc_attr($setup_progress['percentage']); ?>%;"></div>
            </div>
            <div class="cfzt-progress-details">
                <span><?php
                    /* translators: 1: completed task count, 2: total task count */
                    echo esc_html(sprintf(__('%1$d of %2$d tasks completed', 'cf-zero-trust'), $setup_progress['completed_count'], $setup_progress['total_count']));
                ?></span>
                <?php if (!empty($setup_progress['incomplete'])): ?>
                <button type="button" class="button-link cfzt-toggle-tasks">
                    <?php _e('View remaining tasks', 'cf-zero-trust'); ?> ▼
                </button>
                <?php endif; ?>
            </div>
            <?php if (!empty($setup_progress['incomplete'])): ?>
            <div class="cfzt-remaining-tasks" style="display: none;">
                <ul>
                    <?php foreach ($setup_progress['incomplete'] as $task): ?>
                    <li><?php echo esc_html($task); ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
            <?php endif; ?>
        </div>
        <?php elseif ($setup_progress['percentage'] === 100): ?>
        <div class="cfzt-setup-complete">
            <span class="dashicons dashicons-yes-alt" style="color: #00a32a; font-size: 20px;"></span>
            <strong><?php _e('Setup Complete!', 'cf-zero-trust'); ?></strong>
            <span><?php _e('Your Cloudflare Zero Trust integration is fully configured.', 'cf-zero-trust'); ?></span>
        </div>
        <?php endif; ?>

        <!-- Mode Toggle -->
        <div class="cfzt-wizard-mode-toggle">
            <button type="button" id="cfzt-toggle-mode" class="button">
                <?php echo $is_configured ? __('Switch to Wizard Mode', 'cf-zero-trust') : __('Switch to Advanced Mode', 'cf-zero-trust'); ?>
            </button>
        </div>

        <!-- Wizard Mode -->
        <div id="cfzt-wizard-mode" style="display: <?php echo $is_configured ? 'none' : 'block'; ?>;">
            <!-- Progress Tabs -->
            <div class="cfzt-wizard-tabs">
                <div class="cfzt-wizard-tab active" data-step="1">
                    <strong>1.</strong> <?php esc_html_e('Cloudflare Setup', 'cf-zero-trust'); ?>
                </div>
                <div class="cfzt-wizard-tab" data-step="2">
                    <strong>2.</strong> <?php esc_html_e('Configure', 'cf-zero-trust'); ?>
                </div>
                <div class="cfzt-wizard-tab" data-step="3">
                    <strong>3.</strong> <?php esc_html_e('Review', 'cf-zero-trust'); ?>
                </div>
            </div>

            <form method="post" action="options.php" id="cfzt-wizard-form">
                <?php settings_fields('cfzt_settings_group'); ?>

                <input type="hidden" name="cfzt_settings[auth_method]" value="oauth2">

                <!-- Step 1: Cloudflare Setup Instructions -->
                <div class="cfzt-wizard-step active" data-step="1">
                    <h2 class="cfzt-step-title"><?php esc_html_e('Set Up Cloudflare Zero Trust', 'cf-zero-trust'); ?></h2>
                    <p class="cfzt-step-description"><?php esc_html_e('Create the Access application automatically, or follow the manual steps in your Cloudflare dashboard.', 'cf-zero-trust'); ?></p>

                    <!-- OIDC Instructions -->
                    <div id="cfzt-step2-oidc">

                        <?php if ($provisioned) : ?>
                        <!-- Already provisioned by this plugin -->
                        <div class="cfzt-success-box" id="cfzt-provisioned-state">
                            <h3 style="margin-top: 0;">
                                <span class="dashicons dashicons-yes-alt" style="color: #00a32a;"></span>
                                <?php esc_html_e('Connected to Cloudflare', 'cf-zero-trust'); ?>
                            </h3>
                            <p style="margin: 0 0 10px;">
                                <?php esc_html_e('This plugin created the Access application for this site. There is nothing to do here unless you want to start over.', 'cf-zero-trust'); ?>
                            </p>
                            <ul style="margin: 0 0 10px 20px; list-style: disc;">
                                <li><?php esc_html_e('Team domain:', 'cf-zero-trust'); ?> <code><?php echo esc_html($options['team_domain'] ?? ''); ?></code></li>
                                <li><?php esc_html_e('Application ID:', 'cf-zero-trust'); ?> <code><?php echo esc_html($options['provisioned_app_id']); ?></code></li>
                                <?php if (!empty($options['provisioned_account_id'])) : ?>
                                <li><?php esc_html_e('Cloudflare account:', 'cf-zero-trust'); ?> <code><?php echo esc_html($options['provisioned_account_id']); ?></code></li>
                                <?php endif; ?>
                                <?php if (!empty($options['provisioned_at'])) : ?>
                                <li><?php
                                    /* translators: %s: date and time */
                                    echo esc_html(sprintf(__('Created: %s', 'cf-zero-trust'), mysql2date(get_option('date_format') . ' ' . get_option('time_format'), $options['provisioned_at'])));
                                ?></li>
                                <?php endif; ?>
                            </ul>
                            <p style="margin: 0;">
                                <button type="button" class="button" id="cfzt-reprovision-btn">
                                    <?php esc_html_e('Run automatic setup again', 'cf-zero-trust'); ?>
                                </button>
                                <span class="description" style="margin-left: 8px;"><?php esc_html_e('Replaces the Cloudflare application and issues new credentials.', 'cf-zero-trust'); ?></span>
                            </p>
                        </div>
                        <?php endif; ?>

                        <!-- Automatic provisioning -->
                        <div class="cfzt-auto-setup" id="cfzt-auto-setup" <?php echo $provisioned ? 'style="display:none;"' : ''; ?>>
                            <h3 style="margin-top: 0;">
                                <span class="dashicons dashicons-superhero-alt" style="color: #f38020;"></span>
                                <?php _e('Set this up for me', 'cf-zero-trust'); ?>
                            </h3>
                            <p class="cfzt-step-description">
                                <?php _e('Authorize once with a Cloudflare API token and this plugin will create the Access application, read your team domain, and fill in the credentials below. Nothing to copy by hand.', 'cf-zero-trust'); ?>
                            </p>

                            <?php if ($constants_defined) : ?>
                            <div class="cfzt-warning-box">
                                <?php echo wp_kses_post(__('<strong>Automatic setup is unavailable.</strong> <code>CFZT_CLIENT_ID</code> or <code>CFZT_CLIENT_SECRET</code> is defined in <code>wp-config.php</code>, and those values override anything saved here. Cloudflare shows a new client secret exactly once, so provisioning now would create an application whose secret could never be stored. Remove the constants first, or create the application manually and update them.', 'cf-zero-trust')); ?>
                            </div>
                            <?php endif; ?>

                            <!-- Phase 1: token -->
                            <div id="cfzt-auto-phase-token" <?php echo $constants_defined ? 'style="display:none;"' : ''; ?>>
                                <p>
                                    <a href="<?php echo esc_url(CFZT_Provisioner::get_token_template_url()); ?>"
                                       target="_blank" rel="noopener noreferrer"
                                       class="button button-secondary">
                                        <span class="dashicons dashicons-external" style="margin-top: 3px;"></span>
                                        <?php _e('1. Create a token on Cloudflare', 'cf-zero-trust'); ?>
                                    </a>
                                </p>
                                <p class="description">
                                    <?php _e('Opens Cloudflare with the required permissions preselected. Click <strong>Continue to summary</strong>, then <strong>Create Token</strong>, and copy the token it shows you.', 'cf-zero-trust'); ?>
                                </p>
                                <details style="margin: 10px 0;">
                                    <summary style="cursor: pointer;"><?php _e('Permissions this token needs, if you prefer to build it yourself', 'cf-zero-trust'); ?></summary>
                                    <ul style="margin: 10px 0 0 20px; list-style: disc;">
                                        <li><code><?php _e('Account → Access: Apps and Policies → Edit', 'cf-zero-trust'); ?></code></li>
                                        <li><code><?php _e('Account → Access: Organizations, Identity Providers, and Groups → Read', 'cf-zero-trust'); ?></code></li>
                                        <li><code><?php _e('Account → Account Settings → Read', 'cf-zero-trust'); ?></code></li>
                                    </ul>
                                </details>

                                <div class="cfzt-form-group" style="margin-top: 15px;">
                                    <label for="cfzt-cf-token"><?php _e('2. Paste your API token', 'cf-zero-trust'); ?></label>
                                    <input type="password" id="cfzt-cf-token" class="regular-text" autocomplete="off"
                                           spellcheck="false" placeholder="<?php esc_attr_e('Cloudflare API token', 'cf-zero-trust'); ?>">
                                    <button type="button" class="button button-primary" id="cfzt-connect-btn">
                                        <?php _e('Connect', 'cf-zero-trust'); ?>
                                    </button>
                                    <p class="description">
                                        <?php _e('The token is used for this setup only. It is never saved to your database. You can delete it in Cloudflare as soon as setup finishes.', 'cf-zero-trust'); ?>
                                    </p>
                                </div>
                            </div>

                            <!-- Phase 2: choose account + policy -->
                            <div id="cfzt-auto-phase-configure" style="display: none;">
                                <div class="cfzt-form-group" id="cfzt-account-wrap">
                                    <label for="cfzt-cf-account"><?php _e('Cloudflare account', 'cf-zero-trust'); ?></label>
                                    <select id="cfzt-cf-account" class="regular-text"></select>
                                </div>

                                <div class="cfzt-form-group">
                                    <label for="cfzt-app-name"><?php _e('Application name', 'cf-zero-trust'); ?></label>
                                    <input type="text" id="cfzt-app-name" class="regular-text"
                                           value="<?php echo esc_attr(sprintf(__('%s (WordPress)', 'cf-zero-trust'), wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES))); ?>">
                                    <p class="description"><?php _e('How the application will appear in your Cloudflare dashboard.', 'cf-zero-trust'); ?></p>
                                </div>

                                <div class="cfzt-form-group">
                                    <label for="cfzt-policy-mode"><?php _e('Who should be allowed to log in?', 'cf-zero-trust'); ?></label>
                                    <select id="cfzt-policy-mode" class="regular-text">
                                        <option value="email_domain"><?php _e('Anyone with an email at these domains', 'cf-zero-trust'); ?></option>
                                        <option value="emails"><?php _e('Only these specific email addresses', 'cf-zero-trust'); ?></option>
                                        <option value="everyone"><?php _e('Anyone who reaches my identity provider', 'cf-zero-trust'); ?></option>
                                    </select>
                                </div>

                                <div class="cfzt-form-group" id="cfzt-policy-value-wrap">
                                    <label for="cfzt-policy-value" id="cfzt-policy-value-label"><?php _e('Allowed email domains', 'cf-zero-trust'); ?></label>
                                    <input type="text" id="cfzt-policy-value" class="regular-text"
                                           value="<?php
                                           $current_user_email = wp_get_current_user()->user_email;
                                           $email_parts = explode('@', (string) $current_user_email);
                                           echo esc_attr(count($email_parts) === 2 ? $email_parts[1] : '');
                                           ?>">
                                    <p class="description">
                                        <?php _e('Separate multiple entries with commas. This becomes the Access policy on the new application.', 'cf-zero-trust'); ?>
                                        <strong><?php _e('Use the domain your identity provider issues for logins.', 'cf-zero-trust'); ?></strong>
                                        <?php _e('It is prefilled from your WordPress email, which may not be the same thing: if your team signs in with Google Workspace accounts at another domain, enter that domain here or the first login will be denied.', 'cf-zero-trust'); ?>
                                    </p>
                                </div>

                                <div class="cfzt-warning-box" id="cfzt-everyone-warning" style="display: none;">
                                    <?php _e('<strong>Careful:</strong> this allows anyone your identity provider authenticates to reach your WordPress login. Only choose it if your identity provider is already restricted to the right people.', 'cf-zero-trust'); ?>
                                    <?php _e('Combined with <strong>Auto-create Users</strong> (on by default) it also means every one of those people gets a WordPress account the first time they sign in. If Cloudflare\'s One-time PIN login is enabled for your team, that is anyone with an email address.', 'cf-zero-trust'); ?>
                                </div>

                                <div class="cfzt-code-block">
                                    <strong><?php _e('Redirect URL that will be registered:', 'cf-zero-trust'); ?></strong><br>
                                    <span id="cfzt-auto-redirect-uri"><?php echo esc_url(CFZT_Plugin::get_redirect_uri()); ?></span>
                                </div>

                                <p>
                                    <button type="button" class="button button-primary button-hero" id="cfzt-provision-btn">
                                        <?php _e('Create application in Cloudflare', 'cf-zero-trust'); ?>
                                    </button>
                                    <button type="button" class="button button-link" id="cfzt-auto-back-btn">
                                        <?php _e('Use a different token', 'cf-zero-trust'); ?>
                                    </button>
                                </p>
                            </div>

                            <!-- Feedback -->
                            <div id="cfzt-auto-status" style="display: none;" aria-live="polite"></div>
                        </div>

                        <details class="cfzt-manual-setup" style="margin-top: 25px;">
                            <summary style="cursor: pointer; font-weight: 600;">
                                <?php _e('Or set it up manually in the Cloudflare dashboard', 'cf-zero-trust'); ?>
                            </summary>
                        <div class="cfzt-info-box" style="margin-top: 15px;">
                            <strong><?php esc_html_e('In your Cloudflare Zero Trust dashboard:', 'cf-zero-trust'); ?></strong>
                            <ol style="margin: 10px 0 0 20px;">
                                <li><?php echo wp_kses_post(__('Go to <strong>Access → Applications</strong>', 'cf-zero-trust')); ?></li>
                                <li><?php echo wp_kses_post(__('Click <strong>Add an application</strong>', 'cf-zero-trust')); ?></li>
                                <li><?php echo wp_kses_post(__('Select <strong>SaaS</strong> application type', 'cf-zero-trust')); ?></li>
                                <li><?php echo wp_kses_post(__('Choose <strong>OIDC</strong> as the protocol', 'cf-zero-trust')); ?></li>
                                <li><?php echo wp_kses_post(__('Under <strong>Scopes</strong> keep <code>openid</code>, <code>email</code>, <code>profile</code> and <code>groups</code> selected', 'cf-zero-trust')); ?></li>
                                <li><?php esc_html_e('Set the redirect URL to:', 'cf-zero-trust'); ?></li>
                            </ol>
                        </div>

                        <div class="cfzt-code-block" style="position: relative;">
                            <strong><?php esc_html_e('Redirect URL:', 'cf-zero-trust'); ?></strong><br>
                            <span id="cfzt-redirect-url"><?php echo esc_url(CFZT_Plugin::get_redirect_uri()); ?></span>
                            <button type="button" class="button button-small cfzt-copy-btn" data-clipboard-target="cfzt-redirect-url" style="float: right; margin-top: -5px;">
                                <span class="dashicons dashicons-clipboard" style="margin-top: 3px;"></span> <?php esc_html_e('Copy', 'cf-zero-trust'); ?>
                            </button>
                        </div>

                        <div class="cfzt-info-box">
                            <p style="margin: 0;"><?php esc_html_e('After creating the application, Cloudflare will provide you with credentials. Keep this page open - you\'ll need these in the next step.', 'cf-zero-trust'); ?></p>
                        </div>
                        </details>
                    </div>

                </div>

                <!-- Step 2: Enter Credentials -->
                <div class="cfzt-wizard-step" data-step="2">
                    <h2 class="cfzt-step-title"><?php esc_html_e('Enter Your Credentials', 'cf-zero-trust'); ?></h2>
                    <p class="cfzt-step-description"><?php esc_html_e('Copy the credentials from Cloudflare and paste them below.', 'cf-zero-trust'); ?></p>

                    <!-- OIDC Fields -->
                    <div id="cfzt-step3-oidc">
                        <div class="cfzt-form-group">
                            <label for="cfzt_team_domain">
                                <?php esc_html_e('Team Domain *', 'cf-zero-trust'); ?>
                                <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('Your unique Cloudflare team domain. Found in your application\'s Issuer URL. Example: yourteam.cloudflareaccess.com', 'cf-zero-trust'); ?>">?</span>
                            </label>
                            <input type="text" id="cfzt_team_domain" name="cfzt_settings[team_domain]" value="<?php echo esc_attr($options['team_domain'] ?? ''); ?>" class="regular-text" placeholder="yourteam.cloudflareaccess.com" required>
                            <p class="description"><?php esc_html_e('Found in your Cloudflare Issuer URL (without https://)', 'cf-zero-trust'); ?></p>
                        </div>

                        <div class="cfzt-form-group">
                            <label for="cfzt_app_type">
                                <?php esc_html_e('Application Type *', 'cf-zero-trust'); ?>
                                <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('SaaS applications use Cloudflare\'s standard OIDC endpoints and are production-ready. Self-hosted is for custom OAuth2 implementations.', 'cf-zero-trust'); ?>">?</span>
                            </label>
                            <select id="cfzt_app_type" name="cfzt_settings[app_type]" class="regular-text">
                                <option value="saas" <?php selected($options['app_type'] ?? 'saas', 'saas'); ?>><?php esc_html_e('SaaS (Recommended)', 'cf-zero-trust'); ?></option>
                                <option value="self-hosted" <?php selected($options['app_type'] ?? '', 'self-hosted'); ?>><?php esc_html_e('Self-hosted', 'cf-zero-trust'); ?></option>
                            </select>
                            <p class="description"><?php esc_html_e('Match the type you selected in Cloudflare', 'cf-zero-trust'); ?></p>
                        </div>

                        <div class="cfzt-form-group">
                            <label for="cfzt_client_id">
                                <?php esc_html_e('Client ID *', 'cf-zero-trust'); ?>
                                <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('A unique identifier for your application provided by Cloudflare. Looks like a long hexadecimal string.', 'cf-zero-trust'); ?>">?</span>
                            </label>
                            <input type="text" id="cfzt_client_id" name="cfzt_settings[client_id]" value="<?php echo esc_attr($options['client_id'] ?? ''); ?>" class="regular-text" required>
                            <p class="description"><?php esc_html_e('From your Cloudflare application', 'cf-zero-trust'); ?></p>
                        </div>

                        <div class="cfzt-form-group">
                            <label for="cfzt_client_secret">
                                <?php echo $has_saved_secret || $secret_from_constant ? esc_html__('Client Secret', 'cf-zero-trust') : esc_html__('Client Secret *', 'cf-zero-trust'); ?>
                                <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('A secret key used to authenticate your application with Cloudflare. Keep this secure! It is encrypted in your database when OpenSSL is available, and is never shown again on this page.', 'cf-zero-trust'); ?>">?</span>
                            </label>
                            <?php
                            // Never render the stored secret into the page.
                            if ($secret_from_constant) {
                                $secret_placeholder = __('Set via CFZT_CLIENT_SECRET constant', 'cf-zero-trust');
                            } elseif ($has_saved_secret) {
                                $secret_placeholder = __('Saved. Leave blank to keep the current secret.', 'cf-zero-trust');
                            } else {
                                $secret_placeholder = '';
                            }
                            ?>
                            <input type="password" id="cfzt_client_secret" name="cfzt_settings[client_secret]" value="" class="regular-text" autocomplete="new-password" placeholder="<?php echo esc_attr($secret_placeholder); ?>" data-has-secret="<?php echo $has_saved_secret || $secret_from_constant ? '1' : '0'; ?>" <?php echo $secret_from_constant ? 'readonly' : ''; ?> <?php echo $has_saved_secret || $secret_from_constant ? '' : 'required'; ?>>
                            <p class="description"><?php echo $has_saved_secret ? esc_html__('A client secret is saved and encrypted. Enter a new one only to replace it.', 'cf-zero-trust') : esc_html__('From your Cloudflare application (will be encrypted)', 'cf-zero-trust'); ?></p>
                        </div>
                    </div>


                    <!-- Additional Settings -->
                    <h3 style="margin-top: 30px; border-bottom: 1px solid #ccd0d4; padding-bottom: 10px;"><?php esc_html_e('User & Login Settings', 'cf-zero-trust'); ?></h3>

                    <div class="cfzt-form-group">
                        <label for="cfzt_login_mode">
                            <?php esc_html_e('Login Mode', 'cf-zero-trust'); ?>
                            <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('Primary mode disables WordPress password login, password resets and registration, so everyone signs in through Cloudflare (backup codes remain available for emergencies). Secondary mode keeps both options available.', 'cf-zero-trust'); ?>">?</span>
                        </label>
                        <select id="cfzt_login_mode" name="cfzt_settings[login_mode]" class="regular-text">
                            <option value="secondary" <?php selected($options['login_mode'] ?? 'secondary', 'secondary'); ?>><?php esc_html_e('Secondary - Show both login options', 'cf-zero-trust'); ?></option>
                            <option value="primary" <?php selected($options['login_mode'] ?? '', 'primary'); ?>><?php esc_html_e('Primary - Cloudflare only', 'cf-zero-trust'); ?></option>
                        </select>
                        <p class="description"><?php esc_html_e('Choose how users can log in to your site', 'cf-zero-trust'); ?></p>
                    </div>

                    <div class="cfzt-form-group">
                        <label for="cfzt_auto_create_users">
                            <?php esc_html_e('Auto-create Users', 'cf-zero-trust'); ?>
                            <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('When enabled, WordPress user accounts are automatically created for authenticated Cloudflare users on their first login. If disabled, only existing WordPress users can log in.', 'cf-zero-trust'); ?>">?</span>
                        </label>
                        <select id="cfzt_auto_create_users" name="cfzt_settings[auto_create_users]" class="regular-text">
                            <option value="yes" <?php selected($options['auto_create_users'] ?? 'yes', 'yes'); ?>><?php esc_html_e('Yes', 'cf-zero-trust'); ?></option>
                            <option value="no" <?php selected($options['auto_create_users'] ?? '', 'no'); ?>><?php esc_html_e('No', 'cf-zero-trust'); ?></option>
                        </select>
                        <p class="description"><?php esc_html_e('Automatically create WordPress users on first login', 'cf-zero-trust'); ?></p>
                    </div>

                    <div class="cfzt-form-group">
                        <label for="cfzt_default_role">
                            <?php esc_html_e('Default User Role', 'cf-zero-trust'); ?>
                            <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('New users created through Cloudflare authentication will be assigned this WordPress role. Choose carefully based on your security needs.', 'cf-zero-trust'); ?>">?</span>
                        </label>
                        <select id="cfzt_default_role" name="cfzt_settings[default_role]" class="regular-text">
                            <?php wp_dropdown_roles($options['default_role'] ?? 'subscriber'); ?>
                        </select>
                        <p class="description"><?php esc_html_e('Role assigned to new users', 'cf-zero-trust'); ?></p>
                    </div>

                    <div class="cfzt-form-group">
                        <label for="cfzt_enable_logging">
                            <?php esc_html_e('Enable Logging', 'cf-zero-trust'); ?>
                            <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('Logs authentication attempts to your database for debugging and monitoring. Includes timestamp, user, IP address, and success status.', 'cf-zero-trust'); ?>">?</span>
                        </label>
                        <select id="cfzt_enable_logging" name="cfzt_settings[enable_logging]" class="regular-text">
                            <option value="yes" <?php selected($options['enable_logging'] ?? 'no', 'yes'); ?>><?php esc_html_e('Yes', 'cf-zero-trust'); ?></option>
                            <option value="no" <?php selected($options['enable_logging'] ?? '', 'no'); ?>><?php esc_html_e('No', 'cf-zero-trust'); ?></option>
                        </select>
                        <p class="description"><?php esc_html_e('Log authentication attempts for debugging', 'cf-zero-trust'); ?></p>
                    </div>

                    <!-- Advanced Settings -->
                    <h3 style="margin-top: 30px; border-bottom: 1px solid #ccd0d4; padding-bottom: 10px;"><?php esc_html_e('Advanced Settings', 'cf-zero-trust'); ?></h3>

                    <div class="cfzt-form-group">
                        <label for="cfzt_email_domain_restrictions">
                            <?php esc_html_e('Email Domain Restrictions', 'cf-zero-trust'); ?>
                            <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('Restrict Cloudflare logins to specific email domains. Checked on every login, for new and existing accounts alike. Enter one domain per line (e.g., example.com). Leave empty to allow all domains.', 'cf-zero-trust'); ?>">?</span>
                        </label>
                        <textarea id="cfzt_email_domain_restrictions" name="cfzt_settings[email_domain_restrictions]" rows="3" class="large-text" placeholder="example.com&#10;company.org"><?php echo esc_textarea($options['email_domain_restrictions'] ?? ''); ?></textarea>
                        <p class="description"><?php _e('One domain per line. Only users with email addresses from these domains can log in through Cloudflare; this is checked on every login. Make sure your own domain is listed before enabling Primary mode.', 'cf-zero-trust'); ?></p>
                    </div>

                    <div class="cfzt-form-group">
                        <label for="cfzt_redirect_after_login">
                            <?php esc_html_e('Redirect After Login', 'cf-zero-trust'); ?>
                            <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('Custom URL to redirect users after successful login. Leave empty to use WordPress default (wp-admin for admins, home for others).', 'cf-zero-trust'); ?>">?</span>
                        </label>
                        <input type="url" id="cfzt_redirect_after_login" name="cfzt_settings[redirect_after_login]" value="<?php echo esc_attr($options['redirect_after_login'] ?? ''); ?>" class="large-text" placeholder="<?php echo esc_attr(home_url()); ?>">
                        <p class="description"><?php _e('Leave empty to use WordPress default redirect behavior.', 'cf-zero-trust'); ?></p>
                    </div>

                    <div class="cfzt-form-group">
                        <label for="cfzt_redirect_after_logout">
                            <?php esc_html_e('Redirect After Logout', 'cf-zero-trust'); ?>
                            <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('Custom URL to redirect users after logout. Leave empty to redirect to home page.', 'cf-zero-trust'); ?>">?</span>
                        </label>
                        <input type="url" id="cfzt_redirect_after_logout" name="cfzt_settings[redirect_after_logout]" value="<?php echo esc_attr($options['redirect_after_logout'] ?? ''); ?>" class="large-text" placeholder="<?php echo esc_attr(home_url()); ?>">
                        <p class="description"><?php _e('Leave empty to redirect to home page.', 'cf-zero-trust'); ?></p>
                    </div>

                    <div class="cfzt-form-group">
                        <label>
                            <?php esc_html_e('Role Mapping (Cloudflare Groups → WordPress Roles)', 'cf-zero-trust'); ?>
                            <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('Map identity-provider group names (sent by Cloudflare in the groups claim) to WordPress roles. Applied when an account is created and re-applied on every login for accounts this plugin created. Accounts you made by hand keep their role.', 'cf-zero-trust'); ?>">?</span>
                        </label>
                        <input type="hidden" name="cfzt_settings[role_mapping_submitted]" value="1">
                        <div id="cfzt-role-mappings">
                            <?php
                            $role_mappings = isset($options['role_mapping']) && is_array($options['role_mapping']) ? $options['role_mapping'] : array();
                            if (empty($role_mappings)) {
                                $role_mappings = array(array('group' => '', 'role' => 'subscriber'));
                            }
                            foreach ($role_mappings as $index => $mapping):
                            ?>
                            <div class="cfzt-role-mapping-row" style="display: flex; gap: 10px; margin-bottom: 10px; align-items: center;">
                                <input type="text" name="cfzt_settings[role_mapping][<?php echo (int) $index; ?>][group]" value="<?php echo esc_attr($mapping['group']); ?>" placeholder="<?php esc_attr_e('Cloudflare group name', 'cf-zero-trust'); ?>" class="regular-text" style="flex: 1;">
                                <span>→</span>
                                <select name="cfzt_settings[role_mapping][<?php echo (int) $index; ?>][role]" class="regular-text" style="flex: 1;">
                                    <?php
                                    $roles = wp_roles()->get_names();
                                    foreach ($roles as $role_value => $role_name):
                                    ?>
                                    <option value="<?php echo esc_attr($role_value); ?>" <?php selected($mapping['role'], $role_value); ?>><?php echo esc_html($role_name); ?></option>
                                    <?php endforeach; ?>
                                </select>
                                <button type="button" class="button cfzt-remove-mapping" style="color: #d63638;">
                                    <span class="dashicons dashicons-trash"></span>
                                </button>
                            </div>
                            <?php endforeach; ?>
                        </div>
                        <button type="button" id="cfzt-add-role-mapping" class="button button-secondary" style="margin-top: 10px;">
                            <span class="dashicons dashicons-plus-alt"></span> <?php _e('Add Role Mapping', 'cf-zero-trust'); ?>
                        </button>
                        <p class="description"><?php _e('Map Cloudflare Access group names to WordPress roles. First matching group wins.', 'cf-zero-trust'); ?></p>
                    </div>
                </div>

                <!-- Step 4: Review and Complete -->
                <div class="cfzt-wizard-step" data-step="3">
                    <h2 class="cfzt-step-title"><?php esc_html_e('Review Your Configuration', 'cf-zero-trust'); ?></h2>
                    <p class="cfzt-step-description"><?php esc_html_e('Please review your settings before saving.', 'cf-zero-trust'); ?></p>

                    <div class="cfzt-success-box">
                        <h3 style="margin-top: 0;"><?php esc_html_e('Configuration Summary', 'cf-zero-trust'); ?></h3>
                        <ul class="cfzt-checklist" id="cfzt-review-list">
                            <!-- Will be populated by JavaScript -->
                        </ul>
                    </div>

                    <div class="cfzt-info-box">
                        <strong><?php esc_html_e('Before Saving:', 'cf-zero-trust'); ?></strong>
                        <p style="margin: 10px 0;"><?php esc_html_e('We recommend testing your connection to Cloudflare before saving:', 'cf-zero-trust'); ?></p>
                        <button type="button" id="cfzt-test-connection-wizard" class="button button-secondary" style="margin-bottom: 15px;">
                            <span class="dashicons dashicons-yes-alt" style="margin-top: 3px;"></span> <?php esc_html_e('Test Connection Now', 'cf-zero-trust'); ?>
                        </button>
                        <div id="cfzt-test-results-wizard" style="display: none;"></div>
                    </div>

                    <div class="cfzt-info-box">
                        <strong><?php esc_html_e('Next Steps:', 'cf-zero-trust'); ?></strong>
                        <ol style="margin: 10px 0 0 20px;">
                            <li><?php esc_html_e('Test your connection (recommended)', 'cf-zero-trust'); ?></li>
                            <li><?php esc_html_e('Click "Save Configuration" below', 'cf-zero-trust'); ?></li>
                            <li><?php esc_html_e('Visit your WordPress login page', 'cf-zero-trust'); ?></li>
                            <li><?php esc_html_e('Click "Login with Cloudflare Zero Trust"', 'cf-zero-trust'); ?></li>
                            <li><?php esc_html_e('Test the authentication flow', 'cf-zero-trust'); ?></li>
                        </ol>
                    </div>

                    <?php if (!$security_status['encryption_available']): ?>
                    <div class="cfzt-warning-box">
                        <strong><?php esc_html_e('Security Notice:', 'cf-zero-trust'); ?></strong> <?php esc_html_e('OpenSSL is not available. Client secrets will be stored with basic obfuscation. Consider enabling OpenSSL for better security.', 'cf-zero-trust'); ?>
                    </div>
                    <?php endif; ?>
                </div>

                <!-- Wizard Actions -->
                <div class="cfzt-wizard-actions">
                    <button type="button" id="cfzt-prev-step" class="button" style="display: none;"><?php esc_html_e('Previous', 'cf-zero-trust'); ?></button>
                    <div>
                        <button type="button" id="cfzt-next-step" class="button button-primary"><?php esc_html_e('Next', 'cf-zero-trust'); ?></button>
                        <?php submit_button(__('Save Configuration', 'cf-zero-trust'), 'primary', 'submit', false, array('id' => 'cfzt-save-btn', 'style' => 'display:none;')); ?>
                    </div>
                </div>
            </form>
        </div>

        <!-- Advanced Mode (Traditional Settings) -->
        <div id="cfzt-advanced-mode" style="display: <?php echo $is_configured ? 'block' : 'none'; ?>;">
            <form method="post" action="options.php" style="padding: 30px;">
                <?php
                settings_fields('cfzt_settings_group');
                do_settings_sections('cf-zero-trust');
                submit_button();
                ?>
            </form>

            <!-- Import/Export Settings -->
            <div style="padding: 0 30px 30px;">
                <h2 style="border-top: 1px solid #ccd0d4; padding-top: 20px;"><?php _e('Import / Export Settings', 'cf-zero-trust'); ?></h2>
                <p class="description"><?php _e('Export your configuration as a backup or to transfer to another site. Import a previously exported configuration file.', 'cf-zero-trust'); ?></p>

                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px;">
                    <!-- Export -->
                    <div class="cfzt-import-export-box">
                        <h3><?php _e('Export Settings', 'cf-zero-trust'); ?></h3>
                        <p><?php _e('Download your current configuration as a JSON file. The client secret is never included; enter it again after importing on another site.', 'cf-zero-trust'); ?></p>
                        <button type="button" id="cfzt-export-settings" class="button button-secondary">
                            <span class="dashicons dashicons-download" style="margin-top: 3px;"></span>
                            <?php _e('Export Settings', 'cf-zero-trust'); ?>
                        </button>
                    </div>

                    <!-- Import -->
                    <div class="cfzt-import-export-box">
                        <h3><?php _e('Import Settings', 'cf-zero-trust'); ?></h3>
                        <p><?php _e('Upload a previously exported JSON file to restore settings. This will replace your current configuration.', 'cf-zero-trust'); ?></p>
                        <input type="file" id="cfzt-import-file" accept=".json" style="margin-bottom: 10px;">
                        <button type="button" id="cfzt-import-settings" class="button button-secondary" disabled>
                            <span class="dashicons dashicons-upload" style="margin-top: 3px;"></span>
                            <?php _e('Import Settings', 'cf-zero-trust'); ?>
                        </button>
                    </div>
                </div>

                <div id="cfzt-import-export-result" style="margin-top: 20px;"></div>
            </div>
        </div>
    </div>
    


<style>
/* Toast notification */
.cfzt-toast {
    position: fixed;
    bottom: 30px;
    right: 30px;
    background: #2c3338;
    color: #fff;
    padding: 15px 20px;
    border-radius: 4px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    z-index: 999999;
    display: flex;
    align-items: center;
    gap: 10px;
    animation: cfzt-slide-up 0.3s ease-out;
}

.cfzt-toast.success {
    background: #00a32a;
}

.cfzt-toast.error {
    background: #d63638;
}

@keyframes cfzt-slide-up {
    from {
        transform: translateY(100px);
        opacity: 0;
    }
    to {
        transform: translateY(0);
        opacity: 1;
    }
}

.cfzt-toast-icon {
    font-size: 20px;
}

/* Live validation styles */
.cfzt-field-valid {
    border-color: #00a32a !important;
    background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%2300a32a"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>') !important;
    background-repeat: no-repeat !important;
    background-position: right 10px center !important;
    background-size: 20px !important;
    padding-right: 40px !important;
}

.cfzt-field-invalid {
    border-color: #d63638 !important;
    background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%23d63638"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg>') !important;
    background-repeat: no-repeat !important;
    background-position: right 10px center !important;
    background-size: 20px !important;
    padding-right: 40px !important;
}

.cfzt-field-warning {
    border-color: #dba617 !important;
    background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%23dba617"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>') !important;
    background-repeat: no-repeat !important;
    background-position: right 10px center !important;
    background-size: 20px !important;
    padding-right: 40px !important;
}

.cfzt-validation-message {
    display: block;
    margin-top: 5px;
    font-size: 13px;
    font-weight: 500;
}

.cfzt-validation-message.valid {
    color: #00a32a;
}

.cfzt-validation-message.invalid {
    color: #d63638;
}

.cfzt-validation-message.warning {
    color: #dba617;
}
</style>

<script>
jQuery(document).ready(function($) {
    'use strict';

    var currentStep = 1;
    var totalSteps = 3;

    // Toast notification function
    function showToast(message, type) {
        type = type || 'success';
        var icon = type === 'success' ? '✓' : '✕';
        var $toast = $('<div class="cfzt-toast ' + type + '">' +
            '<span class="cfzt-toast-icon">' + icon + '</span>' +
            '<span>' + message + '</span>' +
            '</div>');

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
            showToast('<?php echo esc_js(__('Copied to clipboard!', 'cf-zero-trust')); ?>', 'success');

            // Visual feedback on button
            var $btn = $(this);
            var originalHtml = $btn.html();
            $btn.html('<span class="dashicons dashicons-yes" style="margin-top: 3px;"></span> <?php echo esc_js(__('Copied!', 'cf-zero-trust')); ?>');
            $btn.addClass('button-primary');

            setTimeout(function() {
                $btn.html(originalHtml);
                $btn.removeClass('button-primary');
            }, 2000);
        } catch (err) {
            showToast('<?php echo esc_js(__('Failed to copy. Please copy manually.', 'cf-zero-trust')); ?>', 'error');
        }

        $temp.remove();
    });

    // Mode toggle
    $('#cfzt-toggle-mode').on('click', function() {
        $('#cfzt-wizard-mode').slideToggle();
        $('#cfzt-advanced-mode').slideToggle();

        var btn = $(this);
        if (btn.text().includes('Wizard')) {
            btn.text('<?php _e('Switch to Advanced Mode', 'cf-zero-trust'); ?>');
        } else {
            btn.text('<?php _e('Switch to Wizard Mode', 'cf-zero-trust'); ?>');
        }
    });

    // Toggle remaining tasks
    $('.cfzt-toggle-tasks').on('click', function() {
        $('.cfzt-remaining-tasks').slideToggle();
        var btn = $(this);
        if (btn.text().includes('View')) {
            btn.html('<?php _e('Hide remaining tasks', 'cf-zero-trust'); ?> ▲');
        } else {
            btn.html('<?php _e('View remaining tasks', 'cf-zero-trust'); ?> ▼');
        }
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
                alert('<?php echo esc_js(__('Please enter your Team Domain', 'cf-zero-trust')); ?>');
                return false;
            }
            if (!$('#cfzt_client_id').val()) {
                alert('<?php echo esc_js(__('Please enter your Client ID', 'cf-zero-trust')); ?>');
                return false;
            }
            // An empty secret field means "keep the saved one" once a secret exists.
            var $secret = $('#cfzt_client_secret');
            if (!$secret.val() && $secret.data('has-secret') !== 1) {
                alert('<?php echo esc_js(__('Please enter your Client Secret', 'cf-zero-trust')); ?>');
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
            ? '<?php echo esc_js(__('New secret entered', 'cf-zero-trust')); ?>'
            : ($secret.data('has-secret') === 1
                ? '<?php echo esc_js(__('Keeping saved secret', 'cf-zero-trust')); ?>'
                : '<?php echo esc_js(__('Not set', 'cf-zero-trust')); ?>');

        row('<?php echo esc_js(__('Authentication Method', 'cf-zero-trust')); ?>', 'OIDC');
        row('<?php echo esc_js(__('Team Domain', 'cf-zero-trust')); ?>', $('#cfzt_team_domain').val());
        row('<?php echo esc_js(__('Application Type', 'cf-zero-trust')); ?>', $('#cfzt_app_type option:selected').text());
        row('<?php echo esc_js(__('Client ID', 'cf-zero-trust')); ?>', clientId.length > 20 ? clientId.substring(0, 20) + '…' : clientId);
        row('<?php echo esc_js(__('Client Secret', 'cf-zero-trust')); ?>', secretState);
        row('<?php echo esc_js(__('Login Mode', 'cf-zero-trust')); ?>', $('#cfzt_login_mode option:selected').text());
        row('<?php echo esc_js(__('Auto-create Users', 'cf-zero-trust')); ?>', $('#cfzt_auto_create_users').val() === 'yes'
            ? '<?php echo esc_js(__('Enabled', 'cf-zero-trust')); ?>'
            : '<?php echo esc_js(__('Disabled', 'cf-zero-trust')); ?>');
        row('<?php echo esc_js(__('Default Role', 'cf-zero-trust')); ?>', $('#cfzt_default_role option:selected').text());
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
                    showToast('<?php echo esc_js(__('Saving configuration...', 'cf-zero-trust')); ?>', 'success');
                }
            } else if ($('#cfzt-advanced-mode').is(':visible')) {
                $('#cfzt-advanced-mode form').submit();
                showToast('<?php echo esc_js(__('Saving configuration...', 'cf-zero-trust')); ?>', 'success');
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
                '<span><?php echo esc_js(__('Tip: Press <strong>Ctrl/Cmd + S</strong> to save', 'cf-zero-trust')); ?></span>' +
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
        $button.prop('disabled', true).html('<span class="dashicons dashicons-update spin" style="margin-top: 3px;"></span> <?php echo esc_js(__('Testing...', 'cf-zero-trust')); ?>');

        if ($resultsContainer) {
            $resultsContainer.hide().html('');
        }

        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'cfzt_test_connection',
                nonce: '<?php echo wp_create_nonce('cfzt_test_connection'); ?>'
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
                        html += '<strong>⚠ <?php echo esc_js(__('Warnings:', 'cf-zero-trust')); ?></strong><ul style="margin: 5px 0 0 20px;">';
                        response.data.warnings.forEach(function(warning) {
                            html += '<li>' + warning + '</li>';
                        });
                        html += '</ul></div>';
                    }

                    html += '</div>';
                    showToast('<?php echo esc_js(__('Connection test passed!', 'cf-zero-trust')); ?>', 'success');
                } else {
                    html = '<div class="cfzt-warning-box" style="margin-top: 15px; background: #fcf2f2; border-left-color: #d63638;">';
                    html += '<strong style="color: #d63638;">✗ ' + (response.data.message || '<?php echo esc_js(__('Connection test failed', 'cf-zero-trust')); ?>') + '</strong>';

                    if (response.data.issues && response.data.issues.length > 0) {
                        html += '<ul style="margin: 10px 0 0 20px;">';
                        response.data.issues.forEach(function(issue) {
                            html += '<li>' + issue + '</li>';
                        });
                        html += '</ul>';
                    }

                    if (response.data.warnings && response.data.warnings.length > 0) {
                        html += '<div style="margin-top: 10px; padding: 10px; background: rgba(255, 193, 7, 0.1); border-left: 3px solid #ffc107;">';
                        html += '<strong>⚠ <?php echo esc_js(__('Additional warnings:', 'cf-zero-trust')); ?></strong><ul style="margin: 5px 0 0 20px;">';
                        response.data.warnings.forEach(function(warning) {
                            html += '<li>' + warning + '</li>';
                        });
                        html += '</ul></div>';
                    }

                    html += '</div>';
                    showToast('<?php echo esc_js(__('Connection test failed', 'cf-zero-trust')); ?>', 'error');
                }

                if ($resultsContainer) {
                    $resultsContainer.html(html).slideDown();
                }
            },
            error: function() {
                var html = '<div class="cfzt-warning-box" style="margin-top: 15px; background: #fcf2f2; border-left-color: #d63638;">';
                html += '<strong style="color: #d63638;">✗ <?php echo esc_js(__('Connection test failed', 'cf-zero-trust')); ?></strong>';
                html += '<p><?php echo esc_js(__('An unexpected error occurred. Please try again.', 'cf-zero-trust')); ?></p>';
                html += '</div>';

                if ($resultsContainer) {
                    $resultsContainer.html(html).slideDown();
                }
                showToast('<?php echo esc_js(__('Connection test failed', 'cf-zero-trust')); ?>', 'error');
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

    // Add spinning animation for dashicons
    $('<style>.dashicons.spin { animation: spin 1s linear infinite; } @keyframes spin { 100% { transform: rotate(360deg); } }</style>').appendTo('head');

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
                message = '<?php echo esc_js(__('Should end with .cloudflareaccess.com', 'cf-zero-trust')); ?>';
            } else {
                message = '<?php echo esc_js(__('Valid team domain format', 'cf-zero-trust')); ?>';
            }
        }

        if (rules.clientId) {
            if (value.length < 16) {
                isValid = false;
                message = '<?php echo esc_js(__('Client ID seems too short', 'cf-zero-trust')); ?>';
            } else if (!value.match(/^[a-f0-9]+$/i)) {
                isWarning = true;
                message = '<?php echo esc_js(__('Client ID usually contains only hex characters', 'cf-zero-trust')); ?>';
            } else {
                message = '<?php echo esc_js(__('Valid client ID format', 'cf-zero-trust')); ?>';
            }
        }

        if (rules.clientSecret) {
            if (value === '[SET VIA CONSTANT]') {
                isWarning = true;
                message = '<?php echo esc_js(__('Value set via constant (cannot be changed here)', 'cf-zero-trust')); ?>';
            } else if (value.length < 16) {
                isValid = false;
                message = '<?php echo esc_js(__('Client secret seems too short', 'cf-zero-trust')); ?>';
            } else {
                message = '<?php echo esc_js(__('Client secret looks good', 'cf-zero-trust')); ?>';
            }
        }

        if (rules.url) {
            try {
                new URL(value);
                message = '<?php echo esc_js(__('Valid URL format', 'cf-zero-trust')); ?>';
            } catch (e) {
                isValid = false;
                message = '<?php echo esc_js(__('Please enter a valid URL', 'cf-zero-trust')); ?>';
            }
        }

        if (rules.alphanumeric) {
            if (!value.match(/^[a-z0-9-_]+$/i)) {
                isValid = false;
                message = '<?php echo esc_js(__('Should contain only letters, numbers, hyphens, and underscores', 'cf-zero-trust')); ?>';
            } else {
                message = '<?php echo esc_js(__('Valid format', 'cf-zero-trust')); ?>';
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
    var roleMappingIndex = <?php echo count($role_mappings); ?>;
    $('#cfzt-add-role-mapping').on('click', function() {
        var roleOptions = '';
        <?php
        $roles = wp_roles()->get_names();
        foreach ($roles as $role_value => $role_name):
        ?>
        roleOptions += '<option value="<?php echo esc_js($role_value); ?>"><?php echo esc_js($role_name); ?></option>';
        <?php endforeach; ?>

        var newRow = '<div class="cfzt-role-mapping-row" style="display: flex; gap: 10px; margin-bottom: 10px; align-items: center;">' +
            '<input type="text" name="cfzt_settings[role_mapping][' + roleMappingIndex + '][group]" placeholder="<?php echo esc_js(__('Cloudflare group name', 'cf-zero-trust')); ?>" class="regular-text" style="flex: 1;">' +
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
                alert('<?php _e('Please select a valid JSON file.', 'cf-zero-trust'); ?>');
            }
        }
    });

    // Export settings
    $('#cfzt-export-settings').on('click', function() {
        var $btn = $(this);
        var originalHtml = $btn.html();

        $btn.prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span> <?php _e('Exporting...', 'cf-zero-trust'); ?>');

        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'cfzt_export_settings',
                nonce: '<?php echo wp_create_nonce('cfzt_import_export'); ?>'
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

                    showToast('<?php _e('Settings exported successfully!', 'cf-zero-trust'); ?>', 'success');

                    var html = '<div class="notice notice-success"><p>';
                    html += '<strong><?php _e('Export Successful!', 'cf-zero-trust'); ?></strong><br>';
                    html += '<?php _e('Your settings have been downloaded as', 'cf-zero-trust'); ?> <code>' + response.data.filename + '</code>';
                    html += '</p></div>';
                    $('#cfzt-import-export-result').html(html);
                } else {
                    showToast(response.data || '<?php _e('Export failed', 'cf-zero-trust'); ?>', 'error');
                }
            },
            error: function() {
                showToast('<?php _e('Export failed. Please try again.', 'cf-zero-trust'); ?>', 'error');
            },
            complete: function() {
                $btn.prop('disabled', false).html(originalHtml);
            }
        });
    });

    // Import settings
    $('#cfzt-import-settings').on('click', function() {
        if (!importFileData) {
            alert('<?php _e('Please select a file first.', 'cf-zero-trust'); ?>');
            return;
        }

        if (!confirm('<?php _e('Warning: This will replace your current settings. Are you sure you want to continue?', 'cf-zero-trust'); ?>')) {
            return;
        }

        var $btn = $(this);
        var originalHtml = $btn.html();

        $btn.prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span> <?php _e('Importing...', 'cf-zero-trust'); ?>');

        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'cfzt_import_settings',
                nonce: '<?php echo wp_create_nonce('cfzt_import_export'); ?>',
                import_data: importFileData
            },
            success: function(response) {
                if (response.success) {
                    showToast('<?php _e('Settings imported successfully! Reloading page...', 'cf-zero-trust'); ?>', 'success');

                    var html = '<div class="notice notice-success"><p>';
                    html += '<strong><?php _e('Import Successful!', 'cf-zero-trust'); ?></strong><br>';
                    html += response.data + '<br>';
                    html += '<?php _e('The page will reload in 2 seconds...', 'cf-zero-trust'); ?>';
                    html += '</p></div>';
                    $('#cfzt-import-export-result').html(html);

                    // Reload page after 2 seconds
                    setTimeout(function() {
                        window.location.reload();
                    }, 2000);
                } else {
                    showToast(response.data || '<?php _e('Import failed', 'cf-zero-trust'); ?>', 'error');

                    var html = '<div class="notice notice-error"><p>';
                    html += '<strong><?php _e('Import Failed', 'cf-zero-trust'); ?></strong><br>';
                    html += response.data;
                    html += '</p></div>';
                    $('#cfzt-import-export-result').html(html);

                    $btn.prop('disabled', false).html(originalHtml);
                }
            },
            error: function() {
                showToast('<?php _e('Import failed. Please try again.', 'cf-zero-trust'); ?>', 'error');
                $btn.prop('disabled', false).html(originalHtml);
            }
        });
    });

    /* ------------------------------------------------------------------
     * Automatic Cloudflare provisioning
     * ------------------------------------------------------------------ */

    var cfztSetupNonce = <?php echo wp_json_encode(wp_create_nonce(CFZT_Setup::NONCE_ACTION)); ?>;

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
            $('#cfzt-policy-value-label').text('<?php echo esc_js(__('Allowed email addresses', 'cf-zero-trust')); ?>');
        } else {
            $('#cfzt-policy-value-label').text('<?php echo esc_js(__('Allowed email domains', 'cf-zero-trust')); ?>');
        }
    });

    $('#cfzt-connect-btn').on('click', function() {
        var $btn = $(this);
        var originalText = $btn.text();
        var token = $.trim($('#cfzt-cf-token').val());

        if (!token) {
            cfztStatus('error', '<?php echo esc_js(__('Paste your Cloudflare API token first.', 'cf-zero-trust')); ?>');
            return;
        }

        cfztClearStatus();
        $btn.prop('disabled', true).text('<?php echo esc_js(__('Connecting…', 'cf-zero-trust')); ?>');

        $.post(ajaxurl, {
            action: 'cfzt_connect_cloudflare',
            nonce: cfztSetupNonce,
            token: token
        }).done(function(response) {
            if (!response || !response.success) {
                var msg = (response && response.data && response.data.message)
                    ? response.data.message
                    : '<?php echo esc_js(__('Could not connect to Cloudflare.', 'cf-zero-trust')); ?>';
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
                    label += ' — <?php echo esc_js(__('no Zero Trust team domain', 'cf-zero-trust')); ?>';
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
                cfztStatus('error', '<?php echo esc_js(__('None of the accounts this token can reach have a Zero Trust team domain yet. Set one up in the Cloudflare Zero Trust dashboard, then connect again.', 'cf-zero-trust')); ?>', notices);
                return;
            }

            // Preselect the first usable account.
            $select.find('option:not(:disabled)').first().prop('selected', true);

            $('#cfzt-auto-phase-token').hide();
            $('#cfzt-auto-phase-configure').show();
            $('#cfzt-account-wrap').toggle(accounts.length > 1);

            cfztStatus('info', accounts.length > 1
                ? '<?php echo esc_js(__('Token accepted. Choose an account and confirm who should be able to log in.', 'cf-zero-trust')); ?>'
                : '<?php echo esc_js(__('Token accepted. Confirm who should be able to log in.', 'cf-zero-trust')); ?>');
        }).fail(function() {
            cfztStatus('error', '<?php echo esc_js(__('The request failed. Check your connection and try again.', 'cf-zero-trust')); ?>');
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
        $btn.prop('disabled', true).text('<?php echo esc_js(__('Creating application…', 'cf-zero-trust')); ?>');

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
                var msg = data.message || '<?php echo esc_js(__('Provisioning failed.', 'cf-zero-trust')); ?>';

                // An existing app is recoverable: offer to replace it.
                if (data.can_replace) {
                    cfztStatus('error', msg);
                    $('#cfzt-auto-status').append(
                        $('<p>').append(
                            $('<button type="button" class="button">')
                                .text('<?php echo esc_js(__('Replace the existing application', 'cf-zero-trust')); ?>')
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
                '<?php echo esc_js(__('Done. The Access application was created and your credentials are saved.', 'cf-zero-trust')); ?>',
                warnings
            );

            $('#cfzt-auto-status').append(
                $('<p>').append(
                    $('<button type="button" class="button button-primary">')
                        .text('<?php echo esc_js(__('Continue', 'cf-zero-trust')); ?>')
                        .on('click', function() { window.location.reload(); })
                ).append(
                    $('<span style="margin-left:10px;">').text(
                        '<?php echo esc_js(__('You can now delete the API token in Cloudflare — it is no longer needed.', 'cf-zero-trust')); ?>'
                    )
                )
            );

            showToast('<?php echo esc_js(__('Cloudflare application created', 'cf-zero-trust')); ?>', 'success');

            // Give the reader a moment with any warnings, then reload. Without
            // warnings there is nothing to read, so go straight away.
            setTimeout(function() { window.location.reload(); }, warnings.length ? 8000 : 1500);
        }).fail(function() {
            cfztStatus('error', '<?php echo esc_js(__('The request failed. Check your connection and try again.', 'cf-zero-trust')); ?>');
        }).always(function() {
            $btn.prop('disabled', false).text(originalText);
        });
    }

    $('#cfzt-provision-btn').on('click', function() {
        cfztProvision(false);
    });
});
</script>

</div>