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
$auth_method = isset($options['auth_method']) ? $options['auth_method'] : 'oauth2';

// Check if setup is complete
$is_configured = !empty($options['team_domain']) && !empty($options['client_id']) && !empty($options['client_secret']);

// Get setup progress
$setup_progress = CFZT_Plugin::get_setup_progress();
?>

<style>
/* Dark mode support */
@media (prefers-color-scheme: dark) {
    body.admin-color-modern .cfzt-wizard-container,
    body[class*="admin-color-"] .cfzt-wizard-container {
        background: #1e1e1e;
        border-color: #3c434a;
    }

    body.admin-color-modern .cfzt-wizard-step,
    body[class*="admin-color-"] .cfzt-wizard-step {
        background: #1e1e1e;
    }

    body.admin-color-modern .cfzt-step-title,
    body[class*="admin-color-"] .cfzt-step-title {
        color: #e4e4e7;
    }

    body.admin-color-modern .cfzt-step-description,
    body[class*="admin-color-"] .cfzt-step-description {
        color: #a0a5aa;
    }

    body.admin-color-modern .cfzt-wizard-tabs,
    body[class*="admin-color-"] .cfzt-wizard-tabs {
        background: #2c2c2c;
        border-bottom-color: #3c434a;
    }

    body.admin-color-modern .cfzt-wizard-tab,
    body[class*="admin-color-"] .cfzt-wizard-tab {
        color: #a0a5aa;
    }

    body.admin-color-modern .cfzt-wizard-tab.active,
    body[class*="admin-color-"] .cfzt-wizard-tab.active {
        background: #1e1e1e;
        color: #f38020;
    }

    body.admin-color-modern .cfzt-radio-card,
    body[class*="admin-color-"] .cfzt-radio-card {
        background: #2c2c2c;
        border-color: #3c434a;
    }

    body.admin-color-modern .cfzt-radio-card.selected,
    body[class*="admin-color-"] .cfzt-radio-card.selected {
        background: #2d2417;
        border-color: #f38020;
    }

    body.admin-color-modern .cfzt-info-box,
    body[class*="admin-color-"] .cfzt-info-box {
        background: #1a2734;
        border-left-color: #3582c4;
    }

    body.admin-color-modern .cfzt-warning-box,
    body[class*="admin-color-"] .cfzt-warning-box {
        background: #2d2617;
        border-left-color: #f0b429;
    }

    body.admin-color-modern .cfzt-success-box,
    body[class*="admin-color-"] .cfzt-success-box {
        background: #1a2d1f;
        border-left-color: #4ab866;
    }

    body.admin-color-modern .cfzt-code-block,
    body[class*="admin-color-"] .cfzt-code-block {
        background: #2c2c2c;
        border-color: #3c434a;
        color: #e4e4e7;
    }

    body.admin-color-modern .cfzt-wizard-actions,
    body[class*="admin-color-"] .cfzt-wizard-actions {
        background: #2c2c2c;
        border-top-color: #3c434a;
    }

    body.admin-color-modern .cfzt-form-group label,
    body[class*="admin-color-"] .cfzt-form-group label {
        color: #e4e4e7;
    }

    body.admin-color-modern .cfzt-form-group .description,
    body[class*="admin-color-"] .cfzt-form-group .description {
        color: #a0a5aa;
    }
}

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
            <h1>Cloudflare Zero Trust Login</h1>
            <p>Secure WordPress authentication with Cloudflare Zero Trust</p>
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
                <span><?php echo esc_html($setup_progress['completed_count']); ?> of <?php echo esc_html($setup_progress['total_count']); ?> tasks completed</span>
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
                    <strong>1.</strong> Choose Method
                </div>
                <div class="cfzt-wizard-tab" data-step="2">
                    <strong>2.</strong> Cloudflare Setup
                </div>
                <div class="cfzt-wizard-tab" data-step="3">
                    <strong>3.</strong> Configure
                </div>
                <div class="cfzt-wizard-tab" data-step="4">
                    <strong>4.</strong> Review
                </div>
            </div>

            <form method="post" action="options.php" id="cfzt-wizard-form">
                <?php settings_fields('cfzt_settings_group'); ?>

                <!-- Step 1: Choose Authentication Method -->
                <div class="cfzt-wizard-step active" data-step="1">
                    <h2 class="cfzt-step-title">Choose Your Authentication Method</h2>
                    <p class="cfzt-step-description">Select the protocol you want to use with Cloudflare Zero Trust.</p>

                    <div class="cfzt-radio-cards">
                        <label class="cfzt-radio-card <?php echo $auth_method === 'oauth2' ? 'selected' : ''; ?>">
                            <input type="radio" name="cfzt_settings[auth_method]" value="oauth2" <?php checked($auth_method, 'oauth2'); ?>>
                            <div class="cfzt-radio-card-title">OIDC (Recommended)</div>
                            <div class="cfzt-radio-card-desc">OpenID Connect - Production-ready and secure. Best for most users.</div>
                        </label>

                        <label class="cfzt-radio-card <?php echo $auth_method === 'saml' ? 'selected' : ''; ?>">
                            <input type="radio" name="cfzt_settings[auth_method]" value="saml" <?php checked($auth_method, 'saml'); ?>>
                            <div class="cfzt-radio-card-title">SAML (Experimental)</div>
                            <div class="cfzt-radio-card-desc">SAML 2.0 - For enterprise environments. Not production-ready.</div>
                        </label>
                    </div>

                    <div class="cfzt-warning-box" id="cfzt-saml-warning" style="display: <?php echo $auth_method === 'saml' ? 'block' : 'none'; ?>;">
                        <strong>Warning:</strong> SAML support is experimental and does not perform signature validation. Use OIDC for production environments.
                    </div>
                </div>

                <!-- Step 2: Cloudflare Setup Instructions -->
                <div class="cfzt-wizard-step" data-step="2">
                    <h2 class="cfzt-step-title">Set Up Cloudflare Zero Trust</h2>
                    <p class="cfzt-step-description">Follow these steps in your Cloudflare dashboard to create your application.</p>

                    <!-- OIDC Instructions -->
                    <div id="cfzt-step2-oidc" style="display: <?php echo $auth_method === 'oauth2' ? 'block' : 'none'; ?>;">
                        <div class="cfzt-info-box">
                            <strong>In your Cloudflare Zero Trust dashboard:</strong>
                            <ol style="margin: 10px 0 0 20px;">
                                <li>Go to <strong>Access → Applications</strong></li>
                                <li>Click <strong>Add an application</strong></li>
                                <li>Select <strong>SaaS</strong> application type</li>
                                <li>Choose <strong>OIDC</strong> as the protocol</li>
                                <li>Set the redirect URL to:</li>
                            </ol>
                        </div>

                        <div class="cfzt-code-block" style="position: relative;">
                            <strong>Redirect URL:</strong><br>
                            <span id="cfzt-redirect-url"><?php echo esc_url(home_url('/wp-login.php?cfzt_callback=1')); ?></span>
                            <button type="button" class="button button-small cfzt-copy-btn" data-clipboard-target="cfzt-redirect-url" style="float: right; margin-top: -5px;">
                                <span class="dashicons dashicons-clipboard" style="margin-top: 3px;"></span> Copy
                            </button>
                        </div>

                        <div class="cfzt-info-box">
                            <p style="margin: 0;">After creating the application, Cloudflare will provide you with credentials. Keep this page open - you'll need these in the next step.</p>
                        </div>
                    </div>

                    <!-- SAML Instructions -->
                    <div id="cfzt-step2-saml" style="display: <?php echo $auth_method === 'saml' ? 'block' : 'none'; ?>;">
                        <div class="cfzt-info-box">
                            <strong>In your Cloudflare Zero Trust dashboard:</strong>
                            <ol style="margin: 10px 0 0 20px;">
                                <li>Go to <strong>Access → Applications</strong></li>
                                <li>Click <strong>Add an application</strong></li>
                                <li>Select <strong>SaaS</strong> application type</li>
                                <li>Choose <strong>SAML</strong> as the protocol</li>
                                <li>Enter the following URLs:</li>
                            </ol>
                        </div>

                        <div class="cfzt-code-block">
                            <div style="margin-bottom: 15px;">
                                <strong>Entity ID:</strong><br>
                                <span id="cfzt-entity-id"><?php echo esc_url(home_url()); ?></span>
                                <button type="button" class="button button-small cfzt-copy-btn" data-clipboard-target="cfzt-entity-id" style="margin-left: 10px;">
                                    <span class="dashicons dashicons-clipboard" style="margin-top: 3px;"></span> Copy
                                </button>
                            </div>
                            <div style="margin-bottom: 15px;">
                                <strong>Assertion Consumer Service URL:</strong><br>
                                <span id="cfzt-acs-url"><?php echo esc_url(home_url('cfzt-saml/acs/')); ?></span>
                                <button type="button" class="button button-small cfzt-copy-btn" data-clipboard-target="cfzt-acs-url" style="margin-left: 10px;">
                                    <span class="dashicons dashicons-clipboard" style="margin-top: 3px;"></span> Copy
                                </button>
                            </div>
                            <div>
                                <strong>Single Logout URL:</strong><br>
                                <span id="cfzt-sls-url"><?php echo esc_url(home_url('cfzt-saml/sls/')); ?></span>
                                <button type="button" class="button button-small cfzt-copy-btn" data-clipboard-target="cfzt-sls-url" style="margin-left: 10px;">
                                    <span class="dashicons dashicons-clipboard" style="margin-top: 3px;"></span> Copy
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Step 3: Enter Credentials -->
                <div class="cfzt-wizard-step" data-step="3">
                    <h2 class="cfzt-step-title">Enter Your Credentials</h2>
                    <p class="cfzt-step-description">Copy the credentials from Cloudflare and paste them below.</p>

                    <!-- OIDC Fields -->
                    <div id="cfzt-step3-oidc" style="display: <?php echo $auth_method === 'oauth2' ? 'block' : 'none'; ?>;">
                        <div class="cfzt-form-group">
                            <label for="cfzt_team_domain">
                                Team Domain *
                                <span class="cfzt-help-icon" data-tooltip="Your unique Cloudflare team domain. Found in your application's Issuer URL. Example: yourteam.cloudflareaccess.com">?</span>
                            </label>
                            <input type="text" id="cfzt_team_domain" name="cfzt_settings[team_domain]" value="<?php echo esc_attr($options['team_domain'] ?? ''); ?>" class="regular-text" placeholder="yourteam.cloudflareaccess.com" required>
                            <p class="description">Found in your Cloudflare Issuer URL (without https://)</p>
                        </div>

                        <div class="cfzt-form-group">
                            <label for="cfzt_app_type">
                                Application Type *
                                <span class="cfzt-help-icon" data-tooltip="SaaS applications use Cloudflare's standard OIDC endpoints and are production-ready. Self-hosted is for custom OAuth2 implementations.">?</span>
                            </label>
                            <select id="cfzt_app_type" name="cfzt_settings[app_type]" class="regular-text">
                                <option value="saas" <?php selected($options['app_type'] ?? 'saas', 'saas'); ?>>SaaS (Recommended)</option>
                                <option value="self-hosted" <?php selected($options['app_type'] ?? '', 'self-hosted'); ?>>Self-hosted</option>
                            </select>
                            <p class="description">Match the type you selected in Cloudflare</p>
                        </div>

                        <div class="cfzt-form-group">
                            <label for="cfzt_client_id">
                                Client ID *
                                <span class="cfzt-help-icon" data-tooltip="A unique identifier for your application provided by Cloudflare. Looks like a long hexadecimal string.">?</span>
                            </label>
                            <input type="text" id="cfzt_client_id" name="cfzt_settings[client_id]" value="<?php echo esc_attr($options['client_id'] ?? ''); ?>" class="regular-text" required>
                            <p class="description">From your Cloudflare application</p>
                        </div>

                        <div class="cfzt-form-group">
                            <label for="cfzt_client_secret">
                                Client Secret *
                                <span class="cfzt-help-icon" data-tooltip="A secret key used to authenticate your application with Cloudflare. Keep this secure! It will be encrypted in your database.">?</span>
                            </label>
                            <input type="password" id="cfzt_client_secret" name="cfzt_settings[client_secret]" value="<?php echo isset($options['client_secret']) ? esc_attr($security->decrypt_data($options['client_secret'])) : ''; ?>" class="regular-text" required>
                            <p class="description">From your Cloudflare application (will be encrypted)</p>
                        </div>
                    </div>

                    <!-- SAML Fields -->
                    <div id="cfzt-step3-saml" style="display: <?php echo $auth_method === 'saml' ? 'block' : 'none'; ?>;">
                        <div class="cfzt-form-group">
                            <label for="cfzt_team_domain_saml">Team Domain *</label>
                            <input type="text" id="cfzt_team_domain_saml" name="cfzt_settings[team_domain]" value="<?php echo esc_attr($options['team_domain'] ?? ''); ?>" class="regular-text" placeholder="yourteam.cloudflareaccess.com">
                            <p class="description">Your Cloudflare team domain</p>
                        </div>

                        <div class="cfzt-form-group">
                            <label for="cfzt_saml_sso_target_url">SSO Target URL ID *</label>
                            <input type="text" id="cfzt_saml_sso_target_url" name="cfzt_settings[saml_sso_target_url]" value="<?php echo esc_attr($options['saml_sso_target_url'] ?? ''); ?>" class="regular-text">
                            <p class="description">The unique ID from your Cloudflare SAML SSO endpoint URL</p>
                        </div>

                        <div class="cfzt-form-group">
                            <label for="cfzt_saml_sp_entity_id">SP Entity ID</label>
                            <input type="text" id="cfzt_saml_sp_entity_id" name="cfzt_settings[saml_sp_entity_id]" value="<?php echo esc_attr($options['saml_sp_entity_id'] ?? ''); ?>" class="regular-text" placeholder="<?php echo esc_attr(home_url()); ?>">
                            <p class="description">Leave empty to use your site URL</p>
                        </div>

                        <div class="cfzt-form-group">
                            <label for="cfzt_saml_x509_cert">X.509 Certificate (Optional)</label>
                            <textarea id="cfzt_saml_x509_cert" name="cfzt_settings[saml_x509_cert]" rows="6" class="large-text code"><?php echo esc_textarea($options['saml_x509_cert'] ?? ''); ?></textarea>
                            <p class="description">Include the entire certificate including BEGIN/END lines</p>
                        </div>
                    </div>

                    <!-- Additional Settings -->
                    <h3 style="margin-top: 30px; border-bottom: 1px solid #ccd0d4; padding-bottom: 10px;">User & Login Settings</h3>

                    <div class="cfzt-form-group">
                        <label for="cfzt_login_mode">
                            Login Mode
                            <span class="cfzt-help-icon" data-tooltip="Primary mode disables WordPress login, forcing all users to use Cloudflare. Secondary mode keeps both options available.">?</span>
                        </label>
                        <select id="cfzt_login_mode" name="cfzt_settings[login_mode]" class="regular-text">
                            <option value="secondary" <?php selected($options['login_mode'] ?? 'secondary', 'secondary'); ?>>Secondary - Show both login options</option>
                            <option value="primary" <?php selected($options['login_mode'] ?? '', 'primary'); ?>>Primary - Cloudflare only</option>
                        </select>
                        <p class="description">Choose how users can log in to your site</p>
                    </div>

                    <div class="cfzt-form-group">
                        <label for="cfzt_auto_create_users">
                            Auto-create Users
                            <span class="cfzt-help-icon" data-tooltip="When enabled, WordPress user accounts are automatically created for authenticated Cloudflare users on their first login. If disabled, only existing WordPress users can log in.">?</span>
                        </label>
                        <select id="cfzt_auto_create_users" name="cfzt_settings[auto_create_users]" class="regular-text">
                            <option value="yes" <?php selected($options['auto_create_users'] ?? 'yes', 'yes'); ?>>Yes</option>
                            <option value="no" <?php selected($options['auto_create_users'] ?? '', 'no'); ?>>No</option>
                        </select>
                        <p class="description">Automatically create WordPress users on first login</p>
                    </div>

                    <div class="cfzt-form-group">
                        <label for="cfzt_default_role">
                            Default User Role
                            <span class="cfzt-help-icon" data-tooltip="New users created through Cloudflare authentication will be assigned this WordPress role. Choose carefully based on your security needs.">?</span>
                        </label>
                        <select id="cfzt_default_role" name="cfzt_settings[default_role]" class="regular-text">
                            <?php wp_dropdown_roles($options['default_role'] ?? 'subscriber'); ?>
                        </select>
                        <p class="description">Role assigned to new users</p>
                    </div>

                    <div class="cfzt-form-group">
                        <label for="cfzt_enable_logging">
                            Enable Logging
                            <span class="cfzt-help-icon" data-tooltip="Logs authentication attempts to your database for debugging and monitoring. Includes timestamp, user, IP address, and success status.">?</span>
                        </label>
                        <select id="cfzt_enable_logging" name="cfzt_settings[enable_logging]" class="regular-text">
                            <option value="yes" <?php selected($options['enable_logging'] ?? 'no', 'yes'); ?>>Yes</option>
                            <option value="no" <?php selected($options['enable_logging'] ?? '', 'no'); ?>>No</option>
                        </select>
                        <p class="description">Log authentication attempts for debugging</p>
                    </div>

                    <!-- Advanced Settings -->
                    <h3 style="margin-top: 30px; border-bottom: 1px solid #ccd0d4; padding-bottom: 10px;">Advanced Settings</h3>

                    <div class="cfzt-form-group">
                        <label for="cfzt_email_domain_restrictions">
                            Email Domain Restrictions
                            <span class="cfzt-help-icon" data-tooltip="Restrict authentication to specific email domains. Enter one domain per line (e.g., example.com). Leave empty to allow all domains.">?</span>
                        </label>
                        <textarea id="cfzt_email_domain_restrictions" name="cfzt_settings[email_domain_restrictions]" rows="3" class="large-text" placeholder="example.com&#10;company.org"><?php echo esc_textarea($options['email_domain_restrictions'] ?? ''); ?></textarea>
                        <p class="description"><?php _e('One domain per line. Users with email addresses from these domains will be allowed to log in.', 'cf-zero-trust'); ?></p>
                    </div>

                    <div class="cfzt-form-group">
                        <label for="cfzt_redirect_after_login">
                            Redirect After Login
                            <span class="cfzt-help-icon" data-tooltip="Custom URL to redirect users after successful login. Leave empty to use WordPress default (wp-admin for admins, home for others).">?</span>
                        </label>
                        <input type="url" id="cfzt_redirect_after_login" name="cfzt_settings[redirect_after_login]" value="<?php echo esc_attr($options['redirect_after_login'] ?? ''); ?>" class="large-text" placeholder="<?php echo esc_attr(home_url()); ?>">
                        <p class="description"><?php _e('Leave empty to use WordPress default redirect behavior.', 'cf-zero-trust'); ?></p>
                    </div>

                    <div class="cfzt-form-group">
                        <label for="cfzt_redirect_after_logout">
                            Redirect After Logout
                            <span class="cfzt-help-icon" data-tooltip="Custom URL to redirect users after logout. Leave empty to redirect to home page.">?</span>
                        </label>
                        <input type="url" id="cfzt_redirect_after_logout" name="cfzt_settings[redirect_after_logout]" value="<?php echo esc_attr($options['redirect_after_logout'] ?? ''); ?>" class="large-text" placeholder="<?php echo esc_attr(home_url()); ?>">
                        <p class="description"><?php _e('Leave empty to redirect to home page.', 'cf-zero-trust'); ?></p>
                    </div>

                    <div class="cfzt-form-group">
                        <label>
                            Role Mapping (Cloudflare Groups → WordPress Roles)
                            <span class="cfzt-help-icon" data-tooltip="Map Cloudflare Access groups to WordPress roles. When a user logs in, their WordPress role will be automatically set based on their Cloudflare group membership.">?</span>
                        </label>
                        <div id="cfzt-role-mappings">
                            <?php
                            $role_mappings = isset($options['role_mapping']) && is_array($options['role_mapping']) ? $options['role_mapping'] : array();
                            if (empty($role_mappings)) {
                                $role_mappings = array(array('group' => '', 'role' => 'subscriber'));
                            }
                            foreach ($role_mappings as $index => $mapping):
                            ?>
                            <div class="cfzt-role-mapping-row" style="display: flex; gap: 10px; margin-bottom: 10px; align-items: center;">
                                <input type="text" name="cfzt_settings[role_mapping][<?php echo $index; ?>][group]" value="<?php echo esc_attr($mapping['group']); ?>" placeholder="Cloudflare group name" class="regular-text" style="flex: 1;">
                                <span>→</span>
                                <select name="cfzt_settings[role_mapping][<?php echo $index; ?>][role]" class="regular-text" style="flex: 1;">
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
                <div class="cfzt-wizard-step" data-step="4">
                    <h2 class="cfzt-step-title">Review Your Configuration</h2>
                    <p class="cfzt-step-description">Please review your settings before saving.</p>

                    <div class="cfzt-success-box">
                        <h3 style="margin-top: 0;">Configuration Summary</h3>
                        <ul class="cfzt-checklist" id="cfzt-review-list">
                            <!-- Will be populated by JavaScript -->
                        </ul>
                    </div>

                    <div class="cfzt-info-box">
                        <strong>Before Saving:</strong>
                        <p style="margin: 10px 0;">We recommend testing your connection to Cloudflare before saving:</p>
                        <button type="button" id="cfzt-test-connection-wizard" class="button button-secondary" style="margin-bottom: 15px;">
                            <span class="dashicons dashicons-yes-alt" style="margin-top: 3px;"></span> Test Connection Now
                        </button>
                        <div id="cfzt-test-results-wizard" style="display: none;"></div>
                    </div>

                    <div class="cfzt-info-box">
                        <strong>Next Steps:</strong>
                        <ol style="margin: 10px 0 0 20px;">
                            <li>Test your connection (recommended)</li>
                            <li>Click "Save Configuration" below</li>
                            <li>Visit your WordPress login page</li>
                            <li>Click "Login with Cloudflare Zero Trust"</li>
                            <li>Test the authentication flow</li>
                        </ol>
                    </div>

                    <?php if (!$security_status['encryption_available']): ?>
                    <div class="cfzt-warning-box">
                        <strong>Security Notice:</strong> OpenSSL is not available. Client secrets will be stored with basic obfuscation. Consider enabling OpenSSL for better security.
                    </div>
                    <?php endif; ?>
                </div>

                <!-- Wizard Actions -->
                <div class="cfzt-wizard-actions">
                    <button type="button" id="cfzt-prev-step" class="button" style="display: none;">Previous</button>
                    <div>
                        <button type="button" id="cfzt-next-step" class="button button-primary">Next</button>
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
                        <p><?php _e('Download your current configuration as a JSON file. This includes all settings except sensitive data is decrypted for portability.', 'cf-zero-trust'); ?></p>
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
    var totalSteps = 4;

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
            showToast('Copied to clipboard!', 'success');

            // Visual feedback on button
            var $btn = $(this);
            var originalHtml = $btn.html();
            $btn.html('<span class="dashicons dashicons-yes" style="margin-top: 3px;"></span> Copied!');
            $btn.addClass('button-primary');

            setTimeout(function() {
                $btn.html(originalHtml);
                $btn.removeClass('button-primary');
            }, 2000);
        } catch (err) {
            showToast('Failed to copy. Please copy manually.', 'error');
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

        // Show/hide SAML warning
        if ($(this).val() === 'saml') {
            $('#cfzt-saml-warning').slideDown();
        } else {
            $('#cfzt-saml-warning').slideUp();
        }

        // Update step 2 and 3 content
        updateStepContent();
    });

    // Update step content based on selected auth method
    function updateStepContent() {
        var authMethod = $('input[name="cfzt_settings[auth_method]"]:checked').val();

        if (authMethod === 'saml') {
            $('#cfzt-step2-oidc, #cfzt-step3-oidc').hide();
            $('#cfzt-step2-saml, #cfzt-step3-saml').show();
        } else {
            $('#cfzt-step2-oidc, #cfzt-step3-oidc').show();
            $('#cfzt-step2-saml, #cfzt-step3-saml').hide();
        }
    }

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
        if (step === 3) {
            var authMethod = $('input[name="cfzt_settings[auth_method]"]:checked').val();
            var teamDomain = $('#cfzt_team_domain').val() || $('#cfzt_team_domain_saml').val();

            if (!teamDomain) {
                alert('<?php _e('Please enter your Team Domain', 'cf-zero-trust'); ?>');
                return false;
            }

            if (authMethod === 'oauth2') {
                if (!$('#cfzt_client_id').val()) {
                    alert('<?php _e('Please enter your Client ID', 'cf-zero-trust'); ?>');
                    return false;
                }
                if (!$('#cfzt_client_secret').val()) {
                    alert('<?php _e('Please enter your Client Secret', 'cf-zero-trust'); ?>');
                    return false;
                }
            } else {
                if (!$('#cfzt_saml_sso_target_url').val()) {
                    alert('<?php _e('Please enter your SSO Target URL ID', 'cf-zero-trust'); ?>');
                    return false;
                }
            }
        }
        return true;
    }

    function populateReview() {
        var authMethod = $('input[name="cfzt_settings[auth_method]"]:checked').val();
        var authMethodText = authMethod === 'saml' ? 'SAML' : 'OIDC';
        var teamDomain = $('#cfzt_team_domain').val() || $('#cfzt_team_domain_saml').val();
        var loginMode = $('#cfzt_login_mode option:selected').text();
        var autoCreate = $('#cfzt_auto_create_users').val() === 'yes' ? 'Enabled' : 'Disabled';
        var defaultRole = $('#cfzt_default_role option:selected').text();

        var html = '';
        html += '<li>Authentication Method: <strong>' + authMethodText + '</strong></li>';
        html += '<li>Team Domain: <strong>' + teamDomain + '</strong></li>';

        if (authMethod === 'oauth2') {
            html += '<li>Application Type: <strong>' + $('#cfzt_app_type option:selected').text() + '</strong></li>';
            html += '<li>Client ID: <strong>' + $('#cfzt_client_id').val().substring(0, 20) + '...</strong></li>';
        } else {
            html += '<li>SSO Target URL configured</li>';
        }

        html += '<li>Login Mode: <strong>' + loginMode + '</strong></li>';
        html += '<li>Auto-create Users: <strong>' + autoCreate + '</strong></li>';
        html += '<li>Default Role: <strong>' + defaultRole + '</strong></li>';

        $('#cfzt-review-list').html(html);
    }

    // Initialize
    updateStepContent();
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
                    showToast('Saving configuration...', 'success');
                }
            } else if ($('#cfzt-advanced-mode').is(':visible')) {
                $('#cfzt-advanced-mode form').submit();
                showToast('Saving configuration...', 'success');
            }
        }

        // ESC to close dismissible notices
        if (e.key === 'Escape') {
            $('.notice.is-dismissible .notice-dismiss').click();
        }
    });

    // Show keyboard hint tooltip on form focus
    var keyboardHintShown = false;
    $('form input, form select, form textarea').one('focus', function() {
        if (!keyboardHintShown) {
            keyboardHintShown = true;
            var hint = $('<div class="cfzt-toast" style="bottom: 80px; background: #2271b1;">' +
                '<span class="dashicons dashicons-info" style="margin-top: 3px;"></span>' +
                '<span>Tip: Press <strong>Ctrl/Cmd + S</strong> to save</span>' +
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
        $button.prop('disabled', true).html('<span class="dashicons dashicons-update spin" style="margin-top: 3px;"></span> Testing...');

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
                        html += '<strong>⚠ Warnings:</strong><ul style="margin: 5px 0 0 20px;">';
                        response.data.warnings.forEach(function(warning) {
                            html += '<li>' + warning + '</li>';
                        });
                        html += '</ul></div>';
                    }

                    html += '</div>';
                    showToast('Connection test passed!', 'success');
                } else {
                    html = '<div class="cfzt-warning-box" style="margin-top: 15px; background: #fcf2f2; border-left-color: #d63638;">';
                    html += '<strong style="color: #d63638;">✗ ' + (response.data.message || 'Connection test failed') + '</strong>';

                    if (response.data.issues && response.data.issues.length > 0) {
                        html += '<ul style="margin: 10px 0 0 20px;">';
                        response.data.issues.forEach(function(issue) {
                            html += '<li>' + issue + '</li>';
                        });
                        html += '</ul>';
                    }

                    if (response.data.warnings && response.data.warnings.length > 0) {
                        html += '<div style="margin-top: 10px; padding: 10px; background: rgba(255, 193, 7, 0.1); border-left: 3px solid #ffc107;">';
                        html += '<strong>⚠ Additional warnings:</strong><ul style="margin: 5px 0 0 20px;">';
                        response.data.warnings.forEach(function(warning) {
                            html += '<li>' + warning + '</li>';
                        });
                        html += '</ul></div>';
                    }

                    html += '</div>';
                    showToast('Connection test failed', 'error');
                }

                if ($resultsContainer) {
                    $resultsContainer.html(html).slideDown();
                }
            },
            error: function() {
                var html = '<div class="cfzt-warning-box" style="margin-top: 15px; background: #fcf2f2; border-left-color: #d63638;">';
                html += '<strong style="color: #d63638;">✗ Connection test failed</strong>';
                html += '<p>An unexpected error occurred. Please try again.</p>';
                html += '</div>';

                if ($resultsContainer) {
                    $resultsContainer.html(html).slideDown();
                }
                showToast('Connection test failed', 'error');
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
                message = 'Should end with .cloudflareaccess.com';
            } else {
                message = 'Valid team domain format';
            }
        }

        if (rules.clientId) {
            if (value.length < 16) {
                isValid = false;
                message = 'Client ID seems too short';
            } else if (!value.match(/^[a-f0-9]+$/i)) {
                isWarning = true;
                message = 'Client ID usually contains only hex characters';
            } else {
                message = 'Valid client ID format';
            }
        }

        if (rules.clientSecret) {
            if (value === '[SET VIA CONSTANT]') {
                isWarning = true;
                message = 'Value set via constant (cannot be changed here)';
            } else if (value.length < 16) {
                isValid = false;
                message = 'Client secret seems too short';
            } else {
                message = 'Client secret looks good';
            }
        }

        if (rules.url) {
            try {
                new URL(value);
                message = 'Valid URL format';
            } catch (e) {
                isValid = false;
                message = 'Please enter a valid URL';
            }
        }

        if (rules.alphanumeric) {
            if (!value.match(/^[a-z0-9-_]+$/i)) {
                isValid = false;
                message = 'Should contain only letters, numbers, hyphens, and underscores';
            } else {
                message = 'Valid format';
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
    $('#cfzt_team_domain, #cfzt_team_domain_saml').on('input blur', function() {
        validateField($(this), { teamDomain: true });
    });

    $('#cfzt_client_id').on('input blur', function() {
        validateField($(this), { clientId: true });
    });

    $('#cfzt_client_secret').on('input blur', function() {
        validateField($(this), { clientSecret: true });
    });

    $('#cfzt_saml_sso_target_url').on('input blur', function() {
        validateField($(this), { alphanumeric: true });
    });

    $('#cfzt_saml_sp_entity_id').on('input blur', function() {
        var val = $(this).val().trim();
        if (val !== '') {
            validateField($(this), { url: true });
        }
    });

    // Trigger validation on existing values (for edit mode)
    setTimeout(function() {
        $('#cfzt_team_domain, #cfzt_team_domain_saml').each(function() {
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
            '<input type="text" name="cfzt_settings[role_mapping][' + roleMappingIndex + '][group]" placeholder="Cloudflare group name" class="regular-text" style="flex: 1;">' +
            '<span>→</span>' +
            '<select name="cfzt_settings[role_mapping][' + roleMappingIndex + '][role]" class="regular-text" style="flex: 1;">' + roleOptions + '</select>' +
            '<button type="button" class="button cfzt-remove-mapping" style="color: #d63638;"><span class="dashicons dashicons-trash"></span></button>' +
            '</div>';

        $('#cfzt-role-mappings').append(newRow);
        roleMappingIndex++;
    });

    // Role mapping - Remove row
    $(document).on('click', '.cfzt-remove-mapping', function() {
        if ($('.cfzt-role-mapping-row').length > 1) {
            $(this).closest('.cfzt-role-mapping-row').remove();
        } else {
            alert('<?php _e('You must have at least one role mapping.', 'cf-zero-trust'); ?>');
        }
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
});
</script>

</div>