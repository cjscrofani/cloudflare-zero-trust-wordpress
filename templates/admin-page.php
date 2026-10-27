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

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- included from a CFZT_Admin method, so these variables are local to that call

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

<div class="wrap">
    <div class="cfzt-wizard-container">
        <!-- Header -->
        <div class="cfzt-wizard-header">
            <h1><?php esc_html_e('Zero Trust Login for Cloudflare', 'zero-trust-login-for-cloudflare'); ?></h1>
            <p><?php esc_html_e('Secure WordPress authentication with Cloudflare Zero Trust', 'zero-trust-login-for-cloudflare'); ?></p>
        </div>

        <!-- Setup Progress Indicator -->
        <?php if ($setup_progress['percentage'] < 100): ?>
        <div class="cfzt-setup-progress-container">
            <div class="cfzt-progress-header">
                <span class="cfzt-progress-title">
                    <span class="dashicons dashicons-admin-settings" style="font-size: 16px; width: 16px; height: 16px;"></span>
                    <?php esc_html_e('Setup Progress', 'zero-trust-login-for-cloudflare'); ?>
                </span>
                <span class="cfzt-progress-percentage"><?php echo esc_html($setup_progress['percentage']); ?>%</span>
            </div>
            <div class="cfzt-progress-bar-wrapper">
                <div class="cfzt-progress-bar" style="width: <?php echo esc_attr($setup_progress['percentage']); ?>%;"></div>
            </div>
            <div class="cfzt-progress-details">
                <span><?php
                    /* translators: 1: completed task count, 2: total task count */
                    echo esc_html(sprintf(__('%1$d of %2$d tasks completed', 'zero-trust-login-for-cloudflare'), $setup_progress['completed_count'], $setup_progress['total_count']));
                ?></span>
                <?php if (!empty($setup_progress['incomplete'])): ?>
                <button type="button" class="button-link cfzt-toggle-tasks">
                    <?php esc_html_e('View remaining tasks', 'zero-trust-login-for-cloudflare'); ?> ▼
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
            <strong><?php esc_html_e('Setup Complete!', 'zero-trust-login-for-cloudflare'); ?></strong>
            <span><?php esc_html_e('Your Cloudflare Zero Trust integration is fully configured.', 'zero-trust-login-for-cloudflare'); ?></span>
        </div>
        <?php endif; ?>

        <!-- Mode Toggle -->
        <div class="cfzt-wizard-mode-toggle">
            <button type="button" id="cfzt-toggle-mode" class="button">
                <?php echo $is_configured ? esc_html__('Switch to Wizard Mode', 'zero-trust-login-for-cloudflare') : esc_html__('Switch to Advanced Mode', 'zero-trust-login-for-cloudflare'); ?>
            </button>
        </div>

        <!-- Wizard Mode -->
        <div id="cfzt-wizard-mode" style="display: <?php echo $is_configured ? 'none' : 'block'; ?>;">
            <!-- Progress Tabs -->
            <div class="cfzt-wizard-tabs">
                <div class="cfzt-wizard-tab active" data-step="1">
                    <strong>1.</strong> <?php esc_html_e('Cloudflare Setup', 'zero-trust-login-for-cloudflare'); ?>
                </div>
                <div class="cfzt-wizard-tab" data-step="2">
                    <strong>2.</strong> <?php esc_html_e('Configure', 'zero-trust-login-for-cloudflare'); ?>
                </div>
                <div class="cfzt-wizard-tab" data-step="3">
                    <strong>3.</strong> <?php esc_html_e('Review', 'zero-trust-login-for-cloudflare'); ?>
                </div>
            </div>

            <form method="post" action="options.php" id="cfzt-wizard-form">
                <?php settings_fields('cfzt_settings_group'); ?>

                <input type="hidden" name="cfzt_settings[auth_method]" value="oauth2">

                <!-- Step 1: Cloudflare Setup Instructions -->
                <div class="cfzt-wizard-step active" data-step="1">
                    <h2 class="cfzt-step-title"><?php esc_html_e('Set Up Cloudflare Zero Trust', 'zero-trust-login-for-cloudflare'); ?></h2>
                    <p class="cfzt-step-description"><?php esc_html_e('Create the Access application automatically, or follow the manual steps in your Cloudflare dashboard.', 'zero-trust-login-for-cloudflare'); ?></p>

                    <!-- OIDC Instructions -->
                    <div id="cfzt-step2-oidc">

                        <?php if ($provisioned) : ?>
                        <!-- Already provisioned by this plugin -->
                        <div class="cfzt-success-box" id="cfzt-provisioned-state">
                            <h3 style="margin-top: 0;">
                                <span class="dashicons dashicons-yes-alt" style="color: #00a32a;"></span>
                                <?php esc_html_e('Connected to Cloudflare', 'zero-trust-login-for-cloudflare'); ?>
                            </h3>
                            <p style="margin: 0 0 10px;">
                                <?php esc_html_e('This plugin created the Access application for this site. There is nothing to do here unless you want to start over.', 'zero-trust-login-for-cloudflare'); ?>
                            </p>
                            <ul style="margin: 0 0 10px 20px; list-style: disc;">
                                <li><?php esc_html_e('Team domain:', 'zero-trust-login-for-cloudflare'); ?> <code><?php echo esc_html($options['team_domain'] ?? ''); ?></code></li>
                                <li><?php esc_html_e('Application ID:', 'zero-trust-login-for-cloudflare'); ?> <code><?php echo esc_html($options['provisioned_app_id']); ?></code></li>
                                <?php if (!empty($options['provisioned_account_id'])) : ?>
                                <li><?php esc_html_e('Cloudflare account:', 'zero-trust-login-for-cloudflare'); ?> <code><?php echo esc_html($options['provisioned_account_id']); ?></code></li>
                                <?php endif; ?>
                                <?php if (!empty($options['provisioned_at'])) : ?>
                                <li><?php
                                    /* translators: %s: date and time */
                                    echo esc_html(sprintf(__('Created: %s', 'zero-trust-login-for-cloudflare'), mysql2date(get_option('date_format') . ' ' . get_option('time_format'), $options['provisioned_at'])));
                                ?></li>
                                <?php endif; ?>
                            </ul>
                            <p style="margin: 0;">
                                <button type="button" class="button" id="cfzt-reprovision-btn">
                                    <?php esc_html_e('Run automatic setup again', 'zero-trust-login-for-cloudflare'); ?>
                                </button>
                                <span class="description" style="margin-left: 8px;"><?php esc_html_e('Replaces the Cloudflare application and issues new credentials.', 'zero-trust-login-for-cloudflare'); ?></span>
                            </p>
                        </div>
                        <?php endif; ?>

                        <!-- Automatic provisioning -->
                        <div class="cfzt-auto-setup" id="cfzt-auto-setup" <?php echo $provisioned ? 'style="display:none;"' : ''; ?>>
                            <h3 style="margin-top: 0;">
                                <span class="dashicons dashicons-superhero-alt" style="color: #f38020;"></span>
                                <?php esc_html_e('Set this up for me', 'zero-trust-login-for-cloudflare'); ?>
                            </h3>
                            <p class="cfzt-step-description">
                                <?php esc_html_e('Authorize once with a Cloudflare API token and this plugin will create the Access application, read your team domain, and fill in the credentials below. Nothing to copy by hand.', 'zero-trust-login-for-cloudflare'); ?>
                            </p>

                            <?php if ($constants_defined) : ?>
                            <div class="cfzt-warning-box">
                                <?php echo wp_kses_post(__('<strong>Automatic setup is unavailable.</strong> <code>CFZT_CLIENT_ID</code> or <code>CFZT_CLIENT_SECRET</code> is defined in <code>wp-config.php</code>, and those values override anything saved here. Cloudflare shows a new client secret exactly once, so provisioning now would create an application whose secret could never be stored. Remove the constants first, or create the application manually and update them.', 'zero-trust-login-for-cloudflare')); ?>
                            </div>
                            <?php endif; ?>

                            <!-- Phase 1: token -->
                            <div id="cfzt-auto-phase-token" <?php echo $constants_defined ? 'style="display:none;"' : ''; ?>>
                                <p>
                                    <a href="<?php echo esc_url(CFZT_Provisioner::get_token_template_url()); ?>"
                                       target="_blank" rel="noopener noreferrer"
                                       class="button button-secondary">
                                        <span class="dashicons dashicons-external" style="margin-top: 3px;"></span>
                                        <?php esc_html_e('1. Create a token on Cloudflare', 'zero-trust-login-for-cloudflare'); ?>
                                    </a>
                                </p>
                                <p class="description">
                                    <?php echo wp_kses_post(__('Opens Cloudflare with the required permissions preselected. Click <strong>Continue to summary</strong>, then <strong>Create Token</strong>, and copy the token it shows you.', 'zero-trust-login-for-cloudflare')); ?>
                                </p>
                                <details style="margin: 10px 0;">
                                    <summary style="cursor: pointer;"><?php esc_html_e('Permissions this token needs, if you prefer to build it yourself', 'zero-trust-login-for-cloudflare'); ?></summary>
                                    <ul style="margin: 10px 0 0 20px; list-style: disc;">
                                        <li><code><?php esc_html_e('Account → Access: Apps and Policies → Edit', 'zero-trust-login-for-cloudflare'); ?></code></li>
                                        <li><code><?php esc_html_e('Account → Access: Organizations, Identity Providers, and Groups → Read', 'zero-trust-login-for-cloudflare'); ?></code></li>
                                        <li><code><?php esc_html_e('Account → Account Settings → Read', 'zero-trust-login-for-cloudflare'); ?></code></li>
                                    </ul>
                                </details>

                                <div class="cfzt-form-group" style="margin-top: 15px;">
                                    <label for="cfzt-cf-token"><?php esc_html_e('2. Paste your API token', 'zero-trust-login-for-cloudflare'); ?></label>
                                    <input type="password" id="cfzt-cf-token" class="regular-text" autocomplete="off"
                                           spellcheck="false" placeholder="<?php esc_attr_e('Cloudflare API token', 'zero-trust-login-for-cloudflare'); ?>">
                                    <button type="button" class="button button-primary" id="cfzt-connect-btn">
                                        <?php esc_html_e('Connect', 'zero-trust-login-for-cloudflare'); ?>
                                    </button>
                                    <p class="description">
                                        <?php esc_html_e('The token is used for this setup only. It is never saved to your database. You can delete it in Cloudflare as soon as setup finishes.', 'zero-trust-login-for-cloudflare'); ?>
                                    </p>
                                </div>
                            </div>

                            <!-- Phase 2: choose account + policy -->
                            <div id="cfzt-auto-phase-configure" style="display: none;">
                                <div class="cfzt-form-group" id="cfzt-account-wrap">
                                    <label for="cfzt-cf-account"><?php esc_html_e('Cloudflare account', 'zero-trust-login-for-cloudflare'); ?></label>
                                    <select id="cfzt-cf-account" class="regular-text"></select>
                                </div>

                                <div class="cfzt-form-group">
                                    <label for="cfzt-app-name"><?php esc_html_e('Application name', 'zero-trust-login-for-cloudflare'); ?></label>
                                    <input type="text" id="cfzt-app-name" class="regular-text"
                                           value="<?php /* translators: %s: site name */ echo esc_attr(sprintf(__('%s (WordPress)', 'zero-trust-login-for-cloudflare'), wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES))); ?>">
                                    <p class="description"><?php esc_html_e('How the application will appear in your Cloudflare dashboard.', 'zero-trust-login-for-cloudflare'); ?></p>
                                </div>

                                <div class="cfzt-form-group">
                                    <label for="cfzt-policy-mode"><?php esc_html_e('Who should be allowed to log in?', 'zero-trust-login-for-cloudflare'); ?></label>
                                    <select id="cfzt-policy-mode" class="regular-text">
                                        <option value="email_domain"><?php esc_html_e('Anyone with an email at these domains', 'zero-trust-login-for-cloudflare'); ?></option>
                                        <option value="emails"><?php esc_html_e('Only these specific email addresses', 'zero-trust-login-for-cloudflare'); ?></option>
                                        <option value="everyone"><?php esc_html_e('Anyone who reaches my identity provider', 'zero-trust-login-for-cloudflare'); ?></option>
                                    </select>
                                </div>

                                <div class="cfzt-form-group" id="cfzt-policy-value-wrap">
                                    <label for="cfzt-policy-value" id="cfzt-policy-value-label"><?php esc_html_e('Allowed email domains', 'zero-trust-login-for-cloudflare'); ?></label>
                                    <input type="text" id="cfzt-policy-value" class="regular-text"
                                           value="<?php
                                           $current_user_email = wp_get_current_user()->user_email;
                                           $email_parts = explode('@', (string) $current_user_email);
                                           echo esc_attr(count($email_parts) === 2 ? $email_parts[1] : '');
                                           ?>">
                                    <p class="description">
                                        <?php esc_html_e('Separate multiple entries with commas. This becomes the Access policy on the new application.', 'zero-trust-login-for-cloudflare'); ?>
                                        <strong><?php esc_html_e('Use the domain your identity provider issues for logins.', 'zero-trust-login-for-cloudflare'); ?></strong>
                                        <?php esc_html_e('It is prefilled from your WordPress email, which may not be the same thing: if your team signs in with Google Workspace accounts at another domain, enter that domain here or the first login will be denied.', 'zero-trust-login-for-cloudflare'); ?>
                                    </p>
                                </div>

                                <div class="cfzt-warning-box" id="cfzt-everyone-warning" style="display: none;">
                                    <?php echo wp_kses_post(__('<strong>Careful:</strong> this allows anyone your identity provider authenticates to reach your WordPress login. Only choose it if your identity provider is already restricted to the right people.', 'zero-trust-login-for-cloudflare')); ?>
                                    <?php echo wp_kses_post(__('Combined with <strong>Auto-create Users</strong> (on by default) it also means every one of those people gets a WordPress account the first time they sign in. If Cloudflare\'s One-time PIN login is enabled for your team, that is anyone with an email address.', 'zero-trust-login-for-cloudflare')); ?>
                                </div>

                                <div class="cfzt-code-block">
                                    <strong><?php esc_html_e('Redirect URL that will be registered:', 'zero-trust-login-for-cloudflare'); ?></strong><br>
                                    <span id="cfzt-auto-redirect-uri"><?php echo esc_url(CFZT_Plugin::get_redirect_uri()); ?></span>
                                </div>

                                <p>
                                    <button type="button" class="button button-primary button-hero" id="cfzt-provision-btn">
                                        <?php esc_html_e('Create application in Cloudflare', 'zero-trust-login-for-cloudflare'); ?>
                                    </button>
                                    <button type="button" class="button button-link" id="cfzt-auto-back-btn">
                                        <?php esc_html_e('Use a different token', 'zero-trust-login-for-cloudflare'); ?>
                                    </button>
                                </p>
                            </div>

                            <!-- Feedback -->
                            <div id="cfzt-auto-status" style="display: none;" aria-live="polite"></div>
                        </div>

                        <details class="cfzt-manual-setup" style="margin-top: 25px;">
                            <summary style="cursor: pointer; font-weight: 600;">
                                <?php esc_html_e('Or set it up manually in the Cloudflare dashboard', 'zero-trust-login-for-cloudflare'); ?>
                            </summary>
                        <div class="cfzt-info-box" style="margin-top: 15px;">
                            <strong><?php esc_html_e('In your Cloudflare Zero Trust dashboard:', 'zero-trust-login-for-cloudflare'); ?></strong>
                            <ol style="margin: 10px 0 0 20px;">
                                <li><?php echo wp_kses_post(__('Go to <strong>Access → Applications</strong>', 'zero-trust-login-for-cloudflare')); ?></li>
                                <li><?php echo wp_kses_post(__('Click <strong>Add an application</strong>', 'zero-trust-login-for-cloudflare')); ?></li>
                                <li><?php echo wp_kses_post(__('Select <strong>SaaS</strong> application type', 'zero-trust-login-for-cloudflare')); ?></li>
                                <li><?php echo wp_kses_post(__('Choose <strong>OIDC</strong> as the protocol', 'zero-trust-login-for-cloudflare')); ?></li>
                                <li><?php echo wp_kses_post(__('Under <strong>Scopes</strong> keep <code>openid</code>, <code>email</code>, <code>profile</code> and <code>groups</code> selected', 'zero-trust-login-for-cloudflare')); ?></li>
                                <li><?php esc_html_e('Set the redirect URL to:', 'zero-trust-login-for-cloudflare'); ?></li>
                            </ol>
                        </div>

                        <div class="cfzt-code-block" style="position: relative;">
                            <strong><?php esc_html_e('Redirect URL:', 'zero-trust-login-for-cloudflare'); ?></strong><br>
                            <span id="cfzt-redirect-url"><?php echo esc_url(CFZT_Plugin::get_redirect_uri()); ?></span>
                            <button type="button" class="button button-small cfzt-copy-btn" data-clipboard-target="cfzt-redirect-url" style="float: right; margin-top: -5px;">
                                <span class="dashicons dashicons-clipboard" style="margin-top: 3px;"></span> <?php esc_html_e('Copy', 'zero-trust-login-for-cloudflare'); ?>
                            </button>
                        </div>

                        <div class="cfzt-info-box">
                            <p style="margin: 0;"><?php esc_html_e('After creating the application, Cloudflare will provide you with credentials. Keep this page open - you\'ll need these in the next step.', 'zero-trust-login-for-cloudflare'); ?></p>
                        </div>
                        </details>
                    </div>

                </div>

                <!-- Step 2: Enter Credentials -->
                <div class="cfzt-wizard-step" data-step="2">
                    <h2 class="cfzt-step-title"><?php esc_html_e('Enter Your Credentials', 'zero-trust-login-for-cloudflare'); ?></h2>
                    <p class="cfzt-step-description"><?php esc_html_e('Copy the credentials from Cloudflare and paste them below.', 'zero-trust-login-for-cloudflare'); ?></p>

                    <!-- OIDC Fields -->
                    <div id="cfzt-step3-oidc">
                        <div class="cfzt-form-group">
                            <label for="cfzt_team_domain">
                                <?php esc_html_e('Team Domain *', 'zero-trust-login-for-cloudflare'); ?>
                                <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('Your unique Cloudflare team domain. Found in your application\'s Issuer URL. Example: yourteam.cloudflareaccess.com', 'zero-trust-login-for-cloudflare'); ?>">?</span>
                            </label>
                            <input type="text" id="cfzt_team_domain" name="cfzt_settings[team_domain]" value="<?php echo esc_attr($options['team_domain'] ?? ''); ?>" class="regular-text" placeholder="yourteam.cloudflareaccess.com" required>
                            <p class="description"><?php esc_html_e('Found in your Cloudflare Issuer URL (without https://)', 'zero-trust-login-for-cloudflare'); ?></p>
                        </div>

                        <div class="cfzt-form-group">
                            <label for="cfzt_app_type">
                                <?php esc_html_e('Application Type *', 'zero-trust-login-for-cloudflare'); ?>
                                <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('SaaS applications use Cloudflare\'s standard OIDC endpoints and are production-ready. Self-hosted is for custom OAuth2 implementations.', 'zero-trust-login-for-cloudflare'); ?>">?</span>
                            </label>
                            <select id="cfzt_app_type" name="cfzt_settings[app_type]" class="regular-text">
                                <option value="saas" <?php selected($options['app_type'] ?? 'saas', 'saas'); ?>><?php esc_html_e('SaaS (Recommended)', 'zero-trust-login-for-cloudflare'); ?></option>
                                <option value="self-hosted" <?php selected($options['app_type'] ?? '', 'self-hosted'); ?>><?php esc_html_e('Self-hosted', 'zero-trust-login-for-cloudflare'); ?></option>
                            </select>
                            <p class="description"><?php esc_html_e('Match the type you selected in Cloudflare', 'zero-trust-login-for-cloudflare'); ?></p>
                        </div>

                        <div class="cfzt-form-group">
                            <label for="cfzt_client_id">
                                <?php esc_html_e('Client ID *', 'zero-trust-login-for-cloudflare'); ?>
                                <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('A unique identifier for your application provided by Cloudflare. Looks like a long hexadecimal string.', 'zero-trust-login-for-cloudflare'); ?>">?</span>
                            </label>
                            <input type="text" id="cfzt_client_id" name="cfzt_settings[client_id]" value="<?php echo esc_attr($options['client_id'] ?? ''); ?>" class="regular-text" required>
                            <p class="description"><?php esc_html_e('From your Cloudflare application', 'zero-trust-login-for-cloudflare'); ?></p>
                        </div>

                        <div class="cfzt-form-group">
                            <label for="cfzt_client_secret">
                                <?php echo $has_saved_secret || $secret_from_constant ? esc_html__('Client Secret', 'zero-trust-login-for-cloudflare') : esc_html__('Client Secret *', 'zero-trust-login-for-cloudflare'); ?>
                                <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('A secret key used to authenticate your application with Cloudflare. Keep this secure! It is encrypted in your database when OpenSSL is available, and is never shown again on this page.', 'zero-trust-login-for-cloudflare'); ?>">?</span>
                            </label>
                            <?php
                            // Never render the stored secret into the page.
                            if ($secret_from_constant) {
                                $secret_placeholder = __('Set via CFZT_CLIENT_SECRET constant', 'zero-trust-login-for-cloudflare');
                            } elseif ($has_saved_secret) {
                                $secret_placeholder = __('Saved. Leave blank to keep the current secret.', 'zero-trust-login-for-cloudflare');
                            } else {
                                $secret_placeholder = '';
                            }
                            ?>
                            <input type="password" id="cfzt_client_secret" name="cfzt_settings[client_secret]" value="" class="regular-text" autocomplete="new-password" placeholder="<?php echo esc_attr($secret_placeholder); ?>" data-has-secret="<?php echo $has_saved_secret || $secret_from_constant ? '1' : '0'; ?>" <?php echo $secret_from_constant ? 'readonly' : ''; ?> <?php echo $has_saved_secret || $secret_from_constant ? '' : 'required'; ?>>
                            <p class="description"><?php echo $has_saved_secret ? esc_html__('A client secret is saved and encrypted. Enter a new one only to replace it.', 'zero-trust-login-for-cloudflare') : esc_html__('From your Cloudflare application (will be encrypted)', 'zero-trust-login-for-cloudflare'); ?></p>
                        </div>
                    </div>

                    <!-- Additional Settings -->
                    <h3 style="margin-top: 30px; border-bottom: 1px solid #ccd0d4; padding-bottom: 10px;"><?php esc_html_e('User & Login Settings', 'zero-trust-login-for-cloudflare'); ?></h3>

                    <div class="cfzt-form-group">
                        <label for="cfzt_login_mode">
                            <?php esc_html_e('Login Mode', 'zero-trust-login-for-cloudflare'); ?>
                            <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('Primary mode disables WordPress password login, password resets and registration, so everyone signs in through Cloudflare (backup codes remain available for emergencies). Secondary mode keeps both options available.', 'zero-trust-login-for-cloudflare'); ?>">?</span>
                        </label>
                        <select id="cfzt_login_mode" name="cfzt_settings[login_mode]" class="regular-text">
                            <option value="secondary" <?php selected($options['login_mode'] ?? 'secondary', 'secondary'); ?>><?php esc_html_e('Secondary - Show both login options', 'zero-trust-login-for-cloudflare'); ?></option>
                            <option value="primary" <?php selected($options['login_mode'] ?? '', 'primary'); ?>><?php esc_html_e('Primary - Cloudflare only', 'zero-trust-login-for-cloudflare'); ?></option>
                        </select>
                        <p class="description"><?php esc_html_e('Choose how users can log in to your site', 'zero-trust-login-for-cloudflare'); ?></p>
                    </div>

                    <div class="cfzt-form-group">
                        <label for="cfzt_auto_create_users">
                            <?php esc_html_e('Auto-create Users', 'zero-trust-login-for-cloudflare'); ?>
                            <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('When enabled, WordPress user accounts are automatically created for authenticated Cloudflare users on their first login. If disabled, only existing WordPress users can log in.', 'zero-trust-login-for-cloudflare'); ?>">?</span>
                        </label>
                        <select id="cfzt_auto_create_users" name="cfzt_settings[auto_create_users]" class="regular-text">
                            <option value="yes" <?php selected($options['auto_create_users'] ?? 'yes', 'yes'); ?>><?php esc_html_e('Yes', 'zero-trust-login-for-cloudflare'); ?></option>
                            <option value="no" <?php selected($options['auto_create_users'] ?? '', 'no'); ?>><?php esc_html_e('No', 'zero-trust-login-for-cloudflare'); ?></option>
                        </select>
                        <p class="description"><?php esc_html_e('Automatically create WordPress users on first login', 'zero-trust-login-for-cloudflare'); ?></p>
                    </div>

                    <div class="cfzt-form-group">
                        <label for="cfzt_default_role">
                            <?php esc_html_e('Default User Role', 'zero-trust-login-for-cloudflare'); ?>
                            <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('New users created through Cloudflare authentication will be assigned this WordPress role. Choose carefully based on your security needs.', 'zero-trust-login-for-cloudflare'); ?>">?</span>
                        </label>
                        <select id="cfzt_default_role" name="cfzt_settings[default_role]" class="regular-text">
                            <?php wp_dropdown_roles($options['default_role'] ?? 'subscriber'); ?>
                        </select>
                        <p class="description"><?php esc_html_e('Role assigned to new users', 'zero-trust-login-for-cloudflare'); ?></p>
                    </div>

                    <div class="cfzt-form-group">
                        <label for="cfzt_enable_logging">
                            <?php esc_html_e('Enable Logging', 'zero-trust-login-for-cloudflare'); ?>
                            <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('Logs authentication attempts to your database for debugging and monitoring. Includes timestamp, user, IP address, and success status.', 'zero-trust-login-for-cloudflare'); ?>">?</span>
                        </label>
                        <select id="cfzt_enable_logging" name="cfzt_settings[enable_logging]" class="regular-text">
                            <option value="yes" <?php selected($options['enable_logging'] ?? 'no', 'yes'); ?>><?php esc_html_e('Yes', 'zero-trust-login-for-cloudflare'); ?></option>
                            <option value="no" <?php selected($options['enable_logging'] ?? '', 'no'); ?>><?php esc_html_e('No', 'zero-trust-login-for-cloudflare'); ?></option>
                        </select>
                        <p class="description"><?php esc_html_e('Log authentication attempts for debugging', 'zero-trust-login-for-cloudflare'); ?></p>
                    </div>

                    <!-- Advanced Settings -->
                    <h3 style="margin-top: 30px; border-bottom: 1px solid #ccd0d4; padding-bottom: 10px;"><?php esc_html_e('Advanced Settings', 'zero-trust-login-for-cloudflare'); ?></h3>

                    <div class="cfzt-form-group">
                        <label for="cfzt_email_domain_restrictions">
                            <?php esc_html_e('Email Domain Restrictions', 'zero-trust-login-for-cloudflare'); ?>
                            <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('Restrict Cloudflare logins to specific email domains. Checked on every login, for new and existing accounts alike. Enter one domain per line (e.g., example.com). Leave empty to allow all domains.', 'zero-trust-login-for-cloudflare'); ?>">?</span>
                        </label>
                        <textarea id="cfzt_email_domain_restrictions" name="cfzt_settings[email_domain_restrictions]" rows="3" class="large-text" placeholder="example.com&#10;company.org"><?php echo esc_textarea($options['email_domain_restrictions'] ?? ''); ?></textarea>
                        <p class="description"><?php esc_html_e('One domain per line. Only users with email addresses from these domains can log in through Cloudflare; this is checked on every login. Make sure your own domain is listed before enabling Primary mode.', 'zero-trust-login-for-cloudflare'); ?></p>
                    </div>

                    <div class="cfzt-form-group">
                        <label for="cfzt_redirect_after_login">
                            <?php esc_html_e('Redirect After Login', 'zero-trust-login-for-cloudflare'); ?>
                            <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('Custom URL to redirect users after successful login. Leave empty to use WordPress default (wp-admin for admins, home for others).', 'zero-trust-login-for-cloudflare'); ?>">?</span>
                        </label>
                        <input type="url" id="cfzt_redirect_after_login" name="cfzt_settings[redirect_after_login]" value="<?php echo esc_attr($options['redirect_after_login'] ?? ''); ?>" class="large-text" placeholder="<?php echo esc_attr(home_url()); ?>">
                        <p class="description"><?php esc_html_e('Leave empty to use WordPress default redirect behavior.', 'zero-trust-login-for-cloudflare'); ?></p>
                    </div>

                    <div class="cfzt-form-group">
                        <label for="cfzt_redirect_after_logout">
                            <?php esc_html_e('Redirect After Logout', 'zero-trust-login-for-cloudflare'); ?>
                            <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('Custom URL to redirect users after logout. Leave empty to redirect to home page.', 'zero-trust-login-for-cloudflare'); ?>">?</span>
                        </label>
                        <input type="url" id="cfzt_redirect_after_logout" name="cfzt_settings[redirect_after_logout]" value="<?php echo esc_attr($options['redirect_after_logout'] ?? ''); ?>" class="large-text" placeholder="<?php echo esc_attr(home_url()); ?>">
                        <p class="description"><?php esc_html_e('Leave empty to redirect to home page.', 'zero-trust-login-for-cloudflare'); ?></p>
                    </div>

                    <div class="cfzt-form-group">
                        <label>
                            <?php esc_html_e('Role Mapping (Cloudflare Groups → WordPress Roles)', 'zero-trust-login-for-cloudflare'); ?>
                            <span class="cfzt-help-icon" data-tooltip="<?php esc_attr_e('Map identity-provider group names (sent by Cloudflare in the groups claim) to WordPress roles. Applied when an account is created and re-applied on every login for accounts this plugin created. Accounts you made by hand keep their role.', 'zero-trust-login-for-cloudflare'); ?>">?</span>
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
                                <input type="text" name="cfzt_settings[role_mapping][<?php echo (int) $index; ?>][group]" value="<?php echo esc_attr($mapping['group']); ?>" placeholder="<?php esc_attr_e('Cloudflare group name', 'zero-trust-login-for-cloudflare'); ?>" class="regular-text" style="flex: 1;">
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
                            <span class="dashicons dashicons-plus-alt"></span> <?php esc_html_e('Add Role Mapping', 'zero-trust-login-for-cloudflare'); ?>
                        </button>
                        <p class="description"><?php esc_html_e('Map Cloudflare Access group names to WordPress roles. First matching group wins.', 'zero-trust-login-for-cloudflare'); ?></p>
                    </div>
                </div>

                <!-- Step 4: Review and Complete -->
                <div class="cfzt-wizard-step" data-step="3">
                    <h2 class="cfzt-step-title"><?php esc_html_e('Review Your Configuration', 'zero-trust-login-for-cloudflare'); ?></h2>
                    <p class="cfzt-step-description"><?php esc_html_e('Please review your settings before saving.', 'zero-trust-login-for-cloudflare'); ?></p>

                    <div class="cfzt-success-box">
                        <h3 style="margin-top: 0;"><?php esc_html_e('Configuration Summary', 'zero-trust-login-for-cloudflare'); ?></h3>
                        <ul class="cfzt-checklist" id="cfzt-review-list">
                            <!-- Will be populated by JavaScript -->
                        </ul>
                    </div>

                    <div class="cfzt-info-box">
                        <strong><?php esc_html_e('Before Saving:', 'zero-trust-login-for-cloudflare'); ?></strong>
                        <p style="margin: 10px 0;"><?php esc_html_e('We recommend testing your connection to Cloudflare before saving:', 'zero-trust-login-for-cloudflare'); ?></p>
                        <button type="button" id="cfzt-test-connection-wizard" class="button button-secondary" style="margin-bottom: 15px;">
                            <span class="dashicons dashicons-yes-alt" style="margin-top: 3px;"></span> <?php esc_html_e('Test Connection Now', 'zero-trust-login-for-cloudflare'); ?>
                        </button>
                        <div id="cfzt-test-results-wizard" style="display: none;"></div>
                    </div>

                    <div class="cfzt-info-box">
                        <strong><?php esc_html_e('Next Steps:', 'zero-trust-login-for-cloudflare'); ?></strong>
                        <ol style="margin: 10px 0 0 20px;">
                            <li><?php esc_html_e('Test your connection (recommended)', 'zero-trust-login-for-cloudflare'); ?></li>
                            <li><?php esc_html_e('Click "Save Configuration" below', 'zero-trust-login-for-cloudflare'); ?></li>
                            <li><?php esc_html_e('Visit your WordPress login page', 'zero-trust-login-for-cloudflare'); ?></li>
                            <li><?php esc_html_e('Click "Login with Cloudflare Zero Trust"', 'zero-trust-login-for-cloudflare'); ?></li>
                            <li><?php esc_html_e('Test the authentication flow', 'zero-trust-login-for-cloudflare'); ?></li>
                        </ol>
                    </div>

                    <?php if (!$security_status['encryption_available']): ?>
                    <div class="cfzt-warning-box">
                        <strong><?php esc_html_e('Security Notice:', 'zero-trust-login-for-cloudflare'); ?></strong> <?php esc_html_e('OpenSSL is not available. Client secrets will be stored with basic obfuscation. Consider enabling OpenSSL for better security.', 'zero-trust-login-for-cloudflare'); ?>
                    </div>
                    <?php endif; ?>
                </div>

                <!-- Wizard Actions -->
                <div class="cfzt-wizard-actions">
                    <button type="button" id="cfzt-prev-step" class="button" style="display: none;"><?php esc_html_e('Previous', 'zero-trust-login-for-cloudflare'); ?></button>
                    <div>
                        <button type="button" id="cfzt-next-step" class="button button-primary"><?php esc_html_e('Next', 'zero-trust-login-for-cloudflare'); ?></button>
                        <?php submit_button(__('Save Configuration', 'zero-trust-login-for-cloudflare'), 'primary', 'submit', false, array('id' => 'cfzt-save-btn', 'style' => 'display:none;')); ?>
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
                <h2 style="border-top: 1px solid #ccd0d4; padding-top: 20px;"><?php esc_html_e('Import / Export Settings', 'zero-trust-login-for-cloudflare'); ?></h2>
                <p class="description"><?php esc_html_e('Export your configuration as a backup or to transfer to another site. Import a previously exported configuration file.', 'zero-trust-login-for-cloudflare'); ?></p>

                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px;">
                    <!-- Export -->
                    <div class="cfzt-import-export-box">
                        <h3><?php esc_html_e('Export Settings', 'zero-trust-login-for-cloudflare'); ?></h3>
                        <p><?php esc_html_e('Download your current configuration as a JSON file. The client secret is never included; enter it again after importing on another site.', 'zero-trust-login-for-cloudflare'); ?></p>
                        <button type="button" id="cfzt-export-settings" class="button button-secondary">
                            <span class="dashicons dashicons-download" style="margin-top: 3px;"></span>
                            <?php esc_html_e('Export Settings', 'zero-trust-login-for-cloudflare'); ?>
                        </button>
                    </div>

                    <!-- Import -->
                    <div class="cfzt-import-export-box">
                        <h3><?php esc_html_e('Import Settings', 'zero-trust-login-for-cloudflare'); ?></h3>
                        <p><?php esc_html_e('Upload a previously exported JSON file to restore settings. This will replace your current configuration.', 'zero-trust-login-for-cloudflare'); ?></p>
                        <input type="file" id="cfzt-import-file" accept=".json" style="margin-bottom: 10px;">
                        <button type="button" id="cfzt-import-settings" class="button button-secondary" disabled>
                            <span class="dashicons dashicons-upload" style="margin-top: 3px;"></span>
                            <?php esc_html_e('Import Settings', 'zero-trust-login-for-cloudflare'); ?>
                        </button>
                    </div>
                </div>

                <div id="cfzt-import-export-result" style="margin-top: 20px;"></div>
            </div>
        </div>
    </div>

</div>
