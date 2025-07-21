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
?>

<div class="wrap">
    <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
    
    <form method="post" action="options.php">
        <?php
        settings_fields('cfzt_settings_group');
        do_settings_sections('cf-zero-trust');
        submit_button();
        ?>
    </form>
    
    <h2><?php _e('Setup Instructions', 'cf-zero-trust'); ?></h2>
    <ol>
        <li><?php _e('In Cloudflare Zero Trust, go to Access > Applications', 'cf-zero-trust'); ?></li>
        <li><?php _e('Add a new application and choose type:', 'cf-zero-trust'); ?>
            <ul>
                <li><strong><?php _e('SaaS', 'cf-zero-trust'); ?></strong> <?php _e('(Recommended) - Provides standard OIDC endpoints', 'cf-zero-trust'); ?></li>
                <li><strong><?php _e('Self-hosted', 'cf-zero-trust'); ?></strong> <?php _e('- For custom applications', 'cf-zero-trust'); ?></li>
            </ul>
        </li>
        <li><?php _e('Configure OIDC settings with redirect URL:', 'cf-zero-trust'); ?> <code><?php echo esc_url(home_url('/wp-login.php?cfzt_callback=1')); ?></code></li>
        <li><?php _e('Copy the provided credentials:', 'cf-zero-trust'); ?>
            <ul>
                <li><strong><?php _e('Client ID', 'cf-zero-trust'); ?></strong> - <?php _e('The unique identifier', 'cf-zero-trust'); ?></li>
                <li><strong><?php _e('Client Secret', 'cf-zero-trust'); ?></strong> - <?php _e('The authentication secret', 'cf-zero-trust'); ?></li>
                <li><strong><?php _e('Team Domain', 'cf-zero-trust'); ?></strong> - <?php _e('From the Issuer URL (e.g.,', 'cf-zero-trust'); ?> <code>yourteam.cloudflareaccess.com</code>)</li>
            </ul>
        </li>
        <li><?php _e('Enter these values above and save', 'cf-zero-trust'); ?></li>
    </ol>
    
    <h3><?php _e('For SaaS Applications', 'cf-zero-trust'); ?></h3>
    <p><?php _e('If you created a SaaS application, Cloudflare provides these endpoints:', 'cf-zero-trust'); ?></p>
    <ul>
        <li><strong><?php _e('Authorization:', 'cf-zero-trust'); ?></strong> <code>/cdn-cgi/access/sso/oidc/{client_id}/authorization</code></li>
        <li><strong><?php _e('Token:', 'cf-zero-trust'); ?></strong> <code>/cdn-cgi/access/sso/oidc/{client_id}/token</code></li>
        <li><strong><?php _e('Userinfo:', 'cf-zero-trust'); ?></strong> <code>/cdn-cgi/access/sso/oidc/{client_id}/userinfo</code></li>
    </ul>
    <p><?php _e('The plugin automatically uses the correct endpoints based on your Application Type setting.', 'cf-zero-trust'); ?></p>
    
    <h2><?php _e('Security Status', 'cf-zero-trust'); ?> <a href="#" id="cfzt-toggle-security" class="button button-small"><?php _e('Show Details', 'cf-zero-trust'); ?></a></h2>
    <table class="widefat" id="cfzt-security-details">
        <tr>
            <td><strong><?php _e('Plugin Version:', 'cf-zero-trust'); ?></strong></td>
            <td><?php echo CFZT_PLUGIN_VERSION; ?>
            <?php
            // Check for updates
            $update_data = get_site_transient('update_plugins');
            if (isset($update_data->response[CFZT_PLUGIN_BASENAME])) {
                $update = $update_data->response[CFZT_PLUGIN_BASENAME];
                echo ' <a href="' . admin_url('plugins.php') . '" style="color: #d63638;">' . 
                     sprintf(__('Update available (v%s)', 'cf-zero-trust'), $update->new_version) . '</a>';
            } else {
                echo ' <span style="color: #00a32a;">✓ ' . __('Up to date', 'cf-zero-trust') . '</span>';
            }
            ?>
            <?php if (class_exists('CFZT_GitHub_Updater')): ?>
                <button type="button" id="cfzt-check-updates" class="button button-small" style="margin-left: 10px;">
                    <?php _e('Check for Updates', 'cf-zero-trust'); ?>
                </button>
                <div id="cfzt-update-check-status" class="notice inline"></div>
            <?php endif; ?>
            </td>
        </tr>
        <tr>
            <td><strong><?php _e('Encryption Method:', 'cf-zero-trust'); ?></strong></td>
            <td><?php echo $security_status['encryption_available'] ? 
                '✓ ' . $security_status['encryption_method'] : 
                '⚠ ' . $security_status['encryption_method'] . ' (' . __('Install OpenSSL for better security', 'cf-zero-trust') . ')'; ?></td>
        </tr>
        <tr>
            <td><strong><?php _e('Auth Salt:', 'cf-zero-trust'); ?></strong></td>
            <td><?php echo $security_status['auth_salt_configured'] ? 
                '✓ ' . __('Configured', 'cf-zero-trust') : 
                '✗ ' . __('Using default (insecure)', 'cf-zero-trust'); ?></td>
        </tr>
        <tr>
            <td><strong><?php _e('Secure Auth Salt:', 'cf-zero-trust'); ?></strong></td>
            <td><?php echo $security_status['secure_auth_salt_configured'] ? 
                '✓ ' . __('Configured', 'cf-zero-trust') : 
                '✗ ' . __('Using default (insecure)', 'cf-zero-trust'); ?></td>
        </tr>
        <tr>
            <td><strong><?php _e('Client ID Source:', 'cf-zero-trust'); ?></strong></td>
            <td><?php echo $security_status['client_id_source'] === 'constant' ? 
                '✓ ' . __('Set via constant/environment', 'cf-zero-trust') : 
                '⚠ ' . __('Stored in database', 'cf-zero-trust'); ?></td>
        </tr>
        <tr>
            <td><strong><?php _e('Client Secret Source:', 'cf-zero-trust'); ?></strong></td>
            <td><?php echo $security_status['client_secret_source'] === 'constant' ? 
                '✓ ' . __('Set via constant/environment', 'cf-zero-trust') : 
                '⚠ ' . __('Stored in database (encrypted)', 'cf-zero-trust'); ?></td>
        </tr>
        <tr>
            <td><strong><?php _e('Rate Limiting:', 'cf-zero-trust'); ?></strong></td>
            <td>✓ <?php _e('Active (10 attempts per 5 minutes)', 'cf-zero-trust'); ?></td>
        </tr>
        <tr>
            <td><strong><?php _e('Security Headers:', 'cf-zero-trust'); ?></strong></td>
            <td>✓ <?php _e('Active on login page', 'cf-zero-trust'); ?></td>
        </tr>
        <tr>
            <td><strong><?php _e('GitHub Updates:', 'cf-zero-trust'); ?></strong></td>
            <td><?php echo class_exists('CFZT_GitHub_Updater') ? 
                '✓ ' . __('Enabled', 'cf-zero-trust') : 
                '⚠ ' . __('Not available', 'cf-zero-trust'); ?> 
                <?php _e('from', 'cf-zero-trust'); ?> <a href="https://github.com/<?php echo CFZT_GITHUB_USERNAME . '/' . CFZT_GITHUB_REPOSITORY; ?>" target="_blank"><?php _e('GitHub repository', 'cf-zero-trust'); ?></a></td>
        </tr>
    </table>
    
    <?php if (!$security_status['auth_salt_configured'] || !$security_status['secure_auth_salt_configured']): ?>
    <div class="notice notice-error inline">
        <p><?php _e('Your WordPress salts are not properly configured. Please update your <code>wp-config.php</code> file with unique salts from', 'cf-zero-trust'); ?> <a href="https://api.wordpress.org/secret-key/1.1/salt/" target="_blank">WordPress.org</a></p>
    </div>
    <?php endif; ?>
    
    <h2><?php _e('Using Environment Variables (Recommended)', 'cf-zero-trust'); ?></h2>
    <p><?php _e('For better security, you can set credentials via environment variables or constants in <code>wp-config.php</code>:', 'cf-zero-trust'); ?></p>
    <pre style="background: #f0f0f0; padding: 10px; overflow-x: auto;">
// <?php _e('Method 1: Environment variables (add to .env or server config)', 'cf-zero-trust'); ?>
CFZT_CLIENT_ID=your-client-id-here
CFZT_CLIENT_SECRET=your-client-secret-here

// <?php _e('Method 2: wp-config.php constants', 'cf-zero-trust'); ?>
define('CFZT_CLIENT_ID', 'your-client-id-here');
define('CFZT_CLIENT_SECRET', 'your-client-secret-here');

// <?php _e('Method 3: wp-config.php with environment variables', 'cf-zero-trust'); ?>
define('CFZT_CLIENT_ID', getenv('CFZT_CLIENT_ID'));
define('CFZT_CLIENT_SECRET', getenv('CFZT_CLIENT_SECRET'));</pre>
    
    <h2><?php _e('Troubleshooting', 'cf-zero-trust'); ?></h2>
    <ul>
        <li><strong><?php _e('Login button not appearing:', 'cf-zero-trust'); ?></strong> <?php _e('Ensure Team Domain and Client ID are configured.', 'cf-zero-trust'); ?></li>
        <li><strong><?php _e('Authentication fails:', 'cf-zero-trust'); ?></strong> <?php _e('Check that your redirect URL matches exactly in Cloudflare.', 'cf-zero-trust'); ?></li>
        <li><strong><?php _e('Users cannot be created:', 'cf-zero-trust'); ?></strong> <?php _e('Enable "Auto-create Users" in settings.', 'cf-zero-trust'); ?></li>
        <li><strong><?php _e('Rate limit errors:', 'cf-zero-trust'); ?></strong> <?php _e('Wait 5 minutes or check for brute force attempts.', 'cf-zero-trust'); ?></li>
    </ul>
    
    <?php if ($options['enable_logging'] === 'yes'): ?>
    <p><em><?php _e('Authentication logging is enabled. Check your error logs for authentication attempts.', 'cf-zero-trust'); ?></em></p>
    <?php endif; ?>
</div>