<?php
/**
 * Login button template
 *
 * @package CloudflareZeroTrustLogin
 * @var string $auth_url The authentication URL
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}
?>

<div class="cfzt-login-wrapper">
    <div class="cfzt-divider">
        <span><?php _e('OR', 'cf-zero-trust'); ?></span>
    </div>
    <a href="<?php echo esc_url($auth_url); ?>" class="cfzt-login-button">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
            <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
        </svg>
        <?php _e('Login with Cloudflare Zero Trust', 'cf-zero-trust'); ?>
    </a>
</div>