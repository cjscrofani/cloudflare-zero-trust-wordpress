<?php
/**
 * Centralized logging for Cloudflare Zero Trust
 *
 * @package CloudflareZeroTrustLogin
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class CFZT_Logger {

    // Log levels
    const LEVEL_ERROR = 'ERROR';
    const LEVEL_WARNING = 'WARNING';
    const LEVEL_INFO = 'INFO';
    const LEVEL_DEBUG = 'DEBUG';

    /**
     * Check if logging is enabled
     *
     * @return bool
     */
    private static function is_logging_enabled(): bool {
        $options = CFZT_Plugin::get_option();
        return isset($options['enable_logging']) && $options['enable_logging'] === CFZT_Plugin::OPTION_YES;
    }

    /**
     * Log a message
     *
     * @param string $level Log level
     * @param string $message Log message
     * @param array $context Additional context data
     */
    private static function log(string $level, string $message, array $context = []): void {
        if (!self::is_logging_enabled()) {
            return;
        }

        $log_message = sprintf('[CF Zero Trust][%s] %s', $level, $message);

        // Add context if provided
        if (!empty($context)) {
            $log_message .= ' | Context: ' . json_encode($context);
        }

        error_log($log_message);
    }

    /**
     * Log an error message
     *
     * @param string $message Error message
     * @param array $context Additional context
     */
    public static function error(string $message, array $context = []): void {
        self::log(self::LEVEL_ERROR, $message, $context);
    }

    /**
     * Log a warning message
     *
     * @param string $message Warning message
     * @param array $context Additional context
     */
    public static function warning(string $message, array $context = []): void {
        self::log(self::LEVEL_WARNING, $message, $context);
    }

    /**
     * Log an info message
     *
     * @param string $message Info message
     * @param array $context Additional context
     */
    public static function info(string $message, array $context = []): void {
        self::log(self::LEVEL_INFO, $message, $context);
    }

    /**
     * Log a debug message
     *
     * @param string $message Debug message
     * @param array $context Additional context
     */
    public static function debug(string $message, array $context = []): void {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            self::log(self::LEVEL_DEBUG, $message, $context);
        }
    }

    /**
     * Log authentication attempt
     *
     * @param string $identifier User email or username
     * @param bool $success Whether authentication succeeded
     * @param string $auth_method Authentication method (oidc/saml)
     * @param string $reason Optional reason for failure
     */
    public static function auth_attempt(string $identifier, bool $success, string $auth_method = 'oidc', string $reason = ''): void {
        $status = $success ? 'SUCCESS' : 'FAILED';
        $remote_ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field($_SERVER['REMOTE_ADDR']) : 'unknown';

        $message = sprintf(
            'Authentication %s for: %s | Method: %s | IP: %s',
            $status,
            $identifier,
            strtoupper($auth_method),
            $remote_ip
        );

        if (!$success && !empty($reason)) {
            $message .= ' | Reason: ' . $reason;
        }

        if ($success) {
            self::info($message);
        } else {
            self::warning($message);
        }

        // Trigger action for other plugins to hook into
        do_action('cfzt_authentication_attempt', $identifier, $success, $auth_method, $reason);
    }

    /**
     * Log user creation
     *
     * @param int $user_id Created user ID
     * @param string $email User email
     * @param string $auth_method Authentication method
     */
    public static function user_created(int $user_id, string $email, string $auth_method = 'oidc'): void {
        self::info(sprintf(
            'User created | ID: %d | Email: %s | Method: %s',
            $user_id,
            $email,
            strtoupper($auth_method)
        ));
    }

    /**
     * Log security event
     *
     * @param string $event Event description
     * @param array $context Event context
     */
    public static function security_event(string $event, array $context = []): void {
        self::warning('Security Event: ' . $event, $context);
    }
}
