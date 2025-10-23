<?php
/**
 * Security handler for encryption, rate limiting, and headers
 *
 * @package CloudflareZeroTrustLogin
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class CFZT_Security {
    
    /**
     * Constructor
     */
    public function __construct() {
        $this->init_hooks();
    }
    
    /**
     * Initialize hooks
     */
    private function init_hooks() {
        add_action('login_init', array($this, 'add_security_headers'));
    }
    
    /**
     * Encrypt sensitive data
     * 
     * @param string $data Data to encrypt
     * @return string Encrypted data
     */
    public function encrypt_data($data) {
        if (empty($data)) {
            return '';
        }
        
        // Use WordPress salts for encryption
        $key = wp_salt('auth');
        $salt = wp_salt('secure_auth');

        // Create a unique random nonce for this encryption
        // Using wp_generate_password for cryptographically secure random bytes
        $nonce = bin2hex(wp_generate_password(16, false));

        // Combine data with nonce for added security
        $data_with_nonce = $nonce . '::' . $data;

        // Use OpenSSL if available
        if ($this->is_encryption_available()) {
            $method = 'AES-256-CBC';
            $iv = substr(hash('sha256', $salt), 0, 16);
            $encrypted = openssl_encrypt($data_with_nonce, $method, $key, 0, $iv);
            return base64_encode($encrypted);
        } else {
            // Fallback to a simpler obfuscation method
            return base64_encode($data_with_nonce . '::' . hash_hmac('sha256', $data, $key));
        }
    }
    
    /**
     * Decrypt sensitive data
     * 
     * @param string $encrypted_data Encrypted data
     * @return string Decrypted data
     */
    public function decrypt_data($encrypted_data) {
        if (empty($encrypted_data)) {
            return '';
        }
        
        $key = wp_salt('auth');
        $salt = wp_salt('secure_auth');
        
        if ($this->is_encryption_available()) {
            $method = 'AES-256-CBC';
            $iv = substr(hash('sha256', $salt), 0, 16);
            $decrypted = openssl_decrypt(base64_decode($encrypted_data), $method, $key, 0, $iv);
            
            if ($decrypted !== false) {
                // Extract the original data without the nonce
                $parts = explode('::', $decrypted, 2);
                return isset($parts[1]) ? $parts[1] : '';
            }
        } else {
            // Fallback for simple obfuscation
            $decoded = base64_decode($encrypted_data);
            $parts = explode('::', $decoded, 3);
            return isset($parts[1]) ? $parts[1] : '';
        }
        
        return '';
    }
    
    /**
     * Get client secret (decrypted if necessary)
     * 
     * @return string Client secret
     */
    public function get_client_secret() {
        $options = CFZT_Plugin::get_option();
        
        // Check if it's from a constant
        if (isset($options['client_secret_is_constant']) && $options['client_secret_is_constant']) {
            return $options['client_secret'];
        }
        
        // Decrypt if encrypted
        return $this->decrypt_data($options['client_secret']);
    }
    
    /**
     * Check if encryption is available
     * 
     * @return bool
     */
    public function is_encryption_available() {
        return function_exists('openssl_encrypt') && function_exists('openssl_decrypt');
    }
    
    /**
     * Check rate limit
     * 
     * @return bool True if within rate limit
     */
    public function check_rate_limit() {
        $ip = $this->get_client_ip();
        $attempts_key = 'cfzt_attempts_' . $ip;
        $attempts = get_transient($attempts_key) ?: 0;
        
        if ($attempts >= 10) {
            return false;
        }
        
        set_transient($attempts_key, $attempts + 1, 300); // 5 minutes
        return true;
    }
    
    /**
     * Get client IP address
     *
     * @return string IP address
     */
    private function get_client_ip() {
        // Check for Cloudflare's CF-Connecting-IP header first
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            return sanitize_text_field($_SERVER['HTTP_CF_CONNECTING_IP']);
        }

        // Check for X-Forwarded-For
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', sanitize_text_field($_SERVER['HTTP_X_FORWARDED_FOR']));
            return trim($ips[0]);
        }

        // Check for X-Real-IP
        if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
            return sanitize_text_field($_SERVER['HTTP_X_REAL_IP']);
        }

        // Fallback to REMOTE_ADDR
        return isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field($_SERVER['REMOTE_ADDR']) : '';
    }
    
    /**
     * Add security headers
     */
    public function add_security_headers() {
        // Only add headers if we haven't already sent them
        if (headers_sent()) {
            return;
        }
        
        // Prevent clickjacking
        header('X-Frame-Options: DENY');
        
        // Prevent MIME type sniffing
        header('X-Content-Type-Options: nosniff');
        
        // Enable XSS protection
        header('X-XSS-Protection: 1; mode=block');
        
        // Referrer policy
        header('Referrer-Policy: strict-origin-when-cross-origin');
        
        // Content Security Policy
        $csp = "default-src 'self'; ";
        $csp .= "script-src 'self' 'unsafe-inline' https://*.cloudflareaccess.com; ";
        $csp .= "style-src 'self' 'unsafe-inline'; ";
        $csp .= "img-src 'self' data: https://*.cloudflareaccess.com; ";
        $csp .= "connect-src 'self' https://*.cloudflareaccess.com; ";
        $csp .= "frame-ancestors 'none';";
        
        header("Content-Security-Policy: $csp");
    }
    
    /**
     * Protect session after login
     */
    public function protect_session() {
        // Regenerate session ID after CF Zero Trust login
        if (function_exists('session_regenerate_id') && session_status() === PHP_SESSION_ACTIVE) {
            session_regenerate_id(true);
        }
        
        // Add additional session protection
        if (!session_id()) {
            session_start();
        }
        
        // Store session fingerprint
        $_SESSION['cfzt_fingerprint'] = $this->generate_session_fingerprint();
    }
    
    /**
     * Generate session fingerprint
     *
     * @return string Session fingerprint
     */
    private function generate_session_fingerprint() {
        $fingerprint = '';

        // User agent
        if (isset($_SERVER['HTTP_USER_AGENT'])) {
            $fingerprint .= sanitize_text_field($_SERVER['HTTP_USER_AGENT']);
        }

        // Accept headers
        if (isset($_SERVER['HTTP_ACCEPT'])) {
            $fingerprint .= sanitize_text_field($_SERVER['HTTP_ACCEPT']);
        }

        // Accept language
        if (isset($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
            $fingerprint .= substr(sanitize_text_field($_SERVER['HTTP_ACCEPT_LANGUAGE']), 0, 2);
        }

        return hash('sha256', $fingerprint);
    }
    
    /**
     * Validate session fingerprint
     * 
     * @return bool True if valid
     */
    public function validate_session_fingerprint() {
        if (!isset($_SESSION['cfzt_fingerprint'])) {
            return true; // No fingerprint to validate
        }
        
        $current_fingerprint = $this->generate_session_fingerprint();
        return hash_equals($_SESSION['cfzt_fingerprint'], $current_fingerprint);
    }
    
    /**
     * Get security status
     * 
     * @return array Security status information
     */
    public function get_security_status() {
        return array(
            'encryption_available' => $this->is_encryption_available(),
            'encryption_method' => $this->is_encryption_available() ? 'AES-256-CBC (OpenSSL)' : 'Basic Obfuscation',
            'auth_salt_configured' => defined('AUTH_SALT') && AUTH_SALT !== 'put your unique phrase here',
            'secure_auth_salt_configured' => defined('SECURE_AUTH_SALT') && SECURE_AUTH_SALT !== 'put your unique phrase here',
            'client_id_source' => defined('CFZT_CLIENT_ID') && CFZT_CLIENT_ID ? 'constant' : 'database',
            'client_secret_source' => defined('CFZT_CLIENT_SECRET') && CFZT_CLIENT_SECRET ? 'constant' : 'database',
            'rate_limiting' => true,
            'security_headers' => true
        );
    }
}