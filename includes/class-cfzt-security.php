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
     * Prefix that marks a value as already encrypted by this class
     *
     * Lets the settings sanitizer tell plaintext from ciphertext, so a value
     * can pass through update_option() any number of times and only ever be
     * encrypted once.
     *
     * @since 2.0.0
     */
    const ENCRYPTED_PREFIX = 'cfzt-enc:v1:';

    /**
     * Failed attempts allowed per IP before the limiter trips
     */
    const RATE_LIMIT_ATTEMPTS = 10;

    /**
     * Window, in seconds, that failed attempts are counted over
     */
    const RATE_LIMIT_WINDOW = 300;

    /**
     * Cloudflare's published edge ranges, used to decide when the
     * CF-Connecting-IP header can be believed.
     *
     * Source: https://www.cloudflare.com/ips-v4 and /ips-v6 (2026-10-23).
     * Extend with the `cfzt_trusted_proxies` filter for other proxies.
     */
    const CLOUDFLARE_RANGES = array(
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
        '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
    );

    /**
     * Constructor
     *
     * Registers no hooks. Several places construct a throwaway instance just
     * to reach encrypt/decrypt, and each used to re-add the header hook.
     * CFZT_Plugin wires add_security_headers() exactly once.
     */
    public function __construct() {
    }

    /**
     * Encrypt sensitive data
     *
     * @param string $data Data to encrypt
     * @return string Encrypted data, prefixed so it is recognisable as such
     */
    public function encrypt_data(string $data): string {
        if ('' === $data) {
            return '';
        }

        // Already encrypted by us: never wrap it a second time.
        if ($this->is_encrypted($data)) {
            return $data;
        }

        // Use WordPress salts for encryption
        $key = wp_salt('auth');
        $salt = wp_salt('secure_auth');

        // Create a unique random nonce for this encryption
        $nonce = bin2hex(wp_generate_password(16, false));

        // Combine data with nonce for added security
        $data_with_nonce = $nonce . '::' . $data;

        if ($this->is_encryption_available()) {
            $method = 'AES-256-CBC';
            $iv = substr(hash('sha256', $salt), 0, 16);
            $encrypted = openssl_encrypt($data_with_nonce, $method, $key, 0, $iv);
            return self::ENCRYPTED_PREFIX . base64_encode($encrypted);
        }

        // Fallback to a simpler obfuscation method
        return self::ENCRYPTED_PREFIX . base64_encode($data_with_nonce . '::' . hash_hmac('sha256', $data, $key));
    }

    /**
     * Decrypt sensitive data
     *
     * Accepts both prefixed values written by 2.0.0+ and the unprefixed blobs
     * that 1.x stored.
     *
     * @param string $encrypted_data Encrypted data
     * @return string Decrypted data, or an empty string if it cannot be read
     */
    public function decrypt_data(string $encrypted_data): string {
        if ('' === $encrypted_data) {
            return '';
        }

        if ($this->is_encrypted($encrypted_data)) {
            $encrypted_data = substr($encrypted_data, strlen(self::ENCRYPTED_PREFIX));
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
     * Whether a stored value carries this class's encryption marker
     *
     * @since 2.0.0
     *
     * @param string $value Stored value.
     * @return bool
     */
    public function is_encrypted(string $value): bool {
        return 0 === strpos($value, self::ENCRYPTED_PREFIX);
    }

    /**
     * Get client secret (decrypted if necessary)
     *
     * @return string Client secret
     */
    public function get_client_secret(): string {
        $options = CFZT_Plugin::get_option();

        // Check if it's from a constant
        if (!empty($options['client_secret_is_constant'])) {
            return (string) $options['client_secret'];
        }

        if (empty($options['client_secret'])) {
            return '';
        }

        // Decrypt if encrypted
        return $this->decrypt_data((string) $options['client_secret']);
    }

    /**
     * Check if encryption is available
     *
     * @return bool
     */
    public function is_encryption_available(): bool {
        return function_exists('openssl_encrypt') && function_exists('openssl_decrypt');
    }

    /**
     * Whether the current client has exceeded the failed-attempt limit
     *
     * Only failures count (see record_failed_attempt()), so legitimate users
     * logging in repeatedly are never locked out by their own successes.
     *
     * @since 2.0.0
     *
     * @return bool True if the client is currently rate limited.
     */
    public function is_rate_limited(): bool {
        $attempts = (int) get_transient($this->rate_limit_key());
        return $attempts >= self::RATE_LIMIT_ATTEMPTS;
    }

    /**
     * Count a failed authentication attempt against the current client
     *
     * @since 2.0.0
     *
     * @return void
     */
    public function record_failed_attempt(): void {
        $key = $this->rate_limit_key();
        $attempts = (int) get_transient($key);
        set_transient($key, $attempts + 1, self::RATE_LIMIT_WINDOW);
    }

    /**
     * Transient key for the current client's failure counter
     *
     * @return string
     */
    private function rate_limit_key(): string {
        return 'cfzt_attempts_' . md5($this->get_client_ip());
    }

    /**
     * Get the client IP address
     *
     * Forwarding headers are trivially spoofed, so they are only believed when
     * the connecting peer is a proxy we trust: Cloudflare's own edge for
     * CF-Connecting-IP, and anything added through `cfzt_trusted_proxies` for
     * X-Forwarded-For / X-Real-IP. Otherwise REMOTE_ADDR is the answer.
     *
     * @return string IP address, or an empty string when unknown.
     */
    public function get_client_ip(): string {
        $remote_addr = isset($_SERVER['REMOTE_ADDR']) ? trim((string) $_SERVER['REMOTE_ADDR']) : '';

        /**
         * Filter the CIDR ranges whose forwarding headers are trusted.
         *
         * Cloudflare's ranges are always included. Add your own load balancer
         * or reverse proxy here if it sits in front of the site.
         *
         * @since 2.0.0
         *
         * @param array  $ranges      CIDR strings.
         * @param string $remote_addr The connecting peer.
         */
        $trusted = apply_filters('cfzt_trusted_proxies', array(), $remote_addr);
        $trusted = array_merge(self::CLOUDFLARE_RANGES, is_array($trusted) ? $trusted : array());

        if ('' === $remote_addr || !$this->ip_in_ranges($remote_addr, $trusted)) {
            return $remote_addr;
        }

        $candidates = array();
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $candidates[] = $_SERVER['HTTP_CF_CONNECTING_IP'];
        }
        if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
            $candidates[] = $_SERVER['HTTP_X_REAL_IP'];
        }
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $forwarded = explode(',', (string) $_SERVER['HTTP_X_FORWARDED_FOR']);
            $candidates[] = $forwarded[0];
        }

        foreach ($candidates as $candidate) {
            $candidate = trim((string) $candidate);
            if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                return $candidate;
            }
        }

        return $remote_addr;
    }

    /**
     * Whether an IP falls inside any of the given CIDR ranges
     *
     * @param string $ip     IPv4 or IPv6 address.
     * @param array  $ranges CIDR strings.
     * @return bool
     */
    private function ip_in_ranges(string $ip, array $ranges): bool {
        $packed = @inet_pton($ip);
        if (false === $packed) {
            return false;
        }

        foreach ($ranges as $range) {
            if (!is_string($range) || false === strpos($range, '/')) {
                continue;
            }
            list($subnet, $bits) = explode('/', $range, 2);
            $subnet_packed = @inet_pton(trim($subnet));
            $bits = (int) $bits;

            if (false === $subnet_packed || strlen($subnet_packed) !== strlen($packed)) {
                continue;
            }

            $bytes = intdiv($bits, 8);
            $remainder = $bits % 8;

            if ($bytes > 0 && substr($packed, 0, $bytes) !== substr($subnet_packed, 0, $bytes)) {
                continue;
            }

            if ($remainder > 0) {
                $mask = 0xFF & (0xFF << (8 - $remainder));
                if ((ord($packed[$bytes]) & $mask) !== (ord($subnet_packed[$bytes]) & $mask)) {
                    continue;
                }
            }

            return true;
        }

        return false;
    }

    /**
     * Add security headers on the login screen
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
     * Get security status
     *
     * @return array Security status information
     */
    public function get_security_status(): array {
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
