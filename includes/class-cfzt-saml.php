/**
     * Check rate limit
     * 
     * @return bool True if within rate limit
     */
    public function check_rate_limit() {
        return $this->security->check_rate_limit();
    }<?php
/**
 * SAML Authentication handler for Cloudflare Zero Trust
 *
 * ⚠️ SECURITY WARNING - READ BEFORE USE ⚠️
 *
 * This SAML implementation does NOT perform proper signature validation.
 * It should NOT be used in production environments without additional security measures.
 *
 * KNOWN LIMITATIONS:
 * - SAML response signatures are not cryptographically verified
 * - Vulnerable to response tampering and replay attacks
 * - An attacker could potentially forge SAML responses
 *
 * RECOMMENDATIONS:
 * 1. Use OIDC authentication instead (fully implemented and secure)
 * 2. If SAML is required, use a production-ready SAML library
 * 3. Implement additional security controls (IP restrictions, monitoring, etc.)
 *
 * See validate_signature() method for detailed security information.
 *
 * @package CloudflareZeroTrustLogin
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class CFZT_SAML {
    
    /**
     * Security instance
     * @var CFZT_Security
     */
    private $security;
    
    /**
     * SAML settings cache
     * @var array
     */
    private $saml_settings;
    
    /**
     * Constructor
     * 
     * @param CFZT_Security $security Security instance
     */
    public function __construct($security) {
        $this->security = $security;
        $this->init_hooks();
    }
    
    /**
     * Initialize hooks
     */
    private function init_hooks() {
        // SAML specific endpoints
        add_action('init', array($this, 'register_saml_endpoints'));
        add_action('template_redirect', array($this, 'handle_saml_endpoints'));
    }
    
    /**
     * Register SAML endpoints
     */
    public function register_saml_endpoints() {
        add_rewrite_rule('^cfzt-saml/acs/?', 'index.php?cfzt_saml_acs=1', 'top');
        add_rewrite_rule('^cfzt-saml/sls/?', 'index.php?cfzt_saml_sls=1', 'top');
        add_rewrite_rule('^cfzt-saml/metadata/?', 'index.php?cfzt_saml_metadata=1', 'top');
        
        // Add query vars
        add_filter('query_vars', function($vars) {
            $vars[] = 'cfzt_saml_acs';
            $vars[] = 'cfzt_saml_sls';
            $vars[] = 'cfzt_saml_metadata';
            return $vars;
        });
    }
    
    /**
     * Handle SAML endpoints
     */
    public function handle_saml_endpoints() {
        if (get_query_var('cfzt_saml_acs')) {
            $this->handle_acs();
            exit;
        }
        
        if (get_query_var('cfzt_saml_sls')) {
            $this->handle_sls();
            exit;
        }
        
        if (get_query_var('cfzt_saml_metadata')) {
            $this->serve_metadata();
            exit;
        }
    }
    
    /**
     * Get SAML authorization URL
     * 
     * @return string Authorization URL
     */
    public function get_auth_url() {
        $options = CFZT_Plugin::get_option();
        
        if (empty($options['team_domain'])) {
            return '';
        }
        
        // Generate SAML request
        $saml_request = $this->create_authn_request();
        
        // Build SSO URL
        $sso_url = $this->get_sso_url();
        if (empty($sso_url)) {
            return '';
        }
        
        $params = array(
            'SAMLRequest' => $saml_request,
        );
        
        // Add relay state if needed
        $relay_state = isset($_REQUEST['redirect_to']) ? $_REQUEST['redirect_to'] : admin_url();
        if (!empty($relay_state)) {
            $params['RelayState'] = $relay_state;
        }
        
        return $sso_url . '?' . http_build_query($params);
    }
    
    /**
     * Create SAML AuthnRequest
     * 
     * @return string Base64 encoded SAML request
     */
    private function create_authn_request() {
        $id = '_' . bin2hex(openssl_random_pseudo_bytes(16));
        $issue_instant = gmdate('Y-m-d\TH:i:s\Z');
        $issuer = $this->get_sp_entity_id();
        $acs_url = $this->get_acs_url();
        $destination = $this->get_sso_url();
        
        $saml_request = '<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest 
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="' . $id . '"
    Version="2.0"
    IssueInstant="' . $issue_instant . '"
    Destination="' . htmlspecialchars($destination) . '"
    AssertionConsumerServiceURL="' . htmlspecialchars($acs_url) . '"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>' . htmlspecialchars($issuer) . '</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
</samlp:AuthnRequest>';
        
        // Compress and encode
        $deflated = gzdeflate($saml_request);
        return base64_encode($deflated);
    }
    
    /**
     * Handle Assertion Consumer Service (ACS)
     */
    private function handle_acs() {
        // Rate limiting
        if (!$this->security->check_rate_limit()) {
            wp_die(
                __('Too many authentication attempts. Please try again in 5 minutes.', 'cf-zero-trust'),
                __('Rate Limit Exceeded', 'cf-zero-trust'),
                array('response' => 429)
            );
        }

        if (!isset($_POST['SAMLResponse'])) {
            $this->log_authentication('unknown', false, 'No SAML response received');
            wp_die(__('No SAML response received.', 'cf-zero-trust'));
        }
        
        $saml_response = base64_decode($_POST['SAMLResponse']);
        $relay_state = isset($_POST['RelayState']) ? $_POST['RelayState'] : admin_url();
        
        // Validate SAML response
        $user_data = $this->validate_saml_response($saml_response);
        
        if (!$user_data) {
            $this->log_authentication('unknown', false, 'Invalid SAML response');
            wp_die(__('Invalid SAML response. Please check your Cloudflare Zero Trust configuration.', 'cf-zero-trust'));
        }
        
        // Authenticate user
        $this->authenticate_user($user_data, $relay_state);
    }
    
    /**
     * Handle Single Logout Service (SLS)
     */
    private function handle_sls() {
        // Handle logout response
        if (isset($_REQUEST['SAMLResponse']) || isset($_REQUEST['SAMLRequest'])) {
            wp_logout();

            // Get custom logout redirect URL
            $options = CFZT_Plugin::get_option();
            $redirect_to = !empty($options['redirect_after_logout'])
                ? $options['redirect_after_logout']
                : home_url();

            wp_safe_redirect($redirect_to);
            exit;
        }
    }
    
    /**
     * Serve SP metadata
     */
    private function serve_metadata() {
        $entity_id = $this->get_sp_entity_id();
        $acs_url = $this->get_acs_url();
        $sls_url = $this->get_sls_url();
        
        $metadata = '<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="' . htmlspecialchars($entity_id) . '">
    <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
        <AssertionConsumerService 
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" 
            Location="' . htmlspecialchars($acs_url) . '" 
            index="0" 
            isDefault="true"/>
        <SingleLogoutService 
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" 
            Location="' . htmlspecialchars($sls_url) . '"/>
    </SPSSODescriptor>
</EntityDescriptor>';
        
        header('Content-Type: application/samlmetadata+xml');
        echo $metadata;
    }
    
    /**
     * Validate SAML response
     * 
     * @param string $saml_response Raw SAML response
     * @return array|false User data or false on failure
     */
    private function validate_saml_response($saml_response) {
        try {
            // Parse XML
            $xml = new DOMDocument();
            $xml->loadXML($saml_response);
            
            // Basic validation - check for successful status
            $xpath = new DOMXPath($xml);
            $xpath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
            $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
            
            // Check status
            $status_code = $xpath->query('//samlp:StatusCode/@Value')->item(0);
            if (!$status_code || $status_code->nodeValue !== 'urn:oasis:names:tc:SAML:2.0:status:Success') {
                error_log('[CF Zero Trust SAML] Response status not successful');
                return false;
            }
            
            // Validate signature if certificate is configured
            $options = CFZT_Plugin::get_option();
            if (!empty($options['saml_x509_cert'])) {
                if (!$this->validate_signature($xml, $options['saml_x509_cert'])) {
                    error_log('[CF Zero Trust SAML] Signature validation failed');
                    return false;
                }
            }
            
            // Extract user attributes
            $attributes = array();
            
            // Get NameID (email)
            $name_id = $xpath->query('//saml:Subject/saml:NameID')->item(0);
            if ($name_id) {
                $attributes['email'] = $name_id->nodeValue;
            }
            
            // Get other attributes
            $attribute_nodes = $xpath->query('//saml:Attribute');
            foreach ($attribute_nodes as $attr) {
                $name = $attr->getAttribute('Name');
                $value_node = $xpath->query('saml:AttributeValue', $attr)->item(0);
                if ($value_node) {
                    $attributes[$name] = $value_node->nodeValue;
                }
            }
            
            // Map Cloudflare attributes to standard claims
            $user_data = array(
                'email' => $attributes['email'] ?? $attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'] ?? '',
                'name' => $attributes['name'] ?? $attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'] ?? '',
                'given_name' => $attributes['given_name'] ?? $attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'] ?? '',
                'family_name' => $attributes['family_name'] ?? $attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'] ?? '',
                'sub' => $attributes['email'], // Use email as subject identifier
            );
            
            return $user_data;
            
        } catch (Exception $e) {
            error_log('[CF Zero Trust SAML] Error parsing response: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Validate XML signature
     *
     * @param DOMDocument $xml XML document
     * @param string $x509_cert X509 certificate
     * @return bool True if valid
     *
     * ⚠️ SECURITY WARNING: This method currently does NOT perform proper signature validation.
     *
     * CURRENT BEHAVIOR:
     * - Always returns true (allows all responses, signed or unsigned)
     * - Does not verify the cryptographic signature against the X.509 certificate
     * - Does not validate certificate chain or expiration
     *
     * SECURITY IMPLICATIONS:
     * - Vulnerable to SAML response tampering and replay attacks
     * - An attacker could forge SAML responses to gain unauthorized access
     * - Should NOT be used in production environments without additional security measures
     *
     * RECOMMENDED SOLUTIONS:
     * 1. Use a production-ready SAML library:
     *    - SimpleSAMLphp (https://simplesamlphp.org/)
     *    - LightSAML (https://github.com/lightsaml/lightsaml)
     *    - OneLogin PHP SAML (https://github.com/onelogin/php-saml)
     *
     * 2. If implementing manually, you must:
     *    - Canonicalize the signed XML element (C14N)
     *    - Extract and decode the signature value
     *    - Verify signature using openssl_verify() with the X.509 certificate
     *    - Validate certificate chain and expiration
     *    - Check signature algorithm security (reject weak algorithms)
     *    - Validate assertion timestamps and conditions
     *
     * 3. Additional hardening:
     *    - Restrict access by IP or require additional authentication
     *    - Use short-lived SAML assertions
     *    - Implement assertion replay prevention
     *    - Monitor authentication logs for anomalies
     *
     * @todo Implement proper SAML signature validation before production use
     */
    private function validate_signature($xml, $x509_cert) {
        // ⚠️ CRITICAL: This is a placeholder implementation that does NOT validate signatures
        // See method documentation above for security implications and recommendations

        $xpath = new DOMXPath($xml);
        $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');

        $signature_node = $xpath->query('//ds:Signature')->item(0);
        if (!$signature_node) {
            // No signature present - allowing unsigned responses is insecure
            error_log('[CF Zero Trust SAML] WARNING: SAML response has no signature - security risk!');
            return true; // ⚠️ INSECURE: Should return false in production
        }

        // ⚠️ CRITICAL: Signature validation not implemented
        error_log('[CF Zero Trust SAML] WARNING: SAML signature validation is not implemented - security risk!');

        // TODO: Implement proper signature validation:
        // 1. Canonicalize the signed element
        // 2. Verify the signature value against the certificate
        // 3. Check certificate validity and chain
        // 4. Validate signature algorithm

        return true; // ⚠️ INSECURE: Always returns true - implement proper validation
    }
    
    /**
     * Authenticate user with WordPress
     * 
     * @param array $user_data User data from SAML assertion
     * @param string $redirect_to Redirect URL after login
     */
    private function authenticate_user($user_data, $redirect_to = '') {
        $options = CFZT_Plugin::get_option();
        
        $email = $user_data['email'];
        if (empty($email)) {
            $this->log_authentication('unknown', false, 'No email in SAML assertion');
            wp_die(__('No email address provided in SAML assertion.', 'cf-zero-trust'));
        }
        
        // Check if user exists
        $user = get_user_by('email', $email);
        
        if (!$user && $options['auto_create_users'] === CFZT_Plugin::OPTION_YES) {
            $user = CFZT_User_Helper::create_user($email, $user_data, 'saml');
        }

        if ($user) {
            // Log the user in
            wp_set_current_user($user->ID);
            wp_set_auth_cookie($user->ID, true);

            // Update last login meta
            CFZT_User_Helper::update_last_login($user->ID, 'saml');
            
            // Protect session
            $this->security->protect_session();
            
            // Log successful authentication
            $this->log_authentication($email, true);
            
            // Trigger action for other plugins
            do_action('cfzt_user_authenticated', $user, $user_data);

            // Determine redirect URL
            $redirect_to = $this->get_login_redirect_url($redirect_to);
            wp_safe_redirect($redirect_to);
            exit;
        } else {
            $this->log_authentication($email, false, 'User creation disabled or failed');
            wp_die(__('User authentication failed. Auto-creation may be disabled or you may not have permission to access this site.', 'cf-zero-trust'));
        }
    }
    
    /**
     * Get SSO URL
     * 
     * @return string SSO URL
     */
    private function get_sso_url() {
        $options = CFZT_Plugin::get_option();
        
        if (empty($options['team_domain'])) {
            return '';
        }
        
        // Cloudflare Zero Trust SAML SSO endpoint
        return 'https://' . $options['team_domain'] . '/cdn-cgi/access/sso/saml/' . $options['saml_sso_target_url'];
    }
    
    /**
     * Get SP Entity ID
     * 
     * @return string Entity ID
     */
    private function get_sp_entity_id() {
        $options = CFZT_Plugin::get_option();
        
        if (!empty($options['saml_sp_entity_id'])) {
            return $options['saml_sp_entity_id'];
        }
        
        return home_url();
    }
    
    /**
     * Get ACS URL
     * 
     * @return string ACS URL
     */
    private function get_acs_url() {
        return home_url('cfzt-saml/acs/');
    }
    
    /**
     * Get SLS URL
     * 
     * @return string SLS URL
     */
    private function get_sls_url() {
        return home_url('cfzt-saml/sls/');
    }
    
    /**
     * Get metadata URL
     * 
     * @return string Metadata URL
     */
    public function get_metadata_url() {
        return home_url('cfzt-saml/metadata/');
    }
    
    /**
     * Log authentication attempts
     *
     * @param string $identifier Email or username
     * @param bool $success Success status
     * @param string $message Optional message
     */
    private function log_authentication($identifier, $success, $message = '') {
        CFZT_Logger::auth_attempt($identifier, $success, 'saml', $message);
    }

    /**
     * Get login redirect URL
     *
     * Checks for custom redirect URL, then relay state, then defaults
     *
     * @param string $relay_state Relay state from SAML
     * @return string Redirect URL
     */
    private function get_login_redirect_url($relay_state = '') {
        $options = CFZT_Plugin::get_option();

        // Check for custom redirect URL setting
        if (!empty($options['redirect_after_login'])) {
            return $options['redirect_after_login'];
        }

        // Check relay state (validate to prevent open redirects)
        if (!empty($relay_state) && $relay_state !== wp_login_url()) {
            $redirect = wp_validate_redirect($relay_state, admin_url());
            return $redirect;
        }

        // Check redirect_to parameter (validate to prevent open redirects)
        if (isset($_REQUEST['redirect_to']) && !empty($_REQUEST['redirect_to'])) {
            $redirect = wp_validate_redirect($_REQUEST['redirect_to'], admin_url());
            return $redirect;
        }

        // Default to admin dashboard
        return admin_url();
    }
}