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
            wp_die('Too many authentication attempts. Please try again in 5 minutes.', 'Rate Limit Exceeded', array('response' => 429));
        }
        
        if (!isset($_POST['SAMLResponse'])) {
            $this->log_authentication('unknown', false, 'No SAML response received');
            wp_die('No SAML response received.');
        }
        
        $saml_response = base64_decode($_POST['SAMLResponse']);
        $relay_state = isset($_POST['RelayState']) ? $_POST['RelayState'] : admin_url();
        
        // Validate SAML response
        $user_data = $this->validate_saml_response($saml_response);
        
        if (!$user_data) {
            $this->log_authentication('unknown', false, 'Invalid SAML response');
            wp_die('Invalid SAML response. Please check your Cloudflare Zero Trust configuration.');
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
            wp_redirect(home_url());
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
     */
    private function validate_signature($xml, $x509_cert) {
        // This is a simplified signature validation
        // In production, you should use a proper SAML library like LightSAML or SimpleSAMLphp
        
        // For now, we'll do basic validation
        $xpath = new DOMXPath($xml);
        $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
        
        $signature_node = $xpath->query('//ds:Signature')->item(0);
        if (!$signature_node) {
            // No signature present
            return true; // Allow unsigned for now
        }
        
        // TODO: Implement proper signature validation
        // This would involve:
        // 1. Canonicalizing the signed element
        // 2. Verifying the signature value against the certificate
        // 3. Checking certificate validity
        
        return true; // Placeholder - implement proper validation
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
            wp_die('No email address provided in SAML assertion.');
        }
        
        // Check if user exists
        $user = get_user_by('email', $email);
        
        if (!$user && $options['auto_create_users'] === 'yes') {
            $user = $this->create_user($email, $user_data);
        }
        
        if ($user) {
            // Log the user in
            wp_set_current_user($user->ID);
            wp_set_auth_cookie($user->ID, true);
            
            // Update last login meta
            update_user_meta($user->ID, 'cfzt_last_login', current_time('mysql'));
            update_user_meta($user->ID, 'cfzt_auth_method', 'saml');
            
            // Protect session
            $this->security->protect_session();
            
            // Log successful authentication
            $this->log_authentication($email, true);
            
            // Trigger action for other plugins
            do_action('cfzt_user_authenticated', $user, $user_data);
            
            // Redirect
            if (empty($redirect_to) || $redirect_to === wp_login_url()) {
                $redirect_to = admin_url();
            }
            
            wp_safe_redirect($redirect_to);
            exit;
        } else {
            $this->log_authentication($email, false, 'User creation disabled or failed');
            wp_die('User authentication failed. Auto-creation may be disabled or you may not have permission to access this site.');
        }
    }
    
    /**
     * Create new WordPress user from SAML data
     * 
     * @param string $email User email
     * @param array $user_data User data from SAML
     * @return WP_User|false User object or false on failure
     */
    private function create_user($email, $user_data) {
        $options = CFZT_Plugin::get_option();
        
        // Generate username
        $username = sanitize_user(current(explode('@', $email)));
        $username = $this->ensure_unique_username($username);
        
        $user_id = wp_create_user(
            $username,
            wp_generate_password(),
            $email
        );
        
        if (is_wp_error($user_id)) {
            error_log('[CF Zero Trust SAML] Failed to create user: ' . $user_id->get_error_message());
            return false;
        }
        
        $user = get_user_by('id', $user_id);
        
        // Set user role
        $user->set_role($options['default_role']);
        
        // Update user meta
        update_user_meta($user_id, 'cfzt_user', true);
        update_user_meta($user_id, 'cfzt_auth_method', 'saml');
        update_user_meta($user_id, 'cfzt_sub', $user_data['sub']);
        
        // Update display name if available
        $display_name = $user_data['name'];
        if (empty($display_name) && (!empty($user_data['given_name']) || !empty($user_data['family_name']))) {
            $display_name = trim($user_data['given_name'] . ' ' . $user_data['family_name']);
        }
        
        if (!empty($display_name)) {
            wp_update_user(array(
                'ID' => $user_id,
                'display_name' => $display_name
            ));
        }
        
        // Trigger action for other plugins
        do_action('cfzt_user_created', $user, $user_data);
        
        return $user;
    }
    
    /**
     * Ensure username is unique
     * 
     * @param string $username Proposed username
     * @return string Unique username
     */
    private function ensure_unique_username($username) {
        $original = $username;
        $counter = 1;
        
        while (username_exists($username)) {
            $username = $original . $counter;
            $counter++;
        }
        
        return $username;
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
        $options = CFZT_Plugin::get_option();
        
        if (isset($options['enable_logging']) && $options['enable_logging'] === 'yes') {
            $status = $success ? 'SUCCESS' : 'FAILED';
            $log_message = sprintf(
                '[CF Zero Trust SAML] Authentication %s for: %s from IP: %s',
                $status,
                $identifier,
                $_SERVER['REMOTE_ADDR']
            );
            
            if (!empty($message)) {
                $log_message .= ' - ' . $message;
            }
            
            error_log($log_message);
        }
        
        // Trigger action for other plugins to hook into
        do_action('cfzt_authentication_attempt', $identifier, $success, $message);
    }
}