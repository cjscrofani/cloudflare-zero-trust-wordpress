<?php
/**
 * Login UI customization handler
 *
 * @package CloudflareZeroTrustLogin
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class CFZT_Login_UI {
    
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
        add_action('login_form', array($this, 'add_login_button'));
        add_action('login_enqueue_scripts', array($this, 'enqueue_login_assets'));
    }
    
    /**
     * Add login button to form
     */
    public function add_login_button() {
        $options = CFZT_Plugin::get_option();
        
        if (empty($options['team_domain']) || empty($options['client_id'])) {
            return;
        }
        
        // Get auth URL from auth handler
        $auth = new CFZT_Auth(new CFZT_Security());
        $auth_url = $auth->get_auth_url();
        
        if (empty($auth_url)) {
            return;
        }
        
        // Load template
        require CFZT_PLUGIN_DIR . 'templates/login-button.php';
    }
    
    /**
     * Enqueue login assets
     */
    public function enqueue_login_assets() {
        // Check if CSS file exists, if not create it
        $css_file = CFZT_PLUGIN_DIR . 'assets/css/cfzt-login.css';
        if (!file_exists($css_file)) {
            $this->create_login_css();
        }
        
        // Enqueue the CSS file
        wp_enqueue_style(
            'cfzt-login',
            CFZT_PLUGIN_URL . 'assets/css/cfzt-login.css',
            array(),
            CFZT_PLUGIN_VERSION
        );
        
        // Add inline styles for primary login mode
        $options = CFZT_Plugin::get_option();
        if (isset($options['login_mode']) && $options['login_mode'] === 'primary') {
            $custom_css = '
                #loginform,
                #lostpasswordform,
                #registerform {
                    display: none !important;
                }
                
                .cfzt-divider {
                    display: none;
                }
                
                .cfzt-login-wrapper {
                    margin-top: 0;
                }
            ';
            wp_add_inline_style('cfzt-login', $custom_css);
        }
    }
    
    /**
     * Create login CSS file
     */
    private function create_login_css() {
        $css_content = '/* Cloudflare Zero Trust Login Styles */

.cfzt-login-wrapper {
    margin: 20px 0;
}

.cfzt-divider {
    text-align: center;
    margin: 20px 0;
    position: relative;
}

.cfzt-divider span {
    background: #fff;
    padding: 0 10px;
    position: relative;
    color: #72777c;
    font-size: 14px;
    z-index: 1;
}

.cfzt-divider:before {
    content: "";
    position: absolute;
    top: 50%;
    left: 0;
    right: 0;
    height: 1px;
    background: #ddd;
}

.cfzt-login-button {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 100%;
    padding: 12px;
    background: #f38020;
    color: #fff;
    text-decoration: none;
    border-radius: 4px;
    font-size: 14px;
    font-weight: 500;
    transition: background 0.2s;
    box-sizing: border-box;
}

.cfzt-login-button:hover {
    background: #e56f0e;
    color: #fff;
}

.cfzt-login-button:focus {
    outline: 2px solid #2271b1;
    outline-offset: 2px;
    color: #fff;
}

.cfzt-login-button svg {
    margin-right: 8px;
    flex-shrink: 0;
}

/* Dark mode support */
@media (prefers-color-scheme: dark) {
    .login .cfzt-divider span {
        background: #1e1e1e;
    }
}

/* Mobile responsive */
@media screen and (max-width: 782px) {
    .cfzt-login-button {
        padding: 14px;
        font-size: 16px;
    }
}';
        
        // Create directories if they don't exist
        wp_mkdir_p(CFZT_PLUGIN_DIR . 'assets/css');
        
        // Write CSS file
        file_put_contents(CFZT_PLUGIN_DIR . 'assets/css/cfzt-login.css', $css_content);
    }
}