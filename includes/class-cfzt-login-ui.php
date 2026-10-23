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
        // The URL is a local endpoint that mints per-browser state, so there
        // is no need to construct a second CFZT_Auth (which would register a
        // duplicate set of authentication hooks on every render).
        $redirect_to = !empty($_REQUEST['redirect_to'])
            ? wp_validate_redirect((string) wp_unslash($_REQUEST['redirect_to']), '')
            : '';
        $auth_url = CFZT_Auth::get_login_start_url($redirect_to);

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
        wp_enqueue_style(
            'cfzt-login',
            CFZT_PLUGIN_URL . 'assets/css/cfzt-login.css',
            array(),
            CFZT_PLUGIN_VERSION
        );

        // Primary mode: hide the password form, but keep it reachable for the
        // backup-code emergency path (the body class is toggled by the
        // "Use a backup code" link). The password field itself stays hidden
        // because a password never grants access in this mode.
        if (CFZT_Auth::is_primary_mode()) {
            $custom_css = '
                .login:not(.cfzt-backup-mode) #loginform,
                #lostpasswordform,
                #registerform,
                #nav {
                    display: none !important;
                }

                .login.cfzt-backup-mode #loginform .user-pass-wrap,
                .login.cfzt-backup-mode #loginform .forgetmenot {
                    display: none !important;
                }

                .login:not(.cfzt-backup-mode) .cfzt-divider {
                    display: none;
                }

                .cfzt-login-wrapper {
                    margin-top: 0;
                }
            ';
            wp_add_inline_style('cfzt-login', $custom_css);
        }
    }
}
