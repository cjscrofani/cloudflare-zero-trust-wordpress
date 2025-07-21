<?php
/**
 * GitHub Updater Class for Cloudflare Zero Trust Login Plugin
 * 
 * This class handles checking for updates from GitHub releases and integrating
 * with WordPress's built-in update system.
 * 
 * @package CloudflareZeroTrustLogin
 * @subpackage Updater
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

if (!class_exists('CFZT_GitHub_Updater')) {
    
    class CFZT_GitHub_Updater {
        
        /**
         * Plugin file path
         * @var string
         */
        private $plugin_file;
        
        /**
         * GitHub username
         * @var string
         */
        private $github_username;
        
        /**
         * GitHub repository name
         * @var string
         */
        private $github_repository;
        
        /**
         * Plugin data cache
         * @var array|null
         */
        private $plugin_data;
        
        /**
         * GitHub API response cache
         * @var array|null
         */
        private $github_response;
        
        /**
         * Constructor
         * 
         * @param string $plugin_file Full path to the main plugin file
         * @param string $github_username GitHub username or organization
         * @param string $github_repository GitHub repository name
         */
        public function __construct($plugin_file, $github_username, $github_repository) {
            $this->plugin_file = $plugin_file;
            $this->github_username = $github_username;
            $this->github_repository = $github_repository;
            
            // Hook into WordPress update system
            add_filter('pre_set_site_transient_update_plugins', array($this, 'check_for_update'));
            add_filter('plugins_api', array($this, 'plugin_info'), 20, 3);
            add_action('upgrader_process_complete', array($this, 'after_update'), 10, 2);
            
            // Add custom update message
            add_action('in_plugin_update_message-' . plugin_basename($plugin_file), array($this, 'update_message'), 10, 2);
        }
        
        /**
         * Get plugin data
         * 
         * @return array Plugin headers
         */
        private function get_plugin_data() {
            if (null === $this->plugin_data) {
                $this->plugin_data = get_plugin_data($this->plugin_file);
            }
            return $this->plugin_data;
        }
        
        /**
         * Get latest release from GitHub
         * 
         * @return array|false GitHub release data or false on failure
         */
        private function get_github_release() {
            if (null === $this->github_response) {
                $transient_name = 'cfzt_github_release_' . md5($this->github_username . $this->github_repository);
                
                // Check if we have a cached version
                $cached = get_transient($transient_name);
                if ($cached !== false) {
                    $this->github_response = $cached;
                    return $this->github_response;
                }
                
                // Fetch from GitHub API
                $url = sprintf(
                    'https://api.github.com/repos/%s/%s/releases/latest',
                    $this->github_username,
                    $this->github_repository
                );
                
                $response = wp_remote_get($url, array(
                    'timeout' => 10,
                    'headers' => array(
                        'Accept' => 'application/vnd.github.v3+json',
                        'User-Agent' => 'WordPress/' . get_bloginfo('version') . '; ' . get_bloginfo('url'),
                    ),
                ));
                
                if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200) {
                    $body = wp_remote_retrieve_body($response);
                    $release = json_decode($body, true);
                    
                    if (json_last_error() === JSON_ERROR_NONE && isset($release['tag_name'])) {
                        $this->github_response = $release;
                        // Cache for 6 hours
                        set_transient($transient_name, $release, 6 * HOUR_IN_SECONDS);
                    }
                } else {
                    // If we get a 404, there might not be any releases yet
                    if (wp_remote_retrieve_response_code($response) === 404) {
                        // Cache the "no releases" state for 1 hour
                        set_transient($transient_name, array('no_releases' => true), HOUR_IN_SECONDS);
                    }
                }
            }
            
            return $this->github_response;
        }
        
        /**
         * Check for plugin updates
         * 
         * @param object $transient WordPress update transient
         * @return object Modified transient
         */
        public function check_for_update($transient) {
            if (empty($transient->checked)) {
                return $transient;
            }
            
            $plugin_data = $this->get_plugin_data();
            $github_release = $this->get_github_release();
            
            if (!$github_release || !isset($github_release['tag_name']) || isset($github_release['no_releases'])) {
                return $transient;
            }
            
            // Extract version from tag (remove 'v' prefix if present)
            $latest_version = ltrim($github_release['tag_name'], 'v');
            $current_version = $plugin_data['Version'];
            
            // Check if update is available
            if (version_compare($current_version, $latest_version, '<')) {
                $plugin_slug = plugin_basename($this->plugin_file);
                
                // Get download URL
                $download_url = $this->get_download_url($github_release);
                
                $transient->response[$plugin_slug] = (object) array(
                    'id' => $plugin_slug,
                    'slug' => dirname($plugin_slug),
                    'plugin' => $plugin_slug,
                    'new_version' => $latest_version,
                    'url' => 'https://github.com/' . $this->github_username . '/' . $this->github_repository,
                    'package' => $download_url,
                    'icons' => $this->get_plugin_icons(),
                    'banners' => $this->get_plugin_banners(),
                    'banners_rtl' => array(),
                    'tested' => $this->get_tested_version($github_release),
                    'requires_php' => $plugin_data['RequiresPHP'] ?? '5.6',
                    'requires' => $plugin_data['RequiresWP'] ?? '4.7',
                    'compatibility' => new stdClass(),
                );
            }
            
            return $transient;
        }
        
        /**
         * Get download URL from release
         * 
         * @param array $release GitHub release data
         * @return string Download URL
         */
        private function get_download_url($release) {
            // First, look for a ZIP file in the assets
            if (!empty($release['assets'])) {
                foreach ($release['assets'] as $asset) {
                    if (strpos($asset['name'], '.zip') !== false) {
                        return $asset['browser_download_url'];
                    }
                }
            }
            
            // Fallback to zipball URL
            // Note: GitHub's zipball creates a folder structure that might need adjustment
            return sprintf(
                'https://github.com/%s/%s/archive/refs/tags/%s.zip',
                $this->github_username,
                $this->github_repository,
                $release['tag_name']
            );
        }
        
        /**
         * Get plugin icons
         * 
         * @return array Icon URLs
         */
        private function get_plugin_icons() {
            // You can add icon URLs here if you have them in your repository
            return array(
                '1x' => CFZT_PLUGIN_URL . 'assets/icon-128x128.png',
                '2x' => CFZT_PLUGIN_URL . 'assets/icon-256x256.png',
                'svg' => CFZT_PLUGIN_URL . 'assets/icon.svg',
            );
        }
        
        /**
         * Get plugin banners
         * 
         * @return array Banner URLs
         */
        private function get_plugin_banners() {
            // You can add banner URLs here if you have them in your repository
            return array(
                'low' => CFZT_PLUGIN_URL . 'assets/banner-772x250.png',
                'high' => CFZT_PLUGIN_URL . 'assets/banner-1544x500.png',
            );
        }
        
        /**
         * Get tested WordPress version
         * 
         * @param array $release GitHub release data
         * @return string WordPress version
         */
        private function get_tested_version($release) {
            // Look for "Tested up to" in release body
            if (!empty($release['body'])) {
                if (preg_match('/tested up to:?\s*([0-9.]+)/i', $release['body'], $matches)) {
                    return $matches[1];
                }
            }
            
            // Default to current WordPress version
            return get_bloginfo('version');
        }
        
        /**
         * Provide plugin information for the update details
         * 
         * @param false|object|array $result The result object or array
         * @param string $action The type of information being requested
         * @param object $args Plugin API arguments
         * @return false|object
         */
        public function plugin_info($result, $action, $args) {
            if ($action !== 'plugin_information') {
                return $result;
            }
            
            if (!isset($args->slug) || $args->slug !== dirname(plugin_basename($this->plugin_file))) {
                return $result;
            }
            
            $plugin_data = $this->get_plugin_data();
            $github_release = $this->get_github_release();
            
            if (!$github_release || isset($github_release['no_releases'])) {
                return $result;
            }
            
            $plugin_info = new stdClass();
            $plugin_info->name = $plugin_data['Name'];
            $plugin_info->slug = dirname(plugin_basename($this->plugin_file));
            $plugin_info->version = ltrim($github_release['tag_name'], 'v');
            $plugin_info->author = sprintf('<a href="%s">%s</a>', 
                'https://github.com/' . $this->github_username,
                $plugin_data['Author']
            );
            $plugin_info->homepage = $plugin_data['PluginURI'];
            $plugin_info->short_description = $plugin_data['Description'];
            $plugin_info->sections = array(
                'description' => $this->get_plugin_description(),
                'changelog' => $this->parse_changelog($github_release['body'] ?? ''),
                'installation' => $this->get_installation_instructions(),
            );
            
            $plugin_info->download_link = $this->get_download_url($github_release);
            $plugin_info->trunk = $plugin_info->download_link;
            $plugin_info->last_updated = $github_release['published_at'] ?? $github_release['created_at'];
            $plugin_info->added = $github_release['created_at'];
            
            return $plugin_info;
        }
        
        /**
         * Get plugin description
         * 
         * @return string HTML description
         */
        private function get_plugin_description() {
            $description = '<p>' . $this->get_plugin_data()['Description'] . '</p>';
            $description .= '<h3>Features</h3>';
            $description .= '<ul>';
            $description .= '<li>Secure authentication using Cloudflare Zero Trust OIDC</li>';
            $description .= '<li>Support for both SaaS and Self-hosted applications</li>';
            $description .= '<li>Automatic user creation with role assignment</li>';
            $description .= '<li>Built-in security features (rate limiting, encryption, session protection)</li>';
            $description .= '<li>Flexible login modes (primary or secondary)</li>';
            $description .= '<li>Environment variable support for credentials</li>';
            $description .= '</ul>';
            
            return $description;
        }
        
        /**
         * Get installation instructions
         * 
         * @return string HTML installation instructions
         */
        private function get_installation_instructions() {
            $instructions = '<ol>';
            $instructions .= '<li>Upload the plugin files to the <code>/wp-content/plugins/cloudflare-zero-trust-login</code> directory, or install the plugin through the WordPress plugins screen directly.</li>';
            $instructions .= '<li>Activate the plugin through the "Plugins" screen in WordPress.</li>';
            $instructions .= '<li>Configure your Cloudflare Zero Trust application and obtain the necessary credentials.</li>';
            $instructions .= '<li>Use the Settings → CF Zero Trust screen to configure the plugin.</li>';
            $instructions .= '</ol>';
            
            return $instructions;
        }
        
        /**
         * Parse changelog from markdown
         * 
         * @param string $markdown Markdown changelog
         * @return string HTML changelog
         */
        private function parse_changelog($markdown) {
            if (empty($markdown)) {
                return '<p>No changelog available.</p>';
            }
            
            // Convert markdown to HTML-ish format for WordPress
            $changelog = $markdown;
            
            // Convert headers
            $changelog = preg_replace('/^#### (.+)$/m', '<h5>$1</h5>', $changelog);
            $changelog = preg_replace('/^### (.+)$/m', '<h4>$1</h4>', $changelog);
            $changelog = preg_replace('/^## (.+)$/m', '<h3>$1</h3>', $changelog);
            $changelog = preg_replace('/^# (.+)$/m', '<h2>$1</h2>', $changelog);
            
            // Convert bold
            $changelog = preg_replace('/\*\*(.+?)\*\*/', '<strong>$1</strong>', $changelog);
            
            // Convert lists
            $changelog = preg_replace('/^\* (.+)$/m', '<li>$1</li>', $changelog);
            $changelog = preg_replace('/^\- (.+)$/m', '<li>$1</li>', $changelog);
            $changelog = preg_replace('/^\d+\. (.+)$/m', '<li>$1</li>', $changelog);
            
            // Wrap consecutive list items
            $changelog = preg_replace('/(<li>.*<\/li>\s*)+/s', '<ul>$0</ul>', $changelog);
            
            // Convert code blocks
            $changelog = preg_replace('/`([^`]+)`/', '<code>$1</code>', $changelog);
            
            // Convert line breaks
            $changelog = nl2br($changelog);
            
            return $changelog;
        }
        
        /**
         * Add custom message to update notice
         * 
         * @param array $plugin_data Plugin data
         * @param object $response Update response data
         */
        public function update_message($plugin_data, $response) {
            $github_release = $this->get_github_release();
            
            if ($github_release && !empty($github_release['body'])) {
                echo '<br><br>';
                echo '<strong>What\'s New:</strong><br>';
                
                // Extract first few lines of changelog
                $lines = explode("\n", $github_release['body']);
                $preview_lines = array_slice($lines, 0, 5);
                $preview = implode("\n", $preview_lines);
                
                // Simple markdown parsing for the preview
                $preview = preg_replace('/\*\*(.+?)\*\*/', '<strong>$1</strong>', $preview);
                $preview = preg_replace('/^\* (.+)$/m', '• $1', $preview);
                
                echo nl2br(esc_html($preview));
                
                if (count($lines) > 5) {
                    echo '<br><a href="#" onclick="event.preventDefault(); window.open(\'plugin-install.php?tab=plugin-information&plugin=' . 
                         dirname(plugin_basename($this->plugin_file)) . 
                         '&TB_iframe=true&width=600&height=800\', \'plugin-details\', \'width=600,height=800\');">View full changelog</a>';
                }
            }
        }
        
        /**
         * Clear cache after update
         * 
         * @param object $upgrader_object WordPress upgrader instance
         * @param array $options Update options
         */
        public function after_update($upgrader_object, $options) {
            if ($options['action'] === 'update' && $options['type'] === 'plugin') {
                $our_plugin = plugin_basename($this->plugin_file);
                
                // Check if our plugin was updated
                if (isset($options['plugins']) && in_array($our_plugin, $options['plugins'])) {
                    // Clear our transient after update
                    $transient_name = 'cfzt_github_release_' . md5($this->github_username . $this->github_repository);
                    delete_transient($transient_name);
                }
            }
        }
    }
}