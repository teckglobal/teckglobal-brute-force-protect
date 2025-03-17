<?php
/*
 * Plugin Name: TeckGlobal Brute Force Protect
 * Author: TeckGlobal LLC, xAI-Grok
 * Author URI: https://teck-global.com/
 * Plugin URI: https://teck-global.com/wordpress-plugins/
 * Description: A WordPress plugin by TeckGlobal LLC to prevent brute force login attacks and exploit scans with IP management and geolocation features. If you enjoy this free product please donate at https://teck-global.com/buy-me-a-coffee/
 * Version: 1.0.0
 * License: GPL-2.0+
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain: teckglobal-brute-force-protect
 * Requires at least: 5.0
 * Tested up to: 6.7
 * Requires PHP: 7.4 or later
 * WordPress Available: yes
 * Requires License: no
*/

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Define constants
define('TECKGLOBAL_BFP_PATH', plugin_dir_path(__FILE__));
define('TECKGLOBAL_BFP_URL', plugin_dir_url(__FILE__));
define('TECKGLOBAL_BFP_VERSION', '1.0.0');
define('TECKGLOBAL_BFP_GITHUB_API', 'https://api.github.com/repos/teckglobal/teckglobal-brute-force-protect/releases/latest');
define('TECKGLOBAL_BFP_GEO_DIR', WP_CONTENT_DIR . '/teckglobal-geoip/');
define('TECKGLOBAL_BFP_GEO_FILE', TECKGLOBAL_BFP_GEO_DIR . 'GeoLite2-City.mmdb');

// Include functions file
require_once TECKGLOBAL_BFP_PATH . 'includes/functions.php';

// Debug logging function
function teckglobal_bfp_debug(string $message): void {
    if (defined('WP_DEBUG') && WP_DEBUG && defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
        $log_file = WP_CONTENT_DIR . '/teckglobal-bfp-debug.log';
        $timestamp = current_time('Y-m-d H:i:s');
        file_put_contents($log_file, "[$timestamp] $message\n", FILE_APPEND);
    }
}

// Get client IP address
function teckglobal_bfp_get_client_ip(): string {
    $ip = '0.0.0.0';
    $headers = [
        'HTTP_CLIENT_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_FORWARDED',
        'HTTP_X_CLUSTER_CLIENT_IP',
        'HTTP_FORWARDED_FOR',
        'HTTP_FORWARDED',
        'REMOTE_ADDR',
    ];

    foreach ($headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ip_list = explode(',', $_SERVER[$header]);
            $ip = trim($ip_list[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                teckglobal_bfp_debug("Client IP detected from $header: $ip");
                break;
            }
        }
    }

    if ($ip === '0.0.0.0') {
        teckglobal_bfp_debug("Failed to detect valid client IP. Using fallback: $ip");
    }
    return $ip;
}

// Hook into failed login attempts
function teckglobal_bfp_login_failed($username) {
    $ip = teckglobal_bfp_get_client_ip();
    teckglobal_bfp_debug("Login failed for username '$username' from IP $ip");
    teckglobal_bfp_log_attempt($ip);

    $max_attempts = (int) get_option('teckglobal_bfp_max_attempts', 5);
    $attempts = teckglobal_bfp_get_attempts($ip);

    if ($attempts >= $max_attempts) {
        teckglobal_bfp_ban_ip($ip, 'brute_force');
        teckglobal_bfp_debug("IP $ip exceeded $max_attempts attempts. Banned for brute force.");
    } else {
        teckglobal_bfp_debug("IP $ip failed login, attempts: $attempts/$max_attempts");
    }
}
add_action('wp_login_failed', 'teckglobal_bfp_login_failed');

// Hook into successful logins
function teckglobal_bfp_login_success($username) {
    $ip = teckglobal_bfp_get_client_ip();
    teckglobal_bfp_debug("Successful login for username '$username' from IP $ip");
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $row = $wpdb->get_row($wpdb->prepare("SELECT banned, ban_expiry FROM $table_name WHERE ip = %s", $ip));
    if ($row && $row->banned == 1 && $row->ban_expiry && current_time('mysql') < $row->ban_expiry) {
        teckglobal_bfp_debug("IP $ip is banned with active expiry; not resetting ban status");
    } else {
        $wpdb->update($table_name, ['attempts' => 0, 'banned' => 0, 'ban_expiry' => null, 'scan_exploit' => 0, 'brute_force' => 0, 'manual_ban' => 0], ['ip' => $ip]);
        teckglobal_bfp_debug("Reset attempts and ban status for IP $ip on successful login");
    }
}
add_action('wp_login', 'teckglobal_bfp_login_success');

// Check for invalid username attempts only on form submission
function teckglobal_bfp_check_invalid_username($username, $password) {
    $ip = teckglobal_bfp_get_client_ip();
    $auto_ban_invalid = get_option('teckglobal_bfp_auto_ban_invalid', 0);

    if (!isset($_POST['log']) || empty($username)) {
        teckglobal_bfp_debug("No login form submission detected for IP $ip; skipping check");
        return;
    }

    teckglobal_bfp_debug("Checking username '$username' from IP $ip on form submission");
    if ($auto_ban_invalid && !username_exists($username) && !email_exists($username)) {
        teckglobal_bfp_debug("Invalid username '$username' detected from IP $ip");
        teckglobal_bfp_log_attempt($ip);
        teckglobal_bfp_ban_ip($ip, 'brute_force');
        teckglobal_bfp_debug("IP $ip auto-banned for invalid username (brute_force)");
    } else {
        teckglobal_bfp_debug("Username '$username' is valid or auto-ban is off; no action taken");
    }
}
add_action('wp_authenticate', 'teckglobal_bfp_check_invalid_username', 10, 2);

// Detect exploit scans and ban IPs
function teckglobal_bfp_check_exploit_scans() {
    $ip = teckglobal_bfp_get_client_ip();
    $enable_exploit_protection = get_option('teckglobal_bfp_exploit_protection', 0);

    if (!$enable_exploit_protection) {
        return;
    }

    $request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
    $suspicious_patterns = [
        '/phpMyAdmin/i',
        '/adminer/i',
        '/wp-config\.php/i',
        '/xmlrpc\.php/i',
        '/\.env/i',
        '/admin/i',
        '/db/i',
        '/test/i',
    ];

    foreach ($suspicious_patterns as $pattern) {
        if (preg_match($pattern, $request_uri)) {
            teckglobal_bfp_debug("Exploit scan detected from IP $ip: $request_uri matches $pattern");
            teckglobal_bfp_log_attempt($ip);
            $max_attempts = (int) get_option('teckglobal_bfp_exploit_max_attempts', 3);
            $attempts = teckglobal_bfp_get_attempts($ip);

            if ($attempts >= $max_attempts) {
                teckglobal_bfp_ban_ip($ip, 'scan_exploit');
                teckglobal_bfp_debug("IP $ip banned for exceeding $max_attempts exploit scan attempts");
            } else {
                teckglobal_bfp_debug("IP $ip exploit scan attempt logged, attempts: $attempts/$max_attempts");
            }
            break;
        }
    }
}
add_action('init', 'teckglobal_bfp_check_exploit_scans', 2);

// Block banned IPs during authentication
function teckglobal_bfp_block_banned_ips_login($user, $username, $password) {
    $ip = teckglobal_bfp_get_client_ip();
    if (teckglobal_bfp_is_ip_banned($ip)) {
        teckglobal_bfp_debug("Blocking banned IP $ip during authentication attempt");
        wp_die(
            'Your IP has been banned due to suspicious activity. Please contact the site administrator.',
            'Access Denied',
            ['response' => 403]
        );
    }
    teckglobal_bfp_debug("IP $ip not banned; proceeding with authentication");
    return $user;
}
add_filter('authenticate', 'teckglobal_bfp_block_banned_ips_login', 5, 3);

// Block banned IPs on all other requests
function teckglobal_bfp_block_banned_ips() {
    $ip = teckglobal_bfp_get_client_ip();
    if (teckglobal_bfp_is_ip_banned($ip) && strpos($_SERVER['REQUEST_URI'], 'wp-login.php') === false) {
        teckglobal_bfp_debug("Blocking banned IP $ip on non-login page");
        wp_die(
            'Your IP has been banned due to suspicious activity. Please contact the site administrator.',
            'Access Denied',
            ['response' => 403]
        );
    }
}
add_action('init', 'teckglobal_bfp_block_banned_ips', 1);

// Register admin menu
function teckglobal_bfp_admin_menu() {
    add_menu_page(
        'TeckGlobal BFP',
        'Brute Force Protect',
        'manage_options',
        'teckglobal-bfp',
        'teckglobal_bfp_settings_page',
        'dashicons-shield',
        80
    );
    add_submenu_page(
        'teckglobal-bfp',
        'Settings',
        'Settings',
        'manage_options',
        'teckglobal-bfp',
        'teckglobal_bfp_settings_page'
    );
    add_submenu_page(
        'teckglobal-bfp',
        'Manage IPs',
        'Manage IPs',
        'manage_options',
        'teckglobal-bfp-manage-ips',
        'teckglobal_bfp_manage_ips_page'
    );
    add_submenu_page(
        'teckglobal-bfp',
        'IP Logs & Map',
        'IP Logs & Map',
        'manage_options',
        'teckglobal-bfp-ip-logs',
        'teckglobal_bfp_ip_logs_page'
    );
}
add_action('admin_menu', 'teckglobal_bfp_admin_menu');

// Enqueue admin assets
function teckglobal_bfp_enqueue_admin_assets($hook) {
    teckglobal_bfp_debug("Enqueue hook triggered: $hook");
    if (strpos($hook, 'teckglobal-bfp') !== false) {
        wp_enqueue_style('teckglobal-bfp-style', TECKGLOBAL_BFP_URL . 'assets/css/style.css', [], TECKGLOBAL_BFP_VERSION);
        wp_enqueue_style('leaflet-css', TECKGLOBAL_BFP_URL . 'assets/css/leaflet.css', [], '1.9.4');
        wp_enqueue_script('leaflet-js', TECKGLOBAL_BFP_URL . 'assets/js/leaflet.js', [], '1.9.4', true);
        wp_enqueue_script('teckglobal_bfp-script', TECKGLOBAL_BFP_URL . 'assets/js/script.js', ['leaflet-js', 'jquery'], TECKGLOBAL_BFP_VERSION, true);

        if (strpos($hook, 'teckglobal-bfp-ip-logs') !== false) {
            wp_localize_script('teckglobal_bfp-script', 'teckglobal_bfp_ajax', [
                'ajax_url' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('teckglobal_bfp_unban_nonce'),
            ]);
        }
    }
}
add_action('admin_enqueue_scripts', 'teckglobal_bfp_enqueue_admin_assets');

// AJAX handler for unban action
function teckglobal_bfp_ajax_unban_ip() {
    check_ajax_referer('teckglobal_bfp_unban_nonce', 'nonce');

    if (!current_user_can('manage_options')) {
        wp_send_json_error(['message' => 'Insufficient permissions']);
    }

    $ip = sanitize_text_field($_POST['ip']);
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        wp_send_json_error(['message' => 'Invalid IP address']);
    }

    teckglobal_bfp_unban_ip($ip);
    wp_send_json_success(['ip' => $ip]);
}
add_action('wp_ajax_teckglobal_bfp_unban_ip', 'teckglobal_bfp_ajax_unban_ip');

// Database setup and GeoIP download on activation
function teckglobal_bfp_activate() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE $table_name (
        id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        ip VARCHAR(45) NOT NULL,
        timestamp DATETIME NOT NULL,
        attempts INT NOT NULL DEFAULT 0,
        banned TINYINT(1) NOT NULL DEFAULT 0,
        ban_expiry DATETIME DEFAULT NULL,
        country VARCHAR(100) DEFAULT 'Unknown',
        latitude DECIMAL(10,7) DEFAULT NULL,
        longitude DECIMAL(10,7) DEFAULT NULL,
        scan_exploit TINYINT(1) NOT NULL DEFAULT 0,
        brute_force TINYINT(1) NOT NULL DEFAULT 0,
        manual_ban TINYINT(1) NOT NULL DEFAULT 0,
        PRIMARY KEY (id),
        UNIQUE KEY ip (ip)
    ) $charset_collate;";

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta($sql);

    // Set default options (use update_option to overwrite old paths)
    update_option('teckglobal_bfp_geo_path', TECKGLOBAL_BFP_GEO_FILE);
    add_option('teckglobal_bfp_max_attempts', 5);
    add_option('teckglobal_bfp_ban_time', 60);
    add_option('teckglobal_bfp_auto_ban_invalid', 0);
    add_option('teckglobal_bfp_excluded_ips', '');
    add_option('teckglobal_bfp_exploit_protection', 0);
    add_option('teckglobal_bfp_exploit_max_attempts', 3);
    add_option('teckglobal_bfp_maxmind_key', '');

    // Download GeoIP file if not present
    teckglobal_bfp_download_geoip();

    // Schedule cron for GeoIP updates (Tues/Fri, 1 AM UTC)
    if (!wp_next_scheduled('teckglobal_bfp_update_geoip')) {
        wp_schedule_event(strtotime('next Tuesday 01:00:00 UTC'), 'weekly', 'teckglobal_bfp_update_geoip');
        wp_schedule_event(strtotime('next Friday 01:00:00 UTC'), 'weekly', 'teckglobal_bfp_update_geoip');
    }
}
register_activation_hook(__FILE__, 'teckglobal_bfp_activate');

// Clean up on deactivation
function teckglobal_bfp_deactivate() {
    wp_clear_scheduled_hook('teckglobal_bfp_update_geoip');
}
register_deactivation_hook(__FILE__, 'teckglobal_bfp_deactivate');

// Plugin update checker
function teckglobal_bfp_check_for_updates($transient) {
    if (empty($transient->checked)) {
        return $transient;
    }

    $response = wp_remote_get(TECKGLOBAL_BFP_GITHUB_API, [
        'timeout' => 10,
        'headers' => [
            'Accept' => 'application/vnd.github.v3+json',
            'User-Agent' => 'TeckGlobal-Brute-Force-Protect/' . TECKGLOBAL_BFP_VERSION,
        ],
    ]);

    if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
        teckglobal_bfp_debug("Failed to check GitHub for updates: " . (is_wp_error($response) ? $response->get_error_message() : 'HTTP ' . wp_remote_retrieve_response_code($response)));
        return $transient;
    }

    $release = json_decode(wp_remote_retrieve_body($response));
    if (!$release || empty($release->tag_name)) {
        teckglobal_bfp_debug("Invalid GitHub release data received");
        return $transient;
    }

    $new_version = ltrim($release->tag_name, 'v');
    $current_version = TECKGLOBAL_BFP_VERSION;

    if (version_compare($new_version, $current_version, '>')) {
        $plugin_data = [
            'slug' => 'teckglobal-brute-force-protect',
            'new_version' => $new_version,
            'url' => 'https://github.com/teckglobal/teckglobal-brute-force-protect',
            'package' => $release->zipball_url,
        ];
        $transient->response['teckglobal-brute-force-protect/teckglobal-brute-force-protect.php'] = (object) $plugin_data;
        teckglobal_bfp_debug("Update available: $current_version -> $new_version");
        teckglobal_bfp_download_geoip(); // Check GeoIP on plugin update
    } else {
        teckglobal_bfp_debug("No update available: Current $current_version, Latest $new_version");
    }

    return $transient;
}
add_filter('pre_set_site_transient_update_plugins', 'teckglobal_bfp_check_for_updates');
