<?php
/*
 * Plugin Name: TeckGlobal Brute Force Protect
 * Author: TeckGlobal LLC, xAI-Grok
 * Author URI: https://teck-global.com/
 * Plugin URI: https://teck-global.com/wordpress-plugins/
 * Description: A WordPress plugin by TeckGlobal LLC to prevent brute force login attacks and exploit scans with IP management and geolocation features. If you enjoy this free product please donate at https://teck-global.com/buy-me-a-coffee/
 * Version: 1.1.2
 * License: GPL-2.0+
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain: teckglobal-brute-force-protect
 * Requires at least: 5.0
 * Tested up to: 6.7.2
 * Requires PHP: 7.4 or later
 * WordPress Available: yes
 * Requires License: no
 */

if (!defined('ABSPATH')) {
    exit;
}

define('TECKGLOBAL_BFP_PATH', plugin_dir_path(__FILE__));
define('TECKGLOBAL_BFP_URL', plugin_dir_url(__FILE__));
define('TECKGLOBAL_BFP_VERSION', '1.1.2');
define('TECKGLOBAL_BFP_GEO_DIR', WP_CONTENT_DIR . '/teckglobal-geoip/');
define('TECKGLOBAL_BFP_GEO_FILE', TECKGLOBAL_BFP_GEO_DIR . 'GeoLite2-City.mmdb');

require_once TECKGLOBAL_BFP_PATH . 'includes/functions.php';

function teckglobal_bfp_debug(string $message): void {
    if (get_option('teckglobal_bfp_enable_logging', 0)) {
        $log_file = WP_CONTENT_DIR . '/teckglobal-bfp-debug.log';
        $timestamp = current_time('Y-m-d H:i:s');
        file_put_contents($log_file, "[$timestamp] $message\n", FILE_APPEND);
    }
}

function teckglobal_bfp_get_client_ip(): string {
    $ip = '0.0.0.0';
    $headers = [
        'HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED',
        'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED',
        'REMOTE_ADDR'
    ];

    foreach ($headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ip_list = explode(',', $_SERVER[$header]);
            $ip = trim($ip_list[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                static $logged_ip = null;
                if ($ip !== $logged_ip) {
                    teckglobal_bfp_debug("Client IP detected from $header: $ip");
                    $logged_ip = $ip;
                }
                break;
            }
        }
    }

    if ($ip === '0.0.0.0') {
        teckglobal_bfp_debug("Failed to detect valid client IP. Using fallback: $ip");
    }
    return $ip;
}

function teckglobal_bfp_login_failed($username) {
    $ip = teckglobal_bfp_get_client_ip();
    if (teckglobal_bfp_check_threat_feed($ip)) {
        teckglobal_bfp_ban_ip($ip, 'threat_feed');
        return;
    }
    teckglobal_bfp_log_attempt($ip);

    $max_attempts = (int) get_option('teckglobal_bfp_max_attempts', 5);
    $attempts = teckglobal_bfp_get_attempts($ip);

    if (!teckglobal_bfp_check_rate_limit($ip)) {
        teckglobal_bfp_debug("IP $ip rate-limited.");
        return;
    }

    if ($attempts >= $max_attempts) {
        teckglobal_bfp_ban_ip($ip, 'brute_force');
        teckglobal_bfp_debug("IP $ip banned for exceeding $max_attempts login attempts.");
        if (get_option('teckglobal_bfp_enable_notifications', 0)) {
            wp_mail(
                get_option('teckglobal_bfp_notification_email', get_option('admin_email')),
                'Brute Force Ban Notification',
                "IP $ip was banned after $attempts failed login attempts."
            );
        }
    }
}
add_action('wp_login_failed', 'teckglobal_bfp_login_failed');

function teckglobal_bfp_login_success($username) {
    $ip = teckglobal_bfp_get_client_ip();
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $row = $wpdb->get_row($wpdb->prepare("SELECT banned, ban_expiry FROM $table_name WHERE ip = %s", $ip));
    if ($row && $row->banned == 1 && $row->ban_expiry && current_time('mysql') < $row->ban_expiry) {
        teckglobal_bfp_debug("IP $ip is banned with active expiry; not resetting ban status");
    } else {
        $wpdb->update($table_name, ['attempts' => 0, 'banned' => 0, 'ban_expiry' => null, 'scan_exploit' => 0, 'brute_force' => 0, 'manual_ban' => 0], ['ip' => $ip]);
    }
}
add_action('wp_login', 'teckglobal_bfp_login_success');

function teckglobal_bfp_check_invalid_username($username, $password) {
    $ip = teckglobal_bfp_get_client_ip();
    $auto_ban_invalid = get_option('teckglobal_bfp_auto_ban_invalid', 0);

    if (!isset($_POST['log']) || empty($username)) {
        return;
    }

    if ($auto_ban_invalid && !username_exists($username) && !email_exists($username)) {
        teckglobal_bfp_log_attempt($ip);
        teckglobal_bfp_ban_ip($ip, 'brute_force');
        teckglobal_bfp_debug("IP $ip auto-banned for invalid username: $username");
    }
}
add_action('wp_authenticate', 'teckglobal_bfp_check_invalid_username', 10, 2);

function teckglobal_bfp_check_exploit_scans() {
    $ip = teckglobal_bfp_get_client_ip();
    $enable_exploit_protection = get_option('teckglobal_bfp_exploit_protection', 0);

    if (!$enable_exploit_protection || is_user_logged_in()) {
        return;
    }

    $request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
    $suspicious_patterns = [
        '/phpMyAdmin/i', '/adminer/i', '/wp-config\.php/i',
        '/xmlrpc\.php/i', '/\.env/i', '/admin/i', '/db/i', '/test/i'
    ];

    foreach ($suspicious_patterns as $pattern) {
        if (preg_match($pattern, $request_uri)) {
            teckglobal_bfp_log_attempt($ip);
            $max_attempts = (int) get_option('teckglobal_bfp_exploit_max_attempts', 3);
            $attempts = teckglobal_bfp_get_attempts($ip);

            if ($attempts >= $max_attempts) {
                teckglobal_bfp_ban_ip($ip, 'scan_exploit');
                teckglobal_bfp_debug("IP $ip banned for exceeding $max_attempts exploit scan attempts");
            }
            break;
        }
    }
}
add_action('init', 'teckglobal_bfp_check_exploit_scans', 2);

function teckglobal_bfp_block_banned_ips_login($user, $username, $password) {
    $ip = teckglobal_bfp_get_client_ip();
    if (teckglobal_bfp_is_ip_banned($ip)) {
        teckglobal_bfp_debug("Blocking banned IP $ip during authentication attempt");
        $block_message = get_option('teckglobal_bfp_block_message', 'Your IP has been banned due to suspicious activity. Please contact the site administrator.');
        wp_die($block_message, 'Access Denied', ['response' => 403]);
    }
    return $user;
}
add_filter('authenticate', 'teckglobal_bfp_block_banned_ips_login', 5, 3);

function teckglobal_bfp_block_banned_ips() {
    $ip = teckglobal_bfp_get_client_ip();
    if (teckglobal_bfp_is_ip_banned($ip) && strpos($_SERVER['REQUEST_URI'], 'wp-login.php') === false) {
        teckglobal_bfp_debug("Blocking banned IP $ip on non-login page");
        $block_message = get_option('teckglobal_bfp_block_message', 'Your IP has been banned due to suspicious activity. Please contact the site administrator.');
        wp_die($block_message, 'Access Denied', ['response' => 403]);
    }
}
add_action('init', 'teckglobal_bfp_block_banned_ips', 1);

function teckglobal_bfp_admin_menu() {
    add_menu_page('TeckGlobal BFP', 'Brute Force Protect', 'manage_options', 'teckglobal-bfp', 'teckglobal_bfp_settings_page', 'dashicons-shield', 80);
    add_submenu_page('teckglobal-bfp', 'Settings', 'Settings', 'manage_options', 'teckglobal-bfp', 'teckglobal_bfp_settings_page');
    add_submenu_page('teckglobal-bfp', 'Manage IPs', 'Manage IPs', 'manage_options', 'teckglobal-bfp-manage-ips', 'teckglobal_bfp_manage_ips_page');
    add_submenu_page('teckglobal-bfp', 'IP Logs & Map', 'IP Logs & Map', 'manage_options', 'teckglobal-bfp-ip-logs', 'teckglobal_bfp_ip_logs_page');
}
add_action('admin_menu', 'teckglobal_bfp_admin_menu');

function teckglobal_bfp_enqueue_admin_assets($hook) {
    if (strpos($hook, 'teckglobal-bfp') === false && $hook !== 'plugins.php' && $hook !== 'index.php') {
        return;
    }

    wp_enqueue_style('teckglobal-bfp-style', TECKGLOBAL_BFP_URL . 'assets/css/style.css', [], TECKGLOBAL_BFP_VERSION);
    wp_enqueue_script('jquery');

    $script_handle = 'teckglobal-bfp-script';
    wp_enqueue_script($script_handle, TECKGLOBAL_BFP_URL . 'assets/js/script.js', ['jquery'], TECKGLOBAL_BFP_VERSION, true);

    $auto_updates = (array) get_option('auto_update_plugins', []);
    $is_enabled = in_array('teckglobal-brute-force-protect/teckglobal-brute-force-protect.php', $auto_updates);
    $localize_data = [
        'ajax_url' => admin_url('admin-ajax.php'),
        'unban_nonce' => wp_create_nonce('teckglobal_bfp_unban_nonce'),
        'toggle_nonce' => wp_create_nonce('toggle-auto-update'),
        'plugin_slug' => 'teckglobal-brute-force-protect/teckglobal-brute-force-protect.php',
        'auto_update_status' => $is_enabled ? 'enabled' : 'disabled',
        'image_path' => TECKGLOBAL_BFP_URL . 'assets/css/images/',
        'captcha_enabled' => get_option('teckglobal_bfp_enable_captcha', 0),
        'captcha_site_key' => get_option('teckglobal_bfp_recaptcha_site_key', ''),
        'ip' => teckglobal_bfp_get_client_ip(),
        'is_banned' => teckglobal_bfp_is_ip_banned(teckglobal_bfp_get_client_ip()),
        'attempts_left' => teckglobal_bfp_get_attempts_left(teckglobal_bfp_get_client_ip())
    ];
    wp_localize_script($script_handle, 'teckglobal_bfp_ajax', $localize_data);

    if (strpos($hook, 'brute-force-protect_page_teckglobal-bfp-ip-logs') !== false) {
        wp_enqueue_style('leaflet-css', 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css', [], '1.9.4');
        wp_enqueue_script('leaflet-js', 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js', ['jquery'], '1.9.4', true);

        $fallback_script = "
            if (typeof L === 'undefined') {
                document.write('<link rel=\"stylesheet\" href=\"" . TECKGLOBAL_BFP_URL . "assets/css/leaflet.css\" />');
                document.write('<script src=\"" . TECKGLOBAL_BFP_URL . "assets/js/leaflet.js\"><\/script>');
                console.warn('Leaflet CDN failed; loaded local fallback at: ' + new Date().toISOString());
            } else {
                console.log('Leaflet CDN loaded successfully at: ' + new Date().toISOString());
            }
        ";
        wp_add_inline_script('leaflet-js', $fallback_script);

        // Localize locations data for the IP Logs & Map page
        $limit = isset($_GET['log_limit']) ? absint($_GET['log_limit']) : 10;
        $page = max(1, isset($_GET['log_page']) ? absint($_GET['log_page']) : 1);
        $data = teckglobal_bfp_get_ip_logs($limit, $page);
        $locations = array_map(function($log) {
            return [
                'lat' => floatval($log->latitude ?? 0),
                'lng' => floatval($log->longitude ?? 0),
                'ip' => esc_js($log->ip),
                'country' => esc_js($log->country),
                'user_agent' => esc_js($log->user_agent ?? 'Unknown')
            ];
        }, array_filter($data['logs'], fn($log) => $log->banned && $log->latitude && $log->longitude));
        wp_localize_script($script_handle, 'teckglobal_bfp_locations', array_values($locations)); // Convert to plain array
    }
}
add_action('admin_enqueue_scripts', 'teckglobal_bfp_enqueue_admin_assets');

function teckglobal_bfp_enqueue_login_assets() {
    wp_enqueue_style('teckglobal-bfp-style', TECKGLOBAL_BFP_URL . 'assets/css/style.css', [], TECKGLOBAL_BFP_VERSION);
    wp_enqueue_script('teckglobal-bfp-script', TECKGLOBAL_BFP_URL . 'assets/js/script.js', ['jquery'], TECKGLOBAL_BFP_VERSION, true);

    $localize_data = [
        'ajax_url' => admin_url('admin-ajax.php'),
        'captcha_enabled' => get_option('teckglobal_bfp_enable_captcha', 0),
        'captcha_site_key' => get_option('teckglobal_bfp_recaptcha_site_key', ''),
        'ip' => teckglobal_bfp_get_client_ip(),
        'is_banned' => teckglobal_bfp_is_ip_banned(teckglobal_bfp_get_client_ip()),
        'attempts_left' => teckglobal_bfp_get_attempts_left(teckglobal_bfp_get_client_ip())
    ];
    wp_localize_script('teckglobal-bfp-script', 'teckglobal_bfp_ajax', $localize_data);

    if (get_option('teckglobal_bfp_enable_captcha', 0)) {
        wp_enqueue_script('recaptcha', 'https://www.google.com/recaptcha/api.js', [], null, true);
    }
}
add_action('login_enqueue_scripts', 'teckglobal_bfp_enqueue_login_assets');

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
        user_agent VARCHAR(255) DEFAULT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY ip (ip)
    ) $charset_collate;";

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta($sql);

    update_option('teckglobal_bfp_geo_path', TECKGLOBAL_BFP_GEO_FILE);
    add_option('teckglobal_bfp_max_attempts', 5);
    add_option('teckglobal_bfp_ban_time', '60-minutes');
    add_option('teckglobal_bfp_auto_ban_invalid', 0);
    add_option('teckglobal_bfp_excluded_ips', []);
    add_option('teckglobal_bfp_exploit_protection', 0);
    add_option('teckglobal_bfp_exploit_max_attempts', 3);
    add_option('teckglobal_bfp_maxmind_key', '');
    add_option('teckglobal_bfp_remove_data', 0);
    add_option('teckglobal_bfp_enable_logging', 0);
    add_option('teckglobal_bfp_block_message', 'Your IP has been banned due to suspicious activity. Please contact the site administrator.');
    add_option('teckglobal_bfp_enable_debug_log', 0);
    add_option('teckglobal_bfp_whitelist_ips', '');
    add_option('teckglobal_bfp_enable_notifications', 0);
    add_option('teckglobal_bfp_notification_email', get_option('admin_email'));
    add_option('teckglobal_bfp_enable_captcha', 0);
    add_option('teckglobal_bfp_recaptcha_site_key', '');
    add_option('teckglobal_bfp_recaptcha_secret_key', '');
    add_option('teckglobal_bfp_enable_rate_limit', 0);
    add_option('teckglobal_bfp_rate_limit_attempts', 3);
    add_option('teckglobal_bfp_rate_limit_interval', 60);
    add_option('teckglobal_bfp_threat_feeds', ['abuseipdb' => 0, 'project_honeypot' => 0]);
    add_option('teckglobal_bfp_abuseipdb_key', '');
    add_option('teckglobal_bfp_project_honeypot_key', '');

    if (!wp_next_scheduled('teckglobal_bfp_initial_geoip_download')) {
        wp_schedule_single_event(time() + 10, 'teckglobal_bfp_initial_geoip_download');
    }

    if (!wp_next_scheduled('teckglobal_bfp_update_geoip')) {
        wp_schedule_event(strtotime('next Tuesday 01:00:00 UTC'), 'weekly', 'teckglobal_bfp_update_geoip');
        wp_schedule_event(strtotime('next Friday 01:00:00 UTC'), 'weekly', 'teckglobal_bfp_update_geoip');
    }
}
register_activation_hook(__FILE__, 'teckglobal_bfp_activate');

function teckglobal_bfp_initial_geoip_download() {
    teckglobal_bfp_download_geoip();
}
add_action('teckglobal_bfp_initial_geoip_download', 'teckglobal_bfp_initial_geoip_download');

function teckglobal_bfp_deactivate() {
    wp_clear_scheduled_hook('teckglobal_bfp_update_geoip');
    wp_clear_scheduled_hook('teckglobal_bfp_initial_geoip_download');

    if (get_option('teckglobal_bfp_remove_data', 0)) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
        $wpdb->query("DROP TABLE IF EXISTS $table_name");
        $options = [
            'teckglobal_bfp_geo_path', 'teckglobal_bfp_max_attempts', 'teckglobal_bfp_ban_time',
            'teckglobal_bfp_auto_ban_invalid', 'teckglobal_bfp_excluded_ips',
            'teckglobal_bfp_exploit_protection', 'teckglobal_bfp_exploit_max_attempts',
            'teckglobal_bfp_maxmind_key', 'teckglobal_bfp_remove_data', 'teckglobal_bfp_enable_logging',
            'teckglobal_bfp_block_message', 'teckglobal_bfp_enable_debug_log', 'teckglobal_bfp_whitelist_ips',
            'teckglobal_bfp_enable_notifications', 'teckglobal_bfp_notification_email', 'teckglobal_bfp_enable_captcha',
            'teckglobal_bfp_recaptcha_site_key', 'teckglobal_bfp_recaptcha_secret_key', 'teckglobal_bfp_enable_rate_limit',
            'teckglobal_bfp_rate_limit_attempts', 'teckglobal_bfp_rate_limit_interval', 'teckglobal_bfp_threat_feeds',
            'teckglobal_bfp_abuseipdb_key', 'teckglobal_bfp_project_honeypot_key'
        ];
        foreach ($options as $option) {
            delete_option($option);
        }
    }
}
register_deactivation_hook(__FILE__, 'teckglobal_bfp_deactivate');

function teckglobal_bfp_handle_settings_save() {
    if (!isset($_POST['submit']) || !isset($_POST['teckglobal_bfp_nonce']) || !current_user_can('manage_options')) {
        return;
    }

    if (!isset($_GET['page']) || $_GET['page'] !== 'teckglobal-bfp') {
        return;
    }

    teckglobal_bfp_debug("Nonce received: " . $_POST['teckglobal_bfp_nonce']);
    if (!wp_verify_nonce($_POST['teckglobal_bfp_nonce'], 'teckglobal_bfp_save_settings')) {
        teckglobal_bfp_debug("Nonce verification failed. Expected action: teckglobal_bfp_save_settings, Received nonce: " . $_POST['teckglobal_bfp_nonce']);
        wp_die('Nonce verification failed. Please try again.');
    }

    update_option('teckglobal_bfp_max_attempts', absint($_POST['max_attempts']));
    update_option('teckglobal_bfp_ban_time', sanitize_text_field($_POST['ban_time']));
    update_option('teckglobal_bfp_auto_ban_invalid', isset($_POST['auto_ban_invalid']) ? 1 : 0);

    $excluded_ips = [];
    if (isset($_POST['excluded_ip']) && is_array($_POST['excluded_ip'])) {
        foreach ($_POST['excluded_ip'] as $index => $ip) {
            $ip = sanitize_text_field($ip);
            $note = sanitize_text_field($_POST['excluded_note'][$index] ?? '');
            if (!empty($ip) && (filter_var($ip, FILTER_VALIDATE_IP) || preg_match('/^\d+\.\d+\.\d+\.\d+\/\d+$/', $ip))) {
                $excluded_ips[] = ['ip' => $ip, 'note' => $note];
            }
        }
    }
    update_option('teckglobal_bfp_excluded_ips', $excluded_ips);

    update_option('teckglobal_bfp_exploit_protection', isset($_POST['exploit_protection']) ? 1 : 0);
    update_option('teckglobal_bfp_exploit_max_attempts', absint($_POST['exploit_max_attempts']));
    update_option('teckglobal_bfp_maxmind_key', sanitize_text_field($_POST['maxmind_key']));
    update_option('teckglobal_bfp_remove_data', isset($_POST['remove_data']) ? 1 : 0);
    update_option('teckglobal_bfp_enable_logging', isset($_POST['enable_logging']) ? 1 : 0);
    update_option('teckglobal_bfp_block_message', sanitize_text_field($_POST['block_message']));
    update_option('teckglobal_bfp_enable_debug_log', isset($_POST['enable_debug_log']) ? 1 : 0);
    update_option('teckglobal_bfp_whitelist_ips', sanitize_textarea_field($_POST['whitelist_ips']));
    update_option('teckglobal_bfp_enable_notifications', isset($_POST['enable_notifications']) ? 1 : 0);
    update_option('teckglobal_bfp_notification_email', sanitize_email($_POST['notification_email']));
    update_option('teckglobal_bfp_enable_captcha', isset($_POST['enable_captcha']) ? 1 : 0);
    update_option('teckglobal_bfp_recaptcha_site_key', sanitize_text_field($_POST['recaptcha_site_key']));
    update_option('teckglobal_bfp_recaptcha_secret_key', sanitize_text_field($_POST['recaptcha_secret_key']));
    update_option('teckglobal_bfp_enable_rate_limit', isset($_POST['enable_rate_limit']) ? 1 : 0);
    update_option('teckglobal_bfp_rate_limit_attempts', absint($_POST['rate_limit_attempts']));
    update_option('teckglobal_bfp_rate_limit_interval', absint($_POST['rate_limit_interval']));
    $threat_feeds = [
        'abuseipdb' => isset($_POST['threat_feeds']['abuseipdb']) ? 1 : 0,
        'project_honeypot' => isset($_POST['threat_feeds']['project_honeypot']) ? 1 : 0
    ];
    update_option('teckglobal_bfp_threat_feeds', $threat_feeds);
    update_option('teckglobal_bfp_abuseipdb_key', sanitize_text_field($_POST['abuseipdb_key']));
    update_option('teckglobal_bfp_project_honeypot_key', sanitize_text_field($_POST['project_honeypot_key']));

    teckglobal_bfp_debug("Settings saved, preparing redirect");

    $redirect_url = add_query_arg(['page' => 'teckglobal-bfp', 'updated' => 'true'], admin_url('admin.php'));
    if (!headers_sent()) {
        wp_redirect($redirect_url);
        exit;
    } else {
        teckglobal_bfp_debug("Headers already sent, falling back to JavaScript redirect");
        echo "<script>window.location.href = '" . esc_url_raw($redirect_url) . "';</script>";
        exit;
    }
}
add_action('admin_init', 'teckglobal_bfp_handle_settings_save');

function teckglobal_bfp_settings_page() {
    if (!current_user_can('manage_options')) {
        wp_die('Unauthorized access');
    }

    if (isset($_POST['teckglobal_bfp_export_settings']) && check_admin_referer('teckglobal_bfp_export')) {
        teckglobal_bfp_export_settings();
    }
    if (isset($_FILES['import_file']) && isset($_POST['teckglobal_bfp_import_settings']) && check_admin_referer('teckglobal_bfp_import')) {
        teckglobal_bfp_import_settings();
    }

    $excluded_ips = get_option('teckglobal_bfp_excluded_ips', []);
    $threat_feeds = get_option('teckglobal_bfp_threat_feeds', ['abuseipdb' => 0, 'project_honeypot' => 0]);
    ?>
    <div class="wrap">
        <h1>TeckGlobal Brute Force Protect Settings</h1>
        <?php if (isset($_GET['updated']) && $_GET['updated'] === 'true') : ?>
            <div class="updated"><p>Settings saved.</p></div>
        <?php endif; ?>
        <form method="post" action="" enctype="multipart/form-data">
            <?php wp_nonce_field('teckglobal_bfp_save_settings', 'teckglobal_bfp_nonce'); ?>
            <h2>General Settings</h2>
            <table class="form-table">
                <tr>
                    <th>Max Login Attempts</th>
                    <td><input type="number" name="max_attempts" value="<?php echo esc_attr(get_option('teckglobal_bfp_max_attempts', 5)); ?>" min="1" /></td>
                </tr>
                <tr>
                    <th>Ban Duration</th>
                    <td>
                        <select name="ban_time">
                            <?php
                            $current_ban_time = get_option('teckglobal_bfp_ban_time', '60-minutes');
                            $options = [
                                '15-minutes' => '15 Minutes',
                                '30-minutes' => '30 Minutes',
                                '60-minutes' => '1 Hour',
                                '180-minutes' => '3 Hours',
                                '1440-minutes' => '1 Day',
                                '4320-minutes' => '3 Days',
                                '10080-minutes' => '1 Week',
                            ];
                            foreach ($options as $value => $label) {
                                $selected = $current_ban_time === $value ? 'selected' : '';
                                echo "<option value='$value' $selected>$label</option>";
                            }
                            ?>
                        </select>
                    </td>
                </tr>
                <tr>
                    <th>Auto-Ban Invalid Usernames</th>
                    <td><input type="checkbox" name="auto_ban_invalid" <?php checked(get_option('teckglobal_bfp_auto_ban_invalid', 0), 1); ?> /></td>
                </tr>
                <tr>
                    <th>Excluded IPs</th>
                    <td>
                        <table id="excluded-ips-table" class="widefat" style="max-width: 600px;">
                            <thead>
                                <tr>
                                    <th>IP or Subnet</th>
                                    <th>Note</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody id="excluded-ips-rows">
                                <?php
                                foreach ($excluded_ips as $index => $entry) {
                                    echo '<tr>';
                                    echo '<td><input type="text" name="excluded_ip[]" value="' . esc_attr($entry['ip']) . '" /></td>';
                                    echo '<td><input type="text" name="excluded_note[]" value="' . esc_attr($entry['note']) . '" /></td>';
                                    echo '<td><button type="button" class="button remove-row">Remove</button></td>';
                                    echo '</tr>';
                                }
                                ?>
                            </tbody>
                        </table>
                        <p><button type="button" id="add-excluded-ip" class="button">Add IP/Subnet</button></p>
                        <p><small>Enter one IP (e.g., 192.168.1.1) or CIDR subnet (e.g., 10.0.0.0/24) per row with an optional note.</small></p>
                    </td>
                </tr>
                <tr>
                    <th>Enable Exploit Protection</th>
                    <td><input type="checkbox" name="exploit_protection" <?php checked(get_option('teckglobal_bfp_exploit_protection', 0), 1); ?> /></td>
                </tr>
                <tr>
                    <th>Max Exploit Attempts</th>
                    <td><input type="number" name="exploit_max_attempts" value="<?php echo esc_attr(get_option('teckglobal_bfp_exploit_max_attempts', 3)); ?>" min="1" /></td>
                </tr>
                <tr>
                    <th>MaxMind License Key</th>
                    <td>
                        <input type="text" name="maxmind_key" value="<?php echo esc_attr(get_option('teckglobal_bfp_maxmind_key', '')); ?>" size="50" />
                        <p><small>Enter your MaxMind License Key for geolocation data. Get a free key at <a href="https://www.maxmind.com/en/geolite2/signup" target="_blank">MaxMind GeoLite2 Signup</a>.</small></p>
                    </td>
                </tr>
                <tr>
                    <th>Remove Data on Deactivation</th>
                    <td><input type="checkbox" name="remove_data" <?php checked(get_option('teckglobal_bfp_remove_data', 0), 1); ?> /> <small>(Drops table and options)</small></td>
                </tr>
                <tr>
                    <th>Enable Debug Logging</th>
                    <td><input type="checkbox" name="enable_logging" <?php checked(get_option('teckglobal_bfp_enable_logging', 0), 1); ?> /> <small>(Logs to wp-content/teckglobal-bfp-debug.log)</small></td>
                </tr>
                <tr>
                    <th>Block Message</th>
                    <td><input type="text" name="block_message" value="<?php echo esc_attr(get_option('teckglobal_bfp_block_message', 'Your IP has been banned due to suspicious activity. Please contact the site administrator.')); ?>" size="50" /></td>
                </tr>
                <tr>
                    <th>Enable Detailed Debug Log</th>
                    <td><input type="checkbox" name="enable_debug_log" <?php checked(get_option('teckglobal_bfp_enable_debug_log', 0), 1); ?> /> <small>(Logs detailed attempts to wp-content/teckglobal-bfp-detailed.log)</small></td>
                </tr>
                <tr>
                    <th>IP Whitelist</th>
                    <td><textarea name="whitelist_ips" rows="5" cols="50"><?php echo esc_textarea(get_option('teckglobal_bfp_whitelist_ips', '')); ?></textarea><br><small>Enter one IP per line to bypass brute force checks.</small></td>
                </tr>
            </table>

            <h2>Advanced Features</h2>
            <table class="form-table">
                <tr>
                    <th>Enable Notifications</th>
                    <td><input type="checkbox" name="enable_notifications" <?php checked(get_option('teckglobal_bfp_enable_notifications', 0), 1); ?> /></td>
                </tr>
                <tr>
                    <th>Notification Email</th>
                    <td><input type="email" name="notification_email" value="<?php echo esc_attr(get_option('teckglobal_bfp_notification_email', get_option('admin_email'))); ?>" size="50" /></td>
                </tr>
                <tr>
                    <th>Enable CAPTCHA</th>
                    <td>
                        <input type="checkbox" name="enable_captcha" <?php checked(get_option('teckglobal_bfp_enable_captcha', 0), 1); ?> />
                        <p><small>Adds Google reCAPTCHA v2 to the login form to block bots. Requires keys below. Get them at <a href="https://www.google.com/recaptcha" target="_blank">Google reCAPTCHA</a>.</small></p>
                    </td>
                </tr>
                <tr>
                    <th>reCAPTCHA Site Key</th>
                    <td>
                        <input type="text" name="recaptcha_site_key" value="<?php echo esc_attr(get_option('teckglobal_bfp_recaptcha_site_key', '')); ?>" size="50" />
                        <p><small>Your public reCAPTCHA key. Obtain it from <a href="https://www.google.com/recaptcha" target="_blank">Google reCAPTCHA</a> after registering your site.</small></p>
                    </td>
                </tr>
                <tr>
                    <th>reCAPTCHA Secret Key</th>
                    <td>
                        <input type="text" name="recaptcha_secret_key" value="<?php echo esc_attr(get_option('teckglobal_bfp_recaptcha_secret_key', '')); ?>" size="50" />
                        <p><small>Your private reCAPTCHA key. Find it at <a href="https://www.google.com/recaptcha" target="_blank">Google reCAPTCHA</a> in your admin console.</small></p>
                    </td>
                </tr>
                <tr>
                    <th>Enable Rate Limiting</th>
                    <td><input type="checkbox" name="enable_rate_limit" <?php checked(get_option('teckglobal_bfp_enable_rate_limit', 0), 1); ?> /></td>
                </tr>
                <tr>
                    <th>Rate Limit Attempts</th>
                    <td><input type="number" name="rate_limit_attempts" value="<?php echo esc_attr(get_option('teckglobal_bfp_rate_limit_attempts', 3)); ?>" min="1" /></td>
                </tr>
                <tr>
                    <th>Rate Limit Interval (seconds)</th>
                    <td><input type="number" name="rate_limit_interval" value="<?php echo esc_attr(get_option('teckglobal_bfp_rate_limit_interval', 60)); ?>" min="1" /></td>
                </tr>
                <tr>
                    <th>Enable Threat Feeds</th>
                    <td>
                        <label><input type="checkbox" name="threat_feeds[abuseipdb]" <?php checked($threat_feeds['abuseipdb'], 1); ?> /> AbuseIPDB</label><br>
                        <label><input type="checkbox" name="threat_feeds[project_honeypot]" <?php checked($threat_feeds['project_honeypot'], 1); ?> /> Project Honeypot</label>
                        <p><small>Select one or more threat feeds to check IPs against. Requires API keys below.</small></p>
                    </td>
                </tr>
                <tr>
                    <th>AbuseIPDB API Key</th>
                    <td>
                        <input type="text" name="abuseipdb_key" value="<?php echo esc_attr(get_option('teckglobal_bfp_abuseipdb_key', '')); ?>" size="50" />
                        <p><small>Get your free API key from <a href="https://www.abuseipdb.com/register" target="_blank">AbuseIPDB Register</a> to enable threat detection.</small></p>
                    </td>
                </tr>
                <tr>
                    <th>Project Honeypot API Key</th>
                    <td>
                        <input type="text" name="project_honeypot_key" value="<?php echo esc_attr(get_option('teckglobal_bfp_project_honeypot_key', '')); ?>" size="50" />
                        <p><small>Get your key from <a href="https://www.projecthoneypot.org/httpbl_configure.php" target="_blank">Project Honeypot</a>.</small></p>
                    </td>
                </tr>
            </table>

            <h2>Export/Import Settings</h2>
            <table class="form-table">
                <tr>
                    <th>Export Settings</th>
                    <td><input type="submit" name="teckglobal_bfp_export_settings" class="button" value="Export" /> <?php wp_nonce_field('teckglobal_bfp_export'); ?></td>
                </tr>
                <tr>
                    <th>Import Settings</th>
                    <td><input type="file" name="import_file" accept=".json" /> <input type="submit" name="teckglobal_bfp_import_settings" class="button" value="Import" /> <?php wp_nonce_field('teckglobal_bfp_import'); ?></td>
                </tr>
            </table>

            <p class="submit">
                <input type="submit" name="submit" class="button-primary" value="Save Changes" />
            </p>
        </form>
    </div>
    <?php
}

function teckglobal_bfp_dashboard_widget() {
    wp_add_dashboard_widget(
        'teckglobal_bfp_dashboard_widget',
        'Brute Force Protection Stats',
        'teckglobal_bfp_dashboard_widget_display'
    );
}

function teckglobal_bfp_dashboard_widget_display() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $today = current_time('Y-m-d');
    $blocked_today = $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM $table_name WHERE banned = 1 AND DATE(timestamp) = %s",
        $today
    ));
    $top_blocked = $wpdb->get_results("SELECT ip, attempts FROM $table_name WHERE banned = 1 ORDER BY attempts DESC LIMIT 5");
    ?>
    <p><strong>Blocked Attempts Today:</strong> <?php echo esc_html($blocked_today); ?></p>
    <p><strong>Top Blocked IPs:</strong></p>
    <ul>
        <?php foreach ($top_blocked as $ip) : ?>
            <li><?php echo esc_html($ip->ip) . ' (' . esc_html($ip->attempts) . ' attempts)'; ?></li>
        <?php endforeach; ?>
    </ul>
    <p><a href="<?php echo admin_url('admin.php?page=teckglobal-bfp'); ?>">View Settings</a></p>
    <?php
}
add_action('wp_dashboard_setup', 'teckglobal_bfp_dashboard_widget');

function teckglobal_bfp_auto_update_toggle($enabled, $plugin) {
    if (isset($plugin->plugin) && $plugin->plugin === 'teckglobal-brute-force-protect/teckglobal-brute-force-protect.php') {
        $auto_updates = (array) get_option('auto_update_plugins', []);
        return in_array('teckglobal-brute-force-protect/teckglobal-brute-force-protect.php', $auto_updates);
    }
    return $enabled;
}
add_filter('auto_update_plugin', 'teckglobal_bfp_auto_update_toggle', 10, 2);

function teckglobal_bfp_force_auto_update_ui($html, $plugin_file, $plugin_data) {
    if ($plugin_file === 'teckglobal-brute-force-protect/teckglobal-brute-force-protect.php') {
        $auto_updates = (array) get_option('auto_update_plugins', []);
        $is_enabled = in_array($plugin_file, $auto_updates);
        $action = $is_enabled ? 'disable' : 'enable';
        return sprintf(
            '<a href="#" class="teckglobal-bfp-toggle" data-action="%s" data-plugin="%s" aria-label="%s">%s</a>',
            esc_attr($action),
            esc_attr($plugin_file),
            esc_attr($is_enabled ? 'Disable auto-updates' : 'Enable auto-updates'),
            $is_enabled ? __('Disable auto-updates') : __('Enable auto-updates')
        );
    }
    return $html;
}
add_filter('plugin_auto_update_setting_html', 'teckglobal_bfp_force_auto_update_ui', 20, 3);

function teckglobal_bfp_toggle_auto_update() {
    check_ajax_referer('toggle-auto-update', '_wpnonce');
    if (!current_user_can('manage_options')) {
        wp_send_json_error(['message' => 'Insufficient permissions']);
    }

    $plugin = sanitize_text_field($_POST['plugin'] ?? '');
    $action = sanitize_text_field($_POST['toggle_action'] ?? '');

    if (empty($plugin) || $plugin !== 'teckglobal-brute-force-protect/teckglobal-brute-force-protect.php' || !in_array($action, ['enable', 'disable'])) {
        wp_send_json_error(['message' => 'Invalid request']);
    }

    $auto_updates = (array) get_option('auto_update_plugins', []);
    if ($action === 'enable' && !in_array($plugin, $auto_updates)) {
        $auto_updates[] = $plugin;
        update_option('auto_update_plugins', $auto_updates);
        wp_send_json_success(['status' => 'enabled', 'message' => 'Auto-updates enabled']);
    } elseif ($action === 'disable' && ($key = array_search($plugin, $auto_updates)) !== false) {
        unset($auto_updates[$key]);
        update_option('auto_update_plugins', array_values($auto_updates));
        wp_send_json_success(['status' => 'disabled', 'message' => 'Auto-updates disabled']);
    } else {
        wp_send_json_success(['status' => $action === 'enable' ? 'enabled' : 'disabled', 'message' => 'No change needed']);
    }
}
add_action('wp_ajax_toggle_auto_update_plugin', 'teckglobal_bfp_toggle_auto_update');

function teckglobal_bfp_fix_update_folder($upgrader, $data) {
    if ($data['type'] !== 'plugin' || !isset($data['plugins']) || !in_array('teckglobal-brute-force-protect/teckglobal-brute-force-protect.php', $data['plugins'])) {
        return;
    }

    $plugin_dir = WP_PLUGIN_DIR . '/teckglobal-brute-force-protect';
    $temp_dir = isset($upgrader->result['destination']) ? trailingslashit($upgrader->result['destination']) : '';

    teckglobal_bfp_debug("Update detected. Expected plugin dir: $plugin_dir");
    teckglobal_bfp_debug("Real temp dir from upgrader: $temp_dir");

    if ($temp_dir && file_exists($temp_dir) && $temp_dir !== $plugin_dir) {
        teckglobal_bfp_debug("Temp dir exists: $temp_dir");
        if (file_exists($plugin_dir)) {
            teckglobal_bfp_remove_dir($plugin_dir);
            teckglobal_bfp_debug("Removed old plugin directory: $plugin_dir");
        }
        if (rename($temp_dir, $plugin_dir)) {
            teckglobal_bfp_debug("Renamed updated folder from $temp_dir to $plugin_dir");
            activate_plugin('teckglobal-brute-force-protect/teckglobal-brute-force-protect.php');
            teckglobal_bfp_debug("Plugin reactivated successfully");
        } else {
            teckglobal_bfp_debug("Failed to rename $temp_dir to $plugin_dir. Check permissions.");
        }
    } else {
        teckglobal_bfp_debug("Temp dir not found or already correct: $temp_dir");
    }
}
add_action('upgrader_process_complete', 'teckglobal_bfp_fix_update_folder', 20, 2);

function teckglobal_bfp_check_github_updates($transient) {
    if (empty($transient->checked)) {
        return $transient;
    }

    $plugin_slug = 'teckglobal-brute-force-protect/teckglobal-brute-force-protect.php';
    $repo = 'teckglobal/teckglobal-brute-force-protect';
    $api_url = "https://api.github.com/repos/{$repo}/releases/latest";

    $response = wp_remote_get($api_url, [
        'headers' => ['User-Agent' => 'WordPress/TeckGlobal-BFP-' . TECKGLOBAL_BFP_VERSION],
        'timeout' => 15,
    ]);

    if (is_wp_error($response)) {
        teckglobal_bfp_debug("GitHub API error: " . $response->get_error_message());
        return $transient;
    }

    if (wp_remote_retrieve_response_code($response) !== 200) {
        teckglobal_bfp_debug("GitHub API returned non-200: " . wp_remote_retrieve_response_code($response));
        return $transient;
    }

    $release = json_decode(wp_remote_retrieve_body($response), true);
    if (!is_array($release) || empty($release['tag_name'])) {
        teckglobal_bfp_debug("GitHub API response invalid or missing tag_name");
        return $transient;
    }

    $version = ltrim($release['tag_name'], 'v');
    $current_version = TECKGLOBAL_BFP_VERSION;

    if (version_compare($version, $current_version, '>')) {
        $transient->response[$plugin_slug] = (object) [
            'id' => 'teckglobal-brute-force-protect',
            'slug' => 'teckglobal-brute-force-protect',
            'plugin' => $plugin_slug,
            'new_version' => $version,
            'url' => "https://github.com/{$repo}",
            'package' => $release['zipball_url'],
            'tested' => '6.7.2',
            'requires' => '5.0',
            'requires_php' => '7.4',
        ];
        teckglobal_bfp_debug("Update available: v$version");
    } else {
        $transient->no_update[$plugin_slug] = (object) [
            'id' => 'teckglobal-brute-force-protect',
            'slug' => 'teckglobal-brute-force-protect',
            'plugin' => $plugin_slug,
            'new_version' => $current_version,
            'url' => "https://github.com/{$repo}",
            'package' => null,
        ];
        teckglobal_bfp_debug("No update needed: v$current_version");
    }

    return $transient;
}
add_filter('pre_set_site_transient_update_plugins', 'teckglobal_bfp_check_github_updates', 10, 1);

function teckglobal_bfp_plugins_api_filter($result, $action, $args) {
    if ($action !== 'plugin_information' || empty($args->slug) || $args->slug !== 'teckglobal-brute-force-protect') {
        return $result;
    }

    $repo = 'teckglobal/teckglobal-brute-force-protect';
    $api_url = "https://api.github.com/repos/{$repo}/releases/latest";
    $response = wp_remote_get($api_url, [
        'headers' => ['User-Agent' => 'WordPress/TeckGlobal-BFP-' . TECKGLOBAL_BFP_VERSION],
        'timeout' => 15,
    ]);

    if (is_wp_error($response)) {
        teckglobal_bfp_debug("GitHub API request failed: " . $response->get_error_message());
        return $result;
    }

    $response_code = wp_remote_retrieve_response_code($response);
    if ($response_code !== 200) {
        $response_body = wp_remote_retrieve_body($response);
        teckglobal_bfp_debug("GitHub API returned non-200 status: $response_code. Response: $response_body");
        return $result;
    }

    $response_body = wp_remote_retrieve_body($response);
    $release = json_decode($response_body, true);

    if (!is_array($release)) {
        teckglobal_bfp_debug("GitHub API response is not a valid JSON array: $response_body");
        return $result;
    }

    if (isset($release['message'])) {
        teckglobal_bfp_debug("GitHub API error: " . $release['message']);
        return $result;
    }

    if (empty($release['tag_name']) || empty($release['zipball_url']) || empty($release['published_at'])) {
        teckglobal_bfp_debug("GitHub API response missing required fields: " . print_r($release, true));
        return $result;
    }

    $version = ltrim($release['tag_name'], 'v');
    return (object) [
        'name' => 'TeckGlobal Brute Force Protect',
        'slug' => 'teckglobal-brute-force-protect',
        'version' => $version,
        'author' => '<a href="https://teck-global.com/">TeckGlobal LLC</a>, <a href="https://x.ai/">xAI-Grok</a>',
        'download_link' => $release['zipball_url'],
        'trunk' => $release['zipball_url'],
        'requires' => '5.0',
        'tested' => '6.7.2',
        'requires_php' => '7.4',
        'last_updated' => $release['published_at'],
        'homepage' => 'https://teck-global.com/wordpress-plugins/',
        'sections' => [
            'description' => '<p><strong>TeckGlobal Brute Force Protect</strong> is a comprehensive security plugin designed to shield your WordPress site from brute force login attacks and malicious exploit scans. Developed by TeckGlobal LLC in collaboration with xAI\'s Grok, this free, open-source tool empowers you with advanced IP management, real-time geolocation tracking via MaxMind GeoLite2, and integration with multiple threat intelligence feeds (AbuseIPDB and Project Honeypot). Key features include a dashboard widget for quick stats, customizable block messages, visual login feedback, detailed debug logging, IP whitelisting, email notifications, Google reCAPTCHA v2 support, rate limiting, user agent tracking, and settings export/import capabilities.</p><p>Whether you\'re protecting a personal blog or a business site, this plugin offers robust, user-friendly security without compromising performance. Support our mission to keep WordPress secure by donating at <a href="https://teck-global.com/buy-me-a-coffee/" target="_blank">TeckGlobal\'s Buy Me a Coffee</a>.</p>',
            'installation' => '<ol><li><strong>Download</strong>: Grab the ZIP from <a href="https://github.com/teckglobal/teckglobal-brute-force-protect/releases" target="_blank">GitHub Releases</a> or WordPress.org.</li><li><strong>Install</strong>: Upload via <code>Plugins > Add New > Upload Plugin</code>, then activate.</li><li><strong>Configure</strong>: Visit <code>TeckGlobal BFP > Settings</code> to tailor options like login attempts, ban duration, and integrations.</li><li><strong>Optional Integrations</strong>: Add a <a href="https://www.maxmind.com/en/geolite2/signup" target="_blank">MaxMind License Key</a> for geolocation, <a href="https://www.google.com/recaptcha" target="_blank">reCAPTCHA keys</a> for CAPTCHA, or API keys from <a href="https://www.abuseipdb.com/register" target="_blank">AbuseIPDB</a> and <a href="https://www.projecthoneypot.org/httpbl_configure.php" target="_blank">Project Honeypot</a> for threat feeds.</li><li><strong>Monitor</strong>: Check the dashboard widget or <code>IP Logs & Map</code> for activity.</li></ol>',
            'features' => '<ul><li><strong>Brute Force Defense</strong>: Bans IPs after excessive login attempts (default: 5).</li><li><strong>Exploit Scan Protection</strong>: Blocks probes for sensitive files (e.g., <code>/wp-config.php</code>).</li><li><strong>Geolocation</strong>: Maps IPs with MaxMind GeoLite2 (optional key required).</li><li><strong>IP Management</strong>: Manual ban/unban, exclude subnets, whitelist IPs.</li><li><strong>Dashboard Widget</strong>: Real-time stats on blocked attempts.</li><li><strong>Custom Block Messages</strong>: Personalize messages for banned users.</li><li><strong>Visual Feedback</strong>: Login form shakes for banned IPs.</li><li><strong>Debug Logs</strong>: Detailed logs for troubleshooting.</li><li><strong>Notifications</strong>: Email alerts on bans.</li><li><strong>CAPTCHA</strong>: Google reCAPTCHA v2 integration.</li><li><strong>Rate Limiting</strong>: Limits login attempts in a time window.</li><li><strong>Threat Feeds</strong>: Auto-bans via AbuseIPDB and Project Honeypot.</li><li><strong>User Agent Logging</strong>: Tracks browser details.</li><li><strong>Settings Management</strong>: Export/import configurations.</li></ul>',
            'faq' => '<h4>How does it detect brute force attacks?</h4><p>It tracks failed login attempts per IP and bans them after exceeding your set limit (default: 5). Enable "Auto-Ban Invalid Usernames" to catch fake login attempts instantly.</p><h4>Can I customize the ban message?</h4><p>Yes! Set your own message in <code>Settings > Block Message</code>—it’s shown to banned IPs.</p><h4>What’s geolocation good for?</h4><p>With a MaxMind key, it maps IP locations on <code>IP Logs & Map</code>, helping you spot attack origins.</p><h4>How do threat feeds work?</h4><p>Enable AbuseIPDB or Project Honeypot in settings with API keys. They auto-ban IPs with high threat scores before they hit your limits.</p><h4>Why use CAPTCHA?</h4><p>It adds reCAPTCHA v2 to <code>wp-login.php</code>, stopping bots cold. Requires Google keys.</p><h4>What’s rate limiting?</h4><p>It caps login attempts within a time frame (e.g., 3 in 60 seconds), thwarting rapid attacks.</p><h4>Can I exclude my IP?</h4><p>Yes, add IPs or subnets to "Excluded IPs" or "IP Whitelist" to bypass checks.</p><h4>How do I monitor activity?</h4><p>Use the dashboard widget for daily stats or <code>IP Logs & Map</code> for detailed logs and a banned IP map.</p>',
            'changelog' => '<h4>1.1.2 - 2025-03-20</h4><ul><li>Enhanced settings page with detailed descriptions and links for AbuseIPDB, reCAPTCHA, and MaxMind.</li><li>Improved "View Details" popup with richer FAQ and full changelog.</li></ul><h4>1.1.1 - 2025-03-01</h4><ul><li>Added multiple threat feed support (AbuseIPDB and Project Honeypot) with settings selector.</li></ul><h4>1.1.0 - 2025-02-15</h4><ul><li>Introduced email notifications for ban events.</li><li>Added Google reCAPTCHA v2 support.</li><li>Implemented rate limiting for login attempts.</li><li>Integrated AbuseIPDB threat feed.</li><li>Enabled user agent logging.</li><li>Added settings export/import functionality.</li></ul><h4>1.0.3 - 2025-01-20</h4><ul><li>Added dashboard widget for quick stats.</li><li>Introduced customizable block messages.</li><li>Implemented visual login feedback (shake animation).</li><li>Added detailed debug log toggle.</li><li>Included IP whitelist feature.</li><li>Enhanced UI and documentation.</li></ul><h4>1.0.2 - 2024-12-15</h4><ul><li>Improved GeoIP download stability.</li><li>Fixed auto-update toggle UI.</li></ul><h4>1.0.1 - 2024-11-30</h4><ul><li>Added exploit scan protection.</li><li>Optimized database queries.</li></ul><h4>1.0.0 - 2024-11-01</h4><ul><li>Initial release with brute force protection and geolocation.</li></ul>',
            'screenshots' => '<ol><li><strong>Settings Page</strong><br><img src="' . TECKGLOBAL_BFP_URL . 'assets/css/images/screenshot1.webp" alt="Settings Page" style="max-width:100%;"></li><li><strong>Manage IPs</strong><br><img src="' . TECKGLOBAL_BFP_URL . 'assets/css/images/screenshot2.webp" alt="Manage IPs" style="max-width:100%;"></li><li><strong>IP Logs & Map</strong><br><img src="' . TECKGLOBAL_BFP_URL . 'assets/css/images/screenshot3.webp" alt="IP Logs & Map" style="max-width:100%;"></li></ol>',
        ],
        'banners' => [
            'low' => TECKGLOBAL_BFP_URL . 'assets/css/images/banner-772x250.jpg',
            'high' => TECKGLOBAL_BFP_URL . 'assets/css/images/banner-1544x500.jpg'
        ],
        'icons' => [
            '1x' => TECKGLOBAL_BFP_URL . 'assets/css/images/icon-128x128.jpg',
            '2x' => TECKGLOBAL_BFP_URL . 'assets/css/images/icon-256x256.jpg'
        ],
        'donate_link' => 'https://teck-global.com/buy-me-a-coffee/'
    ];
}
add_filter('plugins_api', 'teckglobal_bfp_plugins_api_filter', 10, 3);
