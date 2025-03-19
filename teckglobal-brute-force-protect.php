<?php
/*
 * Plugin Name: TeckGlobal Brute Force Protect
 * Author: TeckGlobal LLC, xAI-Grok
 * Author URI: https://teck-global.com/
 * Plugin URI: https://teck-global.com/wordpress-plugins/
 * Description: A WordPress plugin by TeckGlobal LLC to prevent brute force login attacks and exploit scans with IP management and geolocation features. If you enjoy this free product please donate at https://teck-global.com/buy-me-a-coffee/
 * Version: 1.0.2
 * License: GPL-2.0+
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain: teckglobal-brute-force-protect
 * Requires at least: 5.0
 * Tested up to: 6.7
 * Requires PHP: 7.4 or later
 * WordPress Available: yes
 * Requires License: no
 */

if (!defined('ABSPATH')) {
    exit;
}

define('TECKGLOBAL_BFP_PATH', plugin_dir_path(__FILE__));
define('TECKGLOBAL_BFP_URL', plugin_dir_url(__FILE__));
define('TECKGLOBAL_BFP_VERSION', '1.0.2');
define('TECKGLOBAL_BFP_GEO_DIR', WP_CONTENT_DIR . '/teckglobal-geoip/');
define('TECKGLOBAL_BFP_GEO_FILE', TECKGLOBAL_BFP_GEO_DIR . 'GeoLite2-City.mmdb');

require_once TECKGLOBAL_BFP_PATH . 'includes/functions.php';

function teckglobal_bfp_debug(string $message): void {
    if (get_option('teckglobal_bfp_enable_logging', 0) && (is_admin() || defined('DOING_CRON') || defined('DOING_AJAX'))) {
        $log_file = WP_CONTENT_DIR . '/teckglobal-bfp-debug.log';
        $timestamp = current_time('Y-m-d H:i:s');
        file_put_contents($log_file, "[$timestamp] $message\n", FILE_APPEND);
    }
}

global $wpdb;
if (is_admin() || defined('DOING_CRON') || defined('DOING_AJAX')) {
    teckglobal_bfp_debug("Database table prefix: " . $wpdb->prefix);
    teckglobal_bfp_debug("Checking auto_update_plugins option: " . json_encode(get_option('auto_update_plugins', 'Not set')));
}

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
        teckglobal_bfp_debug("Username '$username' is valid or auto-ban is disabled; no action taken");
    }
}
add_action('wp_authenticate', 'teckglobal_bfp_check_invalid_username', 10, 2);

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

function teckglobal_bfp_enqueue_admin_assets($hook) {
    teckglobal_bfp_debug("Enqueue hook triggered with value: $hook");

    if (strpos($hook, 'teckglobal-bfp') === false && $hook !== 'plugins.php') {
        teckglobal_bfp_debug("Hook $hook does not match teckglobal-bfp or plugins.php; skipping enqueue");
        return;
    }

    wp_enqueue_style('teckglobal-bfp-style', TECKGLOBAL_BFP_URL . 'assets/css/style.css', [], TECKGLOBAL_BFP_VERSION);

    wp_enqueue_script('jquery');

    wp_enqueue_script('teckglobal-bfp-script', TECKGLOBAL_BFP_URL . 'assets/js/script.js', ['jquery'], TECKGLOBAL_BFP_VERSION, true);
    teckglobal_bfp_debug("Plugin script enqueued with jQuery dependency");

    $auto_updates = (array) get_option('auto_update_plugins', []);
    $is_enabled = in_array('teckglobal-brute-force-protect/teckglobal-brute-force-protect.php', $auto_updates);
    $localize_data = [
        'ajax_url' => admin_url('admin-ajax.php'),
        'unban_nonce' => wp_create_nonce('teckglobal_bfp_unban_nonce'),
        'toggle_nonce' => wp_create_nonce('toggle-auto-update'),
        'plugin_slug' => 'teckglobal-brute-force-protect/teckglobal-brute-force-protect.php',
        'auto_update_status' => $is_enabled ? 'enabled' : 'disabled',
        'image_path' => TECKGLOBAL_BFP_URL . 'assets/css/images/'
    ];
    wp_localize_script('teckglobal-bfp-script', 'teckglobal_bfp_ajax', $localize_data);
    teckglobal_bfp_debug("Localized teckglobal_bfp_ajax for hook $hook: " . json_encode($localize_data));

    if (strpos($hook, 'brute-force-protect_page_teckglobal-bfp-ip-logs') !== false) {
        teckglobal_bfp_debug("Loading Leaflet assets for IP Logs & Map page: $hook");
        wp_enqueue_style('leaflet-css', 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css', [], '1.9.4');
        wp_enqueue_script('leaflet-js', 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js', ['jquery'], '1.9.4', true);
        wp_add_inline_script('leaflet-js', 'console.log("Leaflet JS loaded at: " + new Date().toISOString() + "; L defined: " + (typeof L !== "undefined"));');
        wp_enqueue_script('teckglobal-bfp-script', TECKGLOBAL_BFP_URL . 'assets/js/script.js', ['jquery', 'leaflet-js'], TECKGLOBAL_BFP_VERSION, true);
        wp_localize_script('teckglobal-bfp-script', 'teckglobal_bfp_ajax', $localize_data);
        teckglobal_bfp_debug("Re-enqueued script with Leaflet dependency and re-localized");
    }
}
add_action('admin_enqueue_scripts', 'teckglobal_bfp_enqueue_admin_assets');

function teckglobal_bfp_ajax_unban_ip() {
    check_ajax_referer('teckglobal_bfp_unban_nonce', 'nonce');

    if (!current_user_can('manage_options')) {
        teckglobal_bfp_debug("Unban failed: Insufficient permissions");
        wp_send_json_error(['message' => 'Insufficient permissions']);
    }

    $ip = sanitize_text_field($_POST['ip']);
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        teckglobal_bfp_debug("Unban failed: Invalid IP address - $ip");
        wp_send_json_error(['message' => 'Invalid IP address']);
    }

    teckglobal_bfp_debug("Attempting to unban IP: $ip");
    teckglobal_bfp_unban_ip($ip);
    teckglobal_bfp_debug("IP $ip unbanned successfully");
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
        PRIMARY KEY (id),
        UNIQUE KEY ip (ip)
    ) $charset_collate;";

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta($sql);
    teckglobal_bfp_debug("Activation: Created or updated table $table_name");

    update_option('teckglobal_bfp_geo_path', TECKGLOBAL_BFP_GEO_FILE);
    add_option('teckglobal_bfp_max_attempts', 5);
    add_option('teckglobal_bfp_ban_time', 60);
    add_option('teckglobal_bfp_auto_ban_invalid', 0);
    add_option('teckglobal_bfp_excluded_ips', '');
    add_option('teckglobal_bfp_exploit_protection', 0);
    add_option('teckglobal_bfp_exploit_max_attempts', 3);
    add_option('teckglobal_bfp_maxmind_key', '');
    add_option('teckglobal_bfp_remove_data', 0);
    add_option('teckglobal_bfp_enable_logging', 0);

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
    ob_start();
    teckglobal_bfp_download_geoip();
    $output = ob_get_clean();
    if (!empty($output)) {
        teckglobal_bfp_debug("Initial GeoIP download output: $output");
    }
}
add_action('teckglobal_bfp_initial_geoip_download', 'teckglobal_bfp_initial_geoip_download');

function teckglobal_bfp_deactivate() {
    wp_clear_scheduled_hook('teckglobal_bfp_update_geoip');
    wp_clear_scheduled_hook('teckglobal_bfp_initial_geoip_download');

    if (get_option('teckglobal_bfp_remove_data', 0)) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
        $wpdb->query("DROP TABLE IF EXISTS $table_name");
        teckglobal_bfp_debug("Deactivation: Dropped table $table_name");

        $options = [
            'teckglobal_bfp_geo_path',
            'teckglobal_bfp_max_attempts',
            'teckglobal_bfp_ban_time',
            'teckglobal_bfp_auto_ban_invalid',
            'teckglobal_bfp_excluded_ips',
            'teckglobal_bfp_exploit_protection',
            'teckglobal_bfp_exploit_max_attempts',
            'teckglobal_bfp_maxmind_key',
            'teckglobal_bfp_remove_data',
            'teckglobal_bfp_enable_logging'
        ];
        foreach ($options as $option) {
            delete_option($option);
            teckglobal_bfp_debug("Deactivation: Deleted option $option");
        }
    }
}
register_deactivation_hook(__FILE__, 'teckglobal_bfp_deactivate');

function teckglobal_bfp_settings_page() {
    if (!current_user_can('manage_options')) {
        wp_die('Unauthorized access');
    }

    if (isset($_POST['teckglobal_bfp_settings_save']) && check_admin_referer('teckglobal_bfp_settings')) {
        update_option('teckglobal_bfp_max_attempts', absint($_POST['max_attempts']));
        update_option('teckglobal_bfp_ban_time', absint($_POST['ban_time']));
        update_option('teckglobal_bfp_auto_ban_invalid', isset($_POST['auto_ban_invalid']) ? 1 : 0);
        update_option('teckglobal_bfp_excluded_ips', sanitize_textarea_field($_POST['excluded_ips']));
        update_option('teckglobal_bfp_exploit_protection', isset($_POST['exploit_protection']) ? 1 : 0);
        update_option('teckglobal_bfp_exploit_max_attempts', absint($_POST['exploit_max_attempts']));
        update_option('teckglobal_bfp_maxmind_key', sanitize_text_field($_POST['maxmind_key']));
        update_option('teckglobal_bfp_remove_data', isset($_POST['remove_data']) ? 1 : 0);
        update_option('teckglobal_bfp_enable_logging', isset($_POST['enable_logging']) ? 1 : 0);
        echo '<div class="updated"><p>Settings saved.</p></div>';
    }

    ?>
    <div class="wrap">
        <h1>TeckGlobal Brute Force Protect Settings</h1>
        <form method="post" action="">
            <?php wp_nonce_field('teckglobal_bfp_settings'); ?>
            <table class="form-table">
                <tr>
                    <th>Max Login Attempts</th>
                    <td><input type="number" name="max_attempts" value="<?php echo esc_attr(get_option('teckglobal_bfp_max_attempts', 5)); ?>" min="1" /></td>
                </tr>
                <tr>
                    <th>Ban Time (minutes)</th>
                    <td><input type="number" name="ban_time" value="<?php echo esc_attr(get_option('teckglobal_bfp_ban_time', 60)); ?>" min="1" /></td>
                </tr>
                <tr>
                    <th>Auto-Ban Invalid Usernames</th>
                    <td><input type="checkbox" name="auto_ban_invalid" <?php checked(get_option('teckglobal_bfp_auto_ban_invalid', 0), 1); ?> /></td>
                </tr>
                <tr>
                    <th>Excluded IPs (one per line)</th>
                    <td><textarea name="excluded_ips" rows="5" cols="50"><?php echo esc_textarea(get_option('teckglobal_bfp_excluded_ips', '')); ?></textarea></td>
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
                    <td><input type="text" name="maxmind_key" value="<?php echo esc_attr(get_option('teckglobal_bfp_maxmind_key', '')); ?>" size="50" /></td>
                </tr>
                <tr>
                    <th>Remove Data on Deactivation</th>
                    <td><input type="checkbox" name="remove_data" <?php checked(get_option('teckglobal_bfp_remove_data', 0), 1); ?> /> <small>(Drops table and options)</small></td>
                </tr>
                <tr>
                    <th>Enable Debug Logging</th>
                    <td><input type="checkbox" name="enable_logging" <?php checked(get_option('teckglobal_bfp_enable_logging', 0), 1); ?> /> <small>(Logs to wp-content/teckglobal-bfp-debug.log)</small></td>
                </tr>
            </table>
            <p class="submit">
                <input type="submit" name="teckglobal_bfp_settings_save" class="button-primary" value="Save Changes" />
            </p>
        </form>
    </div>
    <?php
}

function teckglobal_bfp_auto_update_toggle($enabled, $plugin) {
    teckglobal_bfp_debug("Auto-update filter called with plugin: " . (isset($plugin->plugin) ? $plugin->plugin : 'unknown'));
    if (isset($plugin->plugin) && $plugin->plugin === 'teckglobal-brute-force-protect/teckglobal-brute-force-protect.php') {
        $auto_updates = (array) get_option('auto_update_plugins', []);
        $is_enabled = in_array('teckglobal-brute-force-protect/teckglobal-brute-force-protect.php', $auto_updates);
        teckglobal_bfp_debug("Auto-update status for TeckGlobal BFP: " . ($is_enabled ? 'Enabled' : 'Disabled'));
        return $is_enabled;
    }
    return $enabled;
}
add_filter('auto_update_plugin', 'teckglobal_bfp_auto_update_toggle', 10, 2);

function teckglobal_bfp_force_auto_update_ui($html, $plugin_file, $plugin_data) {
    if ($plugin_file === 'teckglobal-brute-force-protect/teckglobal-brute-force-protect.php') {
        $auto_updates = (array) get_option('auto_update_plugins', []);
        $is_enabled = in_array($plugin_file, $auto_updates);
        $action = $is_enabled ? 'disable' : 'enable';
        $toggle_html = sprintf(
            '<a href="#" class="teckglobal-bfp-toggle" data-action="%s" data-plugin="%s" aria-label="%s">%s</a>',
            esc_attr($action),
            esc_attr($plugin_file),
            esc_attr($is_enabled ? 'Disable auto-updates' : 'Enable auto-updates'),
            $is_enabled ? __('Disable auto-updates') : __('Enable auto-updates')
        );
        teckglobal_bfp_debug("Rendering auto-update UI for TeckGlobal BFP: " . ($is_enabled ? 'Enabled' : 'Disabled') . " - HTML: $toggle_html");
        return $toggle_html;
    }
    return $html;
}
add_filter('plugin_auto_update_setting_html', 'teckglobal_bfp_force_auto_update_ui', 20, 3);

function teckglobal_bfp_toggle_auto_update() {
    teckglobal_bfp_debug("Toggle AJAX raw POST data: " . json_encode($_POST));

    check_ajax_referer('toggle-auto-update', '_wpnonce');

    if (!current_user_can('manage_options')) {
        teckglobal_bfp_debug("Toggle failed: Insufficient permissions");
        wp_send_json_error(['message' => 'Insufficient permissions']);
    }

    $plugin = isset($_POST['plugin']) ? sanitize_text_field($_POST['plugin']) : '';
    $action = isset($_POST['toggle_action']) ? sanitize_text_field($_POST['toggle_action']) : '';

    teckglobal_bfp_debug("Toggle AJAX triggered with plugin: '$plugin', action: '$action'");

    if (empty($plugin)) {
        teckglobal_bfp_debug("Toggle failed: No plugin specified");
        wp_send_json_error(['message' => 'Invalid data: No plugin specified']);
    }

    if (empty($action) || !in_array($action, ['enable', 'disable'])) {
        teckglobal_bfp_debug("Toggle failed: Invalid or missing action - '$action'");
        wp_send_json_error(['message' => 'Invalid data: Invalid or missing action']);
    }

    if ($plugin !== 'teckglobal-brute-force-protect/teckglobal-brute-force-protect.php') {
        teckglobal_bfp_debug("Toggle failed: Invalid plugin - '$plugin'");
        wp_send_json_error(['message' => 'Invalid plugin']);
    }

    $auto_updates = (array) get_option('auto_update_plugins', []);

    if ($action === 'enable') {
        if (!in_array($plugin, $auto_updates)) {
            $auto_updates[] = $plugin;
            update_option('auto_update_plugins', $auto_updates);
            teckglobal_bfp_debug("Enabled auto-updates for $plugin");
            wp_send_json_success(['status' => 'enabled', 'message' => 'Auto-updates enabled']);
        }
        teckglobal_bfp_debug("Toggle: No change needed - $plugin already enabled");
        wp_send_json_success(['status' => 'enabled', 'message' => 'Auto-updates already enabled']);
    } elseif ($action === 'disable') {
        $key = array_search($plugin, $auto_updates);
        if ($key !== false) {
            unset($auto_updates[$key]);
            update_option('auto_update_plugins', array_values($auto_updates));
            teckglobal_bfp_debug("Disabled auto-updates for $plugin");
            wp_send_json_success(['status' => 'disabled', 'message' => 'Auto-updates disabled']);
        }
        teckglobal_bfp_debug("Toggle: No change needed - $plugin already disabled");
        wp_send_json_success(['status' => 'disabled', 'message' => 'Auto-updates already disabled']);
    }
}
add_action('wp_ajax_toggle_auto_update_plugin', 'teckglobal_bfp_toggle_auto_update');