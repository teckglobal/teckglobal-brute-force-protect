<?php
/**
 * TeckGlobal Brute Force Protect - Helper Functions
 *
 * This file contains utility functions for the TeckGlobal Brute Force Protect plugin.
 * It handles IP logging, banning, GeoIP lookups, and admin page logic (except settings, which is in the main file).
 */

if (!defined('ABSPATH')) {
    exit;
}

require_once TECKGLOBAL_BFP_PATH . 'vendor/autoload.php';
use GeoIp2\Database\Reader;

function teckglobal_bfp_log_attempt(string $ip): void {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';

    if (teckglobal_bfp_is_ip_excluded($ip) || teckglobal_bfp_is_ip_whitelisted($ip)) {
        return;
    }

    $geo_path = get_option('teckglobal_bfp_geo_path', TECKGLOBAL_BFP_GEO_FILE);
    $country = 'Unknown';
    $latitude = null;
    $longitude = null;

    if (!empty($geo_path) && file_exists($geo_path)) {
        try {
            $reader = new Reader($geo_path);
            $record = $reader->city($ip);
            $country = $record->country->name ?? 'Unknown';
            $latitude = $record->location->latitude ?? null;
            $longitude = $record->location->longitude ?? null;
        } catch (Exception $e) {
            teckglobal_bfp_debug("GeoIP lookup failed for IP $ip: " . $e->getMessage());
        }
    }

    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table_name WHERE ip = %s", $ip));
    if ($row) {
        $attempts = $row->attempts + 1;
        $wpdb->update(
            $table_name,
            [
                'attempts' => $attempts,
                'timestamp' => current_time('mysql'),
                'country' => $country,
                'latitude' => $latitude,
                'longitude' => $longitude,
                'user_agent' => $user_agent
            ],
            ['ip' => $ip]
        );
        teckglobal_bfp_debug("Updated attempt count for IP $ip: $attempts");
        teckglobal_bfp_detailed_log($ip, 'attempt', "Attempt #$attempts recorded, User-Agent: $user_agent");
    } else {
        $wpdb->insert(
            $table_name,
            [
                'ip' => $ip,
                'timestamp' => current_time('mysql'),
                'attempts' => 1,
                'banned' => 0,
                'country' => $country,
                'latitude' => $latitude,
                'longitude' => $longitude,
                'scan_exploit' => 0,
                'brute_force' => 0,
                'manual_ban' => 0,
                'user_agent' => $user_agent
            ]
        );
        teckglobal_bfp_debug("Logged first attempt for IP $ip");
        teckglobal_bfp_detailed_log($ip, 'attempt', "First attempt recorded, User-Agent: $user_agent");
    }
}

function teckglobal_bfp_get_attempts(string $ip): int {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $row = $wpdb->get_row($wpdb->prepare("SELECT attempts FROM $table_name WHERE ip = %s", $ip));
    return $row ? (int) $row->attempts : 0;
}

function teckglobal_bfp_get_attempts_left(string $ip): int {
    $max_attempts = (int) get_option('teckglobal_bfp_max_attempts', 5);
    $attempts = teckglobal_bfp_get_attempts($ip);
    return max(0, $max_attempts - $attempts);
}

function teckglobal_bfp_ban_ip(string $ip, string $reason = 'manual'): void {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $ban_time = get_option('teckglobal_bfp_ban_time', '60-minutes');

    list($value, $unit) = explode('-', $ban_time);
    $value = (int) $value;
    $interval = ($unit === 'minutes') ? "$value minutes" : "60 minutes";
    $ban_expiry = date('Y-m-d H:i:s', strtotime("+$interval"));

    if (teckglobal_bfp_is_ip_excluded($ip) || teckglobal_bfp_is_ip_whitelisted($ip)) {
        return;
    }

    $geo_path = get_option('teckglobal_bfp_geo_path', TECKGLOBAL_BFP_GEO_FILE);
    $country = 'Unknown';
    $latitude = null;
    $longitude = null;

    if (!empty($geo_path) && file_exists($geo_path)) {
        try {
            $reader = new Reader($geo_path);
            $record = $reader->city($ip);
            $country = $record->country->name ?? 'Unknown';
            $latitude = $record->location->latitude ?? null;
            $longitude = $record->location->longitude ?? null;
        } catch (Exception $e) {
            teckglobal_bfp_debug("GeoIP lookup failed for banned IP $ip: " . $e->getMessage());
        }
    }

    $scan_exploit = ($reason === 'scan_exploit') ? 1 : 0;
    $brute_force = ($reason === 'brute_force') ? 1 : 0;
    $manual_ban = ($reason === 'manual') ? 1 : 0;
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';

    $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table_name WHERE ip = %s", $ip));
    if ($row) {
        $wpdb->update(
            $table_name,
            [
                'banned' => 1,
                'ban_expiry' => $ban_expiry,
                'country' => $country,
                'latitude' => $latitude,
                'longitude' => $longitude,
                'scan_exploit' => $scan_exploit,
                'brute_force' => $brute_force,
                'manual_ban' => $manual_ban,
                'user_agent' => $user_agent
            ],
            ['ip' => $ip]
        );
    } else {
        $wpdb->insert(
            $table_name,
            [
                'ip' => $ip,
                'timestamp' => current_time('mysql'),
                'attempts' => 1,
                'banned' => 1,
                'ban_expiry' => $ban_expiry,
                'country' => $country,
                'latitude' => $latitude,
                'longitude' => $longitude,
                'scan_exploit' => $scan_exploit,
                'brute_force' => $brute_force,
                'manual_ban' => $manual_ban,
                'user_agent' => $user_agent
            ]
        );
    }
    teckglobal_bfp_debug("IP $ip banned until $ban_expiry for reason: $reason");
    teckglobal_bfp_detailed_log($ip, 'banned', "Banned until $ban_expiry for $reason, User-Agent: $user_agent");
}

function teckglobal_bfp_unban_ip(string $ip): void {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $wpdb->update(
        $table_name,
        ['banned' => 0, 'ban_expiry' => null, 'attempts' => 0],
        ['ip' => $ip]
    );
    teckglobal_bfp_debug("IP $ip unbanned");
    teckglobal_bfp_detailed_log($ip, 'unbanned', "IP unbanned");
}

function teckglobal_bfp_is_ip_banned(string $ip): bool {
    if (teckglobal_bfp_is_ip_excluded($ip) || teckglobal_bfp_is_ip_whitelisted($ip)) {
        return false;
    }
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $row = $wpdb->get_row($wpdb->prepare("SELECT banned, ban_expiry FROM $table_name WHERE ip = %s", $ip));
    if ($row && $row->banned == 1) {
        if ($row->ban_expiry && current_time('mysql') > $row->ban_expiry) {
            teckglobal_bfp_unban_ip($ip);
            teckglobal_bfp_debug("IP $ip ban expired, unbanned.");
            return false;
        }
        return true;
    }
    return false;
}

function teckglobal_bfp_is_ip_excluded(string $ip): bool {
    static $last_excluded_ip = null;
    static $last_result = null;

    if ($ip === $last_excluded_ip) {
        return $last_result;
    }

    $excluded_ips = get_option('teckglobal_bfp_excluded_ips', []);
    if (empty($excluded_ips) || !is_array($excluded_ips)) {
        $last_excluded_ip = $ip;
        $last_result = false;
        return false;
    }

    foreach ($excluded_ips as $entry) {
        $excluded = $entry['ip'];
        if (strpos($excluded, '/')) {
            list($subnet, $mask) = explode('/', $excluded);
            if (ip2long($ip) & ~((1 << (32 - $mask)) - 1) === ip2long($subnet)) {
                $last_excluded_ip = $ip;
                $last_result = true;
                return true;
            }
        } elseif ($ip === $excluded) {
            $last_excluded_ip = $ip;
            $last_result = true;
            return true;
        }
    }
    $last_excluded_ip = $ip;
    $last_result = false;
    return false;
}

function teckglobal_bfp_is_ip_whitelisted(string $ip): bool {
    $whitelist = array_filter(explode("\n", trim(get_option('teckglobal_bfp_whitelist_ips', ''))));
    return in_array($ip, $whitelist);
}

function teckglobal_bfp_detailed_log(string $ip, string $type, string $message): void {
    if (get_option('teckglobal_bfp_enable_debug_log', 0)) {
        $log_file = WP_CONTENT_DIR . '/teckglobal-bfp-detailed.log';
        $timestamp = current_time('Y-m-d H:i:s');
        $log_entry = "[$timestamp] IP: $ip - Type: $type - $message\n";
        file_put_contents($log_file, $log_entry, FILE_APPEND);
    }
}

function teckglobal_bfp_remove_dir(string $dir): bool {
    if (!is_dir($dir)) {
        return true;
    }
    $items = scandir($dir);
    if ($items === false) {
        teckglobal_bfp_debug("Failed to scan dir $dir for removal");
        return false;
    }
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        $path = "$dir/$item";
        if (is_dir($path)) {
            teckglobal_bfp_remove_dir($path);
        } else {
            unlink($path);
        }
    }
    return rmdir($dir);
}

function teckglobal_bfp_download_geoip(): void {
    $geo_dir = TECKGLOBAL_BFP_GEO_DIR;
    $geo_file = TECKGLOBAL_BFP_GEO_FILE;
    $api_key = get_option('teckglobal_bfp_maxmind_key', '');

    if (empty($api_key)) {
        teckglobal_bfp_debug("MaxMind API key not set; skipping GeoIP download");
        return;
    }

    if (!file_exists($geo_dir) && !mkdir($geo_dir, 0755, true)) {
        teckglobal_bfp_debug("Failed to create directory $geo_dir");
        return;
    }

    $download_url = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=$api_key&suffix=tar.gz";
    $response = wp_remote_get($download_url, ['timeout' => 30]);

    if (is_wp_error($response)) {
        teckglobal_bfp_debug("GeoIP download failed: " . $response->get_error_message());
        return;
    }

    $tar_data = wp_remote_retrieve_body($response);
    $tar_path = "$geo_dir/GeoLite2-City.tar.gz";
    file_put_contents($tar_path, $tar_data);

    $phar = new PharData($tar_path);
    $phar->extractTo($geo_dir, null, true);
    $mmdb_files = glob("$geo_dir/{,*/}*.mmdb", GLOB_BRACE);
    if (!empty($mmdb_files)) {
        rename($mmdb_files[0], $geo_file);
    }
    unlink($tar_path);
    foreach (scandir($geo_dir) as $item) {
        if ($item === '.' || $item === '..' || $item === 'GeoLite2-City.mmdb') continue;
        $path = "$geo_dir/$item";
        if (is_dir($path)) teckglobal_bfp_remove_dir($path);
    }
    teckglobal_bfp_debug("GeoIP database updated at $geo_file");
}
add_action('teckglobal_bfp_update_geoip', 'teckglobal_bfp_download_geoip');

function teckglobal_bfp_check_rate_limit(string $ip): bool {
    if (!get_option('teckglobal_bfp_enable_rate_limit', 0)) {
        return true;
    }
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $interval = (int) get_option('teckglobal_bfp_rate_limit_interval', 60);
    $max_attempts = (int) get_option('teckglobal_bfp_rate_limit_attempts', 3);

    $row = $wpdb->get_row($wpdb->prepare(
        "SELECT timestamp FROM $table_name WHERE ip = %s AND attempts >= %d",
        $ip, $max_attempts
    ));
    return !$row || (strtotime(current_time('mysql')) - strtotime($row->timestamp) >= $interval);
}

function teckglobal_bfp_check_threat_feed(string $ip): bool {
    if (!get_option('teckglobal_bfp_enable_threat_feed', 0)) {
        return false;
    }
    $api_key = get_option('teckglobal_bfp_abuseipdb_key', '');
    if (empty($api_key)) {
        return false;
    }

    $response = wp_remote_get("https://api.abuseipdb.com/api/v2/check?ipAddress=$ip", [
        'headers' => ['Key' => $api_key, 'Accept' => 'application/json'],
        'timeout' => 10
    ]);

    if (is_wp_error($response)) {
        teckglobal_bfp_debug("Threat feed check failed: " . $response->get_error_message());
        return false;
    }

    $data = json_decode(wp_remote_retrieve_body($response), true);
    return ($data['data']['abuseConfidenceScore'] ?? 0) >= 75;
}

function teckglobal_bfp_manage_ips_page(): void {
    if (!current_user_can('manage_options')) {
        wp_die('Unauthorized access');
    }

    $notice = '';
    if (isset($_POST['teckglobal_bfp_ban_ip']) && check_admin_referer('teckglobal_bfp_ban_ip')) {
        $ip = sanitize_text_field($_POST['ip_to_ban']);
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            teckglobal_bfp_ban_ip($ip, 'manual');
            $notice = '<div class="updated"><p>IP banned successfully.</p></div>';
        } else {
            $notice = '<div class="error"><p>Invalid IP address.</p></div>';
        }
    }
    if (isset($_POST['teckglobal_bfp_unban_ip']) && check_admin_referer('teckglobal_bfp_unban_ip')) {
        $ip = sanitize_text_field($_POST['ip_to_unban']);
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            teckglobal_bfp_unban_ip($ip);
            $notice = '<div class="updated"><p>IP unbanned successfully.</p></div>';
        } else {
            $notice = '<div class="error"><p>Invalid IP address.</p></div>';
        }
    }

    ?>
    <div class="wrap">
        <?php echo $notice; ?>
        <h1>Manage IPs</h1>
        <h2>Ban an IP</h2>
        <form method="post">
            <?php wp_nonce_field('teckglobal_bfp_ban_ip'); ?>
            <p><label>IP Address to Ban: <input type="text" name="ip_to_ban"></label>
            <input type="submit" name="teckglobal_bfp_ban_ip" class="button-primary" value="Ban IP"></p>
        </form>
        <h2>Unban an IP</h2>
        <form method="post">
            <?php wp_nonce_field('teckglobal_bfp_unban_ip'); ?>
            <p><label>IP Address to Unban: <input type="text" name="ip_to_unban"></label>
            <input type="submit" name="teckglobal_bfp_unban_ip" class="button-primary" value="Unban IP"></p>
        </form>
    </div>
    <?php
}

function teckglobal_bfp_get_ip_logs(int $limit = 10, int $page = 1, string $orderby = 'timestamp', string $order = 'DESC'): array {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $offset = ($page - 1) * $limit;
    $logs = $wpdb->get_results($wpdb->prepare(
        "SELECT * FROM $table_name ORDER BY $orderby $order LIMIT %d OFFSET %d",
        $limit, $offset
    ));
    $total = $wpdb->get_var("SELECT COUNT(*) FROM $table_name");
    return ['logs' => $logs, 'total' => (int) $total];
}

function teckglobal_bfp_ip_logs_page(): void {
    if (!current_user_can('manage_options')) {
        wp_die('Unauthorized access');
    }

    $limit = isset($_GET['log_limit']) ? absint($_GET['log_limit']) : 10;
    $limit = in_array($limit, [10, 25, 50, 100]) ? $limit : 10;
    $page = max(1, isset($_GET['log_page']) ? absint($_GET['log_page']) : 1);

    $data = teckglobal_bfp_get_ip_logs($limit, $page);
    $logs = $data['logs'];
    $total_pages = ceil($data['total'] / $limit);
    $base_url = admin_url("admin.php?page=teckglobal-bfp-ip-logs&log_limit=$limit");

    $locations = array_map(function($log) {
        return [
            'lat' => floatval($log->latitude),
            'lng' => floatval($log->longitude),
            'ip' => esc_js($log->ip),
            'country' => esc_js($log->country),
            'user_agent' => esc_js($log->user_agent ?? 'Unknown')
        ];
    }, array_filter($logs, fn($log) => $log->banned && $log->latitude && $log->longitude));
    $locations_json = json_encode($locations);

    $notice = '';
    if (isset($_GET['action']) && $_GET['action'] === 'unban' && check_admin_referer('teckglobal_bfp_unban_ip_log', '_wpnonce')) {
        $ip = sanitize_text_field($_GET['ip']);
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            teckglobal_bfp_unban_ip($ip);
            $notice = "<div class='updated'><p>IP $ip unbanned successfully.</p></div>";
        }
    }

    ?>
    <div class="wrap">
        <?php echo $notice; ?>
        <h1>IP Logs & Map</h1>
        <form method="get">
            <input type="hidden" name="page" value="teckglobal-bfp-ip-logs">
            <label>Show: <select name="log_limit" onchange="this.form.submit()">
                <?php foreach ([10, 25, 50, 100] as $opt) echo "<option value='$opt'" . ($limit == $opt ? ' selected' : '') . ">$opt</option>"; ?>
            </select> entries</label>
        </form>
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th>IP</th><th>Last Attempt</th><th>Attempts</th><th>Banned</th><th>Ban Expiry</th>
                    <th>Country</th><th>Scan Exploit</th><th>Brute Force</th><th>Manual Ban</th><th>User Agent</th><th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php
                foreach ($logs as $log) {
                    $unban_url = wp_nonce_url("$base_url&action=unban&ip=" . urlencode($log->ip) . "&log_page=$page", 'teckglobal_bfp_unban_ip_log');
                    echo "<tr>
                        <td>" . esc_html($log->ip) . "</td>
                        <td>" . esc_html($log->timestamp) . "</td>
                        <td>" . esc_html($log->attempts) . "</td>
                        <td>" . ($log->banned ? 'Yes' : 'No') . "</td>
                        <td>" . ($log->ban_expiry ?: 'N/A') . "</td>
                        <td>" . esc_html($log->country) . "</td>
                        <td>" . ($log->scan_exploit ? 'Yes' : 'No') . "</td>
                        <td>" . ($log->brute_force ? 'Yes' : 'No') . "</td>
                        <td>" . ($log->manual_ban ? 'Yes' : 'No') . "</td>
                        <td>" . esc_html($log->user_agent ?? 'Unknown') . "</td>
                        <td>" . ($log->banned ? "<a href='$unban_url' class='button'>Unban</a>" : '') . "</td>
                    </tr>";
                }
                if (!$logs) echo "<tr><td colspan='11'>No logs found.</td></tr>";
                ?>
            </tbody>
        </table>
        <div class="tablenav bottom">
            <?php
            echo paginate_links([
                'base' => "$base_url&log_page=%#%",
                'format' => '&log_page=%#%',
                'current' => $page,
                'total' => $total_pages
            ]);
            ?>
        </div>
        <h2>Blocked IP Locations</h2>
        <div id="bfp-map" style="height: 400px;"></div>
        <script>
            jQuery(function($) {
                var map = L.map('bfp-map').setView([0, 0], 2);
                L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                    attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
                    maxZoom: 18
                }).addTo(map);
                var locations = <?php echo $locations_json; ?>;
                locations.forEach(loc => {
                    L.marker([loc.lat, loc.lng]).addTo(map)
                        .bindPopup(`<b>IP:</b> ${loc.ip}<br><b>Country:</b> ${loc.country}<br><b>User Agent:</b> ${loc.user_agent}`);
                });
                if (locations.length) map.fitBounds(L.featureGroup(locations.map(loc => L.marker([loc.lat, loc.lng]))).getBounds());
            });
        </script>
    </div>
    <?php
}

function teckglobal_bfp_export_settings(): void {
    $options = [
        'teckglobal_bfp_max_attempts', 'teckglobal_bfp_ban_time', 'teckglobal_bfp_auto_ban_invalid',
        'teckglobal_bfp_excluded_ips', 'teckglobal_bfp_exploit_protection', 'teckglobal_bfp_exploit_max_attempts',
        'teckglobal_bfp_maxmind_key', 'teckglobal_bfp_remove_data', 'teckglobal_bfp_enable_logging',
        'teckglobal_bfp_block_message', 'teckglobal_bfp_enable_debug_log', 'teckglobal_bfp_whitelist_ips',
        'teckglobal_bfp_enable_notifications', 'teckglobal_bfp_notification_email', 'teckglobal_bfp_enable_captcha',
        'teckglobal_bfp_recaptcha_site_key', 'teckglobal_bfp_recaptcha_secret_key', 'teckglobal_bfp_enable_rate_limit',
        'teckglobal_bfp_rate_limit_attempts', 'teckglobal_bfp_rate_limit_interval', 'teckglobal_bfp_enable_threat_feed',
        'teckglobal_bfp_abuseipdb_key'
    ];
    $settings = array_combine($options, array_map('get_option', $options));
    $json = json_encode($settings, JSON_PRETTY_PRINT);
    header('Content-Disposition: attachment; filename="teckglobal-bfp-settings-' . date('Y-m-d-H-i-s') . '.json"');
    header('Content-Type: application/json');
    echo $json;
    exit;
}

function teckglobal_bfp_import_settings(): void {
    if (!isset($_FILES['import_file']) || $_FILES['import_file']['error'] !== UPLOAD_ERR_OK) {
        echo '<div class="error"><p>File upload failed.</p></div>';
        return;
    }
    $settings = json_decode(file_get_contents($_FILES['import_file']['tmp_name']), true);
    if (!is_array($settings)) {
        echo '<div class="error"><p>Invalid settings file.</p></div>';
        return;
    }

    $allowed = [
        'teckglobal_bfp_max_attempts' => 'absint', 'teckglobal_bfp_ban_time' => 'sanitize_text_field',
        'teckglobal_bfp_auto_ban_invalid' => 'bool', 'teckglobal_bfp_excluded_ips' => 'array',
        'teckglobal_bfp_exploit_protection' => 'bool', 'teckglobal_bfp_exploit_max_attempts' => 'absint',
        'teckglobal_bfp_maxmind_key' => 'sanitize_text_field', 'teckglobal_bfp_remove_data' => 'bool',
        'teckglobal_bfp_enable_logging' => 'bool', 'teckglobal_bfp_block_message' => 'sanitize_text_field',
        'teckglobal_bfp_enable_debug_log' => 'bool', 'teckglobal_bfp_whitelist_ips' => 'sanitize_textarea_field',
        'teckglobal_bfp_enable_notifications' => 'bool', 'teckglobal_bfp_notification_email' => 'sanitize_email',
        'teckglobal_bfp_enable_captcha' => 'bool', 'teckglobal_bfp_recaptcha_site_key' => 'sanitize_text_field',
        'teckglobal_bfp_recaptcha_secret_key' => 'sanitize_text_field', 'teckglobal_bfp_enable_rate_limit' => 'bool',
        'teckglobal_bfp_rate_limit_attempts' => 'absint', 'teckglobal_bfp_rate_limit_interval' => 'absint',
        'teckglobal_bfp_enable_threat_feed' => 'bool', 'teckglobal_bfp_abuseipdb_key' => 'sanitize_text_field'
    ];

    foreach ($settings as $key => $value) {
        if (isset($allowed[$key])) {
            $value = match ($allowed[$key]) {
                'absint' => absint($value),
                'sanitize_text_field' => sanitize_text_field($value),
                'sanitize_textarea_field' => sanitize_textarea_field($value),
                'sanitize_email' => sanitize_email($value),
                'bool' => (bool) $value,
                'array' => is_array($value) ? $value : [],
            };
            update_option($key, $value);
        }
    }
    echo '<div class="updated"><p>Settings imported successfully.</p></div>';
}

function teckglobal_bfp_verify_captcha($username, $password): void {
    if (!get_option('teckglobal_bfp_enable_captcha', 0) || empty($_POST['g-recaptcha-response'])) {
        return;
    }
    $secret = get_option('teckglobal_bfp_recaptcha_secret_key', '');
    $response = wp_remote_post('https://www.google.com/recaptcha/api/siteverify', [
        'body' => [
            'secret' => $secret,
            'response' => $_POST['g-recaptcha-response'],
            'remoteip' => teckglobal_bfp_get_client_ip()
        ]
    ]);

    if (is_wp_error($response) || !json_decode(wp_remote_retrieve_body($response), true)['success']) {
        teckglobal_bfp_log_attempt(teckglobal_bfp_get_client_ip());
        wp_die('CAPTCHA verification failed.', 'Access Denied', ['response' => 403]);
    }
}
add_action('wp_authenticate', 'teckglobal_bfp_verify_captcha', 1, 2);
