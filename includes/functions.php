<?php
if (!defined('ABSPATH')) {
    exit;
}

// Include Composer autoload for GeoIP2 library
require_once TECKGLOBAL_BFP_PATH . 'vendor/autoload.php';
use GeoIp2\Database\Reader;

function teckglobal_bfp_log_attempt(string $ip): void {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';

    if (teckglobal_bfp_is_ip_excluded($ip)) {
        teckglobal_bfp_debug("IP $ip is excluded; not logging attempt");
        return;
    }

    // Get GeoIP database path from settings, default to /var/www/html/teck-global.com/wp-content/plugins/teckglobal-brute-force-protect/vendor/maxmind-db/GeoLite2-City.mmdb
    $geo_path = get_option('teckglobal_bfp_geo_path', '/var/www/html/teck-global.com/wp-content/plugins/teckglobal-brute-force-protect/vendor/maxmind-db/GeoLite2-City.mmdb');
    $country = 'Unknown';
    $latitude = null;
    $longitude = null;

    // Attempt GeoIP lookup if the database file exists
    if (!empty($geo_path) && file_exists($geo_path)) {
        try {
            $reader = new Reader($geo_path);
            $record = $reader->city($ip);
            $country = $record->country->name ?? 'Unknown';
            $latitude = $record->location->latitude ?? null;
            $longitude = $record->location->longitude ?? null;
            teckglobal_bfp_debug("GeoIP data retrieved for IP $ip: Country=$country, Lat=$latitude, Lon=$longitude");
        } catch (Exception $e) {
            teckglobal_bfp_debug("GeoIP lookup failed for IP $ip: " . $e->getMessage());
        }
    } else {
        teckglobal_bfp_debug("GeoIP database not configured or missing at path: $geo_path");
    }

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
                'longitude' => $longitude
            ],
            ['ip' => $ip]
        );
        teckglobal_bfp_debug("Updated attempt count for IP $ip: $attempts");
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
            ]
        );
        teckglobal_bfp_debug("Logged first attempt for IP $ip");
    }
}

function teckglobal_bfp_get_attempts(string $ip): int {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $row = $wpdb->get_row($wpdb->prepare("SELECT attempts FROM $table_name WHERE ip = %s", $ip));
    return $row ? (int) $row->attempts : 0;
}

function teckglobal_bfp_ban_ip(string $ip): void {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $ban_time = (int) get_option('teckglobal_bfp_ban_time', 60);
    $ban_expiry = date('Y-m-d H:i:s', strtotime("+$ban_time minutes"));

    if (teckglobal_bfp_is_ip_excluded($ip)) {
        teckglobal_bfp_debug("IP $ip is excluded; not banning");
        return;
    }

    $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table_name WHERE ip = %s", $ip));
    if ($row) {
        $wpdb->update(
            $table_name,
            ['banned' => 1, 'ban_expiry' => $ban_expiry],
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
                'country' => 'Unknown',
            ]
        );
    }
    teckglobal_bfp_debug("IP $ip banned until $ban_expiry");
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
}

function teckglobal_bfp_is_ip_banned(string $ip): bool {
    if (teckglobal_bfp_is_ip_excluded($ip)) {
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
        teckglobal_bfp_debug("IP $ip is currently banned.");
        return true;
    }
    return false;
}

function teckglobal_bfp_is_ip_excluded(string $ip): bool {
    $excluded_ips = get_option('teckglobal_bfp_excluded_ips', '');
    if (empty($excluded_ips)) {
        return false;
    }

    $excluded_list = array_map('trim', explode("\n", $excluded_ips));
    foreach ($excluded_list as $excluded) {
        if (strpos($excluded, '/')) {
            list($subnet, $mask) = explode('/', $excluded);
            if (ip2long($ip) & ~((1 << (32 - $mask)) - 1) == ip2long($subnet)) {
                teckglobal_bfp_debug("IP $ip matches excluded subnet $excluded");
                return true;
            }
        } elseif ($ip === $excluded) {
            teckglobal_bfp_debug("IP $ip matches excluded IP $excluded");
            return true;
        }
    }
    return false;
}

function teckglobal_bfp_settings_page(): void {
    if (!current_user_can('manage_options')) {
        wp_die('You do not have sufficient permissions to access this page.');
    }

    if (isset($_POST['teckglobal_bfp_settings']) && check_admin_referer('teckglobal_bfp_settings')) {
        update_option('teckglobal_bfp_geo_path', sanitize_text_field($_POST['teckglobal_bfp_geo_path']));
        update_option('teckglobal_bfp_max_attempts', intval($_POST['teckglobal_bfp_max_attempts']));
        update_option('teckglobal_bfp_ban_time', intval($_POST['teckglobal_bfp_ban_time']));
        update_option('teckglobal_bfp_auto_ban_invalid', isset($_POST['teckglobal_bfp_auto_ban_invalid']) ? 1 : 0);
        update_option('teckglobal_bfp_excluded_ips', sanitize_textarea_field($_POST['teckglobal_bfp_excluded_ips']));
        update_option('teckglobal_bfp_exploit_protection', isset($_POST['teckglobal_bfp_exploit_protection']) ? 1 : 0);
        update_option('teckglobal_bfp_exploit_max_attempts', intval($_POST['teckglobal_bfp_exploit_max_attempts']));
        echo '<div class="updated"><p>Settings saved.</p></div>';
    }

    ?>
    <div class="wrap">
        <h1>TeckGlobal Brute Force Protect Settings</h1>
        <form method="post" action="">
            <?php wp_nonce_field('teckglobal_bfp_settings'); ?>
            <h3>General Settings</h3>
            <p>
                <label for="teckglobal_bfp_geo_path">GeoLite2 Database Path:</label><br />
                <input type="text" name="teckglobal_bfp_geo_path" value="<?php echo esc_attr(get_option('teckglobal_bfp_geo_path', '/var/www/html/teck-global.com/wp-content/plugins/teckglobal-brute-force-protect/vendor/maxmind-db/GeoLite2-City.mmdb')); ?>" size="50" /><br />
                <small>Path to GeoLite2-City.mmdb (optional, for geolocation features). Default: /var/www/html/teck-global.com/wp-content/plugins/teckglobal-brute-force-protect/vendor/maxmind-db/GeoLite2-City.mmdb</small>
            </p>
            <p>
                <label for="teckglobal_bfp_max_attempts">Max Login Attempts Before Ban:</label><br />
                <input type="number" name="teckglobal_bfp_max_attempts" value="<?php echo esc_attr(get_option('teckglobal_bfp_max_attempts', 5)); ?>" min="1" />
            </p>
            <p>
                <label for="teckglobal_bfp_ban_time">Ban Duration (minutes):</label><br />
                <input type="number" name="teckglobal_bfp_ban_time" value="<?php echo esc_attr(get_option('teckglobal_bfp_ban_time', 60)); ?>" min="1" />
            </p>
            <p>
                <input type="checkbox" name="teckglobal_bfp_auto_ban_invalid" value="1" <?php checked(1, get_option('teckglobal_bfp_auto_ban_invalid', 0)); ?> />
                Auto-ban IPs attempting logins with invalid usernames
            </p>
            <p>
                <label for="teckglobal_bfp_excluded_ips">Excluded IPs/Subnets (one per line):</label><br />
                <textarea name="teckglobal_bfp_excluded_ips" rows="5" cols="50"><?php echo esc_textarea(get_option('teckglobal_bfp_excluded_ips', '')); ?></textarea><br />
                <small>Example: 192.168.1.1 or 10.0.0.0/24</small>
            </p>

            <h3>Exploit Scan Protection</h3>
            <p>
                <input type="checkbox" name="teckglobal_bfp_exploit_protection" value="1" <?php checked(1, get_option('teckglobal_bfp_exploit_protection', 0)); ?> />
                Enable exploit scan protection (bans IPs scanning for vulnerabilities)
            </p>
            <p>
                <label for="teckglobal_bfp_exploit_max_attempts">Max Exploit Scan Attempts Before Ban:</label><br />
                <input type="number" name="teckglobal_bfp_exploit_max_attempts" value="<?php echo esc_attr(get_option('teckglobal_bfp_exploit_max_attempts', 3)); ?>" min="1" />
            </p>

            <p><input type="submit" name="teckglobal_bfp_settings" class="button-primary" value="Save Settings" /></p>
        </form>
    </div>
    <?php
}

function teckglobal_bfp_manage_ips_page(): void {
    if (!current_user_can('manage_options')) {
        wp_die('You do not have sufficient permissions to access this page.');
    }

    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';

    if (isset($_POST['teckglobal_bfp_ban_ip']) && check_admin_referer('teckglobal_bfp_ban_ip')) {
        $ip_to_ban = sanitize_text_field($_POST['ip_to_ban']);
        if (filter_var($ip_to_ban, FILTER_VALIDATE_IP)) {
            teckglobal_bfp_ban_ip($ip_to_ban);
            echo '<div class="updated"><p>IP banned successfully.</p></div>';
        } else {
            echo '<div class="error"><p>Invalid IP address.</p></div>';
        }
    }

    if (isset($_POST['teckglobal_bfp_unban_ip']) && check_admin_referer('teckglobal_bfp_unban_ip')) {
        $ip_to_unban = sanitize_text_field($_POST['ip_to_unban']);
        if (filter_var($ip_to_unban, FILTER_VALIDATE_IP)) {
            teckglobal_bfp_unban_ip($ip_to_unban);
            echo '<div class="updated"><p>IP unbanned successfully.</p></div>';
        } else {
            echo '<div class="error"><p>Invalid IP address.</p></div>';
        }
    }

    ?>
    <div class="wrap">
        <h1>Manage IPs</h1>
        <h2>Ban an IP</h2>
        <form method="post" action="">
            <?php wp_nonce_field('teckglobal_bfp_ban_ip'); ?>
            <p>
                <label for="ip_to_ban">IP Address to Ban:</label><br />
                <input type="text" name="ip_to_ban" value="" />
                <input type="submit" name="teckglobal_bfp_ban_ip" class="button-primary" value="Ban IP" />
            </p>
        </form>
        <h2>Unban an IP</h2>
        <form method="post" action="">
            <?php wp_nonce_field('teckglobal_bfp_unban_ip'); ?>
            <p>
                <label for="ip_to_unban">IP Address to Unban:</label><br />
                <input type="text" name="ip_to_unban" value="" />
                <input type="submit" name="teckglobal_bfp_unban_ip" class="button-primary" value="Unban IP" />
            </p>
        </form>
    </div>
    <?php
}

function teckglobal_bfp_ip_logs_page(): void {
    if (!current_user_can('manage_options')) {
        wp_die('You do not have sufficient permissions to access this page.');
    }

    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $logs = $wpdb->get_results("SELECT * FROM $table_name ORDER BY timestamp DESC");

    ?>
    <div class="wrap">
        <h1>IP Logs</h1>
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Last Attempt</th>
                    <th>Attempts</th>
                    <th>Banned</th>
                    <th>Ban Expiry</th>
                    <th>Country</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($logs as $log): ?>
                    <tr>
                        <td><?php echo esc_html($log->ip); ?></td>
                        <td><?php echo esc_html($log->timestamp); ?></td>
                        <td><?php echo esc_html($log->attempts); ?></td>
                        <td><?php echo $log->banned ? 'Yes' : 'No'; ?></td>
                        <td><?php echo esc_html($log->ban_expiry ?: 'N/A'); ?></td>
                        <td><?php echo esc_html($log->country); ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php
}

function teckglobal_bfp_geo_map_page(): void {
    if (!current_user_can('manage_options')) {
        wp_die('You do not have sufficient permissions to access this page.');
    }

    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $logs = $wpdb->get_results("SELECT ip, country, latitude, longitude FROM $table_name WHERE latitude IS NOT NULL AND longitude IS NOT NULL");

    $locations = [];
    foreach ($logs as $log) {
        $locations[] = [
            'lat' => floatval($log->latitude),
            'lng' => floatval($log->longitude),
            'ip' => esc_js($log->ip),
            'country' => esc_js($log->country),
        ];
    }
    $locations_json = json_encode($locations);

    ?>
    <div class="wrap">
        <h1>Geolocation Map</h1>
        <div id="map" style="height: 600px;"></div>
        <script>
            var locations = <?php echo $locations_json; ?>;
        </script>
    </div>
    <?php
}
