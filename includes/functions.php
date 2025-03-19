<?php
/**
 * TeckGlobal Brute Force Protect - Helper Functions
 *
 * This file contains utility functions for the TeckGlobal Brute Force Protect plugin.
 * It handles IP logging, banning, GeoIP lookups, and admin page logic (except settings, which is in the main file).
 */

if (!defined('ABSPATH')) {
    exit; // Prevent direct access
}

require_once TECKGLOBAL_BFP_PATH . 'vendor/autoload.php';
use GeoIp2\Database\Reader;

/**
 * Log an attempt from an IP address
 *
 * @param string $ip The IP address to log
 */
function teckglobal_bfp_log_attempt(string $ip): void {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';

    if (teckglobal_bfp_is_ip_excluded($ip)) {
        return; // Skip logging entirely for excluded IPs
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
                'scan_exploit' => 0,
                'brute_force' => 0,
                'manual_ban' => 0
            ]
        );
        teckglobal_bfp_debug("Logged first attempt for IP $ip");
    }
}

/**
 * Get the number of attempts for an IP
 *
 * @param string $ip The IP address to check
 * @return int The number of attempts
 */
function teckglobal_bfp_get_attempts(string $ip): int {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $row = $wpdb->get_row($wpdb->prepare("SELECT attempts FROM $table_name WHERE ip = %s", $ip));
    return $row ? (int) $row->attempts : 0;
}

/**
 * Ban an IP address
 *
 * @param string $ip The IP address to ban
 * @param string $reason The reason for the ban (brute_force, scan_exploit, manual)
 */
function teckglobal_bfp_ban_ip(string $ip, string $reason = 'manual'): void {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $ban_time = get_option('teckglobal_bfp_ban_time', '60-minutes');

    list($value, $unit) = explode('-', $ban_time);
    $value = (int) $value;
    $interval = match ($unit) {
        'minutes' => "$value minutes",
        default => "60 minutes",
    };
    $ban_expiry = date('Y-m-d H:i:s', strtotime("+$interval"));

    if (teckglobal_bfp_is_ip_excluded($ip)) {
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
                'manual_ban' => $manual_ban
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
                'manual_ban' => $manual_ban
            ]
        );
    }
    teckglobal_bfp_debug("IP $ip banned until $ban_expiry for reason: $reason");
}

/**
 * Unban an IP address
 *
 * @param string $ip The IP address to unban
 */
function teckglobal_bfp_unban_ip(string $ip): void {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $wpdb->update(
        $table_name,
        ['banned' => 0, 'ban_expiry' => null, 'attempts' => 0],
        ['ip' => $ip]
    );
    teckglobal_bfp_debug("IP $ip unbanned, ban reason flags preserved");
}

/**
 * Check if an IP is banned
 *
 * @param string $ip The IP address to check
 * @return bool True if banned, false otherwise
 */
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
            teckglobal_bfp_debug("IP $ip ban expired, unbanned with preserved flags.");
            return false;
        }
        return true;
    }
    return false;
}

/**
 * Check if an IP is excluded from banning/logging
 *
 * @param string $ip The IP address to check
 * @return bool True if excluded, false otherwise
 */
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
            if (ip2long($ip) & ~((1 << (32 - $mask)) - 1) == ip2long($subnet)) {
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

/**
 * Recursively remove a directory and its contents
 *
 * @param string $dir The directory path to remove
 * @return bool True on success, false on failure
 */
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
        $path = $dir . '/' . $item;
        if (is_dir($path)) {
            teckglobal_bfp_remove_dir($path);
        } else {
            if (unlink($path)) {
                teckglobal_bfp_debug("Deleted file $path");
            } else {
                teckglobal_bfp_debug("Failed to delete file $path");
            }
        }
    }
    if (rmdir($dir)) {
        teckglobal_bfp_debug("Removed directory $dir");
        return true;
    } else {
        teckglobal_bfp_debug("Failed to remove directory $dir");
        return false;
    }
}

/**
 * Download or update GeoIP database
 */
function teckglobal_bfp_download_geoip(): void {
    $geo_dir = TECKGLOBAL_BFP_GEO_DIR;
    $geo_file = TECKGLOBAL_BFP_GEO_FILE;
    $api_key = get_option('teckglobal_bfp_maxmind_key', '');

    if (empty($api_key)) {
        teckglobal_bfp_debug("MaxMind API key not set; skipping GeoIP download");
        return;
    }

    if (!file_exists($geo_dir)) {
        if (!mkdir($geo_dir, 0755, true)) {
            teckglobal_bfp_debug("Failed to create directory $geo_dir - Check permissions");
            return;
        }
    }

    $download_url = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=$api_key&suffix=tar.gz";
    $response = wp_remote_get($download_url, ['timeout' => 30]);

    if (is_wp_error($response)) {
        teckglobal_bfp_debug("GeoIP download failed: " . $response->get_error_message());
        return;
    }

    $status_code = wp_remote_retrieve_response_code($response);
    if ($status_code !== 200) {
        teckglobal_bfp_debug("GeoIP download failed: HTTP $status_code - " . wp_remote_retrieve_body($response));
        return;
    }

    $tar_data = wp_remote_retrieve_body($response);
    $tar_path = $geo_dir . 'GeoLite2-City.tar.gz';
    if (!file_put_contents($tar_path, $tar_data)) {
        teckglobal_bfp_debug("Failed to write GeoIP tar file to $tar_path - Check permissions");
        return;
    }

    try {
        $phar = new PharData($tar_path);
        $phar->extractTo($geo_dir, null, true);
        $mmdb_files = glob($geo_dir . '{,*/}*.mmdb', GLOB_BRACE);
        if (empty($mmdb_files)) {
            teckglobal_bfp_debug("No .mmdb files found after extraction in $geo_dir or subdirs");
            return;
        }

        $mmdb = $mmdb_files[0];
        if (rename($mmdb, $geo_file)) {
            teckglobal_bfp_debug("Moved $mmdb to $geo_file");
        } else {
            teckglobal_bfp_debug("Failed to move $mmdb to $geo_file - Check permissions");
            return;
        }

        if (!unlink($tar_path)) {
            teckglobal_bfp_debug("Failed to delete $tar_path");
        }

        $dir_contents = scandir($geo_dir);
        if ($dir_contents === false) {
            teckglobal_bfp_debug("Failed to read $geo_dir - Check permissions");
            return;
        }

        foreach ($dir_contents as $item) {
            if ($item === '.' || $item === '..' || $item === 'GeoLite2-City.mmdb') {
                continue;
            }
            $full_path = $geo_dir . '/' . $item;
            if (is_dir($full_path)) {
                teckglobal_bfp_remove_dir($full_path);
            }
        }
        teckglobal_bfp_debug("GeoIP file downloaded and extracted to $geo_file");
    } catch (Exception $e) {
        teckglobal_bfp_debug("GeoIP extraction failed: " . $e->getMessage());
    }
}
add_action('teckglobal_bfp_update_geoip', 'teckglobal_bfp_download_geoip');

/**
 * Manage IPs page
 */
function teckglobal_bfp_manage_ips_page(): void {
    if (!current_user_can('manage_options')) {
        wp_die('You do not have sufficient permissions to access this page.');
    }

    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';

    if (isset($_POST['teckglobal_bfp_ban_ip']) && check_admin_referer('teckglobal_bfp_ban_ip')) {
        $ip_to_ban = sanitize_text_field($_POST['ip_to_ban']);
        if (filter_var($ip_to_ban, FILTER_VALIDATE_IP)) {
            teckglobal_bfp_ban_ip($ip_to_ban, 'manual');
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

/**
 * Get IP logs with pagination
 *
 * @param int $limit Number of logs per page
 * @param int $page Current page number
 * @param string $orderby Column to sort by
 * @param string $order Sort direction (ASC/DESC)
 * @return array Logs and total count
 */
function teckglobal_bfp_get_ip_logs(int $limit = 10, int $page = 1, string $orderby = 'timestamp', string $order = 'DESC'): array {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';

    $limit = absint($limit);
    $page = absint($page);
    $offset = ($page - 1) * $limit;
    $orderby = in_array($orderby, ['ip', 'timestamp', 'attempts', 'banned', 'ban_expiry', 'country', 'scan_exploit', 'brute_force', 'manual_ban']) ? $orderby : 'timestamp';
    $order = strtoupper($order) === 'ASC' ? 'ASC' : 'DESC';

    $query = $wpdb->prepare(
        "SELECT * FROM $table_name ORDER BY $orderby $order LIMIT %d OFFSET %d",
        $limit,
        $offset
    );
    $logs = $wpdb->get_results($query);
    $total_logs = $wpdb->get_var("SELECT COUNT(*) FROM $table_name");

    return [
        'logs' => $logs,
        'total' => absint($total_logs)
    ];
}

/**
 * IP Logs & Map page
 */
function teckglobal_bfp_ip_logs_page(): void {
    if (!current_user_can('manage_options')) {
        wp_die('You do not have sufficient permissions to access this page.');
    }

    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';

    $notice = '';
    if (isset($_GET['action']) && $_GET['action'] === 'unban' && isset($_GET['ip']) && check_admin_referer('teckglobal_bfp_unban_ip_log')) {
        $ip_to_unban = sanitize_text_field($_GET['ip']);
        if (filter_var($ip_to_unban, FILTER_VALIDATE_IP)) {
            teckglobal_bfp_unban_ip($ip_to_unban);
            $notice = '<div class="updated"><p>IP ' . esc_html($ip_to_unban) . ' unbanned successfully.</p></div>';
        } else {
            $notice = '<div class="error"><p>Invalid IP address.</p></div>';
        }
    }

    $default_limit = 10;
    $valid_limits = [10, 25, 50, 100];
    $limit = get_user_option('teckglobal_bfp_log_limit', get_current_user_id());
    $limit = in_array($limit, $valid_limits) ? $limit : $default_limit;
    if (isset($_GET['log_limit']) && in_array(absint($_GET['log_limit']), $valid_limits)) {
        $limit = absint($_GET['log_limit']);
        update_user_option(get_current_user_id(), 'teckglobal_bfp_log_limit', $limit);
    }

    $page = isset($_GET['log_page']) ? absint($_GET['log_page']) : 1;
    $page = max(1, $page);

    $data = teckglobal_bfp_get_ip_logs($limit, $page);
    $logs = $data['logs'];
    $total = $data['total'];
    $total_pages = ceil($total / $limit);

    $locations = [];
    foreach ($logs as $log) {
        if ($log->latitude && $log->longitude && $log->banned) {
            $locations[] = [
                'lat' => floatval($log->latitude),
                'lng' => floatval($log->longitude),
                'ip' => esc_js($log->ip),
                'country' => esc_js($log->country),
            ];
        }
    }
    $locations_json = json_encode($locations);

    $base_url = admin_url("admin.php?page=teckglobal-bfp-ip-logs&log_limit=$limit");

    ?>
    <div class="wrap">
        <?php echo $notice; ?>
        <h1>TeckGlobal Brute Force Protect - IP Logs & Map</h1>
        <form method="get" id="log-limit-form">
            <input type="hidden" name="page" value="teckglobal-bfp-ip-logs">
            <label for="log_limit">Show:</label>
            <select name="log_limit" id="log_limit" onchange="this.form.submit()">
                <?php
                foreach ($valid_limits as $option) {
                    $selected = $limit === $option ? 'selected' : '';
                    echo "<option value='$option' $selected>$option</option>";
                }
                ?>
            </select> entries
        </form>

        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Last Attempt</th>
                    <th>Attempts</th>
                    <th>Banned</th>
                    <th>Ban Expiry</th>
                    <th>Country</th>
                    <th>Scan Exploit</th>
                    <th>Brute Force</th>
                    <th>Manual Ban</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php
                if ($logs) {
                    foreach ($logs as $log) {
                        $unban_url = wp_nonce_url(
                            "$base_url&action=unban&ip=" . urlencode($log->ip) . "&log_page=$page",
                            'teckglobal_bfp_unban_ip_log'
                        );
                        $is_banned = teckglobal_bfp_is_ip_banned($log->ip);
                        echo '<tr>';
                        echo '<td data-label="IP Address">' . esc_html($log->ip) . '</td>';
                        echo '<td data-label="Last Attempt">' . esc_html($log->timestamp) . '</td>';
                        echo '<td data-label="Attempts">' . esc_html($log->attempts) . '</td>';
                        echo '<td data-label="Banned">' . ($is_banned ? 'Yes' : 'No') . '</td>';
                        echo '<td data-label="Ban Expiry">' . esc_html($log->ban_expiry ?: 'N/A') . '</td>';
                        echo '<td data-label="Country">' . esc_html($log->country) . '</td>';
                        echo '<td data-label="Scan Exploit">' . ($log->scan_exploit ? 'Yes' : 'No') . '</td>';
                        echo '<td data-label="Brute Force">' . ($log->brute_force ? 'Yes' : 'No') . '</td>';
                        echo '<td data-label="Manual Ban">' . ($log->manual_ban ? 'Yes' : 'No') . '</td>';
                        echo '<td data-label="Action">';
                        if ($is_banned) {
                            echo '<a href="' . esc_url($unban_url) . '" class="button button-secondary teckglobal-unban-ip" data-ip="' . esc_attr($log->ip) . '">Remove Ban</a>';
                        } else {
                            echo 'Ban Expired';
                        }
                        echo '</td>';
                        echo '</tr>';
                    }
                } else {
                    echo '<tr><td colspan="10">No logs found.</td></tr>';
                }
                ?>
            </tbody>
        </table>

        <?php if ($total_pages > 1) : ?>
        <div class="teckglobal-pagination">
            <?php
            for ($i = 1; $i <= $total_pages; $i++) {
                $active = $page === $i ? 'class="active"' : '';
                $url = "$base_url&log_page=$i";
                echo "<a href='$url' $active>$i</a>";
            }
            ?>
        </div>
        <?php endif; ?>

        <h2>IP Locations</h2>
        <div id="map" style="height: 400px; width: 100%;"></div>
        <?php if (empty($locations)) : ?>
            <p>No banned IPs with location data available for the current page.</p>
        <?php endif; ?>
        <script>
            console.log('Locations data:', <?php echo $locations_json; ?>);
            var locations = <?php echo $locations_json; ?>;
            document.addEventListener('DOMContentLoaded', function() {
                var select = document.getElementById('log_limit');
                var currentLimit = <?php echo json_encode($limit); ?>;
                if (select && currentLimit) {
                    select.value = currentLimit;
                    console.log('Dropdown forced to: ' + currentLimit);
                }
            });
        </script>
    </div>
    <?php
}
