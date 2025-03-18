<?php
if (!defined('ABSPATH')) {
    exit;
}

require_once TECKGLOBAL_BFP_PATH . 'vendor/autoload.php';
use GeoIp2\Database\Reader;

function teckglobal_bfp_log_attempt(string $ip): void {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';

    if (teckglobal_bfp_is_ip_excluded($ip)) {
        teckglobal_bfp_debug("IP $ip is excluded; not logging attempt");
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
            teckglobal_bfp_debug("GeoIP data retrieved for IP $ip: Country=$country, Lat=$latitude, Lon=$longitude");
        } catch (Exception $e) {
            teckglobal_bfp_debug("GeoIP lookup failed for IP $ip: " . $e->getMessage());
        }
    } else {
        teckglobal_bfp_debug("GeoIP file not found at $geo_path");
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

function teckglobal_bfp_get_attempts(string $ip): int {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $row = $wpdb->get_row($wpdb->prepare("SELECT attempts FROM $table_name WHERE ip = %s", $ip));
    return $row ? (int) $row->attempts : 0;
}

function teckglobal_bfp_ban_ip(string $ip, string $reason = 'manual'): void {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $ban_time = (int) get_option('teckglobal_bfp_ban_time', 60);
    $ban_expiry = date('Y-m-d H:i:s', strtotime("+$ban_time minutes"));

    if (teckglobal_bfp_is_ip_excluded($ip)) {
        teckglobal_bfp_debug("IP $ip is excluded; not banning");
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
            teckglobal_bfp_debug("GeoIP data retrieved for banned IP $ip: Country=$country, Lat=$latitude, Lon=$longitude");
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
        teckglobal_bfp_debug("Created directory $geo_dir");
    }

    $download_url = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=$api_key&suffix=tar.gz";
    teckglobal_bfp_debug("Attempting GeoIP download from $download_url");
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
    teckglobal_bfp_debug("Wrote GeoIP tar file to $tar_path");

    try {
        $phar = new PharData($tar_path);
        $phar->extractTo($geo_dir, null, true);
        teckglobal_bfp_debug("Extracted tar to $geo_dir");

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
        } else {
            teckglobal_bfp_debug("Deleted $tar_path");
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
                if (teckglobal_bfp_remove_dir($full_path)) {
                    teckglobal_bfp_debug("Recursively removed subdir $full_path");
                } else {
                    teckglobal_bfp_debug("Failed to recursively remove subdir $full_path");
                }
            }
        }
        teckglobal_bfp_debug("GeoIP file downloaded and extracted to $geo_file");
    } catch (Exception $e) {
        teckglobal_bfp_debug("GeoIP extraction failed: " . $e->getMessage());
    }
}
add_action('teckglobal_bfp_update_geoip', 'teckglobal_bfp_download_geoip');

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
        update_option('teckglobal_bfp_maxmind_key', sanitize_text_field($_POST['teckglobal_bfp_maxmind_key']));
        teckglobal_bfp_download_geoip();
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
                <input type="text" name="teckglobal_bfp_geo_path" value="<?php echo esc_attr(get_option('teckglobal_bfp_geo_path', TECKGLOBAL_BFP_GEO_FILE)); ?>" size="50" /><br />
                <small>Default: <?php echo esc_html(TECKGLOBAL_BFP_GEO_FILE); ?></small>
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
            <h3>GeoIP Settings</h3>
            <p>
                <label for="teckglobal_bfp_maxmind_key">MaxMind License Key:</label><br />
                <input type="text" name="teckglobal_bfp_maxmind_key" value="<?php echo esc_attr(get_option('teckglobal_bfp_maxmind_key', '')); ?>" size="50" /><br />
                <small>Get your free key from <a href="https://www.maxmind.com/en/geolite2/signup" target="_blank">MaxMind GeoLite2 Signup</a>. Required for automatic GeoIP downloads (updates Tuesdays and Fridays).</small>
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
    teckglobal_bfp_debug("Log limit set to: $limit");

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
    teckglobal_bfp_debug("Locations data prepared for map: " . json_encode($locations));
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
