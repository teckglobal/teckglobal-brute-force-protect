<?php
// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
require_once TECKGLOBAL_BFP_PATH . 'vendor/autoload.php';
use GeoIp2\Database\Reader;

// Check if an IP is excluded
function teckglobal_bfp_is_ip_excluded(string $ip): bool {
    $excluded = get_option('teckglobal_bfp_excluded_ips', '');
    if (empty($excluded)) return false;

    $excluded_list = array_filter(array_map('trim', explode("\n", $excluded)));
    foreach ($excluded_list as $entry) {
        if (strpos($entry, '/') !== false) {
            list($subnet, $mask) = explode('/', $entry);
            $ip_long = ip2long($ip);
            $subnet_long = ip2long($subnet);
            if ($ip_long && $subnet_long && ($ip_long >> (32 - $mask)) == ($subnet_long >> (32 - $mask))) {
                teckglobal_bfp_debug("IP $ip matches excluded CIDR $entry.");
                return true;
            }
        } elseif ($entry === $ip) {
            teckglobal_bfp_debug("IP $ip matches excluded IP $entry.");
            return true;
        }
    }
    return false;
}

function teckglobal_bfp_log_attempt(string $ip): void {
    if (teckglobal_bfp_is_ip_excluded($ip)) {
        teckglobal_bfp_debug("IP $ip is excluded from logging and banning.");
        return;
    }

    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $geo_path = get_option('teckglobal_bfp_geo_path', '/usr/share/GeoIP/GeoLite2-City.mmdb');
    $existing = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table_name WHERE ip = %s", $ip));
    if ($existing) {
        $result = $wpdb->update($table_name, ['attempts' => $existing->attempts + 1, 'timestamp' => current_time('mysql')], ['ip' => $ip]);
        if ($result === false) teckglobal_bfp_debug("Failed to update attempts for IP $ip: " . $wpdb->last_error);
        else teckglobal_bfp_debug("Updated attempts for IP $ip: " . ($existing->attempts + 1));
    } else {
        $country = 'Unknown'; $latitude = null; $longitude = null;
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            teckglobal_bfp_debug("Invalid IP address provided: $ip");
        } elseif (file_exists($geo_path)) {
            teckglobal_bfp_debug("GeoIP database found at: $geo_path");
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
            teckglobal_bfp_debug("GeoIP database NOT found at: $geo_path");
        }
        $result = $wpdb->insert($table_name, ['ip' => $ip, 'timestamp' => current_time('mysql'), 'attempts' => 1, 'country' => $country, 'latitude' => $latitude, 'longitude' => $longitude]);
        if ($result === false) teckglobal_bfp_debug("Failed to insert IP $ip into database: " . $wpdb->last_error);
        else teckglobal_bfp_debug("Inserted new IP $ip into logs with country: $country");
    }
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

function teckglobal_bfp_ban_ip(string $ip): void {
    if (teckglobal_bfp_is_ip_excluded($ip)) {
        teckglobal_bfp_debug("IP $ip is excluded, skipping ban.");
        return;
    }

    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $ban_time = (int) get_option('teckglobal_bfp_ban_time', 60);
    $expiry = date('Y-m-d H:i:s', strtotime("+$ban_time minutes"));

    $existing = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM $table_name WHERE ip = %s", $ip));
    if (!$existing) {
        teckglobal_bfp_log_attempt($ip);
        $wpdb->update($table_name, ['banned' => 1, 'ban_expiry' => $expiry], ['ip' => $ip]);
    } else {
        $result = $wpdb->update($table_name, ['banned' => 1, 'ban_expiry' => $expiry], ['ip' => $ip]);
        if ($result === false) teckglobal_bfp_debug("Failed to ban IP $ip: " . $wpdb->last_error);
        else teckglobal_bfp_debug("IP $ip banned until $expiry.");
    }
}

function teckglobal_bfp_unban_ip(string $ip): void {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $result = $wpdb->update($table_name, ['banned' => 0, 'ban_expiry' => null], ['ip' => $ip]);
    if ($result === false) teckglobal_bfp_debug("Failed to unban IP $ip: " . $wpdb->last_error);
    else teckglobal_bfp_debug("IP $ip unbanned.");
}

function teckglobal_bfp_get_attempts(string $ip): int {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $attempts = $wpdb->get_var($wpdb->prepare("SELECT attempts FROM $table_name WHERE ip = %s", $ip));
    return (int) ($attempts ?? 0);
}

function teckglobal_bfp_get_total_attempts(): int {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $total = $wpdb->get_var("SELECT SUM(attempts) FROM $table_name");
    return (int) ($total ?? 0);
}

function teckglobal_bfp_settings_page(): void {
    global $wpdb;
    if (isset($_POST['teckglobal_bfp_save_settings']) && check_admin_referer('teckglobal_bfp_settings')) {
        update_option('teckglobal_bfp_geo_path', sanitize_text_field($_POST['geo_path']));
        update_option('teckglobal_bfp_max_attempts', absint($_POST['max_attempts']));
        update_option('teckglobal_bfp_ban_time', absint($_POST['ban_time']));
        update_option('teckglobal_bfp_auto_ban_invalid', isset($_POST['auto_ban_invalid']) ? 1 : 0);
        update_option('teckglobal_bfp_excluded_ips', sanitize_textarea_field($_POST['excluded_ips']));
        if (!empty($_FILES['logo_image']['name'])) {
            $upload = wp_handle_upload($_FILES['logo_image'], ['test_form' => false]);
            if (isset($upload['url'])) update_option('teckglobal_bfp_logo', $upload['url']);
        }
        echo '<div class="updated"><p>Settings saved successfully.</p></div>';
    }
    $total_attempts = teckglobal_bfp_get_total_attempts();
    $geo_path = get_option('teckglobal_bfp_geo_path', '/usr/share/GeoIP/GeoLite2-City.mmdb');
    $max_attempts = get_option('teckglobal_bfp_max_attempts', 5);
    $ban_time = get_option('teckglobal_bfp_ban_time', 60);
    $auto_ban_invalid = get_option('teckglobal_bfp_auto_ban_invalid', 0);
    $excluded_ips = get_option('teckglobal_bfp_excluded_ips', '');
    $logo_url = get_option('teckglobal_bfp_logo', '');
    ?>
    <div class="wrap">
        <h1>TeckGlobal LLC Brute Force Protect</h1>
        <div class="teckglobal-summary">
            <h2>Plugin Summary</h2>
            <p><strong>Total Brute Force Attempts Blocked:</strong> <?php echo esc_html($total_attempts); ?></p>
            <p><strong>About TeckGlobal LLC:</strong> Visit our website at <a href="https://teck-global.com" target="_blank">https://teck-global.com</a></p>
            <?php if ($logo_url): ?>
                <p><strong>Logo:</strong><br><img src="<?php echo esc_url($logo_url); ?>" alt="TeckGlobal LLC Logo" style="max-width: 200px;"></p>
            <?php endif; ?>
        </div>
        <form method="post" enctype="multipart/form-data">
            <?php wp_nonce_field('teckglobal_bfp_settings'); ?>
            <h2>Settings</h2>
            <table class="form-table">
                <tr><th><label for="geo_path">GeoLite2-City.mmdb Path</label></th><td><input type="text" name="geo_path" id="geo_path" value="<?php echo esc_attr($geo_path); ?>" class="regular-text"></td></tr>
                <tr><th><label for="max_attempts">Max Login Attempts Before Ban</label></th><td><input type="number" name="max_attempts" id="max_attempts" value="<?php echo esc_attr($max_attempts); ?>" min="1" class="small-text"> attempts</td></tr>
                <tr><th><label for="ban_time">Ban Duration</label></th><td><input type="number" name="ban_time" id="ban_time" value="<?php echo esc_attr($ban_time); ?>" min="1" class="small-text"> minutes</td></tr>
                <tr><th><label for="auto_ban_invalid">Auto Ban Invalid Usernames</label></th><td><input type="checkbox" name="auto_ban_invalid" id="auto_ban_invalid" value="1" <?php checked($auto_ban_invalid, 1); ?>></td></tr>
                <tr><th><label for="excluded_ips">Excluded IPs/Subnets</label></th><td><textarea name="excluded_ips" id="excluded_ips" rows="5" class="regular-text"><?php echo esc_textarea($excluded_ips); ?></textarea><p class="description">Enter one IP or CIDR subnet (e.g., 192.168.1.0/24) per line to exclude from banning.</p></td></tr>
                <tr><th><label for="logo_image">Upload Logo</label></th><td><input type="file" name="logo_image" id="logo_image"></td></tr>
            </table>
            <p class="submit"><input type="submit" name="teckglobal_bfp_save_settings" class="button button-primary" value="Save Settings"></p>
        </form>
    </div>
    <?php
}

function teckglobal_bfp_manage_ips_page(): void {
    if (isset($_POST['ban_ip']) && check_admin_referer('teckglobal_bfp_ban_ip')) {
        $ip = sanitize_text_field($_POST['ip']);
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            teckglobal_bfp_ban_ip($ip);
            echo '<div class="updated"><p>IP ' . esc_html($ip) . ' banned successfully.</p></div>';
        } else {
            echo '<div class="error"><p>Invalid IP address provided.</p></div>';
        }
    }
    if (isset($_POST['unban_ip']) && check_admin_referer('teckglobal_bfp_unban_ip')) {
        $ip = sanitize_text_field($_POST['ip']);
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            teckglobal_bfp_unban_ip($ip);
            echo '<div class="updated"><p>IP ' . esc_html($ip) . ' unbanned successfully.</p></div>';
        } else {
            echo '<div class="error"><p>Invalid IP address provided.</p></div>';
        }
    }
    ?>
    <div class="wrap">
        <h1>Manage IPs</h1>
        <form method="post" action="">
            <?php wp_nonce_field('teckglobal_bfp_ban_ip'); ?>
            <label for="ip">IP Address:</label>
            <input type="text" name="ip" id="ip" required>
            <input type="submit" name="ban_ip" value="Ban IP" class="button button-primary">
            <input type="submit" name="unban_ip" value="Unban IP" class="button">
        </form>
    </div>
    <?php
}

class TeckGlobal_BFP_IP_Table extends WP_List_Table {
    public function __construct() {
        parent::__construct(['singular' => 'IP Log', 'plural' => 'IP Logs', 'ajax' => false]);
    }
    public function get_columns(): array {
        return ['ip' => 'IP Address', 'timestamp' => 'Timestamp', 'attempts' => 'Attempts', 'banned' => 'Banned', 'ban_expiry' => 'Ban Expiry', 'country' => 'Country', 'actions' => 'Actions'];
    }
    public function prepare_items(): void {
        global $wpdb;
        $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
        $per_page = 20;
        $current_page = $this->get_pagenum();
        $search = isset($_REQUEST['s']) ? sanitize_text_field($_REQUEST['s']) : '';
        $columns = $this->get_columns();
        $hidden = [];
        $sortable = $this->get_sortable_columns();
        $this->_column_headers = [$columns, $hidden, $sortable];
        $query = "SELECT * FROM $table_name";
        if ($search) {
            $query .= $wpdb->prepare(" WHERE ip LIKE %s", '%' . $wpdb->esc_like($search) . '%');
        }
        $orderby = !empty($_GET['orderby']) ? sanitize_sql_orderby($_GET['orderby']) : 'timestamp';
        $order = !empty($_GET['order']) ? sanitize_text_field($_GET['order']) : 'DESC';
        $query .= " ORDER BY $orderby $order";
        $total_items = $wpdb->get_var("SELECT COUNT(*) FROM ($query) as count_table");
        $query .= " LIMIT " . (($current_page - 1) * $per_page) . ", $per_page";
        $this->items = $wpdb->get_results($query, ARRAY_A);
        $this->set_pagination_args(['total_items' => $total_items, 'per_page' => $per_page, 'total_pages' => ceil($total_items / $per_page)]);
    }
    public function get_sortable_columns(): array {
        return ['ip' => ['ip', false], 'timestamp' => ['timestamp', true], 'attempts' => ['attempts', false], 'banned' => ['banned', false], 'ban_expiry' => ['ban_expiry', false]];
    }
    public function column_default($item, $column_name) {
        switch ($column_name) {
            case 'ip': case 'timestamp': case 'attempts': case 'country': case 'ban_expiry':
                return $item[$column_name] ?: 'N/A';
            case 'banned':
                return $item[$column_name] ? 'Yes' : 'No';
            case 'actions':
                if ($item['banned']) {
                    $unban_url = wp_nonce_url(admin_url('admin.php?page=teckglobal-bfp-ip-logs&action=unban&ip=' . urlencode($item['ip'])), 'teckglobal_bfp_unban_ip_' . $item['ip']);
                    return '<a href="' . esc_url($unban_url) . '" class="button button-secondary">Remove Ban</a>';
                }
                return '';
            default:
                return '';
        }
    }
}

function teckglobal_bfp_handle_unban_ip() {
    if (isset($_GET['page']) && $_GET['page'] === 'teckglobal-bfp-ip-logs' && isset($_GET['action']) && $_GET['action'] === 'unban' && isset($_GET['ip']) && check_admin_referer('teckglobal_bfp_unban_ip_' . $_GET['ip'])) {
        $ip = sanitize_text_field($_GET['ip']);
        teckglobal_bfp_unban_ip($ip);
        wp_redirect(admin_url('admin.php?page=teckglobal-bfp-ip-logs&unbanned=1'));
        exit;
    }
}
add_action('admin_init', 'teckglobal_bfp_handle_unban_ip');

function teckglobal_bfp_ip_logs_page(): void {
    $table = new TeckGlobal_BFP_IP_Table();
    $table->prepare_items();
    if (isset($_GET['unbanned']) && $_GET['unbanned'] == 1) {
        echo '<div class="updated"><p>IP unbanned successfully.</p></div>';
    }
    ?>
    <div class="wrap">
        <h1>IP Logs</h1>
        <form method="get">
            <input type="hidden" name="page" value="teckglobal-bfp-ip-logs">
            <?php $table->search_box('Search IPs', 'search_id'); ?>
        </form>
        <?php $table->display(); ?>
    </div>
    <?php
}

function teckglobal_bfp_geo_map_page(): void {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $ips = $wpdb->get_results(
        "SELECT ip, country, latitude, longitude, COUNT(*) as count 
         FROM $table_name 
         WHERE latitude IS NOT NULL AND longitude IS NOT NULL AND banned = 1 
         GROUP BY ip, country, latitude, longitude",
        ARRAY_A
    );
    $locations = json_encode($ips);
    ?>
    <div class="wrap">
        <h1>Geolocation Map</h1>
        <div id="map" style="height: 600px; width: 100%;"></div>
        <script>
            document.addEventListener('DOMContentLoaded', function() {
                console.log('Map page loaded. Locations:', <?php echo $locations; ?>);
                if (typeof L === 'undefined') { console.error('Leaflet.js not loaded!'); return; }
                var locations = <?php echo $locations; ?>;
                var map = L.map('map').setView([0, 0], 2);
                L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors' }).addTo(map);
                locations.forEach(function(location) {
                    if (location.latitude && location.longitude) {
                        var marker = L.marker([location.latitude, location.longitude]).addTo(map);
                        marker.bindPopup('<b>IP:</b> ' + location.ip + '<br><b>Country:</b> ' + location.country + '<br><b>Attempts:</b> ' + location.count);
                        console.log('Marker added:', location.ip, location.latitude, location.longitude);
                    } else {
                        console.warn('Invalid coordinates for IP:', location.ip);
                    }
                });
                if (locations.length > 0) {
                    var bounds = locations.map(function(loc) { return [loc.latitude, loc.longitude]; }).filter(function(coord) { return coord[0] && coord[1]; });
                    if (bounds.length > 0) { map.fitBounds(bounds); console.log('Map bounds set to:', bounds); }
                    else { console.warn('No valid bounds to fit.'); }
                } else { console.warn('No locations to display.'); }
            });
        </script>
    </div>
    <?php
}