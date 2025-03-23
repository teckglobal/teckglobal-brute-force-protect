<?php
if (!defined('ABSPATH')) {
    exit;
}

use RobThree\Auth\TwoFactorAuth;

/**
 * Check if the Pro version is active (simplified for this example).
 * In a real plugin, this would validate a license key.
 */
function teckglobal_bfp_is_pro(): bool {
    $license_key = get_option('teckglobal_bfp_license_key', '');
    if (empty($license_key)) {
        return false;
    }
    // Hardcoded test keys for now (replace with real ones as you sell)
    $valid_keys = [
        'TG-BFP-TEST-1234-5678', // Test key for you
        'TG-BFP-0001-ABCD-EFGH'  // Example sold key
    ];
    return in_array($license_key, $valid_keys);
}
//function teckglobal_bfp_is_pro(): bool {
//    $license_key = get_option('teckglobal_bfp_license_key', '');
//    return !empty($license_key);
//}

/**
 * Get the client's IP address.
 */
function teckglobal_bfp_get_client_ip(): string {
    $ip = '';
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = sanitize_text_field(wp_unslash($_SERVER['HTTP_CLIENT_IP']));
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR']));
    } else {
        $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''));
    }
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : 'unknown';
}

/**
 * Check if an IP is banned.
 */
function teckglobal_bfp_is_ip_banned(string $ip): bool {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';

    $whitelist_ips = array_filter(array_map('trim', explode("\n", get_option('teckglobal_bfp_whitelist_ips', ''))));
    if (in_array($ip, $whitelist_ips)) {
        return false;
    }

    $excluded_ips = get_option('teckglobal_bfp_excluded_ips', []);
    foreach ($excluded_ips as $excluded) {
        if (teckglobal_bfp_ip_in_range($ip, $excluded['ip'])) {
            return false;
        }
    }

    $log = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table_name WHERE ip = %s", $ip));
    if (!$log || !$log->banned) {
        return false;
    }

    if ($log->ban_expiry && current_time('mysql') > $log->ban_expiry) {
        teckglobal_bfp_unban_ip($ip);
        return false;
    }

    return true;
}

/**
 * Ban an IP address.
 */
function teckglobal_bfp_ban_ip(string $ip, string $reason = 'brute_force'): void {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';

    $ban_time = get_option('teckglobal_bfp_ban_time', '60-minutes');
    $minutes = (int) str_replace('-minutes', '', $ban_time);
    $ban_expiry = date('Y-m-d H:i:s', strtotime(current_time('mysql') . " + $minutes minutes"));

    $data = [
        'ip' => $ip,
        'timestamp' => current_time('mysql'),
        'attempts' => 0,
        'banned' => 1,
        'ban_expiry' => $ban_expiry,
        'user_agent' => sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'))
    ];

    if ($reason === 'scan_exploit') {
        $data['scan_exploit'] = 1;
    } elseif ($reason === 'brute_force') {
        $data['brute_force'] = 1;
    } elseif ($reason === 'manual_ban') {
        $data['manual_ban'] = 1;
    }

    $geo_data = teckglobal_bfp_get_ip_location($ip);
    if ($geo_data) {
        $data['country'] = $geo_data['country'];
        $data['latitude'] = $geo_data['latitude'];
        $data['longitude'] = $geo_data['longitude'];
    }

    $existing = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table_name WHERE ip = %s", $ip));
    if ($existing) {
        $wpdb->update($table_name, $data, ['ip' => $ip]);
    } else {
        $wpdb->insert($table_name, $data);
    }

    if (get_option('teckglobal_bfp_enable_notifications', 0) && get_option('teckglobal_bfp_notify_on_ban', 1)) {
        $email = get_option('teckglobal_bfp_notification_email', get_option('admin_email'));
        $subject = __('IP Banned', 'teckglobal-brute-force-protect');
        $message = sprintf(__('IP %s was banned due to %s.', 'teckglobal-brute-force-protect'), $ip, $reason);
        wp_mail($email, $subject, $message);
    }
}

/**
 * Unban an IP address.
 */
function teckglobal_bfp_unban_ip(string $ip): void {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $wpdb->update($table_name, ['banned' => 0, 'ban_expiry' => null], ['ip' => $ip]);
}

/**
 * Log a failed attempt for an IP.
 */
function teckglobal_bfp_log_attempt(string $ip): void {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';

    if (!get_option('teckglobal_bfp_enable_logging', 1)) {
        return;
    }

    $existing = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table_name WHERE ip = %s", $ip));
    if ($existing) {
        $wpdb->update(
            $table_name,
            [
                'attempts' => $existing->attempts + 1,
                'timestamp' => current_time('mysql'),
                'user_agent' => sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'))
            ],
            ['ip' => $ip]
        );
    } else {
        $data = [
            'ip' => $ip,
            'timestamp' => current_time('mysql'),
            'attempts' => 1,
            'banned' => 0,
            'user_agent' => sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'))
        ];
        $geo_data = teckglobal_bfp_get_ip_location($ip);
        if ($geo_data) {
            $data['country'] = $geo_data['country'];
            $data['latitude'] = $geo_data['latitude'];
            $data['longitude'] = $geo_data['longitude'];
        }
        $wpdb->insert($table_name, $data);
    }
}

/**
 * Get the number of attempts left before an IP is banned.
 */
function teckglobal_bfp_get_attempts_left(string $ip): int {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $max_attempts = get_option('teckglobal_bfp_max_attempts', 5);
    if (get_option('teckglobal_bfp_exploit_protection', 0)) {
        $max_attempts = min($max_attempts, (int) get_option('teckglobal_bfp_exploit_max_attempts', 5));
    }

    $log = $wpdb->get_row($wpdb->prepare("SELECT attempts FROM $table_name WHERE ip = %s", $ip));
    return $log ? max(0, $max_attempts - (int) $log->attempts) : $max_attempts;
}

/**
 * Check rate limiting for an IP.
 */
function teckglobal_bfp_check_rate_limit(string $ip): bool {
    if (!get_option('teckglobal_bfp_enable_rate_limit', 0)) {
        return true;
    }

    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $rate_limit_attempts = (int) get_option('teckglobal_bfp_rate_limit_attempts', 3);
    $rate_limit_interval = (int) get_option('teckglobal_bfp_rate_limit_interval', 60);

    $log = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table_name WHERE ip = %s", $ip));
    if (!$log) {
        return true;
    }

    $time_diff = strtotime(current_time('mysql')) - strtotime($log->timestamp);
    if ($time_diff < $rate_limit_interval && $log->attempts >= $rate_limit_attempts) {
        return false;
    }

    if ($time_diff >= $rate_limit_interval) {
        $wpdb->update($table_name, ['attempts' => 0], ['ip' => $ip]);
    }

    return true;
}

/**
 * Get IP location using MaxMind GeoLite2.
 */
function teckglobal_bfp_get_ip_location(string $ip): ?array {
    if (!file_exists(TECKGLOBAL_BFP_GEO_FILE)) {
        return null;
    }

    try {
        $reader = new \MaxMind\Db\Reader(TECKGLOBAL_BFP_GEO_FILE);
        $record = $reader->get($ip);
        $reader->close();

        if (!$record) {
            return null;
        }

        return [
            'country' => $record['country']['names']['en'] ?? 'Unknown',
            'latitude' => $record['location']['latitude'] ?? null,
            'longitude' => $record['location']['longitude'] ?? null
        ];
    } catch (Exception $e) {
        if (get_option('teckglobal_bfp_enable_debug_log', 0)) {
            error_log('TeckGlobal BFP GeoIP Error: ' . $e->getMessage());
        }
        return null;
    }
}

/**
 * Get the country of an IP.
 */
function teckglobal_bfp_get_ip_country(string $ip): ?string {
    $location = teckglobal_bfp_get_ip_location($ip);
    return $location['country'] ?? null;
}

/**
 * Get IP logs with pagination.
 */
function teckglobal_bfp_get_ip_logs(int $limit, int $page, bool $banned_only = false): array {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_logs';
    $offset = ($page - 1) * $limit;

    $where = $banned_only ? 'WHERE banned = 1' : '';
    $total = $wpdb->get_var("SELECT COUNT(*) FROM $table_name $where");
    $logs = $wpdb->get_results($wpdb->prepare("SELECT * FROM $table_name $where ORDER BY timestamp DESC LIMIT %d OFFSET %d", $limit, $offset));

    return [
        'logs' => $logs,
        'pages' => ceil($total / $limit)
    ];
}

/**
 * Check if an IP is in a given range (supports CIDR).
 */
function teckglobal_bfp_ip_in_range(string $ip, string $range): bool {
    if (strpos($range, '/') === false) {
        return $ip === $range;
    }

    list($subnet, $bits) = explode('/', $range);
    $ip = ip2long($ip);
    $subnet = ip2long($subnet);
    $mask = -1 << (32 - $bits);
    $subnet &= $mask;
    return ($ip & $mask) === $subnet;
}

/**
 * Get a list of countries (simplified for this example).
 */
function teckglobal_bfp_get_countries(): array {
    return [
        'US' => 'United States',
        'CA' => 'Canada',
        'GB' => 'United Kingdom',
        'DE' => 'Germany',
        'FR' => 'France',
        'CN' => 'China',
        'RU' => 'Russia',
    ];
}

/**
 * Verify a 2FA code using robthree/twofactorauth.
 */
function teckglobal_bfp_verify_2fa_code(int $user_id, string $code): bool {
    $tfa = new TwoFactorAuth('TeckGlobal Brute Force Protect');
    $secret = get_user_meta($user_id, 'teckglobal_bfp_2fa_secret', true);
    if (empty($secret)) {
        return false;
    }
    return $tfa->verifyCode($secret, $code);
}

/**
 * Generate a new 2FA secret.
 */
function teckglobal_bfp_generate_2fa_secret(): string {
    $tfa = new TwoFactorAuth('TeckGlobal Brute Force Protect');
    return $tfa->createSecret();
}

/**
 * Get QR code URL for 2FA setup.
 */
function teckglobal_bfp_get_2fa_qr_code_url(string $secret, string $username): string {
    $tfa = new TwoFactorAuth('TeckGlobal Brute Force Protect');
    return $tfa->getQRCodeImageAsDataUri($username, $secret);
}

/**
 * Get WAF rules.
 */
function teckglobal_bfp_get_waf_rules(): array {
    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_waf_rules';
    return $wpdb->get_results("SELECT * FROM $table_name");
}

/**
 * Check threat feeds (simplified for this example).
 */
function teckglobal_bfp_check_threat_feed(string $ip): bool {
    if (!teckglobal_bfp_is_pro()) {
        return false;
    }

    $threat_feeds = get_option('teckglobal_bfp_threat_feeds', ['abuseipdb' => 0, 'project_honeypot' => 0]);
    $abuseipdb_key = get_option('teckglobal_bfp_abuseipdb_key', '');
    $confidence_score = (int) get_option('teckglobal_bfp_abuseipdb_confidence_score', 75);

    if ($threat_feeds['abuseipdb'] && $abuseipdb_key) {
        $response = wp_remote_get("https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=90", [
            'headers' => ['Key' => $abuseipdb_key, 'Accept' => 'application/json']
        ]);

        if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200) {
            $body = json_decode(wp_remote_retrieve_body($response), true);
            if (isset($body['data']['abuseConfidenceScore']) && $body['data']['abuseConfidenceScore'] >= $confidence_score) {
                return true;
            }
        }
    }

    // Add Project Honeypot check if enabled
    return false;
}

/**
 * Log live traffic (Pro feature).
 */
function teckglobal_bfp_log_live_traffic(string $ip): void {
    if (!teckglobal_bfp_is_pro()) {
        return;
    }

    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_live_traffic';
    $url = esc_url_raw($_SERVER['REQUEST_URI'] ?? '');
    $method = sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'] ?? 'GET'));
    $user_agent = sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'));

    $wpdb->insert($table_name, [
        'ip' => $ip,
        'timestamp' => current_time('mysql'),
        'url' => $url,
        'method' => $method,
        'user_agent' => $user_agent
    ]);
}

/**
 * Get live traffic logs (Pro feature).
 */
function teckglobal_bfp_get_live_traffic(int $limit): array {
    if (!teckglobal_bfp_is_pro()) {
        return [];
    }

    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_live_traffic';
    return $wpdb->get_results($wpdb->prepare("SELECT * FROM $table_name ORDER BY timestamp DESC LIMIT %d", $limit));
}

/**
 * Log user activity (Pro feature).
 */
function teckglobal_bfp_log_user_activity(int $user_id, string $action, string $ip, string $details = ''): void {
    if (!teckglobal_bfp_is_pro()) {
        return;
    }

    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_user_activity';
    $wpdb->insert($table_name, [
        'user_id' => $user_id,
        'action' => $action,
        'timestamp' => current_time('mysql'),
        'ip' => $ip,
        'details' => $details
    ]);
}

/**
 * Get user activity logs (Pro feature).
 */
function teckglobal_bfp_get_user_activity(int $limit, int $page): array {
    if (!teckglobal_bfp_is_pro()) {
        return ['logs' => [], 'pages' => 0];
    }

    global $wpdb;
    $table_name = $wpdb->prefix . 'teckglobal_bfp_user_activity';
    $offset = ($page - 1) * $limit;

    $total = $wpdb->get_var("SELECT COUNT(*) FROM $table_name");
    $logs = $wpdb->get_results($wpdb->prepare("SELECT * FROM $table_name ORDER BY timestamp DESC LIMIT %d OFFSET %d", $limit, $offset));

    return [
        'logs' => $logs,
        'pages' => ceil($total / $limit)
    ];
}

/**
 * Run a malware scan (Pro feature, simplified for this example).
 */
function teckglobal_bfp_run_malware_scan(): array {
    if (!teckglobal_bfp_is_pro()) {
        return ['issues' => []];
    }

    $issues = [];
    $patterns = [
        '/eval\(/i' => 'Potential eval() usage',
        '/base64_decode\(/i' => 'Potential base64_decode() usage',
        '/exec\(/i' => 'Potential exec() usage'
    ];

    $dirs = [ABSPATH . 'wp-content/plugins', ABSPATH . 'wp-content/themes'];
    foreach ($dirs as $dir) {
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir));
        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $content = file_get_contents($file->getPathname());
                foreach ($patterns as $pattern => $desc) {
                    if (preg_match($pattern, $content)) {
                        $issues[] = [
                            'file' => str_replace(ABSPATH, '', $file->getPathname()),
                            'issue' => $desc
                        ];
                    }
                }
            }
        }
    }

    return ['issues' => $issues, 'timestamp' => current_time('mysql')];
}

/**
 * Scan file permissions.
 */
function teckglobal_bfp_scan_file_permissions(): array {
    $issues = [];
    $files_to_check = [
        ABSPATH . 'wp-config.php' => 0640,
        ABSPATH . '.htaccess' => 0644,
        ABSPATH . 'wp-content' => 0755,
        ABSPATH . 'wp-content/plugins' => 0755,
        ABSPATH . 'wp-content/themes' => 0755
    ];

    foreach ($files_to_check as $path => $recommended) {
        if (!file_exists($path)) {
            continue;
        }

        $perms = fileperms($path) & 0777;
        if ($perms !== $recommended) {
            $issues[] = [
                'path' => str_replace(ABSPATH, '', $path),
                'current_perms' => sprintf('%o', $perms),
                'recommended_perms' => sprintf('%o', $recommended),
                'owner_group' => function_exists('posix_getpwuid') ? posix_getpwuid(fileowner($path))['name'] . '/' . posix_getgrgid(filegroup($path))['name'] : 'Unknown'
            ];
        }
    }

    return $issues;
}

/**
 * Fix file permissions (Pro feature).
 */
function teckglobal_bfp_fix_file_permissions(string $file, int $perms): bool {
    if (!teckglobal_bfp_is_pro()) {
        return false;
    }

    $full_path = ABSPATH . ltrim($file, '/');
    return @chmod($full_path, octdec($perms));
}

/**
 * Export plugin settings.
 */
function teckglobal_bfp_export_settings(): void {
    $settings = [];
    $options = [
        'teckglobal_bfp_max_attempts',
        'teckglobal_bfp_ban_time',
        'teckglobal_bfp_auto_ban_invalid',
        'teckglobal_bfp_excluded_ips',
        'teckglobal_bfp_exploit_protection',
        'teckglobal_bfp_exploit_max_attempts',
        'teckglobal_bfp_maxmind_key',
        'teckglobal_bfp_remove_data',
        'teckglobal_bfp_enable_logging',
        'teckglobal_bfp_block_message',
        'teckglobal_bfp_enable_debug_log',
        'teckglobal_bfp_whitelist_ips',
        'teckglobal_bfp_enable_notifications',
        'teckglobal_bfp_notification_email',
        'teckglobal_bfp_notify_on_ban',
        'teckglobal_bfp_notify_on_attempts',
        'teckglobal_bfp_notify_on_threat',
        'teckglobal_bfp_enable_captcha',
        'teckglobal_bfp_recaptcha_site_key',
        'teckglobal_bfp_recaptcha_secret_key',
        'teckglobal_bfp_enable_rate_limit',
        'teckglobal_bfp_rate_limit_attempts',
        'teckglobal_bfp_rate_limit_interval',
        'teckglobal_bfp_threat_feeds',
        'teckglobal_bfp_abuseipdb_key',
        'teckglobal_bfp_project_honeypot_key',
        'teckglobal_bfp_manage_ips_per_page',
        'teckglobal_bfp_ip_logs_per_page',
        'teckglobal_bfp_show_banned_only',
        'teckglobal_bfp_login_banner_message',
        'teckglobal_bfp_blocked_countries',
        'teckglobal_bfp_enable_2fa',
        'teckglobal_bfp_password_policy',
        'teckglobal_bfp_min_password_length',
        'teckglobal_bfp_require_special_chars',
        'teckglobal_bfp_security_headers',
        'teckglobal_bfp_abuseipdb_confidence_score'
    ];

    foreach ($options as $option) {
        $settings[$option] = get_option($option);
    }

    $filename = 'teckglobal-bfp-settings-' . date('Y-m-d-H-i-s') . '.json';
    header('Content-Type: application/json');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    echo wp_json_encode($settings);
    exit;
}

/**
 * Import plugin settings.
 */
function teckglobal_bfp_import_settings(): void {
    if (!isset($_FILES['import_file']) || $_FILES['import_file']['error'] !== UPLOAD_ERR_OK) {
        return;
    }

    $file = $_FILES['import_file']['tmp_name'];
    $content = file_get_contents($file);
    $settings = json_decode($content, true);

    if (!$settings) {
        return;
    }

    foreach ($settings as $option => $value) {
        update_option($option, $value);
    }
}

/**
 * Download GeoIP database.
 */
function teckglobal_bfp_download_geoip(): void {
    $maxmind_key = get_option('teckglobal_bfp_maxmind_key', '');
    if (!$maxmind_key) {
        return;
    }

    if (!file_exists(TECKGLOBAL_BFP_GEO_DIR)) {
        wp_mkdir_p(TECKGLOBAL_BFP_GEO_DIR);
    }

    $url = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=$maxmind_key&suffix=tar.gz";
    $response = wp_remote_get($url, ['timeout' => 30]);

    if (is_wp_error($response)) {
        if (get_option('teckglobal_bfp_enable_debug_log', 0)) {
            error_log('TeckGlobal BFP GeoIP Download Error: ' . $response->get_error_message());
        }
        return;
    }

    $body = wp_remote_retrieve_body($response);
    $temp_file = TECKGLOBAL_BFP_GEO_DIR . '/GeoLite2-City.tar.gz';
    file_put_contents($temp_file, $body);

    $phar = new PharData($temp_file);
    $phar->extractTo(TECKGLOBAL_BFP_GEO_DIR, null, true);

    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(TECKGLOBAL_BFP_GEO_DIR));
    foreach ($iterator as $file) {
        if ($file->getExtension() === 'mmdb') {
            rename($file->getPathname(), TECKGLOBAL_BFP_GEO_FILE);
            break;
        }
    }

    unlink($temp_file);
    $extracted_dir = glob(TECKGLOBAL_BFP_GEO_DIR . '/GeoLite2-City_*', GLOB_ONLYDIR);
    foreach ($extracted_dir as $dir) {
        teckglobal_bfp_remove_dir($dir);
    }

    update_option('teckglobal_bfp_last_geoip_download', current_time('mysql'));
}

/**
 * Remove a directory and its contents.
 */
function teckglobal_bfp_remove_dir(string $dir): void {
    if (!file_exists($dir)) {
        return;
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );

    foreach ($iterator as $file) {
        if ($file->isDir()) {
            rmdir($file->getPathname());
        } else {
            unlink($file->getPathname());
        }
    }

    rmdir($dir);
}

?>
