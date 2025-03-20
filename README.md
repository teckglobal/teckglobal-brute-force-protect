# TeckGlobal Brute Force Protect

A WordPress plugin by TeckGlobal LLC and xAI's Grok to protect your site from brute force login attacks and exploit scans.

- **Plugin URI**: [https://teck-global.com/wordpress-plugins/](https://teck-global.com/wordpress-plugins/)
- **Author**: TeckGlobal LLC, xAI-Grok
- **Version**: 1.1.2
- **License**: GPL-2.0+
- **Requires**: WordPress 5.0+, PHP 7.4+
- **Tested Up To**: WordPress 6.7.2

## Description

TeckGlobal Brute Force Protect secures your WordPress site by blocking IPs after excessive login attempts or exploit scans. It offers geolocation tracking, IP management, a dashboard widget, customizable block messages, visual login feedback, debug logging, an IP whitelist, real-time notifications, CAPTCHA integration, rate limiting, multiple threat intelligence feeds (AbuseIPDB and Project Honeypot), user agent logging, and settings export/import. Support this free plugin with a donation at [TeckGlobal's Buy Me a Coffee](https://teck-global.com/buy-me-a-coffee/).

## Features

- **Brute Force Protection**: Bans IPs after a configurable number of failed logins (default: 5).
- **Exploit Scan Detection**: Blocks attempts to access sensitive files/endpoints (e.g., `/wp-config.php`).
- **Geolocation**: Maps IPs using MaxMind GeoLite2 (requires a free license key).
- **IP Management**: Ban/unban IPs manually, exclude subnets, whitelist trusted IPs.
- **Dashboard Widget**: Displays daily blocked attempts and top IPs.
- **Custom Block Message**: Set a personalized message for banned users.
- **Visual Feedback**: Login form shakes with a red border for banned IPs.
- **Debug Logging**: Toggle logs (`teckglobal-bfp-debug.log`, `teckglobal-bfp-detailed.log`).
- **Auto-Updates**: GitHub-based updates with a toggle on the Plugins page.
- **Real-Time Notifications**: Email alerts for ban events (v1.1.0).
- **CAPTCHA Integration**: Adds Google reCAPTCHA v2 to the login form (v1.1.0).
- **Rate Limiting**: Limits login attempts within a time frame (v1.1.0).
- **Multiple Threat Intelligence**: Integrates with AbuseIPDB and Project Honeypot, selectable via settings (v1.1.1).
- **User Agent Logging**: Records user agents with each attempt for analysis (v1.1.0).
- **Settings Export/Import**: Backup and restore plugin settings (v1.1.0).

## Installation

1. **Download**: Get the ZIP from [GitHub Releases](https://github.com/teckglobal/teckglobal-brute-force-protect/releases) or WordPress.org.
2. **Install**: Upload via `Plugins > Add New > Upload Plugin` and activate.
3. **Configure**: Go to `TeckGlobal BFP > Settings` to customize options.
4. **Optional Integrations**:
   - **Geolocation**: Add a [MaxMind License Key](https://www.maxmind.com/en/geolite2/signup).
   - **CAPTCHA**: Get [Google reCAPTCHA keys](https://www.google.com/recaptcha).
   - **Threat Feeds**: Obtain an [AbuseIPDB API Key](https://www.abuseipdb.com/register) and/or a [Project Honeypot API Key](https://www.projecthoneypot.org/httpbl_configure.php).

## Settings and Usage

Configure all options under **TeckGlobal BFP > Settings**. Here’s what each setting does, how to adjust it, and how to verify it works:

### General Settings

1. **Max Login Attempts**
   - **Purpose**: Number of failed logins before an IP is banned.
   - **Default**: 5
   - **Adjust**: Enter a number (e.g., 8).
   - **Verify**: Fail logins from a test IP beyond this limit. Check `IP Logs & Map`—IP should be banned (red icon).

2. **Ban Duration**
   - **Purpose**: How long a ban lasts.
   - **Default**: 60 minutes
   - **Options**: 15 min, 30 min, 1 hr, 3 hrs, 1 day, 3 days, 1 week
   - **Adjust**: Select from the dropdown.
   - **Verify**: Ban an IP, note the "Ban Expiry" in `IP Logs & Map`, then test access after it expires.

3. **Auto-Ban Invalid Usernames**
   - **Purpose**: Instantly bans IPs using non-existent usernames.
   - **Default**: Off
   - **Adjust**: Check to enable.
   - **Verify**: Login with a fake username (e.g., `fakeuser`). Check `IP Logs & Map`—IP should be banned.

4. **Excluded IPs**
   - **Purpose**: Excludes IPs/subnets from protection (e.g., for admins).
   - **Default**: Empty
   - **Adjust**: Add IPs (e.g., `192.168.1.1`) or subnets (e.g., `10.0.0.0/24`) with notes.
   - **Verify**: Add a test IP, exceed login attempts—it shouldn’t be banned in `IP Logs & Map`.

5. **Enable Exploit Protection**
   - **Purpose**: Bans IPs scanning for vulnerabilities.
   - **Default**: Off
   - **Adjust**: Check to enable.
   - **Verify**: Request `your-site.com/phpMyAdmin` from a test IP beyond "Max Exploit Attempts." Check `IP Logs & Map` for a ban.

6. **Max Exploit Attempts**
   - **Purpose**: Number of exploit attempts before a ban.
   - **Default**: 3
   - **Adjust**: Enter a number (e.g., 5).
   - **Verify**: With exploit protection on, hit suspicious URLs—ban should trigger after this limit.

7. **MaxMind License Key**
   - **Purpose**: Enables geolocation data for IPs.
   - **Default**: Empty
   - **Adjust**: Sign up at [MaxMind](https://www.maxmind.com/en/geolite2/signup), get a key, and enter it.
   - **Verify**: Add a key, trigger a login attempt, then check `IP Logs & Map` for country/coordinates.

8. **Remove Data on Deactivation**
   - **Purpose**: Deletes plugin data when deactivated.
   - **Default**: Off
   - **Adjust**: Check to enable.
   - **Verify**: Enable, deactivate, reactivate—settings and logs should reset.

9. **Enable Debug Logging**
   - **Purpose**: Logs activity to `wp-content/teckglobal-bfp-debug.log`.
   - **Default**: Off
   - **Adjust**: Check to enable.
   - **Verify**: Enable, trigger an action (e.g., failed login), check the log file.

10. **Block Message**
    - **Purpose**: Message shown to banned IPs.
    - **Default**: "Your IP has been banned due to suspicious activity. Please contact the site administrator."
    - **Adjust**: Enter a custom message.
    - **Verify**: Ban a test IP, visit the site—see your message.

11. **Enable Detailed Debug Log**
    - **Purpose**: Logs detailed data to `wp-content/teckglobal-bfp-detailed.log`.
    - **Default**: Off
    - **Adjust**: Check to enable.
    - **Verify**: Enable, trigger an action, check the detailed log.

12. **IP Whitelist**
    - **Purpose**: Bypasses checks for listed IPs.
    - **Default**: Empty
    - **Adjust**: Enter IPs (e.g., `192.168.1.1`), one per line.
    - **Verify**: Add a test IP, exceed limits—it shouldn’t be banned.

### Advanced Features

1. **Enable Notifications**
   - **Purpose**: Emails you when an IP is banned.
   - **Default**: Off
   - **Adjust**: Check to enable.
   - **Verify**: Enable, ban an IP, check your email.

2. **Notification Email**
   - **Purpose**: Email address for notifications.
   - **Default**: Admin email
   - **Adjust**: Enter an email (e.g., `alerts@your-site.com`).
   - **Verify**: Set an email, ban an IP, confirm receipt.

3. **Enable CAPTCHA**
   - **Purpose**: Adds reCAPTCHA to `wp-login.php` to block bots.
   - **Default**: Off
   - **Adjust**: Check to enable (requires keys).
   - **Verify**: Enable with keys, visit `wp-login.php`—see the CAPTCHA widget.

4. **reCAPTCHA Site Key & Secret Key**
   - **Purpose**: Integrates Google reCAPTCHA v2.
   - **Default**: Empty
   - **Adjust**: 
     1. Visit [Google reCAPTCHA](https://www.google.com/recaptcha).
     2. Sign in, click "Admin Console," then "+".
     3. Choose "reCAPTCHA v2" > "Checkbox," add your domain, submit.
     4. Copy the Site Key and Secret Key here.
   - **Verify**: Add keys, enable CAPTCHA, check `wp-login.php`—CAPTCHA should appear.

5. **Enable Rate Limiting**
   - **Purpose**: Limits login attempts per IP in a time window.
   - **Default**: Off
   - **Adjust**: Check to enable.
   - **Verify**: Enable, exceed "Rate Limit Attempts" within "Interval"—attempts should block early.

6. **Rate Limit Attempts**
   - **Purpose**: Number of attempts allowed in the interval.
   - **Default**: 3
   - **Adjust**: Enter a number (e.g., 4).
   - **Verify**: Exceed this within the interval—see a block message.

7. **Rate Limit Interval (seconds)**
   - **Purpose**: Time window for rate limiting.
   - **Default**: 60
   - **Adjust**: Enter seconds (e.g., 120).
   - **Verify**: Exceed attempts, wait out the interval—attempts should resume.

8. **Enable Threat Feeds**
   - **Purpose**: Bans IPs flagged by selected threat feeds (AbuseIPDB, Project Honeypot).
   - **Default**: Off (both feeds unchecked)
   - **Adjust**: Check one or both boxes to enable (requires respective API keys).
   - **Verify**: Enable with keys, use a malicious IP (check [AbuseIPDB](https://www.abuseipdb.com/check) or [Project Honeypot](https://www.projecthoneypot.org/search_ip.php)), attempt login—IP should be banned instantly with "threat_feed" reason in logs.

9. **AbuseIPDB API Key**
   - **Purpose**: Queries AbuseIPDB for threat data (bans IPs with a confidence score ≥ 75).
   - **Default**: Empty
   - **Adjust**: 
     1. Register at [AbuseIPDB](https://www.abuseipdb.com/register).
     2. Go to "API" > "Create Key," name it, copy the key.
     3. Paste it here.
   - **Verify**: Add a key, enable AbuseIPDB feed, test with a reported IP—check `IP Logs & Map` for a "threat_feed" ban.

10. **Project Honeypot API Key**
    - **Purpose**: Queries Project Honeypot via HTTP:BL for threat data (bans IPs with a threat score > 0).
    - **Default**: Empty
    - **Adjust**: 
      1. Register at [Project Honeypot](https://www.projecthoneypot.org/httpbl_configure.php).
      2. Sign up, activate HTTP:BL, generate an API key, copy it.
      3. Paste it here.
    - **Verify**: Add a key, enable Project Honeypot feed, test with a flagged IP—check `IP Logs & Map` for a "threat_feed" ban.

### Export/Import Settings
- **Purpose**: Backup or restore settings.
- **Adjust**: Click "Export" to download a `.json` file, or upload one and click "Import."
- **Verify**: Export, change a setting, import—original value should return.

## Monitoring

- **Dashboard Widget**: See daily stats and top blocked IPs.
- **IP Logs & Map**: View all attempts, ban status, geolocation, and user agents on a Leaflet map (`TeckGlobal BFP > IP Logs & Map`).
- **Manage IPs**: Ban/unban IPs manually (`TeckGlobal BFP > Manage IPs`).

## Troubleshooting

- Enable "Debug Logging" and check `wp-content/teckglobal-bfp-debug.log`.
- Clear caches if settings don’t apply.
- Visit [TeckGlobal Support](https://teck-global.com/support/) or [GitHub Issues](https://github.com/teckglobal/teckglobal-brute-force-protect/issues).

## Changelog

### 1.1.2
- Improved settings page with detailed descriptions and links for AbuseIPDB, reCAPTCHA, and MaxMind.
- Enhanced "View Details" popup on the WordPress Plugins page with local images and more info.

### 1.1.1
- Enhanced threat intelligence with multiple feed support (AbuseIPDB and Project Honeypot) and a selector in settings.

### 1.1.0
- Real-time email notifications.
- Google reCAPTCHA integration.
- Rate limiting for login attempts.
- AbuseIPDB threat intelligence.
- User agent logging.
- Settings export/import.

### 1.0.3
- Dashboard widget for stats.
- Custom block message.
- Visual login feedback (shake animation).
- Detailed debug log toggle.
- IP whitelist.
- UI/documentation updates.

### 1.0.2
- Improved GeoIP download stability.
- Fixed auto-update toggle UI.

### 1.0.1
- Added exploit scan protection.
- Optimized database queries.

### 1.0.0
- Initial release with brute force and geolocation.

## License

[GNU General Public License v2](http://www.gnu.org/licenses/gpl-2.0.txt) or later.

## Credits

- **TeckGlobal LLC**: [https://teck-global.com/](https://teck-global.com/)
- **xAI's Grok**: AI-assisted development
- **MaxMind GeoLite2**: Geolocation data
- **AbuseIPDB**: Threat intelligence
- **Project Honeypot**: Threat intelligence via HTTP:BL

## Donate

Support us at [TeckGlobal's Buy Me a Coffee](https://teck-global.com/buy-me-a-coffee/).
