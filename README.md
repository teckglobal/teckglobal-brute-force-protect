# TeckGlobal Brute Force Protect

A WordPress plugin by TeckGlobal LLC and xAI's Grok to protect your site from brute force login attacks and exploit scans.

- **Plugin URI**: [https://teck-global.com/wordpress-plugins/](https://teck-global.com/wordpress-plugins/)
- **Author**: TeckGlobal LLC, xAI-Grok
- **Version**: 1.1.2
- **License**: GPL-2.0+
- **Requires**: WordPress 5.0+, PHP 7.4+
- **Tested Up To**: WordPress 6.7.2

## Description

**TeckGlobal Brute Force Protect** is a powerful, free, and open-source WordPress plugin designed to secure your site against brute force login attacks and exploit scans. Built by TeckGlobal LLC with assistance from xAI's Grok, it offers advanced features like IP management, real-time geolocation with MaxMind GeoLite2, and integration with threat intelligence feeds (AbuseIPDB and Project Honeypot). Additional tools include a dashboard widget, customizable block messages, visual login feedback, debug logging, IP whitelisting, email notifications, Google reCAPTCHA v2, rate limiting, user agent logging, and settings export/import. Support this community-driven project at [TeckGlobal's Buy Me a Coffee](https://teck-global.com/buy-me-a-coffee/).

**Why Choose This Plugin?**
- **Robust Security**: Stops brute force attacks and exploit scans in their tracks.
- **Actionable Insights**: Maps attack origins and tracks user agents for analysis.
- **Threat Intelligence**: Preemptively bans known bad actors with AbuseIPDB and Project Honeypot.
- **Ease of Use**: Simple setup with powerful monitoring tools.
- **Community-Driven**: Free to use, with donations fueling ongoing improvements.

## Features

- **Brute Force Protection**: Bans IPs after excessive login attempts (default: 5).
- **Exploit Scan Detection**: Blocks attempts to access sensitive files (e.g., `/wp-config.php`).
- **Geolocation**: Maps IPs using MaxMind GeoLite2 (requires a free license key).
- **IP Management**: Manual ban/unban, exclude subnets, whitelist trusted IPs.
- **Dashboard Widget**: Displays daily blocked attempts and top IPs.
- **Custom Block Message**: Personalize messages for banned users.
- **Visual Feedback**: Login form shakes for banned IPs.
- **Debug Logging**: Toggle logs (`teckglobal-bfp-debug.log`, `teckglobal-bfp-detailed.log`).
- **Auto-Updates**: GitHub-based updates with a toggle on the Plugins page.
- **Real-Time Notifications**: Email alerts for ban events (v1.1.0).
- **CAPTCHA Integration**: Adds Google reCAPTCHA v2 to the login form (v1.1.0).
- **Rate Limiting**: Limits login attempts within a time frame (v1.1.0).
- **Multiple Threat Intelligence**: Integrates with AbuseIPDB and Project Honeypot (v1.1.1).
- **User Agent Logging**: Records user agents for analysis (v1.1.0).
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

Configure all options under **TeckGlobal BFP > Settings**. See the [readme.txt](readme.txt) for detailed instructions on each setting, including how to adjust and verify them.

## FAQ

- **How does it detect brute force attacks?**  
  It tracks failed logins per IP and bans them after exceeding the limit (default: 5). "Auto-Ban Invalid Usernames" catches fake logins instantly.

- **Can I customize the ban message?**  
  Yes, set it in `Settings > Block Message`—it’s shown to banned IPs.

- **What’s geolocation for?**  
  With a MaxMind key, it maps IP locations on `IP Logs & Map`, revealing attack origins.

- **How do threat feeds work?**  
  AbuseIPDB and Project Honeypot auto-ban high-risk IPs with API keys enabled in settings.

- **Why use CAPTCHA?**  
  It adds reCAPTCHA v2 to `wp-login.php`, stopping bots. Requires Google keys.

- **What’s rate limiting?**  
  It limits login attempts in a time window (e.g., 3 in 60 seconds), thwarting rapid attacks.

- **Can I exclude my IP?**  
  Yes, use "Excluded IPs" (subnets) or "IP Whitelist" to bypass checks.

- **How do I monitor activity?**  
  The dashboard widget shows daily stats; `IP Logs & Map` offers logs and a banned IP map.

## Monitoring

- **Dashboard Widget**: Daily stats and top blocked IPs.
- **IP Logs & Map**: Detailed logs, ban status, geolocation, and user agents on a Leaflet map.
- **Manage IPs**: Manual ban/unban (`TeckGlobal BFP > Manage IPs`).

## Troubleshooting

- Enable "Debug Logging" and check `wp-content/teckglobal-bfp-debug.log`.
- Clear caches if settings don’t apply.
- Visit [TeckGlobal Support](https://teck-global.com/support/) or [GitHub Issues](https://github.com/teckglobal/teckglobal-brute-force-protect/issues).

## Changelog

### 1.1.2 - 2025-03-20
- Improved settings page with detailed descriptions and links for AbuseIPDB, reCAPTCHA, and MaxMind.
- Enhanced "View Details" popup with FAQ and full changelog.

### 1.1.1 - 2025-03-01
- Added multiple threat feed support (AbuseIPDB and Project Honeypot) with settings selector.

### 1.1.0 - 2025-02-15
- Real-time email notifications.
- Google reCAPTCHA v2 integration.
- Rate limiting for login attempts.
- AbuseIPDB threat intelligence.
- User agent logging.
- Settings export/import.

### 1.0.3 - 2025-01-20
- Dashboard widget for stats.
- Customizable block message.
- Visual login feedback (shake animation).
- Detailed debug log toggle.
- IP whitelist.
- UI/documentation updates.

### 1.0.2 - 2024-12-15
- Improved GeoIP download stability.
- Fixed auto-update toggle UI.

### 1.0.1 - 2024-11-30
- Added exploit scan protection.
- Optimized database queries.

### 1.0.0 - 2024-11-01
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
