=== TeckGlobal Brute Force Protect ===
Contributors: teckglobal, xai-grok
Donate link: https://teck-global.com/buy-me-a-coffee/
Tags: security, brute force, login protection, ip blocking, geolocation
Requires at least: 5.0
Tested up to: 6.7.2
Stable tag: 1.0.3
Requires PHP: 7.4
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.txt

Protect your WordPress site from brute force login attacks and exploit scans with IP management and geolocation features.

== Description ==

TeckGlobal Brute Force Protect is a powerful security plugin by TeckGlobal LLC, enhanced by xAI's Grok, designed to shield your WordPress site from brute force login attempts and malicious exploit scans. It tracks failed login attempts, bans offending IPs, and provides detailed logs with geolocation data. With customizable settings and advanced features, it’s an essential tool for site administrators seeking robust protection.

Key features include a dashboard widget for monitoring, a customizable block message, visual feedback on the login form, toggleable debug logs, and an IP whitelist to bypass checks. If you value this free plugin, please consider a donation at [TeckGlobal's Buy Me a Coffee](https://teck-global.com/buy-me-a-coffee/).

== Installation ==

1. **Upload the Plugin**:
   - Download the plugin ZIP file.
   - Go to `Plugins > Add New` in your WordPress admin panel.
   - Click `Upload Plugin`, select the ZIP, and click `Install Now`.

2. **Activate the Plugin**:
   - After installation, click `Activate` or navigate to `Plugins` and activate it.

3. **Configure Settings**:
   - Go to `TeckGlobal BFP > Settings` in the admin menu.
   - Set max login attempts, ban duration, block message, and other options.
   - (Optional) Add a MaxMind License Key for geolocation.

4. **Monitor**:
   - Check the dashboard widget for stats.
   - Visit `TeckGlobal BFP > IP Logs & Map` for logs and a banned IP map.

== Frequently Asked Questions ==

= How does it detect brute force attempts? =
It logs failed logins per IP and bans after exceeding the set limit (default: 5).

= Can I change the ban message? =
Yes, customize it under `TeckGlobal BFP > Settings` in the "Block Message" field.

= What’s the visual feedback on the login form? =
Banned IPs trigger a shake animation and red border on login attempts.

= How do I enable debug logs? =
Check "Enable Debug Logging" or "Enable Detailed Debug Log" in settings for logs in `wp-content/`.

= How do I whitelist IPs? =
Add IPs (one per line) in the "IP Whitelist" field under settings to skip brute force checks.

= Is a MaxMind key required? =
No, it’s optional for geolocation; without it, country data shows as "Unknown."

== Screenshots ==

1. **Settings Page**: Configure protection settings.
2. **Dashboard Widget**: Daily blocked attempts and top IPs.
3. **IP Logs & Map**: Logs and geolocation map of banned IPs.
4. **Manage IPs**: Ban/unban IPs manually.
5. **Login Form Feedback**: Visual cue for banned IP attempts.

== Changelog ==

= 1.0.3 =
* Added Login Attempt Counter Dashboard Widget.
* Added Customizable Block Message for banned IPs.
* Implemented Visual Feedback on Login Form (shake animation).
* Added Toggleable Debug Log (detailed logging option).
* Introduced IP Whitelist Feature to bypass checks.
* Improved settings interface and documentation.

= 1.0.2 =
* Enhanced GeoIP download reliability.
* Fixed auto-update toggle display.

= 1.0.1 =
* Added exploit scan protection.
* Optimized database performance.

= 1.0.0 =
* Initial release with core brute force and geolocation features.

== Upgrade Notice ==

= 1.0.3 =
Upgrade for new monitoring tools (dashboard widget), user experience improvements (block message, login feedback), and advanced options (debug log, whitelist).

== Additional Information ==

- **Support**: [TeckGlobal Support](https://teck-global.com/support/)
- **Source**: [GitHub Repository](https://github.com/teckglobal/teckglobal-brute-force-protect)
- **License**: GPLv2 or later