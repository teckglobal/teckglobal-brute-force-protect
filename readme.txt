=== TeckGlobal Brute Force Protect ===
Contributors: teckglobal, xai-grok
Tags: security, brute force, ip ban, geolocation, wordpress security, exploit protection
Requires at least: 5.0
Tested up to: 6.7
Stable tag: 1.1.5
Requires PHP: 7.4
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.txt

A WordPress plugin to prevent brute force login attacks and exploit scans with IP management and geolocation features.

== Description ==
TeckGlobal Brute Force Protect is a security plugin designed to safeguard your WordPress site from brute force login attempts and exploit scans. It tracks login attempts, bans IPs after exceeding a set threshold, and provides geolocation insights using the GeoLite2 database. Key features include:

- **IP Tracking and Banning**: Logs failed login attempts and bans IPs after a configurable number of attempts.
- **Geolocation Mapping**: Displays banned IPs on an interactive map with country details.
- **IP Exclusion**: Allows exclusion of specific IPs or CIDR subnets from being logged or banned.
- **Invalid Username Protection**: Option to auto-ban IPs attempting logins with non-existent usernames.
- **Exploit Scan Protection**: Detects and bans IPs scanning for common vulnerabilities (e.g., phpMyAdmin, wp-config.php).
- **Admin Tools**: Manage IPs, view logs, and configure settings via an intuitive dashboard.

This plugin is 100% free and open-source. If you find it useful, please consider donating at [https://teck-global.com/buy-me-a-coffee/](https://teck-global.com/buy-me-a-coffee/).

Special thanks to xAI-Grok for invaluable assistance in development and debugging.

== Installation ==
1. Upload the `teckglobal-brute-force-protect` folder to the `/wp-content/plugins/` directory, or install via WordPress Plugins.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Configure settings under the 'Brute Force Protect' menu in your WordPress admin panel.
4. (Optional) For geolocation features:
   - Download `GeoLite2-City.mmdb` from https://dev.maxmind.com/geoip/geoip2/geolite2/ (free account required).
   - Upload to your server (e.g., `/usr/share/GeoIP/GeoLite2-City.mmdb`) and set permissions: `chmod 644 GeoLite2-City.mmdb; chown www-data:www-data GeoLite2-City.mmdb`.
   - Enter the path in plugin settings.

*Note*: The MaxMind GeoIP2 library is included—no Composer needed unless customizing dependencies. See `vendor/README.md` for advanced setup.

== Frequently Asked Questions ==
= How do I exclude my IP from being banned? =
Go to the plugin settings page and add your IP address or subnet (e.g., 192.168.1.0/24) to the "Excluded IPs/Subnets" field, one per line.

= What happens when an IP is banned? =
Banned IPs are blocked from accessing the site and see an "Access Denied" message until the ban expires (configurable duration).

= Does this plugin require any external services? =
Geolocation requires a GeoLite2-City.mmdb file (free from MaxMind) and the MaxMind GeoIP2 PHP library (installed via Composer). All other features work locally.

= How does exploit scan protection work? =
When enabled, the plugin monitors requests for common exploit targets (e.g., /phpMyAdmin, /wp-config.php) and bans IPs after a set number of attempts.

== Screenshots ==
1. Settings page for configuring max attempts, ban time, IP exclusions, and exploit protection.
2. IP Logs showing banned IPs with geolocation data and unban option.
3. Geolocation Map displaying banned IP locations.

== Changelog ==
= 1.1.5 =
* Bundled `vendor/` with GeoIP2 library for seamless updates.
* Fixed folder renaming issue during GitHub updates.
* Improved documentation for GeoIP setup.

= 1.1.4 =
* Preserved ban reason flags (Scan Exploit, Brute Force, Manual Ban) in IP Logs after ban expires for historical tracking.
* Changed Action column to "Ban Expired" from "N/A" when a ban is removed or expires.
* Added GitHub-based plugin update checker for automatic updates from the repository.

= 1.1.3 =
* Added "Manual Ban" column to IP Logs & Map page to distinguish manually banned IPs.
* Improved ban reason tracking with separate indicators for manual, brute force, and exploit scan bans.
* Bumped version to reflect new feature.

= 1.1.2 =
* Added "Scan Exploit" and "Brute Force" columns to IP Logs & Map page to show ban reason.
* Fixed unban functionality to ensure "Remove Ban" button works correctly.
* Improved ban reason tracking for exploit scans and brute force attempts.

= 1.1.1 =
* Added "Unban" button to IP Logs page.
* Fixed geolocation data not populating for manually banned IPs (e.g., country "Unknown").
* Fixed blank Geolocation Map by ensuring Leaflet integration.
* Added persistent log limit selection (10, 25, 50, 100) across page loads.
* Fixed cosmetic issue where log limit dropdown UI didn’t reflect persisted value.

= 1.1.0 =
* Added exploit scan protection to detect and ban IPs scanning for vulnerabilities (e.g., phpMyAdmin, wp-config.php).

= 1.0.3 =
* Fixed issue where visiting wp-login.php triggered an immediate IP ban.
* Ensured invalid username checks only run on form submission.

= 1.0.2 =
* Fixed regression where valid logins triggered an immediate ban.
* Adjusted IP blocking to use `authenticate` filter for proper timing.

= 1.0.1 =
* Fixed issue where banned IPs could still log in with valid credentials.
* Improved IP blocking logic for consistent enforcement.

= 1.0.0 =
* Initial release with IP tracking, banning, geolocation, and exclusion features.
* Added support for excluding IPs/subnets from logging and banning.
* Fixed issue where IPs were banned on successful logins.
* Enhanced debugging with detailed logs in `wp-content/teckglobal-bfp-debug.log`.

== Upgrade Notice ==
= 1.1.5 =
Update includes GeoIP2 library and fixes folder naming—installs cleanly with optional GeoIP setup.

== License ==
This plugin is licensed under the GPLv2 or later. See the License URI for details.