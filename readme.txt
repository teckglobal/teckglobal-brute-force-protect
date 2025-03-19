=== TeckGlobal Brute Force Protect ===
Contributors: teckglobal, xaigrok
Donate link: https://teck-global.com/buy-me-a-coffee/
Tags: wordpress, security, brute force, login protection, geolocation, ip management, wordpress plugin
Requires at least: 5.0
Tested up to: 6.7.2
Stable tag: 1.0.4
Requires PHP: 7.4
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.txt
A WordPress plugin by TeckGlobal LLC to prevent brute force login attacks and exploit scans, featuring IP management and geolocation capabilities.
== Description ==
TeckGlobal Brute Force Protect is a lightweight, powerful security plugin designed to safeguard your WordPress site from brute force login attempts and exploit scans. It tracks failed login attempts, bans offending IPs after a configurable threshold, and integrates with MaxMind’s GeoLite2 database for geolocation data. With an intuitive admin interface, you can manage banned IPs, view logs, and visualize attacker locations on a map.
Completely free and open-source. If you find this plugin helpful, please consider supporting us with a donation at TeckGlobal’s Buy Me a Coffee page.
Special thanks to xAI-Grok for invaluable assistance in development and debugging.
== Installation ==
Download the plugin ZIP from the latest GitHub release.

In WordPress, go to Plugins > Add New > Upload Plugin, upload the ZIP, and activate.

Configure settings at Brute Force Protect > Settings:
Set max login attempts, ban duration, and optional exploit protection.

Add a MaxMind license key (free at MaxMind GeoLite2 Signup) for GeoIP features.

Visit IP Logs & Map to monitor activity.

== Features ==
Brute Force Protection: Logs failed login attempts and bans IPs after a set number of tries.

Exploit Scan Detection: Blocks IPs scanning for vulnerabilities (e.g., phpMyAdmin, wp-config.php).

GeoIP Integration: Automatically downloads MaxMind GeoLite2 City database (with a free license key).

IP Management: Manually ban/unban IPs and exclude trusted IPs/subnets.

Logs & Map: View detailed logs and a Leaflet-powered map of banned IP locations.

Auto-Updates: Seamless updates via GitHub releases.

== Requirements ==
WordPress 5.0 or higher (tested up to 6.7.2).

PHP 7.4 or later.

Write permissions for wp-content/teckglobal-geoip/ (for GeoIP downloads).

== Configuration ==
Max Login Attempts: Default 5—adjust based on your security needs.

Ban Duration: Default 60 minutes—set how long IPs are banned.

Auto-Ban Invalid Usernames: Enable to ban IPs using non-existent usernames.

Excluded IPs: Add IPs or subnets (e.g., 192.168.1.1, 10.0.0.0/24) to whitelist.

MaxMind Key: Enter your key for automatic GeoIP updates (Tuesdays/Fridays).

== Screenshots ==
Configure max attempts, ban duration, and excluded IPs in the Settings page.
[screenshot-1]: https://teck-global.com/wp-content/uploads/2025/03/screenshot1.webp

Add or remove IPs from the ban list in Manage IPs.
[screenshot-2]: https://teck-global.com/wp-content/uploads/2025/03/screenshot2.webp

View logs of banned IPs with an interactive map in IP Logs & Map.
[screenshot-3]: https://teck-global.com/wp-content/uploads/2025/03/screenshot3.webp

== Changelog ==
= 1.0.6 - 2025-03-19 =
Fixed Wordpress Updating folder rename errors.

= 1.0.5 - 2025-03-19 =
Fixed Wordpress Updating folder rename errors.

= 1.0.4 - 2025-03-19 =
Fixed Wordpress Updating folder rename errors.

= 1.0.3 - 2025-03-19 =
Fixed debug logs to make less chatty.

= 1.0.2 - 2025-03-19 =
Fixed excessive debug logging by limiting to admin, cron, and AJAX contexts.
Fixed auto-update toggle by ensuring proper script localization.

= 1.0.1 - 2025-03-18 =
Added "Enable Debug Logging" option to Settings page for user-controlled debug logs.

Bumped version to test auto-update functionality.

= 1.0.0 - 2025-03-18 =
Initial release with IP tracking, banning, geolocation, and exclusion features.

Added MaxMind API key integration with automatic database updates.
Implemented admin interface with settings, logs, and interactive map.
Enabled auto-updates via GitHub releases.

== Upgrade Notice ==
= 1.0.1 =
Adds a debug logging toggle to Settings—update to test auto-updates and gain more control over logs!
= 1.0.0 =
Initial release—install to protect your WordPress site from brute force attacks and exploit scans!
