=== TeckGlobal Brute Force Protect ===
Contributors: teckglobal, xaigrok
Donate link: https://teck-global.com/buy-me-a-coffee/
Tags: wordpress, security, brute force, login protection, geolocation, ip management, wordpress plugin
Requires at least: 5.0
Tested up to: 6.7.2
Stable tag: 1.0.1
Requires PHP: 7.4
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.txt
A WordPress plugin by TeckGlobal LLC to prevent brute force login attacks and exploit scans, featuring IP management and geolocation capabilities.

== Description ==
TeckGlobal Brute Force Protect is a lightweight, powerful security plugin designed to safeguard your WordPress site from brute force login attempts and exploit scans. It tracks failed login attempts, bans offending IPs after a configurable threshold, and integrates with MaxMind’s GeoLite2 database for geolocation data. With an intuitive admin interface, you can manage banned IPs, view logs, and visualize attacker locations on a Leaflet-powered map (with local CSS/JS fallback if CDN fails).

Completely free and open-source. If you find this plugin helpful, please consider supporting us with a donation at [TeckGlobal’s Buy Me a Coffee page](https://teck-global.com/buy-me-a-coffee/).

Special thanks to xAI-Grok for invaluable assistance in development and debugging.

== Installation ==
1. Download the plugin ZIP from the [latest GitHub release](https://github.com/teckglobal/teckglobal-brute-force-protect/releases).
2. In WordPress, navigate to **Plugins > Add New > Upload Plugin**.
3. Upload the ZIP file and click "Install Now," then activate the plugin.
4. Go to **Brute Force Protect > Settings** to configure:
   - Set max login attempts, ban duration, and enable optional exploit protection.
   - Add a MaxMind license key (free from [MaxMind GeoLite2 Signup](https://www.maxmind.com/en/geolite2/signup)) for GeoIP features.
5. Visit **IP Logs & Map** to monitor activity and banned IPs.

== Features ==
- Brute Force Protection: Logs failed login attempts and bans IPs after a set number of tries.
- Exploit Scan Detection: Blocks IPs scanning for vulnerabilities (e.g., phpMyAdmin, wp-config.php).
- GeoIP Integration: Automatically downloads MaxMind GeoLite2 City database (with a free license key).
- IP Management: Manually ban/unban IPs and exclude trusted IPs/subnets.
- Logs & Map: View detailed logs and a Leaflet-powered map of banned IP locations.
- Auto-Updates: Seamless updates via GitHub releases.

== Requirements ==
- WordPress 5.0 or higher (tested up to 6.7.2).
- PHP 7.4 or later.
- Write permissions for wp-content/teckglobal-geoip/ (for GeoIP downloads).

== Configuration ==
- Max Login Attempts: Default 5—adjust based on your security needs.
- Ban Duration: Default 1 hour—choose from 15 minutes to 1 week.
- Auto-Ban Invalid Usernames: Enable to ban IPs using non-existent usernames.
- Excluded IPs: Add IPs or subnets (e.g., 192.168.1.1, 10.0.0.0/24) to whitelist.
- MaxMind Key: Enter your key for automatic GeoIP updates (Tuesdays/Fridays).

== Screenshots ==
1. Configure max attempts, ban duration, and excluded IPs in the Settings page. (screenshot-1.png)
2. Add or remove IPs from the ban list in Manage IPs. (screenshot-2.png)
3. View logs of banned IPs with an interactive map in IP Logs & Map. (screenshot-3.png)

== Changelog ==
= 1.0.1 - 2025-03-19 =
- Added ban duration dropdown with options from 15 minutes to 1 week.

= 1.0.0 - 2025-03-19 =
- Initial release with IP tracking, banning, geolocation, and exclusion features.
- Added MaxMind API key integration with automatic database updates.
- Implemented admin interface with settings, logs, and interactive map.
- Enabled auto-updates via GitHub releases.

== Upgrade Notice ==
= 1.0.1 =
Updated with a ban duration dropdown—choose from 15 minutes to 1 week for more flexible IP banning!

= 1.0.0 =
Initial release—install to protect your WordPress site from brute force attacks and exploit scans!