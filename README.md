=== TeckGlobal Brute Force Protect ===
Contributors: TeckGlobal LLC, xAI-Grok
Author URI: https://teck-global.com
Plugin URI: https://teck-global.com/wordpress-plugins
Donate link: https://teck-global.com/buy-me-a-coffee/
Requires at least: 5.0
Tested up to: 6.7
Stable tag: 1.0.4
Requires PHP: 7.4 or later
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Tags: wordpress, security, brute force, login protection, geolocation, ip management, wordpress plugin

A WordPress plugin by TeckGlobal LLC to prevent brute force login attacks with IP management and geolocation features.

== Description ==

TeckGlobal Brute Force Protect is a security plugin designed to safeguard your WordPress site from brute force login attempts. It tracks login attempts, bans IPs after exceeding a set threshold, and provides geolocation insights using the GeoLite2 database. Key features include:

- **IP Tracking and Banning**: Logs failed login attempts and bans IPs after a configurable number of attempts.
- **Geolocation Mapping**: Displays banned IPs on an interactive map with country details.
- **IP Exclusion**: Allows exclusion of specific IPs or CIDR subnets from being logged or banned.
- **Invalid Username Protection**: Option to auto-ban IPs attempting logins with non-existent usernames.
- **Admin Tools**: Manage IPs, view logs, and configure settings via an intuitive dashboard.

This plugin is 100% free and open-source. If you find it useful, please consider donating at [https://teck-global.com/buy-me-a-coffee/](https://teck-global.com/buy-me-a-coffee/).

Special thanks to xAI-Grok for invaluable assistance in development and debugging.

== Installation ==

1. Upload the `teckglobal-brute-force-protect` folder to the `/wp-content/plugins/` directory.
2. Run `composer require geoip2/geoip2:~2.0` in the plugin directory (`wp-content/plugins/teckglobal-brute-force-protect/`) to install the MaxMind GeoIP2 library for geolocation features.
3. Activate the plugin through the 'Plugins' menu in WordPress.
4. Configure settings under the 'Brute Force Protect' menu in your WordPress admin panel.
5. (Optional) Provide the path to your GeoLite2-City.mmdb file for geolocation features.

== Frequently Asked Questions ==

= How do I exclude my IP from being banned? =
Go to the plugin settings page and add your IP address or subnet (e.g., 192.168.1.0/24) to the "Excluded IPs/Subnets" field, one per line.

= Why is the country showing as "Unknown"? =
Ensure the `GeoLite2-City.mmdb` path in Settings is correct and the file is readable by PHP. Private IPs (e.g., `127.0.0.1`) may also return "Unknown".

= Why isn’t the map showing? =
Check the browser console (F12 > Console) for errors. Ensure Leaflet.js is loading (via CDN or local files) and that logged IPs have valid latitude/longitude data.

= How do I enable debug logging? =
Add `define('WP_DEBUG', true);` and `define('WP_DEBUG_LOG', true);` to `wp-config.php`. Logs will appear in `wp-content/

= What happens when an IP is banned? =
Banned IPs are blocked from accessing the site and see an "Access Denied" message until the ban expires (configurable duration).

= Does this plugin require any external services? =
Geolocation requires a GeoLite2-City.mmdb file (free from MaxMind) and the MaxMind GeoIP2 PHP library (installed via Composer). All other features work locally.

== Changelog ==
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

= 1.0.0 =
First stable version—upgrade to secure your site with advanced brute force protection!

### Requirements
- **MaxMind GeoIP2 Library**: Install via Composer (`geoip2/geoip2:~2.0`).
- **GeoLite2-City Database**: Download from [MaxMind](https://dev.maxmind.com/geoip/geoip2/geolite2/) (free account required).
- **PHP 7.4+**: Required for GeoIP2 compatibility.

== Compatibility ==
- WordPress: 5.0+
- PHP: 7.4+ (Tested up to 8.3)
- Database: MySQL/MariaDB (no database interaction required)
- Server: Nginx

== Screenshots ==

1. **Settings Page**: Configure max attempts, ban duration, and excluded IPs. 
<img src="https://teck-global.com/wp-content/uploads/2025/03/Screenshot-2025-03-15-at-21.59.04.webp" alt="Settings Main Page" style="width:450px;height:633px;">

2. **IP Logs**: View detailed logs of login attempts and bans.
<img src="https://teck-global.com/wp-content/uploads/2025/03/Screenshot-2025-03-15-at-22.02.33-scaled-e1742095177310.webp" alt="Settings Main Page" style="width:600px;height:189px;">

3. **Geolocation Map**: Interactive map showing banned IP locations.
<img src="https://teck-global.com/wp-content/uploads/2025/03/Screenshot-2025-03-15-at-22.03.07-scaled-e1742095266357.webp" alt="Settings Main Page" style="width:600px;height:175px;">
