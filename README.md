=== TeckGlobal Brute Force Protect ===
 * Contributors: TeckGlobal LLC, xAI-Grok
 * Author URI: https://teck-global.com
 * Plugin URI: https://teck-global.com/wordpress-plugins
 * Donate link: https://teck-global.com/buy-me-a-coffee/
 * Requires at least: 5.0
 * Tested up to: 6.7
 * Stable tag: 1.1.5
 * Requires PHP: 7.4 or later
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Tags: wordpress, security, brute force, login protection, geolocation, ip management, wordpress plugin

A WordPress plugin by TeckGlobal LLC to prevent brute force login attacks and exploit scans, featuring IP management and geolocation capabilities.

## Description

TeckGlobal Brute Force Protect is a lightweight, powerful security plugin designed to safeguard your WordPress site from brute force login attempts and exploit scans. It tracks failed login attempts, bans offending IPs after a configurable threshold, and optionally integrates with MaxMind’s GeoLite2 database for geolocation data. With an intuitive admin interface, you can manage banned IPs, view logs, and visualize attacker locations on a map.

Completely free and open-source. If you find this plugin helpful, please consider supporting us with a donation at [TeckGlobal’s Buy Me a Coffee page](https://teck-global.com/buy-me-a-coffee/).

Special thanks to xAI-Grok for invaluable assistance in development and debugging.

## Features

- **Brute Force Protection**: Logs failed login attempts and bans IPs after a set number of tries.
- **Exploit Scan Detection**: Blocks IPs scanning for vulnerabilities (e.g., `phpMyAdmin`, `wp-config.php`).
- **GeoIP Integration**: Automatically downloads MaxMind GeoLite2 City database (with a free license key) to display attacker countries and coordinates.
- **IP Management**: Manually ban/unban IPs and exclude trusted IPs or subnets.
- **Logs & Map**: View detailed logs and a Leaflet-powered map of banned IP locations.
- **Auto-Updates**: Checks GitHub for new releases seamlessly within WordPress.

## Installation

1. Download the plugin ZIP from the [latest GitHub release](https://github.com/teckglobal/teckglobal-brute-force-protect/releases).
2. In WordPress, go to **Plugins > Add New > Upload Plugin**, upload the ZIP, and activate.
3. Configure settings at **Brute Force Protect > Settings**:
   - Set max login attempts, ban duration, and optional exploit protection.
   - Add a MaxMind license key (free at [MaxMind GeoLite2 Signup](https://www.maxmind.com/en/geolite2/signup)) for GeoIP features.
4. Visit **IP Logs & Map** to monitor activity.

## Requirements

- WordPress 5.0 or higher (tested up to 6.7).
- PHP 7.4 or later.
- Write permissions for `wp-content/teckglobal-geoip/` (for GeoIP downloads).

## Configuration

- **Max Login Attempts**: Default 5—adjust based on your security needs.
- **Ban Duration**: Default 60 minutes—set how long IPs are banned.
- **Auto-Ban Invalid Usernames**: Enable to ban IPs using non-existent usernames.
- **Excluded IPs**: Add IPs or subnets (e.g., `192.168.1.1`, `10.0.0.0/24`) to whitelist.
- **MaxMind Key**: Enter your key for automatic GeoIP database updates (Tuesdays/Fridays).

## Development

- **Repository**: [github.com/teckglobal/teckglobal-brute-force-protect](https://github.com/teckglobal/teckglobal-brute-force-protect)
- **Contributing**: Fork, make changes, and submit a pull request. We welcome feedback!
- **Building**: Requires Composer for dependencies (`vendor/` included in releases).

```bash
git clone https://github.com/teckglobal/teckglobal-brute-force-protect.git
cd teckglobal-brute-force-protect
composer install

Changelog
1.0.0 - 2025-03-17
Initial release with core brute force protection, exploit scan detection, GeoIP integration, and IP management tools.

Added admin interface with settings, logs, and interactive map powered by Leaflet.

Implemented MaxMind API key integration with automatic database updates.

Enabled auto-updates via GitHub releases.
License
GPL-2.0+
Credits
TeckGlobal LLC: Primary development and support.

xAI-Grok: Co-development and debugging.
Built with love for the WordPress community. Stay secure!

== Screenshots ==

1. **Settings Page**: Configure max attempts, ban duration, and excluded IPs. 
<img src="https://teck-global.com/wp-content/uploads/2025/03/screenshot1.webp" alt="Settings Main Page" style="width:521px;height:771px;">

2. **Manage IPs**: Add or Remove IP to the Ban List.
<img src="https://teck-global.com/wp-content/uploads/2025/03/screenshot2.webp" alt="Settings Main Page" style="width:324px;height:296px;">

3. **IP Logs & Map**: Logs of IP's banned with an interactive map showing banned IP locations.
<img src="https://teck-global.com/wp-content/uploads/2025/03/screenshot3.webp" alt="Settings Main Page" style="width:700px;height:296px;">
