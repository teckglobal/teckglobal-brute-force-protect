# TeckGlobal Brute Force Protect

- **Contributors**: TeckGlobal LLC, xAI-Grok
- **Author URI**: [https://teck-global.com](https://teck-global.com)
- **Plugin URI**: [https://teck-global.com/wordpress-plugins](https://teck-global.com/wordpress-plugins)
- **Donate Link**: [https://teck-global.com/buy-me-a-coffee/](https://teck-global.com/buy-me-a-coffee/)
- **Requires at Least**: 5.0
- **Tested Up To**: 6.7.2
- **Stable Tag**: 1.0.0
- **Requires PHP**: 7.4 or later
- **License**: GPLv2 or later
- **License URI**: [https://www.gnu.org/licenses/gpl-2.0.html](https://www.gnu.org/licenses/gpl-2.0.html)
- **Tags**: wordpress, security, brute-force, login-protection, geolocation, ip-management, wordpress-plugin

A lightweight WordPress plugin by TeckGlobal LLC to shield your site from brute force login attacks and exploit scans, complete with IP management and geolocation features.

## Description

TeckGlobal Brute Force Protect is a free, open-source security plugin that locks down your WordPress site against brute force login attempts and exploit scans. It tracks failed logins, bans IPs after a configurable limit, and uses MaxMind’s GeoLite2 database to pinpoint attacker locations. The admin interface lets you manage IPs, review logs, and see banned IPs on a Leaflet-powered map.

If you love this free tool, please consider a donation at [TeckGlobal’s Buy Me a Coffee page](https://teck-global.com/buy-me-a-coffee/). Huge thanks to xAI-Grok for co-development and debugging wizardry!

## Features

- **Brute Force Protection**: Tracks failed logins and bans IPs after a set threshold.
- **Exploit Scan Detection**: Blocks IPs probing for vulnerabilities (e.g., `phpMyAdmin`, `wp-config.php`).
- **GeoIP Integration**: Auto-downloads MaxMind GeoLite2 City database with a free license key.
- **IP Management**: Manually ban/unban IPs and exclude trusted IPs/subnets.
- **Logs & Map**: Detailed logs and an interactive map of banned IP locations.
- **Auto-Updates**: Seamless updates via GitHub releases.

## Installation

1. Grab the plugin ZIP from the [latest GitHub release](https://github.com/teckglobal/teckglobal-brute-force-protect/releases).
2. In WordPress, go to **Plugins > Add New > Upload Plugin**, upload the ZIP, and activate.
3. Head to **Brute Force Protect > Settings** to configure:
   - Max login attempts, ban duration, and exploit protection.
   - Add a MaxMind license key (free from [MaxMind GeoLite2 Signup](https://www.maxmind.com/en/geolite2/signup)) for geolocation.
4. Check **IP Logs & Map** to monitor threats.

## Requirements

- WordPress 5.0+ (tested up to 6.7.2).
- PHP 7.4+.
- Write permissions for `wp-content/teckglobal-geoip/` (GeoIP downloads).

## Configuration

- **Max Login Attempts**: Default 5—tweak as needed.
- **Ban Duration**: Default 60 minutes—set ban length.
- **Auto-Ban Invalid Usernames**: Enable to ban IPs using fake usernames.
- **Excluded IPs**: Whitelist IPs or subnets (e.g., `192.168.1.1`, `10.0.0.0/24`).
- **MaxMind Key**: Add for weekly GeoIP updates (Tuesdays/Fridays).

## Screenshots

1. **Settings Page**: Configure max attempts, ban duration, and exclusions.
   ![Settings Page](https://teck-global.com/wp-content/uploads/2025/03/screenshot1.webp)

2. **Manage IPs**: Ban or unban IPs manually.  
   ![Manage IPs](https://teck-global.com/wp-content/uploads/2025/03/screenshot2.webp)

3. **IP Logs & Map**: View logs and banned IP locations on a map.
   ![IP Logs & Map](https://teck-global.com/wp-content/uploads/2025/03/screenshot3.webp)

## Development

- **Repository**: [github.com/teckglobal/teckglobal-brute-force-protect](https://github.com/teckglobal/teckglobal-brute-force-protect)
- **Contributing**: Fork, tweak, and submit a pull request. We’d love your input!
- **Building**: Requires Composer for dependencies (`vendor/` included in releases).

```bash
git clone https://github.com/teckglobal/teckglobal-brute-force-protect.git
cd teckglobal-brute-force-protect
composer install

## Changelog
### 1.0.0 - 2025-03-19
- Initial release with brute force protection, exploit detection, GeoIP, and IP management.
- Added admin interface with settings, logs, and Leaflet map.
- Integrated MaxMind API key for auto GeoIP updates.
- Enabled auto-updates via GitHub.

## License
Released under GPLv2 or later. Free to use, modify, and distribute.

Credits
TeckGlobal LLC: Core development and support.

xAI-Grok: Co-development and debugging.
Built with passion for the WordPress community. Stay safe out there!
