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

This plugin is 100% free and open-source. If you find this free plugin helpful, please consider supporting us with a donation at [TeckGlobal’s Buy Me a Coffee page](https://teck-global.com/buy-me-a-coffee/).

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

### Notes on Changes
1. **Version**: Set to `1.0.0` for the fresh start, not `1.1.5`.
2. **Formatting**: Removed WordPress-style `===` headers and `*` bullet points, using Markdown `#` and `-` instead.
3. **Screenshots**: Converted your `<img>` tags to Markdown `![alt](url)` syntax. The URLs you provided are fine if they’re live by release—otherwise, we can add placeholder images to the repo (e.g., `screenshots/screenshot1.webp`) and adjust paths.
4. **Changelog**: Added `1.0.0` initial release details. Replace `[Date TBD]` with the actual release date (e.g., `2025-03-25`).
5. **Content**: Kept your personal touches (like the xAI-Grok shoutout—thanks, brother!) and aligned with your draft’s intent.

---

### How It Looks
This `README.md` is GitHub-ready—clean, readable, and professional, with all the key info front and center. The changelog gives a clear picture of what `1.0.0` delivers, setting the stage for future updates. The screenshots will pop once those URLs are live (or if we add them to the repo). If you want to tweak anything—like more details in the changelog or a different tone—just say the word!

---

### Next Steps
1. **Update Repo**:
   - Replace `README.md` with this version.
   - Update `readme.txt` to match (I’ll provide that next if you want, or adapt this one).
   - Ensure `teckglobal-brute-force-protect.php` header and `TECKGLOBAL_BFP_VERSION` are `1.0.0`.

2. **Release `1.0.0`**:
   - Delete all GitHub releases.
   - Tag and ZIP as outlined before:
     ```bash
     git add . && git commit -m "Release v1.0.0" && git push
     git tag v1.0.0 && git push origin v1.0.0
     composer install
     zip -r ../teckglobal-brute-force-protect-1.0.0.zip . -x "*.git*"
     ```
   - Create release titled “Version 1.0.0”, upload ZIP, mark as “Latest”.

3. **Test**:
   - Install `1.0.0` fresh, confirm all features work, especially GeoIP and updates.

4. **Future Ideas**:
   - What features do you want for `1.0.1`? Email alerts, CAPTCHA, or something else?

Let me know what you think of this `README.md`—any tweaks or additions? I’ll whip up the `readme.txt` too if you need it. You’re driving this beast, and I’m loving every minute of it—best teammate ever! :)

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[GPL-2.0+](https://www.gnu.org/licenses/gpl-2.0.txt)

### Requirements
- **GeoLite2-City Database**: Optional, download from [MaxMind](https://dev.maxmind.com/geoip/geoip2/geolite2/).
- **PHP 7.4+**: Required for plugin compatibility.

### Compatibility ###
- WordPress: 5.0+
- PHP: 7.4+ (Tested up to 8.3)
- Database: MySQL/MariaDB (no database interaction required)
- Server: Apache/Nginx

== Screenshots ==

1. **Settings Page**: Configure max attempts, ban duration, and excluded IPs. 
<img src="https://teck-global.com/wp-content/uploads/2025/03/screenshot1.webp" alt="Settings Main Page" style="width:521px;height:771px;">

2. **Manage IPs**: Add or Remove IP to the Ban List.
<img src="https://teck-global.com/wp-content/uploads/2025/03/screenshot2.webp" alt="Settings Main Page" style="width:324px;height:296px;">

3. **IP Logs & Map**: Logs of IP's banned with an interactive map showing banned IP locations.
<img src="https://teck-global.com/wp-content/uploads/2025/03/screenshot3.webp" alt="Settings Main Page" style="width:700px;height:296px;">
