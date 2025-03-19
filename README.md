# TeckGlobal Brute Force Protect

A WordPress plugin by TeckGlobal LLC and xAI's Grok to protect your site from brute force login attacks and exploit scans.

## Description

TeckGlobal Brute Force Protect secures your WordPress site by blocking IPs after excessive login attempts or exploit scans, with features like geolocation tracking, IP management, and detailed monitoring. Key enhancements include a dashboard widget, customizable block messages, visual login form feedback, toggleable debug logs, and an IP whitelist. Support development with a donation at [TeckGlobal's Buy Me a Coffee](https://teck-global.com/buy-me-a-coffee/).

## Features

- **Brute Force Protection**: Bans IPs after a set number of failed logins (default: 5).
- **Exploit Scan Detection**: Blocks access to sensitive files/endpoints.
- **Geolocation**: Maps banned IPs using MaxMind GeoLite2 (optional license key).
- **IP Management**: Ban/unban IPs, exclude subnets, whitelist trusted IPs.
- **Dashboard Widget**: Shows daily blocked attempts and top IPs.
- **Custom Block Message**: Set your own message for banned users.
- **Visual Feedback**: Login form shakes with a red border for banned IPs.
- **Debug Logging**: Toggle logs (`teckglobal-bfp-debug.log`, `teckglobal-bfp-detailed.log`).
- **Auto-Updates**: GitHub-based updates with a plugins page toggle.

## Installation

1. **Download**: Grab the ZIP from [GitHub Releases](https://github.com/teckglobal/teckglobal-brute-force-protect/releases) or WordPress.org.
2. **Install**: Upload via `Plugins > Add New > Upload Plugin` and activate.
3. **Configure**: Visit `TeckGlobal BFP > Settings` to tweak options.
4. **Optional**: Add a [MaxMind License Key](https://www.maxmind.com/) for geolocation.

## Usage

- **Settings**: Adjust limits, enable exploit protection, or set a custom block message.
- **Monitor**: Use the dashboard widget or `IP Logs & Map` page.
- **Whitelist**: Add IPs to skip checks in the settings.

## Requirements

- WordPress 5.0+
- PHP 7.4+
- Tested up to WordPress 6.7.2

## Changelog

### 1.0.3
- Added dashboard widget for login stats.
- Customizable block message for banned IPs.
- Visual feedback on login form (shake animation).
- Toggleable detailed debug log.
- IP whitelist to bypass checks.
- UI and documentation improvements.

### 1.0.2
- Improved GeoIP download stability.
- Fixed auto-update toggle UI.

### 1.0.1
- Added exploit scan protection.
- Optimized database queries.

### 1.0.0
- Initial release with brute force and geolocation.

## Support

- **Website**: [TeckGlobal Support](https://teck-global.com/support/)
- **Issues**: [GitHub Issues](https://github.com/teckglobal/teckglobal-brute-force-protect/issues)

## License

[GNU General Public License v2](http://www.gnu.org/licenses/gpl-2.0.txt) or later.

## Credits

- **TeckGlobal LLC**: [https://teck-global.com/](https://teck-global.com/)
- **xAI's Grok**: AI-assisted development
- **MaxMind GeoLite2**: Geolocation data

## Donate

Support this free plugin at [TeckGlobal's Buy Me a Coffee](https://teck-global.com/buy-me-a-coffee/).