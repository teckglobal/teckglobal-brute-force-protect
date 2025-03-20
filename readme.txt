=== TeckGlobal Brute Force Protect ===
Contributors: teckglobal, xai-grok
Donate link: https://teck-global.com/buy-me-a-coffee/
Tags: security, brute force, login protection, ip blocking, geolocation
Requires at least: 5.0
Tested up to: 6.7.2
Stable tag: 1.1.2
Requires PHP: 7.4
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.txt

A powerful security plugin to protect your WordPress site from brute force login attacks, exploit scans, and more, featuring IP management, geolocation, and threat intelligence.

== Description ==

**TeckGlobal Brute Force Protect** is an advanced, free, and open-source WordPress security plugin crafted by TeckGlobal LLC and xAI's Grok. It safeguards your site against brute force login attacks and exploit scans by monitoring and blocking suspicious IPs. With features like real-time geolocation via MaxMind GeoLite2, integration with threat feeds (AbuseIPDB and Project Honeypot), a dashboard widget, customizable block messages, visual login feedback, detailed debug logs, IP whitelisting, email notifications, Google reCAPTCHA v2, rate limiting, user agent logging, and settings export/import, it offers comprehensive protection tailored for both novice and expert users.

This plugin is ideal for anyone looking to secure their WordPress site without complexity. It’s lightweight, configurable, and community-driven—donations at [TeckGlobal's Buy Me a Coffee](https://teck-global.com/buy-me-a-coffee/) help us keep it free and growing.

**Key Benefits:**
- **Proactive Defense**: Blocks IPs after excessive login attempts or exploit scans.
- **Global Insights**: Maps attack origins with optional geolocation.
- **Threat Intelligence**: Leverages AbuseIPDB and Project Honeypot for preemptive bans.
- **User-Friendly**: Easy setup with powerful monitoring tools.
- **Community Support**: Free to use, with donations fueling further development.

== Installation ==

1. **Upload the Plugin**:
   - Download the ZIP from [GitHub Releases](https://github.com/teckglobal/teckglobal-brute-force-protect/releases) or WordPress.org.
   - Go to `Plugins > Add New`, click `Upload Plugin`, select the ZIP, and click `Install Now`.

2. **Activate the Plugin**:
   - Click `Activate` after installation or go to `Plugins` and activate it.

3. **Configure Settings**:
   - Navigate to `TeckGlobal BFP > Settings`.
   - Adjust max login attempts, ban duration, block message, CAPTCHA, notifications, threat feeds, and more.
   - (Optional) Add a [MaxMind License Key](https://www.maxmind.com/en/geolite2/signup) for geolocation, [reCAPTCHA keys](https://www.google.com/recaptcha) for CAPTCHA, or API keys from [AbuseIPDB](https://www.abuseipdb.com/register) and [Project Honeypot](https://www.projecthoneypot.org/httpbl_configure.php) for threat intelligence.

4. **Monitor**:
   - View stats in the dashboard widget.
   - Check logs and a banned IP map at `TeckGlobal BFP > IP Logs & Map`.

== Frequently Asked Questions ==

= How does it detect brute force attempts? =
It tracks failed logins per IP and bans them after exceeding your set limit (default: 5). Enable "Auto-Ban Invalid Usernames" for instant bans on fake logins.

= Can I change the ban message? =
Yes, customize it in `Settings > Block Message`—it appears to banned IPs.

= What’s the visual feedback on the login form? =
Banned IPs trigger a shake animation with a red border on login attempts.

= How do I enable geolocation? =
Add a free [MaxMind License Key](https://www.maxmind.com/en/geolite2/signup) in settings to see IP locations on the `IP Logs & Map`.

= What are threat feeds? =
AbuseIPDB and Project Honeypot auto-ban high-risk IPs before they hit your limits. Enable them with API keys in settings.

= How does CAPTCHA help? =
It adds Google reCAPTCHA v2 to `wp-login.php`, blocking bots. Requires keys from [Google reCAPTCHA](https://www.google.com/recaptcha).

= What’s rate limiting? =
It caps login attempts within a time frame (e.g., 3 in 60 seconds), stopping rapid attacks.

= Can I exclude my IP? =
Yes, use "Excluded IPs" (for subnets) or "IP Whitelist" to bypass protection.

= How do I monitor activity? =
The dashboard widget shows daily stats; `IP Logs & Map` provides detailed logs and a banned IP map.

= Where are logs stored? =
Enable "Debug Logging" for `wp-content/teckglobal-bfp-debug.log` or "Detailed Debug Log" for `teckglobal-bfp-detailed.log`.

== Screenshots ==

1. **Settings Page**: Configure protection settings.
2. **Dashboard Widget**: Daily blocked attempts and top IPs.
3. **IP Logs & Map**: Logs and geolocation map of banned IPs.
4. **Manage IPs**: Ban/unban IPs manually.
5. **Login Form Feedback**: Visual cue for banned IP attempts.

== Changelog ==

= 1.1.2 =
* Improved settings page with detailed descriptions and links for AbuseIPDB, reCAPTCHA, and MaxMind keys.
* Enhanced "View Details" popup with FAQ and full changelog.

= 1.1.1 =
* Added multiple threat feed support (AbuseIPDB and Project Honeypot) with a settings selector.

= 1.1.0 =
* Added real-time email notifications for ban events.
* Integrated Google reCAPTCHA v2 for login protection.
* Implemented rate limiting for login attempts.
* Added AbuseIPDB threat intelligence.
* Included user agent logging for better tracking.
* Enabled settings export/import functionality.

= 1.0.3 =
* Added dashboard widget for quick stats.
* Introduced customizable block messages.
* Implemented visual login feedback (shake animation).
* Added toggleable detailed debug logs.
* Included IP whitelist feature.
* Improved settings UI and documentation.

= 1.0.2 =
* Enhanced GeoIP download reliability.
* Fixed auto-update toggle display on Plugins page.

= 1.0.1 =
* Added exploit scan protection for sensitive endpoints.
* Optimized database performance for logs.

= 1.0.0 =
* Initial release with core brute force protection and geolocation support.

== Upgrade Notice ==

= 1.1.2 =
Upgrade for a better settings experience and enriched plugin details in the "View Details" popup.

= 1.1.0 =
Upgrade for advanced features like notifications, CAPTCHA, rate limiting, threat intelligence, and settings management.

= 1.0.3 =
Upgrade for enhanced monitoring and user experience improvements.

== Additional Information ==

- **Support**: [TeckGlobal Support](https://teck-global.com/support/)
- **Source**: [GitHub Repository](https://github.com/teckglobal/teckglobal-brute-force-protect)
- **License**: GPLv2 or later
