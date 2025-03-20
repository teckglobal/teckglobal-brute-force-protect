=== TeckGlobal Brute Force Protect ===
Contributors: teckglobal, xai-grok
Donate link: https://teck-global.com/buy-me-a-coffee/
Tags: security, brute force, login protection, ip blocking, geolocation
Requires at least: 5.0
Tested up to: 6.7.2
Stable tag: 1.1.0
Requires PHP: 7.4
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.txt

Protect your WordPress site from brute force login attacks and exploit scans with IP management and geolocation features.

== Description ==

TeckGlobal Brute Force Protect, developed by TeckGlobal LLC with xAI's Grok, is a robust security plugin that defends your WordPress site against brute force login attempts and exploit scans. It tracks failed logins, bans offending IPs, and logs details with optional geolocation. Key features include a dashboard widget, customizable block messages, visual login feedback, debug logs, IP whitelisting, real-time notifications, CAPTCHA integration, rate limiting, threat intelligence, user agent logging, and settings export/import. Support this free plugin at [TeckGlobal's Buy Me a Coffee](https://teck-global.com/buy-me-a-coffee/).

== Installation ==

1. **Upload the Plugin**:
   - Download the plugin ZIP from [GitHub Releases](https://github.com/teckglobal/teckglobal-brute-force-protect/releases) or WordPress.org.
   - Go to `Plugins > Add New`, click `Upload Plugin`, select the ZIP, and click `Install Now`.

2. **Activate the Plugin**:
   - Click `Activate` after installation or go to `Plugins` and activate it.

3. **Configure Settings**:
   - Navigate to `TeckGlobal BFP > Settings`.
   - Adjust max login attempts, ban duration, block message, CAPTCHA, notifications, threat feeds, and more.
   - (Optional) Add a [MaxMind License Key](https://www.maxmind.com/en/geolite2/signup) for geolocation, [reCAPTCHA keys](https://www.google.com/recaptcha) for CAPTCHA, or an [AbuseIPDB API key](https://www.abuseipdb.com/register) for threat intelligence.

4. **Monitor**:
   - View stats in the dashboard widget.
   - Check logs and a banned IP map at `TeckGlobal BFP > IP Logs & Map`.

== Settings and Usage ==

Configure options under `TeckGlobal BFP > Settings`. Here’s what each setting does, how to adjust it, and how to verify it works:

= General Settings =

- **Max Login Attempts**
  - Purpose: Number of failed logins before banning an IP.
  - Default: 5
  - Adjust: Enter a number (e.g., 8).
  - Verify: Fail logins from a test IP beyond this limit; check `IP Logs & Map` for a ban (red icon).

- **Ban Duration**
  - Purpose: Duration of an IP ban.
  - Default: 60 minutes
  - Options: 15 min, 30 min, 1 hr, 3 hrs, 1 day, 3 days, 1 week
  - Adjust: Select from the dropdown.
  - Verify: Ban an IP, note "Ban Expiry" in `IP Logs & Map`, test access after expiry.

- **Auto-Ban Invalid Usernames**
  - Purpose: Bans IPs using non-existent usernames instantly.
  - Default: Off
  - Adjust: Check to enable.
  - Verify: Login with a fake username (e.g., `fakeuser`); check `IP Logs & Map` for a ban.

- **Excluded IPs**
  - Purpose: Excludes IPs/subnets from protection.
  - Default: Empty
  - Adjust: Add IPs (e.g., `192.168.1.1`) or subnets (e.g., `10.0.0.0/24`) with notes.
  - Verify: Add a test IP, exceed attempts; it shouldn’t be banned in `IP Logs & Map`.

- **Enable Exploit Protection**
  - Purpose: Bans IPs scanning for vulnerabilities.
  - Default: Off
  - Adjust: Check to enable.
  - Verify: Request `your-site.com/phpMyAdmin` beyond "Max Exploit Attempts"; check `IP Logs & Map`.

- **Max Exploit Attempts**
  - Purpose: Number of exploit attempts before a ban.
  - Default: 3
  - Adjust: Enter a number (e.g., 5).
  - Verify: Hit suspicious URLs; ban triggers after this limit.

- **MaxMind License Key**
  - Purpose: Enables geolocation data.
  - Default: Empty
  - Adjust: Get a key from [MaxMind](https://www.maxmind.com/en/geolite2/signup) and enter it.
  - Verify: Add a key, trigger a login; check `IP Logs & Map` for country/coordinates.

- **Remove Data on Deactivation**
  - Purpose: Deletes plugin data on deactivation.
  - Default: Off
  - Adjust: Check to enable.
  - Verify: Enable, deactivate, reactivate; data should reset.

- **Enable Debug Logging**
  - Purpose: Logs to `wp-content/teckglobal-bfp-debug.log`.
  - Default: Off
  - Adjust: Check to enable.
  - Verify: Enable, trigger an action; check the log.

- **Block Message**
  - Purpose: Message for banned IPs.
  - Default: "Your IP has been banned due to suspicious activity. Please contact the site administrator."
  - Adjust: Enter a custom message.
  - Verify: Ban a test IP; visit the site to see your message.

- **Enable Detailed Debug Log**
  - Purpose: Detailed logs to `wp-content/teckglobal-bfp-detailed.log`.
  - Default: Off
  - Adjust: Check to enable.
  - Verify: Enable, trigger an action; check the detailed log.

- **IP Whitelist**
  - Purpose: Bypasses checks for listed IPs.
  - Default: Empty
  - Adjust: Enter IPs (e.g., `192.168.1.1`), one per line.
  - Verify: Add a test IP, exceed limits; it shouldn’t be banned.

= Advanced Features =

- **Enable Notifications**
  - Purpose: Emails you on ban events.
  - Default: Off
  - Adjust: Check to enable.
  - Verify: Enable, ban an IP; check your email.

- **Notification Email**
  - Purpose: Email for notifications.
  - Default: Admin email
  - Adjust: Enter an email (e.g., `alerts@your-site.com`).
  - Verify: Set an email, ban an IP; confirm receipt.

- **Enable CAPTCHA**
  - Purpose: Adds reCAPTCHA to `wp-login.php`.
  - Default: Off
  - Adjust: Check to enable (requires keys).
  - Verify: Enable with keys; see CAPTCHA on `wp-login.php`.

- **reCAPTCHA Site Key & Secret Key**
  - Purpose: Integrates Google reCAPTCHA v2.
  - Default: Empty
  - Adjust: Get keys from [Google reCAPTCHA](https://www.google.com/recaptcha): Sign in, click "Admin Console," select "reCAPTCHA v2" > "Checkbox," add your domain, submit, copy keys.
  - Verify: Add keys, enable CAPTCHA; check `wp-login.php`.

- **Enable Rate Limiting**
  - Purpose: Limits login attempts in a time window.
  - Default: Off
  - Adjust: Check to enable.
  - Verify: Exceed "Rate Limit Attempts" within "Interval"; attempts should block.

- **Rate Limit Attempts**
  - Purpose: Number of attempts in the interval.
  - Default: 3
  - Adjust: Enter a number (e.g., 4).
  - Verify: Exceed this within the interval; see a block.

- **Rate Limit Interval (seconds)**
  - Purpose: Time window for rate limiting.
  - Default: 60
  - Adjust: Enter seconds (e.g., 120).
  - Verify: Exceed attempts, wait; attempts resume after.

- **Enable Threat Feed**
  - Purpose: Bans IPs flagged by AbuseIPDB.
  - Default: Off
  - Adjust: Check to enable (requires API key).
  - Verify: Enable with a key, use a malicious IP from [AbuseIPDB](https://www.abuseipdb.com/check); login attempt should ban it.

- **AbuseIPDB API Key**
  - Purpose: Queries AbuseIPDB for threat data.
  - Default: Empty
  - Adjust: Register at [AbuseIPDB](https://www.abuseipdb.com/register), go to "API" > "Create Key," copy and paste it.
  - Verify: Add a key, enable threat feed, test with a reported IP; check `IP Logs & Map`.

= Export/Import Settings =
- Purpose: Backup or restore settings.
- Adjust: Click "Export" for a `.json` file, or upload one and click "Import."
- Verify: Export, change a setting, import; original value returns.

== Frequently Asked Questions ==

= How does it detect brute force attempts? =
It logs failed logins per IP and bans after exceeding the set limit (default: 5).

= Can I change the ban message? =
Yes, customize it in the "Block Message" field under settings.

= What’s the visual feedback on the login form? =
Banned IPs trigger a shake animation and red border on login attempts.

= How do I enable debug logs? =
Check "Enable Debug Logging" or "Enable Detailed Debug Log" for logs in `wp-content/`.

= How do I whitelist IPs? =
Add IPs in the "IP Whitelist" field to skip checks.

= Is a MaxMind key required? =
No, it’s optional for geolocation; without it, country data is "Unknown."

= How do I enable CAPTCHA? =
Enable it and add reCAPTCHA keys from Google.

= What is rate limiting? =
It restricts login attempts within a time frame (configurable).

= How does threat intelligence work? =
It uses AbuseIPDB to auto-ban high-risk IPs (requires API key).

== Screenshots ==

1. **Settings Page**: Configure protection settings.
2. **Dashboard Widget**: Daily blocked attempts and top IPs.
3. **IP Logs & Map**: Logs and geolocation map of banned IPs.
4. **Manage IPs**: Ban/unban IPs manually.
5. **Login Form Feedback**: Visual cue for banned IP attempts.

== Changelog ==

= 1.1.0 =
* Added real-time email notifications.
* Integrated reCAPTCHA for login protection.
* Implemented rate limiting.
* Added AbuseIPDB threat intelligence.
* Included user agent logging.
* Enabled settings export/import.

= 1.0.3 =
* Added dashboard widget.
* Customizable block message.
* Visual login feedback (shake animation).
* Toggleable debug logs.
* IP whitelist feature.
* Improved settings UI/documentation.

= 1.0.2 =
* Enhanced GeoIP download reliability.
* Fixed auto-update toggle display.

= 1.0.1 =
* Added exploit scan protection.
* Optimized database performance.

= 1.0.0 =
* Initial release with brute force and geolocation.

== Upgrade Notice ==

= 1.1.0 =
Upgrade for notifications, CAPTCHA, rate limiting, threat intelligence, user agent logging, and settings management.

= 1.0.3 =
Upgrade for monitoring tools, user experience enhancements, and advanced options.

== Additional Information ==

- **Support**: [TeckGlobal Support](https://teck-global.com/support/)
- **Source**: [GitHub Repository](https://github.com/teckglobal/teckglobal-brute-force-protect)
- **License**: GPLv2 or later