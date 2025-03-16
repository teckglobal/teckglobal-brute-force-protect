Requires Composer: Install Composer on your server (see [getcomposer.org](https://getcomposer.org/)).
   - Navigate to the plugin directory (`wp-content/plugins/teckglobal-brute-force-protect/`) in a terminal.
   - Run `composer require geoip2/geoip2:~2.0` to install the MaxMind GeoIP2 library. This will create a folder named vendor in the main directory, the folder here is just a empty folder that needs to be populated
5. **Set Up GeoIP Database**:
   - Sign up for a free MaxMind account at [MaxMind](https://dev.maxmind.com/geoip/geoip2/geolite2/).
   - Download `GeoLite2-City.mmdb`.
   - Upload it to your server (e.g., `wp-content/uploads/GeoLite2-City.mmdb`) via FTP or file manager.
   - Go to Settings > Brute Force Protect in WordPress admin and enter the full server path (e.g., `/home/username/public_html/wp-content/uploads/GeoLite2-City.mmdb`).
6. **Configure Settings**:
   - Set max login attempts, ban duration, and enable auto-ban for invalid usernames if desired.
   - Optionally upload a logo via the Settings page.